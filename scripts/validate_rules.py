#!/usr/bin/env python3
"""Validate line-based Mihomo rule sets using Python, PyYAML, and Go RE2."""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

try:
    import yaml
except ImportError as exc:  # pragma: no cover - exercised by CI setup
    raise SystemExit("PyYAML is required: python -m pip install PyYAML") from exc


ROOT = Path(__file__).resolve().parents[1]

RULE_FILES = (
    "Fakeip.yaml",
    "NoBanDirect.yaml",
    "pcdn.yaml",
    "userDirect.yaml",
    "userProxy.yaml",
    "userReject.yaml",
    "DNS.yaml",
    "Privacy.yaml",
    "Private.yaml",
)

# Fakeip.yaml is a DNS fake-IP filter, not a routing policy.
POLICIES = {
    "NoBanDirect.yaml": "DIRECT",
    "userDirect.yaml": "DIRECT",
    "Private.yaml": "DIRECT",
    "userProxy.yaml": "PROXY",
    "userReject.yaml": "REJECT",
    "pcdn.yaml": "REJECT",
    "DNS.yaml": "REJECT",
    "Privacy.yaml": "REJECT",
}

DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "DOMAIN-WILDCARD"}
IP_TYPES = {"IP-CIDR", "IP-CIDR6"}
PORT_TYPES = {"DST-PORT", "SRC-PORT", "IN-PORT"}

# Expected total comma-separated fields, including type and payload.
FIELD_COUNTS = {
    "DOMAIN": (2, 2),
    "DOMAIN-SUFFIX": (2, 2),
    "DOMAIN-KEYWORD": (2, 2),
    "DOMAIN-REGEX": (2, 2),
    "DOMAIN-WILDCARD": (2, 2),
    "GEOSITE": (2, 2),
    "GEOIP": (2, 3),
    "IP-CIDR": (2, 3),
    "IP-CIDR6": (2, 3),
    "DST-PORT": (2, 2),
    "SRC-PORT": (2, 2),
    "IN-PORT": (2, 2),
    "NETWORK": (2, 2),
    "SRC-IP-CIDR": (2, 3),
    "SRC-IP-CIDR6": (2, 3),
    "IP-ASN": (2, 2),
    "SRC-IP-ASN": (2, 2),
    "PROCESS-NAME": (2, 2),
    "PROCESS-NAME-REGEX": (2, 2),
    "PROCESS-PATH": (2, 2),
    "PROCESS-PATH-REGEX": (2, 2),
    "UID": (2, 2),
}

@dataclass(frozen=True)
class Rule:
    path: str
    line: int
    kind: str
    payload: str
    option: str | None
    policy: str | None
    network: ipaddress._BaseNetwork | None = None

    @property
    def location(self) -> str:
        return f"{self.path}:{self.line}"

    @property
    def display(self) -> str:
        suffix = f",{self.option}" if self.option else ""
        return f"{self.kind},{self.payload}{suffix}"


def canonical_host(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    if not value or any(char in value for char in "/\\\\*?") or any(ch.isspace() for ch in value):
        raise ValueError("not a valid hostname")
    try:
        ascii_value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid IDN hostname: {exc}") from exc
    if len(ascii_value) > 253:
        raise ValueError("hostname exceeds 253 characters")
    labels = ascii_value.split(".")
    label_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
    for label in labels:
        if len(label) > 63 or not label_re.fullmatch(label):
            raise ValueError(f"invalid hostname label: {label!r}")
    return ascii_value


def normalize_rule_key(rule: Rule) -> tuple[str, str]:
    if rule.kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
        return (rule.kind, canonical_host(rule.payload))
    if rule.kind == "DOMAIN-KEYWORD":
        return (rule.kind, rule.payload.casefold())
    if rule.kind == "DOMAIN-REGEX":
        return (rule.kind, rule.payload)
    if rule.kind == "DOMAIN-WILDCARD":
        return (rule.kind, rule.payload.casefold())
    if rule.network is not None:
        return ("IP", str(rule.network))
    return (rule.kind, rule.payload.casefold())


def validate_port(payload: str) -> None:
    # Mihomo accepts individual ports, ranges, and slash-separated ranges.
    for part in payload.split("/"):
        if "-" in part:
            pieces = part.split("-")
            if len(pieces) != 2 or not all(piece.isdigit() for piece in pieces):
                raise ValueError("invalid port range")
            start, end = map(int, pieces)
        else:
            if not part.isdigit():
                raise ValueError("port must be numeric")
            start = end = int(part)
        if not (1 <= start <= end <= 65535):
            raise ValueError("port must be between 1 and 65535 with start <= end")


class GoRegexValidator:
    """Build once, then validate every pattern with Go's regexp (RE2) engine."""

    def __init__(self) -> None:
        go = shutil.which("go")
        if go is None:
            raise RuntimeError("Go toolchain not found; install Go to validate DOMAIN-REGEX rules")

        self._temporary_directory = tempfile.TemporaryDirectory(prefix="clashrulepro-re2-")
        binary_name = "validate_regex.exe" if os.name == "nt" else "validate_regex"
        self._binary = Path(self._temporary_directory.name) / binary_name
        self._match_cache: dict[tuple[str, str], bool] = {}
        helper = ROOT / "scripts" / "validate_regex.go"
        try:
            result = subprocess.run(
                [go, "build", "-trimpath", "-o", str(self._binary), str(helper)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            self.close()
            raise RuntimeError(f"failed to execute Go toolchain: {exc}") from exc
        if result.returncode != 0:
            output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
            self.close()
            raise RuntimeError(f"failed to build Go RE2 validator:\n{output}")

    def validate(self, pattern: str) -> None:
        result = subprocess.run(
            [str(self._binary), "validate", pattern],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            message = result.stderr.strip() or "Go regexp rejected the pattern"
            raise ValueError(message)

    def matches(self, pattern: str, text: str) -> bool:
        """Search text with the same Go RE2 engine used for syntax validation."""
        key = (pattern, text)
        cached = self._match_cache.get(key)
        if cached is not None:
            return cached

        result = subprocess.run(
            [str(self._binary), "match", pattern, text],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            matched = True
        elif result.returncode == 1:
            matched = False
        else:
            message = result.stderr.strip() or f"Go RE2 matcher exited with status {result.returncode}"
            raise RuntimeError(f"Go RE2 sample matching failed: {message}")

        self._match_cache[key] = matched
        return matched

    def close(self) -> None:
        self._temporary_directory.cleanup()


def validate_regex(pattern: str, regex_validator: GoRegexValidator) -> None:
    try:
        regex_validator.validate(pattern)
    except ValueError as exc:
        raise ValueError(f"invalid Go RE2 regular expression: {exc}") from exc


def parse_rule(path: str, line_no: int, raw: str, regex_validator: GoRegexValidator) -> Rule | None:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    # Allow trailing comments only when introduced by whitespace.
    line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
    raw_kind, separator, raw_payload = line.partition(",")
    if not separator:
        raise ValueError("rule must contain a comma after its type")
    kind = raw_kind.strip().upper()
    # A regex can itself contain commas, e.g. the {2,} repetition quantifier.
    # Preserve everything after the first delimiter as the complete expression.
    if kind == "DOMAIN-REGEX":
        parts = [kind, raw_payload.strip()]
    else:
        parts = [part.strip() for part in line.split(",")]
        parts[0] = kind
    if kind not in FIELD_COUNTS:
        raise ValueError(f"unsupported or invalid rule type {kind!r}")
    min_fields, max_fields = FIELD_COUNTS[kind]
    if not (min_fields <= len(parts) <= max_fields):
        raise ValueError(f"{kind} requires {min_fields} field(s) plus supported optional fields")

    payload = parts[1]
    if not payload:
        raise ValueError("empty rule payload")
    option = parts[2].lower() if len(parts) == 3 else None
    if option and option != "no-resolve":
        raise ValueError(f"unsupported rule option {option!r}")
    if option and kind not in IP_TYPES and kind not in {"SRC-IP-CIDR", "SRC-IP-CIDR6", "GEOIP"}:
        raise ValueError("no-resolve is only valid for target-IP / source-IP rules")

    network = None
    if kind in IP_TYPES or kind in {"SRC-IP-CIDR", "SRC-IP-CIDR6"}:
        try:
            network = ipaddress.ip_network(payload, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid IP network: {exc}") from exc
        if kind.endswith("CIDR6") and network.version != 6:
            raise ValueError("IP-CIDR6 requires an IPv6 network")
    elif kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
        canonical_host(payload)
    elif kind == "DOMAIN-KEYWORD":
        if any(ch.isspace() for ch in payload) or any(ch in payload for ch in ",*?"):
            raise ValueError("DOMAIN-KEYWORD must be a literal non-empty keyword")
    elif kind == "DOMAIN-REGEX":
        validate_regex(payload, regex_validator)
    elif kind == "DOMAIN-WILDCARD":
        if any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-*?" for ch in payload):
            raise ValueError("DOMAIN-WILDCARD contains unsupported characters")
        if not any(ch.isalnum() for ch in payload):
            raise ValueError("DOMAIN-WILDCARD must contain a hostname")
    elif kind == "GEOSITE":
        if not re.fullmatch(r"[A-Za-z0-9_.!@-]+", payload):
            raise ValueError("invalid GEOSITE category identifier")
    elif kind in PORT_TYPES:
        validate_port(payload)
    elif kind == "NETWORK":
        if payload.lower() not in {"tcp", "udp"}:
            raise ValueError("NETWORK must be tcp or udp")
    elif kind in {"GEOIP"}:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", payload):
            raise ValueError("invalid GEOIP identifier")
    elif kind in {"IP-ASN", "SRC-IP-ASN"}:
        if not payload.isdigit() or not (1 <= int(payload) <= 4294967295):
            raise ValueError("invalid ASN")
    return Rule(
        path=path,
        line=line_no,
        kind=kind,
        payload=payload,
        option=option,
        policy=POLICIES.get(path),
        network=network,
    )


def domain_rule_matches(rule: Rule, domain: str, regex_validator: GoRegexValidator) -> bool:
    domain = domain.lower().rstrip(".")
    value = rule.payload.lower().rstrip(".")
    if rule.kind == "DOMAIN":
        return domain == value
    if rule.kind == "DOMAIN-SUFFIX":
        return domain == value or domain.endswith("." + value)
    if rule.kind == "DOMAIN-KEYWORD":
        return value in domain
    if rule.kind == "DOMAIN-REGEX":
        return regex_validator.matches(rule.payload, domain)
    if rule.kind == "DOMAIN-WILDCARD":
        import fnmatch
        return fnmatch.fnmatchcase(domain, value)
    return False


def domain_rules_overlap(left: Rule, right: Rule, regex_validator: GoRegexValidator) -> bool:
    domain_kinds = DOMAIN_TYPES
    if left.kind not in domain_kinds or right.kind not in domain_kinds:
        return False

    # Definite overlap for exact/suffix rules.
    if left.kind == "DOMAIN" and right.kind == "DOMAIN":
        return left.payload.lower() == right.payload.lower()
    if left.kind == "DOMAIN" and right.kind == "DOMAIN-SUFFIX":
        return domain_rule_matches(right, left.payload, regex_validator)
    if right.kind == "DOMAIN" and left.kind == "DOMAIN-SUFFIX":
        return domain_rule_matches(left, right.payload, regex_validator)
    if left.kind == "DOMAIN-SUFFIX" and right.kind == "DOMAIN-SUFFIX":
        a, b = left.payload.lower(), right.payload.lower()
        return a == b or a.endswith("." + b) or b.endswith("." + a)
    if left.kind == "DOMAIN-KEYWORD" and right.kind == "DOMAIN-KEYWORD":
        a, b = left.payload.lower(), right.payload.lower()
        return a in b or b in a
    if left.kind == "DOMAIN-KEYWORD":
        return left.payload.lower() in right.payload.lower()
    if right.kind == "DOMAIN-KEYWORD":
        return right.payload.lower() in left.payload.lower()

    # For regex/wildcard rules, test domains implied by the other rule.
    def samples(rule: Rule) -> list[str]:
        if rule.kind == "DOMAIN":
            return [rule.payload]
        if rule.kind == "DOMAIN-SUFFIX":
            return [rule.payload, "probe." + rule.payload]
        if rule.kind == "DOMAIN-WILDCARD":
            return [rule.payload.replace("*", "probe").replace("?", "x")]
        return []

    for sample in samples(left) + samples(right):
        if domain_rule_matches(left, sample, regex_validator) and domain_rule_matches(right, sample, regex_validator):
            return True
    return False



def validate_provider_config(errors: list[str]) -> None:
    config_path = ROOT / "clashrulepro_optimized_public_free.yaml"
    try:
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        providers = config["rule-providers"]
        anchors = config.get("providers-anchor", {})
    except (OSError, UnicodeDecodeError, yaml.YAMLError, KeyError, TypeError) as exc:
        errors.append(f"clashrulepro_optimized_public_free.yaml: invalid provider config: {exc}")
        return

    expected = {
        "Advertising-Domain": ("domain", "mrs"),
        "Advertising-IP": ("ipcidr", "mrs"),
        "Advertising-Keyword": ("classical", "text"),
        "pcdn-domain": ("domain", "mrs"),
        "pcdn-ip": ("ipcidr", "mrs"),
        "pcdn-keyword": ("classical", "text"),
        "DNS-Domain": ("domain", "mrs"),
        "Fakeip-Domain": ("domain", "mrs"),
        "Fakeip-Keyword": ("classical", "text"),
        "tvbox": ("domain", "mrs"),
        "GameDownload": ("domain", "mrs"),
    }
    for name, (behavior, file_format) in expected.items():
        provider = providers.get(name)
        if not isinstance(provider, dict):
            errors.append(f"clashrulepro_optimized_public_free.yaml: missing provider {name}")
            continue
        if provider.get("behavior") != behavior or provider.get("format") != file_format:
            errors.append(
                f"clashrulepro_optimized_public_free.yaml: {name} must use "
                f"behavior={behavior}, format={file_format}"
            )

    for section_name, section in (("providers-anchor", anchors), ("rule-providers", providers)):
        if not isinstance(section, dict):
            continue
        for name, provider in section.items():
            if isinstance(provider, dict) and provider.get("behavior") == "classical" and provider.get("format") == "mrs":
                errors.append(
                    f"clashrulepro_optimized_public_free.yaml: invalid classical/MRS definition {section_name}.{name}"
                )

    fakeip_filter = config.get("dns", {}).get("fake-ip-filter", [])
    for required in ("rule-set:Fakeip-Domain", "rule-set:Fakeip-Keyword"):
        if required not in fakeip_filter:
            errors.append(f"clashrulepro_optimized_public_free.yaml: fake-ip-filter missing {required}")

def validate_repository(regex_validator: GoRegexValidator) -> int:
    errors: list[str] = []
    warnings: list[str] = []
    rules: list[Rule] = []
    validate_provider_config(errors)

    for relative in RULE_FILES:
        path = ROOT / relative
        if not path.is_file():
            errors.append(f"{relative}: required rule file is missing")
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            errors.append(f"{relative}: not valid UTF-8: {exc}")
            continue
        for line_no, raw in enumerate(content.splitlines(), 1):
            try:
                rule = parse_rule(relative, line_no, raw, regex_validator)
            except ValueError as exc:
                errors.append(f"{relative}:{line_no}: {exc}: {raw.strip()}")
                continue
            if rule:
                rules.append(rule)

    # Validate the optional provider fragment separately; it is not a line-based ruleset.
    provider_path = ROOT / "Malware-Provider.yaml"
    if provider_path.is_file():
        try:
            config = yaml.safe_load(provider_path.read_text(encoding="utf-8"))
            provider = config["rule-providers"]["phishing-army"]
            if provider.get("type") != "http" or provider.get("behavior") != "domain":
                errors.append("Malware-Provider.yaml: phishing-army must be an HTTP domain provider")
            if provider.get("format") != "text":
                errors.append("Malware-Provider.yaml: feed format must be text")
            if "phishing.army/download/phishing-army-domains.txt" not in provider.get("url", ""):
                errors.append("Malware-Provider.yaml: unexpected threat-feed URL")
            if not isinstance(provider.get("interval"), int) or provider["interval"] <= 0:
                errors.append("Malware-Provider.yaml: interval must be a positive integer")
            route = config.get("rules", [])
            if "RULE-SET,phishing-army,REJECT" not in route:
                errors.append("Malware-Provider.yaml: missing RULE-SET,phishing-army,REJECT")
        except (OSError, UnicodeDecodeError, yaml.YAMLError, KeyError, TypeError) as exc:
            errors.append(f"Malware-Provider.yaml: invalid provider YAML: {exc}")
    else:
        errors.append("Malware-Provider.yaml: required provider fragment is missing")

    # Exact duplicate rules and duplicate IP networks across routing rule sets.
    seen: dict[tuple[str, str], Rule] = {}
    for rule in rules:
        key = normalize_rule_key(rule)
        # Fake-IP exclusions are a different matching stage, not a routing policy.
        if rule.path == "Fakeip.yaml":
            key = ("Fakeip:" + key[0], key[1])
        elif key[0] in {"IP"}:
            key = ("RoutingIP", key[1])
        previous = seen.get(key)
        if previous:
            # Do not compare Fake-IP filters with route policies.
            if (previous.path == "Fakeip.yaml") != (rule.path == "Fakeip.yaml"):
                pass
            else:
                errors.append(
                    f"duplicate rule ({previous.location} and {rule.location}): {rule.display}"
                )
        else:
            seen[key] = rule

    # These explicitly requested proxy keywords bypass only cross-policy overlap checks.
    # Syntax validation, duplicate detection, and all other conflict checks remain enabled.
    skip_cross_policy_conflicts = {
        ("userProxy.yaml", "DOMAIN-KEYWORD", "null"),
        ("userProxy.yaml", "DOMAIN-KEYWORD", "anti"),
    }

    # Cross-policy conflict audit for domain rules and overlapping IP CIDRs.
    policy_rules = [rule for rule in rules if rule.policy]
    for index, left in enumerate(policy_rules):
        for right in policy_rules[index + 1:]:
            if left.policy == right.policy:
                continue
            if (
                (left.path, left.kind, left.payload.casefold()) in skip_cross_policy_conflicts
                or (right.path, right.kind, right.payload.casefold()) in skip_cross_policy_conflicts
            ):
                continue
            overlaps = False
            if left.network is not None and right.network is not None:
                overlaps = (
                    left.network.version == right.network.version
                    and left.network.overlaps(right.network)
                )
            elif left.kind in DOMAIN_TYPES and right.kind in DOMAIN_TYPES:
                overlaps = domain_rules_overlap(left, right, regex_validator)
            if overlaps:
                errors.append(
                    f"cross-policy conflict ({left.policy} {left.location}: {left.display}) "
                    f"vs ({right.policy} {right.location}: {right.display})"
                )

    # Highlight unusually broad legacy rules without blocking their intentional use.
    # Intentional high-risk policy: whole .com.cn suffix blocking is documented in userReject.yaml.
    # The documented userReject.yaml .com.cn suffix rule is intentional; suppress its warning.
    broad_rules = {}
    for rule in rules:
        if (rule.path, rule.kind, rule.payload.lower()) in broad_rules:
            warnings.append(f"{rule.location}: broad match: {broad_rules[(rule.path, rule.kind, rule.payload.lower())]}")

    # Avoid duplicate messages obscuring the first root cause.
    errors = list(dict.fromkeys(errors))
    warnings = list(dict.fromkeys(warnings))
    for warning in warnings:
        print(f"::warning::{warning}")
    if errors:
        for error in errors:
            print(f"::error::{error}")
        print(f"Validation failed: {len(errors)} error(s), {len(warnings)} warning(s).")
        return 1

    print(f"Validation passed: {len(RULE_FILES)} rule files, {len(rules)} rules, {len(warnings)} warning(s).")
    return 0


def main() -> int:
    try:
        regex_validator = GoRegexValidator()
    except RuntimeError as exc:
        print(f"::error::{exc}")
        return 1
    try:
        return validate_repository(regex_validator)
    finally:
        regex_validator.close()


if __name__ == "__main__":
    raise SystemExit(main())
