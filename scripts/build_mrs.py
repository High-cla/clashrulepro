#!/usr/bin/env python3
"""Build Mihomo MRS providers from remote feeds and local rule files."""

from __future__ import annotations

import argparse
import ipaddress
import re
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "rule_providers"

SOURCES = {
    "advertising": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Advertising/Advertising.list",
    "tvbox": "https://raw.githubusercontent.com/Sfssup/mihomo-set/main/rule_set/direct.yaml",
    "game_download": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Game/GameDownloadCN/GameDownloadCN.list",
}
DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX"}
KEYWORD_TYPES = {"DOMAIN-KEYWORD"}
IP_TYPES = {"IP-CIDR", "IP-CIDR6"}
LOCAL_SUPPORTED_TYPES = DOMAIN_TYPES | KEYWORD_TYPES | IP_TYPES
KNOWN_RULE_TYPES = LOCAL_SUPPORTED_TYPES | {
    "DOMAIN-REGEX", "DOMAIN-WILDCARD", "GEOSITE", "GEOIP",
    "DST-PORT", "SRC-PORT", "IN-PORT", "NETWORK",
    "SRC-IP-CIDR", "SRC-IP-CIDR6", "IP-ASN", "SRC-IP-ASN",
    "PROCESS-NAME", "PROCESS-NAME-REGEX", "PROCESS-PATH",
    "PROCESS-PATH-REGEX", "UID", "RULE-SET", "MATCH",
}
CONFIG_KEYS = {
    "proxy-providers", "proxy-groups", "rule-providers",
    "mixed-port", "dns", "tun", "proxies",
}


def download_text(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "ClashRulePro-MRS-builder/1.0"})
    with urllib.request.urlopen(request, timeout=45) as response:
        return response.read().decode("utf-8-sig")


def unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def parse_line(raw: str) -> tuple[str, str] | None:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
    line = re.sub(r"^-\s*", "", line)
    parts = [item.strip() for item in line.split(",")]
    if len(parts) < 2 or not parts[1]:
        raise ValueError(f"invalid rule line: {raw!r}")
    return parts[0].upper(), parts[1]


def split_classical(text: str) -> tuple[list[str], list[str], list[str]]:
    domains, ips, keywords = [], [], []
    for line_no, raw in enumerate(text.splitlines(), 1):
        parsed = parse_line(raw)
        if parsed is None:
            continue
        kind, value = parsed
        rule = f"{kind},{value}"
        if kind in DOMAIN_TYPES:
            if kind == "DOMAIN":
                try:
                    address = ipaddress.ip_address(value)
                except ValueError:
                    domains.append(value)
                else:
                    prefix = 32 if address.version == 4 else 128
                    ips.append(f"{address}/{prefix}")
            else:
                # DOMAIN-SUFFIX matches both the apex and all subdomains in Mihomo.
                domains.append(f"+.{value}")
        elif kind in KEYWORD_TYPES:
            keywords.append(rule)
        elif kind in IP_TYPES:
            network = ipaddress.ip_network(value, strict=False)
            ips.append(network.with_prefixlen)
        else:
            raise ValueError(f"unsupported rule at line {line_no}: {raw.strip()}")
    return unique(domains), unique(ips), unique(keywords)


def extract_local_rule_lines(source: Path) -> list[str]:
    """Read either a line-based rule list or a YAML payload containing rule strings."""
    content = source.read_text(encoding="utf-8-sig")
    try:
        document = yaml.safe_load(content)
    except yaml.YAMLError:
        document = None

    if isinstance(document, dict):
        payload = document.get("payload")
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, str)]
        # Do not mistake a full Mihomo profile or provider config for a rule list.
        if CONFIG_KEYS.intersection(document):
            return []
    elif isinstance(document, list) and all(isinstance(item, str) for item in document):
        return document

    return content.splitlines()


def split_local_rules(lines: list[str]) -> tuple[list[str], list[str], list[str], int]:
    """Extract MRS-compatible rules and count known rule types MRS cannot represent."""
    domains, ips, keywords = [], [], []
    skipped = 0

    for line_no, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        line = re.sub(r"^-\s*", "", line)
        raw_kind, separator, _ = line.partition(",")
        if not separator:
            continue

        kind = raw_kind.strip().upper()
        if kind not in LOCAL_SUPPORTED_TYPES:
            if kind in KNOWN_RULE_TYPES:
                skipped += 1
            continue

        parsed = parse_line(line)
        if parsed is None:
            continue
        _, value = parsed
        if kind == "DOMAIN":
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                domains.append(value)
            else:
                prefix = 32 if address.version == 4 else 128
                ips.append(f"{address}/{prefix}")
        elif kind == "DOMAIN-SUFFIX":
            domains.append(f"+.{value}")
        elif kind in KEYWORD_TYPES:
            keywords.append(f"{kind},{value}")
        elif kind in IP_TYPES:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid IP rule at line {line_no}: {raw.strip()}: {exc}") from exc
            if kind == "IP-CIDR6" and network.version != 6:
                raise ValueError(f"IP-CIDR6 requires IPv6 at line {line_no}: {raw.strip()}")
            ips.append(network.with_prefixlen)

    return unique(domains), unique(ips), unique(keywords), skipped


def discover_rule_files(source_dir: Path) -> list[Path]:
    """Find YAML rule files recursively, excluding hidden and generated directories."""
    excluded = {".git", ".github", "__pycache__"}
    files = []
    for path in source_dir.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".yaml", ".yml"}:
            continue
        relative = path.relative_to(source_dir)
        if any(part.startswith(".") or part in excluded for part in relative.parts[:-1]):
            continue
        if OUT.resolve() == path.resolve() or OUT.resolve() in path.resolve().parents:
            continue
        files.append(path)
    return sorted(files)


def local_output_prefix(source: Path, source_dir: Path) -> tuple[str, str]:
    relative = source.relative_to(source_dir)
    parts = [*relative.parent.parts, relative.stem]
    safe_parts = [
        re.sub(r"[^A-Za-z0-9._-]+", "-", part).strip("-") or "rules"
        for part in parts
    ]
    prefix = "-".join(safe_parts)
    # Preserve the existing output suffix casing for names such as pcdn.yaml and Fakeip.yaml.
    suffix_style = "lower" if source.stem.islower() else "title"
    return prefix, suffix_style


def remove_configured_providers(stale_filenames: list[str]) -> None:
    """Remove stale local providers and their rule references from the main profile."""
    config_path = ROOT / "clashrulepro_optimized_public_free.yaml"
    if not config_path.is_file():
        return

    content = config_path.read_text(encoding="utf-8")
    try:
        config = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ValueError(f"cannot update providers in {config_path.name}: {exc}") from exc

    providers = config.get("rule-providers", {}) if isinstance(config, dict) else {}
    stale_names = {
        name for name, provider in providers.items()
        if isinstance(provider, dict)
        and Path(str(provider.get("path", ""))).name in set(stale_filenames)
    }
    if not stale_names:
        return

    lines = content.splitlines()
    output = []
    section = None
    skip_provider_block = False
    for line in lines:
        if line and not line[0].isspace() and not line.startswith("#"):
            section = line.partition(":")[0] if line.endswith(":") else None
            skip_provider_block = False

        if section == "rule-providers" and line.startswith("  ") and not line.startswith("    ") and line.strip().endswith(":"):
            provider_name = line.strip()[:-1]
            skip_provider_block = provider_name in stale_names

        if section == "rule-providers" and skip_provider_block:
            continue

        if any(
            re.search(rf"RULE-SET,{re.escape(name)},", line)
            or f"rule-set:{name}" in line
            for name in stale_names
        ):
            continue
        output.append(line)

    updated = "\n".join(output) + ("\n" if content.endswith("\n") else "")
    if updated != content:
        config_path.write_text(updated, encoding="utf-8")
        print(f"Removed stale provider configuration: {', '.join(sorted(stale_names))}")


def build_local_sources(mihomo: Path, source_dir: Path) -> int:
    generated = 0
    processed = 0
    prefixes: dict[str, Path] = {}

    files = discover_rule_files(source_dir)
    if not files:
        print(f"No YAML rule files found in {source_dir}")
        return generated

    for source in files:
        prefix, suffix_style = local_output_prefix(source, source_dir)
        previous = prefixes.get(prefix)
        if previous is not None:
            raise ValueError(f"source filename collision: {previous} and {source} both map to {prefix}")
        prefixes[prefix] = source

        lines = extract_local_rule_lines(source)
        domains, ips, keywords, skipped = split_local_rules(lines)
        if not (domains or ips or keywords):
            if skipped:
                print(f"{source.relative_to(source_dir)}: skipped; no domain/IP/keyword rules (ignored {skipped} unsupported rule(s))")
            continue

        suffixes = (
            ("domain", "ip", "keyword")
            if suffix_style == "lower"
            else ("Domain", "IP", "Keyword")
        )
        domain_suffix, ip_suffix, keyword_suffix = suffixes
        relative = source.relative_to(source_dir)

        expected_outputs = {
            "domain": OUT / f"{prefix}-{domain_suffix}.mrs",
            "ip": OUT / f"{prefix}-{ip_suffix}.mrs",
            "keyword": OUT / f"{prefix}-{keyword_suffix}.txt",
        }
        active_outputs = {
            "domain": bool(domains),
            "ip": bool(ips),
            "keyword": bool(keywords),
        }
        stale_files = []
        for category, destination in expected_outputs.items():
            if not active_outputs[category]:
                if destination.is_file():
                    destination.unlink()
                    stale_files.append(destination.name)
                continue
            if category == "domain":
                convert(mihomo, "domain", "text", "\n".join(domains) + "\n", destination)
            elif category == "ip":
                convert(mihomo, "ipcidr", "text", "\n".join(ips) + "\n", destination)
            else:
                write_text(destination.name, keywords)
            generated += 1

        if stale_files:
            remove_configured_providers(stale_files)

        processed += 1
        summary = f"{relative}: domain={len(domains)}, ip={len(ips)}, keyword={len(keywords)}"
        if skipped:
            summary += f", skipped_unsupported={skipped}"
        print(summary)

    print(f"Discovered {len(files)} YAML file(s); converted {processed} rule source(s) into {generated} provider file(s)")
    return generated


def valid_domain_expression(value: str) -> bool:
    candidate = value.strip().lower()
    if candidate.startswith("+."):
        candidate = candidate[2:]
    if not candidate or "*" in candidate or "?" in candidate or candidate.startswith("."):
        return False
    candidate = candidate.rstrip(".")
    if not candidate or "/" in candidate or any(ch.isspace() for ch in candidate):
        return False
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    if len(candidate) > 253:
        return False
    label_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
    return all(0 < len(label) <= 63 and label_re.fullmatch(label) for label in candidate.split("."))


def convert(mihomo: Path, behavior: str, source_format: str, content: str, destination: Path) -> None:
    if not content.strip():
        raise ValueError(f"refusing to create empty {behavior} MRS: {destination.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    suffix = ".yaml" if source_format == "yaml" else ".txt"
    with tempfile.TemporaryDirectory(prefix="clashrulepro-mrs-") as temp_dir:
        source = Path(temp_dir) / f"source{suffix}"
        output = Path(temp_dir) / destination.name
        source.write_text(content, encoding="utf-8")
        result = subprocess.run(
            [str(mihomo), "convert-ruleset", behavior, source_format, str(source), str(output)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Mihomo conversion failed for {destination.name}:\n{result.stdout}")
        if not output.is_file() or output.stat().st_size == 0:
            raise RuntimeError(f"Mihomo produced no output for {destination.name}")
        shutil.copyfile(output, destination)


def write_text(name: str, lines: list[str]) -> None:
    if not lines:
        raise ValueError(f"refusing to create empty text provider: {name}")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_text("\n".join(lines) + "\n", encoding="utf-8")


def build(mihomo: Path, source_dir: Path) -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    # Advertising: all outputs come from one Blackmatrix7 source feed.
    ads_domains, ads_ips, ads_keywords = split_classical(download_text(SOURCES["advertising"]))
    convert(mihomo, "domain", "text", "\n".join(ads_domains) + "\n", OUT / "Advertising-Domain.mrs")
    convert(mihomo, "ipcidr", "text", "\n".join(ads_ips) + "\n", OUT / "Advertising-IP.mrs")
    write_text("Advertising-Keyword.txt", ads_keywords)

    # TVBox: keep valid domain YAML entries; drop malformed / wildcard-only entries.
    tvbox = yaml.safe_load(download_text(SOURCES["tvbox"]))
    payload = tvbox.get("payload") if isinstance(tvbox, dict) else None
    if not isinstance(payload, list):
        raise ValueError("TVBox upstream YAML has no payload list")
    valid_payload, skipped = [], 0
    for item in payload:
        if isinstance(item, str) and valid_domain_expression(item):
            valid_payload.append(item.strip().lower())
        else:
            skipped += 1
    if skipped:
        print(f"TVBox: skipped {skipped} malformed or wildcard-only payload entries")
    tvbox_yaml = yaml.safe_dump({"payload": unique(valid_payload)}, allow_unicode=True, sort_keys=False)
    convert(mihomo, "domain", "yaml", tvbox_yaml, OUT / "tvbox.mrs")

    # GameDownloadCN source has only DOMAIN / DOMAIN-SUFFIX rules.
    game_domains, _, game_keywords = split_classical(download_text(SOURCES["game_download"]))
    if game_keywords:
        raise ValueError("GameDownloadCN source unexpectedly contains non-domain rule classes")
    convert(mihomo, "domain", "text", "\n".join(game_domains) + "\n", OUT / "GameDownloadCN.mrs")

    # Local rule lists are discovered recursively instead of naming individual files.
    local_generated = build_local_sources(mihomo, source_dir)
    print(f"Generated {5 + local_generated} provider files in {OUT.relative_to(ROOT)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mihomo", required=True, type=Path, help="path to the official Mihomo binary")
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=ROOT,
        help="directory to scan recursively for .yaml/.yml rule files (default: repository root)",
    )
    args = parser.parse_args()
    if not args.mihomo.is_file():
        parser.error(f"Mihomo binary does not exist: {args.mihomo}")
    source_dir = args.source_dir.resolve()
    if not source_dir.is_dir():
        parser.error(f"rule source directory does not exist: {source_dir}")
    build(args.mihomo.resolve(), source_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
