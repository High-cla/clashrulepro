#!/usr/bin/env python3
"""Build local Mihomo MRS providers from source rule feeds and repository text rules."""

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


def build(mihomo: Path) -> None:
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

    # PCDN: separate domain, IP, and keyword rules.
    pcdn_domains, pcdn_ips, pcdn_keywords = split_classical((ROOT / "pcdn.yaml").read_text(encoding="utf-8"))
    convert(mihomo, "domain", "text", "\n".join(pcdn_domains) + "\n", OUT / "pcdn-domain.mrs")
    convert(mihomo, "ipcidr", "text", "\n".join(pcdn_ips) + "\n", OUT / "pcdn-ip.mrs")
    write_text("pcdn-keyword.txt", pcdn_keywords)

    # DNS: domain rules only; no separate DNS-Port provider is generated.
    dns_domains, _, _ = split_classical((ROOT / "DNS.yaml").read_text(encoding="utf-8"))
    convert(mihomo, "domain", "text", "\n".join(dns_domains) + "\n", OUT / "DNS-Domain.mrs")

    # Fake-IP exclusions: domain and keyword providers remain independent.
    fakeip_domains, _, fakeip_keywords = split_classical((ROOT / "Fakeip.yaml").read_text(encoding="utf-8"))
    convert(mihomo, "domain", "text", "\n".join(fakeip_domains) + "\n", OUT / "Fakeip-Domain.mrs")
    write_text("Fakeip-Keyword.txt", fakeip_keywords)

    # GameDownloadCN source has only DOMAIN / DOMAIN-SUFFIX rules.
    game_domains, _, game_keywords = split_classical(download_text(SOURCES["game_download"]))
    if game_keywords:
        raise ValueError("GameDownloadCN source unexpectedly contains non-domain rule classes")
    convert(mihomo, "domain", "text", "\n".join(game_domains) + "\n", OUT / "GameDownloadCN.mrs")

    counts = {
        "Advertising-Domain": len(ads_domains), "Advertising-IP": len(ads_ips),
        "Advertising-Keyword": len(ads_keywords), "tvbox": len(valid_payload),
        "pcdn-domain": len(pcdn_domains), "pcdn-ip": len(pcdn_ips),
        "pcdn-keyword": len(pcdn_keywords), "DNS-Domain": len(dns_domains),
        "Fakeip-Domain": len(fakeip_domains),
        "Fakeip-Keyword": len(fakeip_keywords), "GameDownloadCN": len(game_domains),
    }
    for name, count in counts.items():
        print(f"{name}: {count} rules")
    print(f"Generated {len(counts)} provider files in {OUT.relative_to(ROOT)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mihomo", required=True, type=Path, help="path to the official Mihomo binary")
    args = parser.parse_args()
    if not args.mihomo.is_file():
        parser.error(f"Mihomo binary does not exist: {args.mihomo}")
    build(args.mihomo.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
