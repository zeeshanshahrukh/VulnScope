#!/usr/bin/env python3
"""
VulnScope - Vulnerability Intelligence & Attack Surface Research Tool

Phase 1 - Foundation:
    CLI entry point, target parsing/validation, config loading, logging.
    No external API calls happen yet — that's Phase 2+.
"""

import argparse
import ipaddress
import logging
import os
import re
import sys
from dataclasses import dataclass
from enum import Enum

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


# --------------------------------------------------------------------------
# Target type detection
# --------------------------------------------------------------------------

class TargetType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    TECHNOLOGY = "technology"
    CVE = "cve"
    UNKNOWN = "unknown"


CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# Very rough domain/hostname pattern: labels separated by dots, valid chars only.
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)

# Technology strings are free-form (e.g. "Apache 2.4.49", "OpenSSH"),
# so we treat "doesn't match anything else, but looks like a product name"
# as the technology fallback rather than trying to whitelist every product.
TECHNOLOGY_HINT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+-]{1,127}$")


@dataclass
class Target:
    raw: str
    normalized: str
    type: TargetType


def detect_target_type(raw: str) -> TargetType:
    """Classify a raw input string as IP, domain/hostname, CVE, or technology."""
    value = raw.strip()

    if not value:
        return TargetType.UNKNOWN

    # CVE ID
    if CVE_PATTERN.match(value):
        return TargetType.CVE

    # IPv4 / IPv6
    try:
        ipaddress.ip_address(value)
        return TargetType.IP
    except ValueError:
        pass

    # Domain vs. bare hostname: a domain has at least one dot with a
    # plausible TLD; a bare hostname (e.g. "labhost") has none.
    if DOMAIN_PATTERN.match(value):
        return TargetType.DOMAIN if "." in value else TargetType.HOSTNAME

    if re.match(r"^[A-Za-z0-9-]{1,63}$", value):
        return TargetType.HOSTNAME

    # Fall back to "technology" only if it's a reasonable free-text string.
    if TECHNOLOGY_HINT_PATTERN.match(value):
        return TargetType.TECHNOLOGY

    return TargetType.UNKNOWN


def normalize_target(raw: str, target_type: TargetType) -> str:
    """Apply light normalization per target type."""
    value = raw.strip()

    if target_type == TargetType.CVE:
        return value.upper()
    if target_type in (TargetType.DOMAIN, TargetType.HOSTNAME):
        return value.lower()
    if target_type == TargetType.IP:
        return str(ipaddress.ip_address(value))
    return value


def validate_target(raw: str) -> Target:
    """
    Validate and classify a single target string.
    Raises ValueError with a human-readable message on failure.
    """
    target_type = detect_target_type(raw)

    if target_type == TargetType.UNKNOWN:
        raise ValueError(
            f"Could not classify '{raw}' as an IP, domain, hostname, "
            f"technology, or CVE ID. Check for typos or unsupported formats."
        )

    normalized = normalize_target(raw, target_type)
    return Target(raw=raw, normalized=normalized, type=target_type)


# --------------------------------------------------------------------------
# Authorization check (safety boundary from the project brief)
# --------------------------------------------------------------------------

def is_authorized(target: Target, authorized_list: list[str]) -> bool:
    """
    Only IP/domain/hostname targets need explicit authorization —
    CVE and technology lookups are just intelligence queries, not
    scans against a live asset.
    """
    if target.type in (TargetType.CVE, TargetType.TECHNOLOGY):
        return True
    return target.normalized in authorized_list


# --------------------------------------------------------------------------
# Config / logging
# --------------------------------------------------------------------------

def load_config() -> dict:
    if load_dotenv is not None:
        load_dotenv()  # loads .env if present; safe no-op otherwise

    authorized_raw = os.getenv("AUTHORIZED_TARGETS", "")
    authorized_targets = [t.strip() for t in authorized_raw.split(",") if t.strip()]

    return {
        "log_level": os.getenv("LOG_LEVEL", "INFO"),
        "reports_dir": os.getenv("REPORTS_DIR", "reports"),
        "data_dir": os.getenv("DATA_DIR", "data"),
        "db_path": os.getenv("DB_PATH", "data/vulnscope.sqlite3"),
        "authorized_targets": authorized_targets,
        "shodan_api_key": os.getenv("SHODAN_API_KEY"),
        "virustotal_api_key": os.getenv("VIRUSTOTAL_API_KEY"),
        "github_token": os.getenv("GITHUB_TOKEN"),
        "nvd_api_key": os.getenv("NVD_API_KEY"),
    }


def setup_logging(level_name: str) -> logging.Logger:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    return logging.getLogger("vulnscope")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscope",
        description=(
            "VulnScope - correlates passive recon (Shodan), vulnerability "
            "intelligence (CVE/NVD), reputation data (VirusTotal), and public "
            "research (GitHub) into prioritized findings for authorized targets."
        ),
    )
    parser.add_argument(
        "target",
        help="Target to investigate: IP, domain, hostname, technology name, or CVE ID "
             "(e.g. 192.168.1.10, example.com, 'Apache 2.4.49', CVE-2023-12345).",
    )
    parser.add_argument(
        "-o", "--output",
        choices=["terminal", "json"],
        default="terminal",
        help="Report output format (default: terminal). HTML support arrives in a later phase.",
    )
    parser.add_argument(
        "--allow-unauthorized",
        action="store_true",
        help="Skip the authorized-targets check. Use only in lab/dev environments.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug-level logging.",
    )
    return parser


def main(argv=None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    config = load_config()
    if args.verbose:
        config["log_level"] = "DEBUG"
    logger = setup_logging(config["log_level"])

    # --- Validate & classify target ---
    try:
        target = validate_target(args.target)
    except ValueError as exc:
        logger.error(str(exc))
        return 1

    logger.info("Target classified as %s: %s", target.type.value.upper(), target.normalized)

    # --- Authorization boundary ---
    if not args.allow_unauthorized and not is_authorized(target, config["authorized_targets"]):
        logger.error(
            "'%s' is not in AUTHORIZED_TARGETS. Refusing to proceed. "
            "Add it to your .env or pass --allow-unauthorized for lab/dev use.",
            target.normalized,
        )
        return 1

    # --- Placeholder for the pipeline (built out in later phases) ---
    # Phase 2: Shodan collection
    # Phase 3: CVE intelligence
    # Phase 4: VirusTotal correlation
    # Phase 5: GitHub research
    # Phase 6: Reporting
    logger.info(
        "Foundation check passed. Collection/correlation modules are not implemented yet "
        "(Phase 2+). Target is validated and ready to be handed to the pipeline."
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
