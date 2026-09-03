"""
VulnScope - Shodan Discovery Module (Phase 2)

Wraps the Shodan API for host lookups and DNS resolution, and normalizes
the raw response into a consistent internal shape so downstream modules
(CVE correlation, VirusTotal, reporting) don't need to know anything
about Shodan's response format.

Raw API responses are always preserved alongside normalized fields —
scoring/correlation later needs to trace a finding back to its evidence.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

try:
    import shodan
except ImportError:
    shodan = None

logger = logging.getLogger("vulnscope.shodan_client")


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------

class ShodanClientError(Exception):
    """Base error for Shodan client failures."""


class ShodanNotConfiguredError(ShodanClientError):
    """Raised when no API key is available or the library isn't installed."""


class ShodanNoResultsError(ShodanClientError):
    """Raised when Shodan has no data for the given target."""


class ShodanRateLimitError(ShodanClientError):
    """Raised when the Shodan API rate limit is hit."""


# --------------------------------------------------------------------------
# Normalized result shape
# --------------------------------------------------------------------------

@dataclass
class ServiceFinding:
    port: int
    transport: str
    product: str | None
    version: str | None
    banner: str | None


@dataclass
class ShodanResult:
    ip: str
    hostnames: list[str]
    org: str | None
    isp: str | None
    country: str | None
    os: str | None
    open_ports: list[int]
    services: list[ServiceFinding]
    tags: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)  # CVE IDs Shodan already flags, if any
    raw: dict = field(default_factory=dict)          # untouched original API response


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------

class ShodanClient:
    def __init__(self, api_key: str | None):
        if shodan is None:
            raise ShodanNotConfiguredError(
                "The 'shodan' package is not installed. Run: pip install shodan"
            )
        if not api_key:
            raise ShodanNotConfiguredError(
                "No SHODAN_API_KEY found. Add it to your .env file."
            )
        self._api = shodan.Shodan(api_key)

    def lookup_ip(self, ip: str) -> ShodanResult:
        """Look up a single IP via Shodan's host endpoint."""
        try:
            raw = self._api.host(ip)
        except shodan.exception.APIError as exc:
            message = str(exc).lower()
            if "no information available" in message or "not found" in message:
                raise ShodanNoResultsError(f"Shodan has no data for {ip}.") from exc
            if "rate limit" in message or "too many requests" in message:
                raise ShodanRateLimitError(
                    "Shodan API rate limit hit. Wait and retry, or upgrade your plan."
                ) from exc
            raise ShodanClientError(f"Shodan API error for {ip}: {exc}") from exc
        except Exception as exc:  # network errors, timeouts, etc.
            raise ShodanClientError(f"Unexpected error querying Shodan for {ip}: {exc}") from exc

        return self._normalize_host(raw)

    def resolve_hostname(self, hostname: str) -> ShodanResult:
        """Resolve a domain/hostname to an IP via Shodan DNS, then look it up."""
        try:
            resolved = self._api.dns.resolve(hostname)
        except Exception as exc:
            raise ShodanClientError(f"Failed to resolve '{hostname}' via Shodan DNS: {exc}") from exc

        ip = resolved.get(hostname)
        if not ip:
            raise ShodanNoResultsError(f"Could not resolve '{hostname}' to an IP address.")

        logger.info("Resolved %s -> %s", hostname, ip)
        return self.lookup_ip(ip)

    @staticmethod
    def _normalize_host(raw: dict) -> ShodanResult:
        services = []
        for item in raw.get("data", []):
            services.append(
                ServiceFinding(
                    port=item.get("port"),
                    transport=item.get("transport", "tcp"),
                    product=item.get("product"),
                    version=item.get("version"),
                    banner=(item.get("data") or "").strip()[:500] or None,
                )
            )

        return ShodanResult(
            ip=raw.get("ip_str", ""),
            hostnames=raw.get("hostnames", []),
            org=raw.get("org"),
            isp=raw.get("isp"),
            country=raw.get("country_name"),
            os=raw.get("os"),
            open_ports=raw.get("ports", []),
            services=services,
            tags=raw.get("tags", []),
            vulns=sorted(raw.get("vulns", [])) if raw.get("vulns") else [],
            raw=raw,
        )


# --------------------------------------------------------------------------
# Convenience formatting for terminal output (Phase 1's --output terminal)
# --------------------------------------------------------------------------

def format_result_terminal(result: ShodanResult) -> str:
    lines = [
        f"IP:         {result.ip}",
        f"Hostnames:  {', '.join(result.hostnames) or '-'}",
        f"Org / ISP:  {result.org or '-'} / {result.isp or '-'}",
        f"Country:    {result.country or '-'}",
        f"OS:         {result.os or '-'}",
        f"Open ports: {', '.join(str(p) for p in result.open_ports) or '-'}",
    ]

    if result.vulns:
        lines.append(f"Shodan-flagged CVEs: {', '.join(result.vulns)}")

    if result.services:
        lines.append("Services:")
        for svc in result.services:
            product = svc.product or "unknown"
            version = f" {svc.version}" if svc.version else ""
            lines.append(f"  - {svc.port}/{svc.transport}: {product}{version}")

    return "\n".join(lines)