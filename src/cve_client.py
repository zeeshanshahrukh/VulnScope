"""
VulnScope - CVE / NVD Intelligence Module (Phase 3)

Takes product/version pairs (typically from ShodanResult.services) and
looks up matching CVEs in the NVD API. Also resolves CVE IDs directly
(used both for direct CVE-ID targets and for CVEs Shodan already flags),
so nothing is looked up twice.

Raw NVD response fragments are preserved on each finding for traceability,
same pattern as shodan_client.py.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

try:
    import requests
except ImportError:
    requests = None

logger = logging.getLogger("vulnscope.cve_client")

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD rate limits: 5 req/30s without a key, 50 req/30s with one.
# We stay comfortably under both by spacing calls out.
_MIN_INTERVAL_NO_KEY = 6.5
_MIN_INTERVAL_WITH_KEY = 0.7


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------

class CVEClientError(Exception):
    """Base error for CVE client failures."""


class CVENotConfiguredError(CVEClientError):
    """Raised when the 'requests' library isn't installed."""


class CVERateLimitError(CVEClientError):
    """Raised when NVD responds with a rate-limit status."""


# --------------------------------------------------------------------------
# Normalized result shape
# --------------------------------------------------------------------------

@dataclass
class CVEFinding:
    cve_id: str
    cvss_score: float | None
    severity: str | None
    description: str
    published: str | None
    source: str  # "nvd-search" | "nvd-lookup" | "shodan-flagged"
    raw: dict = field(default_factory=dict)


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------

class CVEClient:
    def __init__(self, api_key: str | None = None):
        if requests is None:
            raise CVENotConfiguredError(
                "The 'requests' package is not installed. Run: pip install requests"
            )
        self._api_key = api_key
        self._min_interval = _MIN_INTERVAL_WITH_KEY if api_key else _MIN_INTERVAL_NO_KEY
        self._last_call = 0.0

    def _headers(self) -> dict:
        return {"apiKey": self._api_key} if self._api_key else {}

    def _throttle(self) -> None:
        elapsed = time.time() - self._last_call
        wait = self._min_interval - elapsed
        if wait > 0:
            time.sleep(wait)

    def _get(self, params: dict) -> dict:
        self._throttle()
        try:
            resp = requests.get(NVD_BASE_URL, params=params, headers=self._headers(), timeout=20)
        except requests.RequestException as exc:
            raise CVEClientError(f"Network error contacting NVD: {exc}") from exc
        finally:
            self._last_call = time.time()

        if resp.status_code == 403 or resp.status_code == 429:
            raise CVERateLimitError(
                "NVD API rate limit hit. Wait 30s and retry, or add NVD_API_KEY to your .env "
                "for a much higher limit."
            )
        if resp.status_code != 200:
            raise CVEClientError(f"NVD API returned {resp.status_code}: {resp.text[:200]}")

        return resp.json()

    def search_by_product(self, product: str, version: str | None = None, max_results: int = 10) -> list[CVEFinding]:
        """Keyword search NVD for a product (+ optional version)."""
        if not product:
            return []

        keyword = f"{product} {version}".strip() if version else product
        params = {"keywordSearch": keyword, "resultsPerPage": max_results}

        try:
            data = self._get(params)
        except CVEClientError:
            raise

        findings = []
        for item in data.get("vulnerabilities", []):
            finding = self._normalize_cve_item(item, source="nvd-search")
            if finding:
                findings.append(finding)
        return findings

    def get_by_id(self, cve_id: str) -> CVEFinding | None:
        """Look up a single CVE by ID (used for direct CVE targets and Shodan-flagged CVEs)."""
        params = {"cveId": cve_id.upper()}
        data = self._get(params)

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            logger.warning("No NVD record found for %s", cve_id)
            return None

        return self._normalize_cve_item(vulns[0], source="nvd-lookup")

    @staticmethod
    def _normalize_cve_item(item: dict, source: str) -> CVEFinding | None:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            return None

        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            (descriptions[0]["value"] if descriptions else "No description available."),
        )

        metrics = cve.get("metrics", {})
        cvss_score, severity = CVEClient._extract_cvss(metrics)

        return CVEFinding(
            cve_id=cve_id,
            cvss_score=cvss_score,
            severity=severity,
            description=description,
            published=cve.get("published"),
            source=source,
            raw=item,
        )

    @staticmethod
    def _extract_cvss(metrics: dict) -> tuple[float | None, str | None]:
        # Prefer newest CVSS version available.
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = entries[0].get("baseSeverity") or cvss_data.get("baseSeverity")
                return score, severity
        return None, None


# --------------------------------------------------------------------------
# Merge helper: combine Shodan-flagged CVE IDs with product/version search
# --------------------------------------------------------------------------

def gather_cves_for_shodan_result(client: CVEClient, shodan_result) -> list[CVEFinding]:
    """
    Given a ShodanResult, look up:
      1. CVEs Shodan already flags directly (fast, precise)
      2. CVEs matching each service's product/version (broader net)
    Deduplicated by CVE ID, Shodan-flagged entries take priority if both find the same ID.
    """
    findings: dict[str, CVEFinding] = {}

    for cve_id in shodan_result.vulns:
        try:
            finding = client.get_by_id(cve_id)
        except CVEClientError as exc:
            logger.warning("Could not resolve Shodan-flagged %s: %s", cve_id, exc)
            continue
        if finding:
            finding.source = "shodan-flagged"
            findings[finding.cve_id] = finding

    for service in shodan_result.services:
        if not service.product:
            continue
        try:
            results = client.search_by_product(service.product, service.version)
        except CVEClientError as exc:
            logger.warning(
                "CVE search failed for %s %s: %s", service.product, service.version or "", exc
            )
            continue
        for finding in results:
            findings.setdefault(finding.cve_id, finding)

    # Sort by CVSS score descending (unscored last)
    return sorted(
        findings.values(),
        key=lambda f: (f.cvss_score is None, -(f.cvss_score or 0)),
    )


def format_cves_terminal(findings: list[CVEFinding]) -> str:
    if not findings:
        return "No CVEs found."

    lines = ["Known CVEs:"]
    for f in findings:
        score = f"{f.cvss_score}" if f.cvss_score is not None else "-"
        severity = f.severity or "-"
        lines.append(f"  - {f.cve_id}  CVSS {score} ({severity})  [{f.source}]")
        lines.append(f"      {f.description[:160]}{'...' if len(f.description) > 160 else ''}")
    return "\n".join(lines)