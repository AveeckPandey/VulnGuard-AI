"""
VulnGuard AI - NIST NVD Threat Intelligence Service
Fetches vulnerability metadata, CVSS v3.1 metrics, CWEs, and references from NIST NVD API 2.0.
Supports keyless and authenticated rate limits, exponential backoff, and 12-hour caching.
"""
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any
import httpx

from backend.core.config import settings
from backend.core.logging import logger
from backend.core.exceptions import ThreatIntelFetchError, RateLimitExceededError
from backend.schemas.intelligence import NvdIntel, IntelSourceStatus
from backend.services.cache import nvd_cache
from backend.services.rate_limiter import SlidingWindowRateLimiter, calculate_backoff_with_jitter
from backend.tests.fixtures.simulated_intel import SIMULATED_CVE_FIXTURES


class NvdService:
    """Service client for NIST National Vulnerability Database API 2.0."""

    def __init__(self):
        self.rate_limiter = SlidingWindowRateLimiter(
            max_calls=settings.nvd_rate_limit_calls,
            period_seconds=settings.nvd_rate_limit_period
        )

    async def fetch_cve(self, cve_id: str, simulate_offline: bool = False) -> NvdIntel:
        cve_id = cve_id.strip().upper()

        # 1. Check Offline Simulation Mode
        if simulate_offline:
            if cve_id in SIMULATED_CVE_FIXTURES:
                raw = SIMULATED_CVE_FIXTURES[cve_id]["nvd"]
                return NvdIntel(**raw)
            return self._build_simulated_unknown(cve_id)

        # 2. Check In-Memory Cache (12 Hours TTL)
        cached = nvd_cache.get(cve_id)
        if cached:
            logger.info(f"[NVD] Cache hit for {cve_id}")
            return cached

        # 3. Fetch from NIST NVD API 2.0
        headers = {
            "User-Agent": "VulnGuard-AI-Cybersecurity-Platform/1.0"
        }
        if settings.NVD_API_KEY.strip():
            headers["apiKey"] = settings.NVD_API_KEY.strip()

        params = {"cveId": cve_id}
        max_retries = 3

        for attempt in range(max_retries):
            try:
                await self.rate_limiter.acquire()
                logger.info(f"[NVD] Fetching intelligence for {cve_id} (attempt {attempt + 1}/{max_retries})")

                async with httpx.AsyncClient(timeout=settings.NVD_TIMEOUT_SECONDS) as client:
                    response = await client.get(
                        settings.NVD_BASE_URL,
                        headers=headers,
                        params=params
                    )

                if response.status_code == 200:
                    intel = self._parse_nvd_response(cve_id, response.json())
                    nvd_cache.set(cve_id, intel, ttl_seconds=settings.NVD_CACHE_TTL_HOURS * 3600.0)
                    return intel

                if response.status_code == 429:
                    backoff = calculate_backoff_with_jitter(attempt, base_delay=2.0, max_delay=10.0)
                    logger.warning(f"[NVD] Rate limited (429). Retrying in {backoff:.2f}s...")
                    await asyncio.sleep(backoff)
                    continue

                if response.status_code == 404:
                    logger.warning(f"[NVD] {cve_id} not found in NVD database.")
                    return self._build_not_found(cve_id)

                logger.error(f"[NVD] Upstream error {response.status_code}: {response.text[:200]}")
                if attempt == max_retries - 1:
                    break

            except httpx.RequestError as exc:
                logger.warning(f"[NVD] Network error on {cve_id}: {exc}")
                if attempt < max_retries - 1:
                    backoff = calculate_backoff_with_jitter(attempt, base_delay=1.5, max_delay=6.0)
                    await asyncio.sleep(backoff)
                else:
                    break

        # If live fetch fails, return unavailable (never fabricate mock data in live mode)
        return self._build_unavailable(cve_id)

    def _parse_nvd_response(self, cve_id: str, data: Dict[str, Any]) -> NvdIntel:
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return self._build_not_found(cve_id)

        cve_item = vulnerabilities[0].get("cve", {})
        descriptions = cve_item.get("descriptions", [])
        eng_desc = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
        if not eng_desc and descriptions:
            eng_desc = descriptions[0].get("value")

        metrics = cve_item.get("metrics", {})
        cvss_version = None
        cvss_base_score = None
        cvss_severity = None
        cvss_vector = None

        # Prioritize CVSS v4.0, then v3.1, then v3.0, then v2.0
        if "cvssMetricV40" in metrics and metrics["cvssMetricV40"]:
            cvss_data = metrics["cvssMetricV40"][0].get("cvssData", {})
            cvss_version = "4.0"
            cvss_base_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity")
            cvss_vector = cvss_data.get("vectorString")
        elif "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_version = "3.1"
            cvss_base_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity")
            cvss_vector = cvss_data.get("vectorString")
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_version = "3.0"
            cvss_base_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity")
            cvss_vector = cvss_data.get("vectorString")
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
            cvss_version = "2.0"
            cvss_base_score = cvss_data.get("baseScore")
            cvss_severity = metrics["cvssMetricV2"][0].get("baseSeverity")
            cvss_vector = cvss_data.get("vectorString")

        # Weaknesses (CWE)
        weaknesses = []
        for w in cve_item.get("weaknesses", []):
            for d in w.get("description", []):
                val = d.get("value")
                if val and val != "NVD-CWE-Other" and val != "NVD-CWE-noinfo":
                    weaknesses.append(val)

        # References
        refs = [r.get("url") for r in cve_item.get("references", []) if r.get("url")][:8]

        return NvdIntel(
            cve_id=cve_id,
            status=IntelSourceStatus.AVAILABLE,
            description=eng_desc,
            cvss_version=cvss_version,
            cvss_base_score=cvss_base_score,
            cvss_severity=cvss_severity.upper() if cvss_severity else None,
            cvss_vector_string=cvss_vector,
            published_date=cve_item.get("published"),
            last_modified_date=cve_item.get("lastModified"),
            references=refs,
            weaknesses=weaknesses,
            fetched_at=datetime.now(timezone.utc).isoformat(),
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            is_simulated=False,
        )

    def _build_not_found(self, cve_id: str) -> NvdIntel:
        return NvdIntel(
            cve_id=cve_id,
            status=IntelSourceStatus.UNKNOWN_OR_MISSING,
            description="Vulnerability not found in NIST National Vulnerability Database. It may be reserved, rejected, or awaiting primary analysis.",
            cvss_version=None,
            cvss_base_score=None,
            cvss_severity=None,
            cvss_vector_string=None,
            published_date=None,
            last_modified_date=None,
            references=[],
            weaknesses=[],
            fetched_at=datetime.now(timezone.utc).isoformat(),
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            is_simulated=False,
        )

    def _build_unavailable(self, cve_id: str) -> NvdIntel:
        return NvdIntel(
            cve_id=cve_id,
            status=IntelSourceStatus.UNKNOWN_OR_MISSING,
            description="NIST NVD intelligence is temporarily unreachable due to network connectivity or upstream service limits.",
            cvss_version=None,
            cvss_base_score=None,
            cvss_severity=None,
            cvss_vector_string=None,
            published_date=None,
            last_modified_date=None,
            references=[],
            weaknesses=[],
            fetched_at=datetime.now(timezone.utc).isoformat(),
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            is_simulated=False,
        )

    def _build_simulated_unknown(self, cve_id: str) -> NvdIntel:
        return NvdIntel(
            cve_id=cve_id,
            status=IntelSourceStatus.SIMULATED,
            description=f"Simulated test record for {cve_id}.",
            cvss_version="3.1",
            cvss_base_score=5.0,
            cvss_severity="MEDIUM",
            cvss_vector_string="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
            published_date="2026-01-01T00:00:00.000",
            last_modified_date="2026-01-02T00:00:00.000",
            references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
            weaknesses=["CWE-200"],
            fetched_at=datetime.now(timezone.utc).isoformat(),
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            is_simulated=True,
        )


nvd_service = NvdService()
