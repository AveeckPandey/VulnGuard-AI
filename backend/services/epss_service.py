"""
VulnGuard AI - FIRST EPSS Threat Intelligence Service
Fetches Exploit Prediction Scoring System (EPSS) probability and percentile rankings.
Caches scores for 24 hours (scores update daily from FIRST.org).
"""
import asyncio
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any
import httpx

from backend.core.config import settings
from backend.core.logging import logger
from backend.schemas.intelligence import EpssIntel, IntelSourceStatus
from backend.services.cache import epss_cache
from backend.services.rate_limiter import calculate_backoff_with_jitter
from backend.services.simulated_intel import SIMULATED_CVE_FIXTURES


class EpssService:
    """Service client for FIRST.org EPSS API."""

    def __init__(self):
        self.last_status: str = "operational"
        self.last_error: Optional[str] = None
        self.last_check_time: Optional[str] = None

    async def fetch_epss(self, cve_id: str, simulate_offline: bool = False) -> EpssIntel:
        cve_id = cve_id.strip().upper()

        # 1. Offline Simulation Check
        if simulate_offline:
            if cve_id in SIMULATED_CVE_FIXTURES:
                raw = SIMULATED_CVE_FIXTURES[cve_id]["epss"]
                return EpssIntel(**raw)
            return self._build_simulated(cve_id)

        # 2. In-Memory Cache Check (24 Hours TTL)
        cached = epss_cache.get(cve_id)
        if cached:
            logger.info(f"[EPSS] Cache hit for {cve_id}")
            return cached

        # 3. Live API Fetch
        params = {"cve": cve_id}
        max_retries = 3

        for attempt in range(max_retries):
            try:
                logger.info(f"[EPSS] Querying FIRST EPSS for {cve_id} (attempt {attempt + 1})")
                async with httpx.AsyncClient(timeout=settings.EPSS_TIMEOUT_SECONDS) as client:
                    response = await client.get(
                        settings.EPSS_BASE_URL,
                        params=params,
                        headers={"User-Agent": "VulnGuard-AI/1.0"}
                    )

                if response.status_code == 200:
                    try:
                        data = response.json()
                    except (json.JSONDecodeError, ValueError) as json_err:
                        self.last_status = "degraded"
                        self.last_error = f"Malformed upstream JSON: {str(json_err)[:100]}"
                        self.last_check_time = datetime.now(timezone.utc).isoformat()
                        logger.warning(f"[EPSS] Malformed non-JSON response on attempt {attempt + 1}: {json_err}")
                        if attempt < max_retries - 1:
                            backoff = calculate_backoff_with_jitter(attempt, base_delay=1.0, max_delay=4.0)
                            await asyncio.sleep(backoff)
                            continue
                        return self._build_unavailable(cve_id)

                    epss_list = data.get("data", [])
                    item = next((row for row in epss_list if row.get("cve") == cve_id), None)
                    if item and item.get("epss") is not None:
                        prob_str = item.get("epss")
                        pct_str = item.get("percentile")
                        model_date = item.get("date")

                        prob = float(prob_str) if prob_str is not None else None
                        pct = float(pct_str) if pct_str is not None else None

                        intel = EpssIntel(
                            cve_id=cve_id,
                            status=IntelSourceStatus.AVAILABLE,
                            epss_probability=prob,
                            epss_percentile=pct,
                            model_date=model_date,
                            fetched_at=datetime.now(timezone.utc).isoformat(),
                            source_url=f"https://api.first.org/data/v1/epss?cve={cve_id}",
                            is_simulated=False,
                        )
                        self.last_status = "operational"
                        self.last_error = None
                        self.last_check_time = datetime.now(timezone.utc).isoformat()
                        epss_cache.set(cve_id, intel, ttl_seconds=settings.EPSS_CACHE_TTL_HOURS * 3600.0)
                        return intel
                    else:
                        logger.warning(f"[EPSS] No EPSS model score published for {cve_id}")
                        return self._build_missing(cve_id)

                if response.status_code == 429:
                    self.last_status = "rate_limited"
                    self.last_error = "EPSS rate limited (HTTP 429)"
                    self.last_check_time = datetime.now(timezone.utc).isoformat()
                    backoff = calculate_backoff_with_jitter(attempt, base_delay=1.0, max_delay=5.0)
                    await asyncio.sleep(backoff)
                    continue

                self.last_status = "degraded"
                self.last_error = f"HTTP {response.status_code}"
                self.last_check_time = datetime.now(timezone.utc).isoformat()
                logger.error(f"[EPSS] Status {response.status_code}: {response.text[:150]}")

            except httpx.RequestError as exc:
                self.last_status = "unreachable"
                self.last_error = str(exc)[:120]
                self.last_check_time = datetime.now(timezone.utc).isoformat()
                logger.warning(f"[EPSS] Network error fetching {cve_id}: {exc}")
                if attempt < max_retries - 1:
                    backoff = calculate_backoff_with_jitter(attempt, base_delay=1.0, max_delay=4.0)
                    await asyncio.sleep(backoff)

        # If live fetch fails, return unavailable (never fabricate mock data in live mode)
        return self._build_unavailable(cve_id)

    def _build_missing(self, cve_id: str) -> EpssIntel:
        return EpssIntel(
            cve_id=cve_id,
            status=IntelSourceStatus.UNKNOWN_OR_MISSING,
            epss_probability=None,
            epss_percentile=None,
            model_date=None,
            fetched_at=datetime.now(timezone.utc).isoformat(),
            source_url=f"https://api.first.org/data/v1/epss?cve={cve_id}",
            is_simulated=False,
        )

    def _build_unavailable(self, cve_id: str) -> EpssIntel:
        return EpssIntel(
            cve_id=cve_id,
            status=IntelSourceStatus.UNKNOWN_OR_MISSING,
            epss_probability=None,
            epss_percentile=None,
            model_date=None,
            fetched_at=datetime.now(timezone.utc).isoformat(),
            source_url=f"https://api.first.org/data/v1/epss?cve={cve_id}",
            is_simulated=False,
        )

    def _build_simulated(self, cve_id: str) -> EpssIntel:
        return EpssIntel(
            cve_id=cve_id,
            status=IntelSourceStatus.SIMULATED,
            epss_probability=0.05,
            epss_percentile=0.70,
            model_date="2026-11-22",
            fetched_at=datetime.now(timezone.utc).isoformat(),
            source_url=f"https://api.first.org/data/v1/epss?cve={cve_id}",
            is_simulated=True,
        )


epss_service = EpssService()
