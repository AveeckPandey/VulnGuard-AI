"""
VulnGuard AI - CISA KEV Threat Intelligence Service
Downloads and parses the official CISA Known Exploited Vulnerabilities (KEV) Catalog.
Caches the full catalog in memory for 6 hours and indexes by CVE ID for O(1) lookups.
Clearly distinguishes confirmed negative findings from unknown/missing data.
"""
import asyncio
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import httpx

from backend.core.config import settings
from backend.core.logging import logger
from backend.schemas.intelligence import CisaKevIntel, IntelSourceStatus
from backend.services.cache import cisa_cache
from backend.services.simulated_intel import SIMULATED_CVE_FIXTURES

CATALOG_CACHE_KEY = "__cisa_catalog_dict__"
CATALOG_METADATA_KEY = "__cisa_catalog_meta__"


class CisaKevService:
    """Service client for CISA Known Exploited Vulnerabilities catalog."""

    def __init__(self):
        self._refresh_lock = asyncio.Lock()
        self.last_status: str = "operational"
        self.last_error: Optional[str] = None
        self.last_check_time: Optional[str] = None

    async def get_cisa_kev(self, cve_id: str, simulate_offline: bool = False) -> CisaKevIntel:
        cve_id = cve_id.strip().upper()

        # 1. Offline Simulation Check
        if simulate_offline:
            if cve_id in SIMULATED_CVE_FIXTURES:
                raw = SIMULATED_CVE_FIXTURES[cve_id]["cisa_kev"]
                return CisaKevIntel(**raw)
            return self._build_simulated_negative(cve_id)

        # 2. Get or Refresh Catalog Dictionary
        catalog_dict = cisa_cache.get(CATALOG_CACHE_KEY)
        if catalog_dict is None:
            async with self._refresh_lock:
                # Double-check inside lock
                catalog_dict = cisa_cache.get(CATALOG_CACHE_KEY)
                if catalog_dict is None:
                    catalog_dict = await self._fetch_and_cache_catalog()

        # 3. If catalog still unavailable (network error and no cache)
        if catalog_dict is None:
            return self._build_unavailable(cve_id)

        # 4. Check if CVE is present in the KEV Catalog
        if cve_id in catalog_dict:
            entry = catalog_dict[cve_id]
            logger.info(f"[CISA KEV] ACTIVE EXPLOITATION DETECTED: {cve_id} is in CISA KEV catalog!")
            return CisaKevIntel(
                cve_id=cve_id,
                status=IntelSourceStatus.AVAILABLE,
                is_known_exploited=True,
                vulnerability_name=entry.get("vulnerabilityName"),
                date_added=entry.get("dateAdded"),
                required_action=entry.get("requiredAction"),
                due_date=entry.get("dueDate"),
                known_ransomware_use=entry.get("knownRansomwareCampaignUse", "Unknown"),
                notes=entry.get("notes"),
                fetched_at=datetime.now(timezone.utc).isoformat(),
                source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                is_simulated=False,
            )
        else:
            # Confirmed negative: catalog was downloaded and searched, but this CVE is NOT in KEV
            logger.info(f"[CISA KEV] Confirmed Negative: {cve_id} is NOT listed in CISA KEV catalog.")
            return CisaKevIntel(
                cve_id=cve_id,
                status=IntelSourceStatus.CONFIRMED_NEGATIVE,
                is_known_exploited=False,
                vulnerability_name=None,
                date_added=None,
                required_action=None,
                due_date=None,
                known_ransomware_use=None,
                notes="This CVE was absent from the retrieved CISA KEV catalog.",
                fetched_at=datetime.now(timezone.utc).isoformat(),
                source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                is_simulated=False,
            )

    async def _fetch_and_cache_catalog(self) -> Optional[Dict[str, Dict[str, Any]]]:
        """Downloads full CISA KEV JSON feed and parses into a dictionary indexed by cveID."""
        logger.info("[CISA KEV] Downloading fresh CISA KEV JSON catalog...")
        try:
            async with httpx.AsyncClient(timeout=settings.CISA_TIMEOUT_SECONDS) as client:
                response = await client.get(
                    settings.CISA_KEV_URL,
                    headers={"User-Agent": "VulnGuard-AI/1.0"}
                )

            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data["vulnerabilities"]
                catalog_dict: Dict[str, Dict[str, Any]] = {}
                for v in vulnerabilities:
                    cid = v.get("cveID", "").strip().upper()
                    if cid:
                        catalog_dict[cid] = v
                if not catalog_dict or data.get("count", len(vulnerabilities)) != len(catalog_dict):
                    logger.warning("[CISA KEV] Empty or incomplete catalog. Membership is unknown.")
                    return None

                # Cache dictionary for 6 hours
                ttl = settings.CISA_CACHE_TTL_HOURS * 3600.0
                cisa_cache.set(CATALOG_CACHE_KEY, catalog_dict, ttl_seconds=ttl)
                cisa_cache.set(CATALOG_METADATA_KEY, {
                    "count": data.get("count", len(catalog_dict)),
                    "catalog_version": data.get("catalogVersion"),
                    "date_released": data.get("dateReleased"),
                }, ttl_seconds=ttl)

                self.last_status = "operational"
                self.last_error = None
                self.last_check_time = datetime.now(timezone.utc).isoformat()
                logger.info(f"[CISA KEV] Successfully ingested {len(catalog_dict)} KEV catalog entries (cached for {settings.CISA_CACHE_TTL_HOURS}h)")
                return catalog_dict
            else:
                self.last_status = "degraded"
                self.last_error = f"Upstream HTTP error {response.status_code}"
                self.last_check_time = datetime.now(timezone.utc).isoformat()
                logger.error(f"[CISA KEV] Upstream HTTP error {response.status_code}")
                return None

        except Exception as exc:
            self.last_status = "unreachable"
            self.last_error = str(exc)[:120]
            self.last_check_time = datetime.now(timezone.utc).isoformat()
            logger.warning(f"[CISA KEV] Failed to download KEV catalog: {exc}")
            return None

    def _build_unavailable(self, cve_id: str) -> CisaKevIntel:
        return CisaKevIntel(
            cve_id=cve_id,
            status=IntelSourceStatus.UNKNOWN_OR_MISSING,
            is_known_exploited=None,
            vulnerability_name=None,
            date_added=None,
            required_action=None,
            due_date=None,
            known_ransomware_use=None,
            notes="CISA KEV catalog is temporarily unreachable. Exploitation status unknown.",
            fetched_at=datetime.now(timezone.utc).isoformat(),
            source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            is_simulated=False,
        )

    def _build_simulated_negative(self, cve_id: str) -> CisaKevIntel:
        return CisaKevIntel(
            cve_id=cve_id,
            status=IntelSourceStatus.SIMULATED,
            is_known_exploited=False,
            vulnerability_name=None,
            date_added=None,
            required_action=None,
            due_date=None,
            known_ransomware_use=None,
            notes="Simulated record: not known to be actively exploited.",
            fetched_at=datetime.now(timezone.utc).isoformat(),
            source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            is_simulated=True,
        )


cisa_service = CisaKevService()
