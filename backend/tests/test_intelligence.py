"""
VulnGuard AI - Threat Intelligence Services Unit Tests
Tests NVD, EPSS, and CISA KEV clients, caching, and confirmed negative vs missing data distinction.
"""
import pytest
from backend.services.nvd_service import nvd_service
from backend.services.epss_service import epss_service
from backend.services.cisa_service import cisa_service, CATALOG_CACHE_KEY
from backend.services.cache import nvd_cache, epss_cache, cisa_cache, TTLCache
from backend.schemas.intelligence import IntelSourceStatus


@pytest.mark.asyncio
async def test_nvd_simulated_fetch():
    """Tests simulated NVD fetch returns complete CVSS v3.1 details."""
    nvd_intel = await nvd_service.fetch_cve("CVE-2021-44228", simulate_offline=True)
    assert nvd_intel.cve_id == "CVE-2021-44228"
    assert nvd_intel.cvss_base_score == 10.0
    assert nvd_intel.cvss_severity == "CRITICAL"
    assert nvd_intel.status == IntelSourceStatus.SIMULATED
    assert nvd_intel.is_simulated is True
    assert len(nvd_intel.weaknesses) > 0


@pytest.mark.asyncio
async def test_epss_simulated_fetch():
    """Tests simulated EPSS fetch returns exploitation probability."""
    epss_intel = await epss_service.fetch_epss("CVE-2021-44228", simulate_offline=True)
    assert epss_intel.cve_id == "CVE-2021-44228"
    assert epss_intel.epss_probability is not None
    assert epss_intel.epss_probability > 0.90
    assert epss_intel.status == IntelSourceStatus.SIMULATED


@pytest.mark.asyncio
async def test_cisa_kev_active_vs_negative():
    """Tests KEV detection for known exploited CVE vs non-exploited CVE."""
    # Active KEV
    cisa_active = await cisa_service.get_cisa_kev("CVE-2021-44228", simulate_offline=True)
    assert cisa_active.is_known_exploited is True
    assert cisa_active.status == IntelSourceStatus.SIMULATED
    assert "Log4j" in (cisa_active.vulnerability_name or "")

    # Non-exploited / confirmed negative
    cisa_negative = await cisa_service.get_cisa_kev("CVE-2024-3094", simulate_offline=True)
    assert cisa_negative.is_known_exploited is False
    assert cisa_negative.status == IntelSourceStatus.CONFIRMED_NEGATIVE


def test_ttl_cache_expiry():
    """Tests TTL cache expiration mechanics."""
    cache = TTLCache(default_ttl_seconds=0.1)
    cache.set("test_key", {"data": 123}, ttl_seconds=0.05)
    assert cache.get("test_key") == {"data": 123}

    import time
    time.sleep(0.08)
    assert cache.get("test_key") is None
    assert cache.contains("test_key") is False
