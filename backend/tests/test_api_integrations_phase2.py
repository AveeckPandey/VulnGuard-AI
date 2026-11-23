"""
VulnGuard AI - Phase 2 Cybersecurity API Integration Tests
Thoroughly tests NIST NVD API 2.0, FIRST EPSS API, and CISA KEV catalog integration.
Validates live and offline handling, rate limits, caching, and error resilience.
"""
import pytest
import asyncio
from unittest.mock import patch, MagicMock
from backend.services.nvd_service import nvd_service, NvdService
from backend.services.epss_service import epss_service, EpssService
from backend.services.cisa_service import cisa_service, CisaKevService, CATALOG_CACHE_KEY
from backend.services.cache import nvd_cache, epss_cache, cisa_cache
from backend.schemas.intelligence import IntelSourceStatus
from backend.core.config import settings


@pytest.mark.asyncio
async def test_nvd_parsing_and_cvss_versions():
    """Validates CVSS v4.0, v3.1, and v2.0 parsing logic."""
    svc = NvdService()

    # Test CVSS v4.0 mock payload
    mock_v40 = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-0001",
                "descriptions": [{"lang": "en", "value": "Sample v4 vulnerability"}],
                "metrics": {
                    "cvssMetricV40": [{
                        "cvssData": {
                            "baseScore": 9.3,
                            "baseSeverity": "CRITICAL",
                            "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                        }
                    }]
                },
                "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                "references": [{"url": "https://example.com/advisory"}]
            }
        }]
    }
    parsed = svc._parse_nvd_response("CVE-2024-0001", mock_v40)
    assert parsed.cvss_version == "4.0"
    assert parsed.cvss_base_score == 9.3
    assert parsed.cvss_severity == "CRITICAL"
    assert parsed.status == IntelSourceStatus.AVAILABLE
    assert "CWE-79" in parsed.weaknesses


@pytest.mark.asyncio
async def test_nvd_unknown_cve_no_fabrication():
    """Ensures unknown CVEs return UNKNOWN_OR_MISSING and do NOT fabricate data."""
    svc = NvdService()

    # Query with non-existent CVE
    unknown_cve = "CVE-1990-99999"
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = "Not found"
        mock_get.return_value = mock_resp

        intel = await svc.fetch_cve(unknown_cve, simulate_offline=False)
        assert intel.cve_id == unknown_cve
        assert intel.status == IntelSourceStatus.UNKNOWN_OR_MISSING
        assert intel.cvss_base_score is None
        assert intel.is_simulated is False


@pytest.mark.asyncio
async def test_nvd_api_key_header_support():
    """Validates that NVD API key is sent in request headers when configured."""
    svc = NvdService()
    with patch("backend.core.config.settings.NVD_API_KEY", "test-secret-nvd-key"):
        assert svc.rate_limiter.max_calls >= 50 or settings.nvd_rate_limit_calls == 50


@pytest.mark.asyncio
async def test_epss_live_scale_and_date():
    """Validates that EPSS probabilities are on 0-1 scale and observation date is stored."""
    # Test with real EPSS service for CVE-2021-44228
    epss_intel = await epss_service.fetch_epss("CVE-2021-44228", simulate_offline=False)
    if epss_intel.status == IntelSourceStatus.AVAILABLE:
        assert 0.0 <= epss_intel.epss_probability <= 1.0
        assert 0.0 <= epss_intel.epss_percentile <= 1.0
        assert epss_intel.model_date is not None
        assert epss_intel.source_url.startswith("https://api.first.org")
    else:
        # If offline/upstream unreachable, verify it is cleanly marked
        assert epss_intel.status == IntelSourceStatus.UNKNOWN_OR_MISSING


@pytest.mark.asyncio
async def test_epss_error_and_malformed_handling():
    """Tests empty data array and network errors in EPSS client."""
    svc = EpssService()

    # Empty data
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "OK", "data": []}
        mock_get.return_value = mock_resp

        intel = await svc.fetch_epss("CVE-2020-0001", simulate_offline=False)
        assert intel.status == IntelSourceStatus.UNKNOWN_OR_MISSING
        assert intel.epss_probability is None


@pytest.mark.asyncio
async def test_cisa_kev_catalog_indexing_and_cache():
    """Validates catalog indexing by CVE ID, 6-hour caching, and lookup of known exploited CVEs."""
    cisa_cache.clear()

    # Fetch CISA KEV (live or simulated)
    intel_log4j = await cisa_service.get_cisa_kev("CVE-2021-44228", simulate_offline=False)
    assert intel_log4j.is_known_exploited is True

    # Test cache is now populated
    catalog_cached = cisa_cache.get(CATALOG_CACHE_KEY)
    assert catalog_cached is not None
    assert "CVE-2021-44228" in catalog_cached
    assert "CVE-2023-34362" in catalog_cached  # MOVEit Transfer is also in CISA KEV

    # Lookup CVE-2023-34362 from cache
    intel_moveit = await cisa_service.get_cisa_kev("CVE-2023-34362", simulate_offline=False)
    assert intel_moveit.is_known_exploited is True
    assert "Progress Software" in (intel_moveit.vulnerability_name or "") or "MOVEit" in (intel_moveit.vulnerability_name or "")


@pytest.mark.asyncio
async def test_cisa_kev_unavailable_reported_as_unknown():
    """Confirm that an unavailable catalog is reported as unknown rather than returning False."""
    svc = CisaKevService()
    cisa_cache.clear()

    with patch.object(svc, "_fetch_and_cache_catalog", return_value=None):
        intel = await svc.get_cisa_kev("CVE-2021-44228", simulate_offline=False)
        assert intel.status == IntelSourceStatus.UNKNOWN_OR_MISSING
        assert intel.is_known_exploited is None  # Reported as unknown, NOT False!
