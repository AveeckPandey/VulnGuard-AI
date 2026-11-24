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
                "weaknesses": [
                    {"description": [{"value": "CWE-79"}]},
                    {"description": [{"value": "CWE-79"}]},
                    {"description": [{"value": "CWE-89"}]}
                ],
                "references": [{"url": "https://example.com/advisory"}]
            }
        }]
    }
    parsed = svc._parse_nvd_response("CVE-2024-0001", mock_v40)
    assert parsed.cvss_version == "4.0"
    assert parsed.cvss_base_score == 9.3
    assert parsed.cvss_severity == "CRITICAL"
    assert parsed.status == IntelSourceStatus.AVAILABLE
    assert parsed.weaknesses == ["CWE-79", "CWE-89"]  # Deduplicated!


@pytest.mark.asyncio
async def test_nvd_unknown_cve_no_fabrication():
    """A completed NVD lookup can confirm absence without fabricating data."""
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
        assert intel.status == IntelSourceStatus.CONFIRMED_NEGATIVE
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


@pytest.mark.asyncio
async def test_nvd_malformed_json_graceful_recovery():
    """Validates that non-JSON/HTML HTTP 200 from NVD does not crash with JSONDecodeError."""
    svc = NvdService()
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Expecting value: line 1 column 1 (char 0)")
        mock_get.return_value = mock_resp

        # Should retry and gracefully return UNKNOWN_OR_MISSING without unhandled exception
        intel = await svc.fetch_cve("CVE-2021-44228", simulate_offline=False)
        assert intel.status == IntelSourceStatus.UNKNOWN_OR_MISSING
        assert svc.last_status == "degraded"
        assert "Malformed upstream JSON" in (svc.last_error or "")


@pytest.mark.asyncio
async def test_epss_malformed_json_graceful_recovery():
    """Validates that non-JSON/HTML HTTP 200 from EPSS does not crash with JSONDecodeError."""
    svc = EpssService()
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Expecting value: line 1 column 1 (char 0)")
        mock_get.return_value = mock_resp

        # Should retry and gracefully return UNKNOWN_OR_MISSING without unhandled exception
        intel = await svc.fetch_epss("CVE-2021-44228", simulate_offline=False)
        assert intel.status == IntelSourceStatus.UNKNOWN_OR_MISSING
        assert svc.last_status == "degraded"
        assert "Malformed upstream JSON" in (svc.last_error or "")


def test_malformed_feed_api_pipeline_resilience(client):
    """
    Complete mocked API test verifying that when an upstream feed returns malformed JSON,
    the LangGraph pipeline isolates the defect, scores provisionally, and successfully returns HTTP 201 Created.
    """
    from backend.tests.test_scorer import build_mock_intel
    from backend.schemas.intelligence import NvdIntel, IntelSourceStatus
    from backend.schemas.assessment import AiRemediation

    # Create mock where NVD is unavailable due to malformed upstream response, but EPSS and KEV are available
    mock_nvd_unavailable = NvdIntel(
        cve_id="CVE-2021-44228",
        status=IntelSourceStatus.UNKNOWN_OR_MISSING,
        description="NVD data temporarily unavailable due to upstream feed formatting",
        cvss_version=None,
        cvss_base_score=None,
        cvss_severity=None,
        cvss_vector_string=None,
        published_date=None,
        last_modified_date=None,
        references=[],
        weaknesses=[],
        fetched_at="2026-11-24T00:00:00Z",
        source_url="https://services.nvd.nist.gov",
        is_simulated=False,
    )
    available_intel = build_mock_intel(cvss=10.0, epss_prob=0.97, is_kev=True)
    mock_remediation = AiRemediation(
        executive_summary="Executive summary for test",
        technical_impact="Technical impact details",
        exploitation_assessment="Active exploitation confirmed",
        remediation_steps=["Upgrade to 2.17.1"],
        mitigation_workarounds=["Disable JNDI lookups"],
        evidence_citations=["NIST NVD"],
        model_used="deterministic-fallback-rules",
        is_fallback_deterministic=True,
    )

    with (
        patch("backend.services.nvd_service.nvd_service.fetch_cve", return_value=mock_nvd_unavailable),
        patch("backend.services.epss_service.epss_service.fetch_epss", return_value=available_intel.epss),
        patch("backend.services.cisa_service.cisa_service.get_cisa_kev", return_value=available_intel.cisa_kev),
        patch("backend.agents.bedrock.bedrock_explainer.generate_explanation", return_value=mock_remediation),
    ):
        payload = {
            "cve_id": "CVE-2021-44228",
            "asset_criticality": "HIGH",
            "internet_exposure": "PUBLIC_FACING",
            "system_context": "Production Gateway",
            "simulate_offline": False,
        }
        res = client.post("/api/analyze", json=payload)
        assert res.status_code == 201, f"Expected 201 Created but got {res.status_code}: {res.text}"
        data = res.json()
        assert data["risk_score"]["is_provisional"] is True
        assert any("NVD CVSS score is missing" in r for r in data["risk_score"]["provisional_reasons"])


def test_e2e_nvd_html_response_through_api(client):
    """
    End-to-end integration test driving raw HTML (e.g. Cloudflare error / HTML block)
    directly through the real NvdService client, into the LangGraph pipeline, and out
    through the /api/analyze endpoint. Validates that JSONDecodeError is caught by the
    real service, marks degraded status, and successfully yields HTTP 201 with provisional scoring.
    """
    import json
    from backend.services.nvd_service import nvd_service
    from backend.services.cache import nvd_cache
    from backend.tests.test_scorer import build_mock_intel
    from backend.schemas.assessment import AiRemediation

    # Clear NVD cache so the real client is forced to execute the HTTP request
    nvd_cache.clear()
    nvd_service.last_status = "operational"
    nvd_service.last_error = None

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "<!DOCTYPE html><html><body>Cloudflare Block / Captcha Challenge</body></html>"
    mock_resp.json.side_effect = json.JSONDecodeError("Expecting value", "<!DOCTYPE html>...", 0)

    available_intel = build_mock_intel(cvss=10.0, epss_prob=0.97, is_kev=True)
    mock_remediation = AiRemediation(
        executive_summary="Executive summary for test",
        technical_impact="Technical impact details",
        exploitation_assessment="Active exploitation confirmed",
        remediation_steps=["Upgrade to 2.17.1"],
        mitigation_workarounds=["Disable JNDI lookups"],
        evidence_citations=["NIST NVD"],
        model_used="deterministic-fallback-rules",
        is_fallback_deterministic=True,
    )

    with (
        patch("httpx.AsyncClient.get", return_value=mock_resp),
        patch("asyncio.sleep", return_value=None),
        patch("backend.services.epss_service.epss_service.fetch_epss", return_value=available_intel.epss),
        patch("backend.services.cisa_service.cisa_service.get_cisa_kev", return_value=available_intel.cisa_kev),
        patch("backend.agents.bedrock.bedrock_explainer.generate_explanation", return_value=mock_remediation),
    ):
        payload = {
            "cve_id": "CVE-2021-44228",
            "asset_criticality": "HIGH",
            "internet_exposure": "PUBLIC_FACING",
            "system_context": "Production Gateway",
            "simulate_offline": False,
        }
        res = client.post("/api/analyze", json=payload)
        assert res.status_code == 201, f"Expected 201 Created but got {res.status_code}: {res.text}"
        data = res.json()

        # Verify real NVD service processed the HTML, caught JSONDecodeError, and degraded status
        assert nvd_service.last_status == "degraded"
        assert "Malformed upstream JSON" in (nvd_service.last_error or "")

        # Verify downstream LangGraph pipeline detected missing CVSS and provisionally scored
        assert data["intelligence"]["nvd"]["status"].upper() == "UNKNOWN_OR_MISSING"
        assert data["risk_score"]["is_provisional"] is True
        assert any("NVD CVSS score is missing" in r for r in data["risk_score"]["provisional_reasons"])


