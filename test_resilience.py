"""
VulnGuard AI - Local Resilience & Failure Simulation Harness
"""
import asyncio
import json
from unittest.mock import AsyncMock, patch, MagicMock
import httpx
from botocore.exceptions import ClientError

from backend.schemas.intelligence import IntelSourceStatus
from backend.services.nvd_service import nvd_service
from backend.services.epss_service import epss_service
from backend.services.cisa_service import cisa_service, CATALOG_CACHE_KEY
from backend.services.cache import cisa_cache
from backend.agents.bedrock import BedrockExplainer
from backend.services.scorer import scoring_engine
from backend.schemas.risk import AssetCriticality, InternetExposure
from database.dynamodb_repo import DynamoDBAssessmentRepository
from backend.core.exceptions import DatabaseError

resilience_results = []

async def test_nvd_failures():
    print("[FAIL_TEST] Testing NVD Failures...")
    # 1. NVD 429 Rate Limit
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = httpx.Response(429, text="Rate Limit Exceeded", request=httpx.Request("GET", "http://test"))
        res = await nvd_service.fetch_cve("CVE-2021-44228", simulate_offline=False)
        assert res.status == IntelSourceStatus.UNKNOWN_OR_MISSING
        resilience_results.append({"feed": "NVD", "scenario": "HTTP 429", "result_status": res.status.value, "last_status": nvd_service.last_status})

    # 2. NVD 500 Server Error
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = httpx.Response(500, text="Internal Server Error", request=httpx.Request("GET", "http://test"))
        res = await nvd_service.fetch_cve("CVE-2021-44228", simulate_offline=False)
        assert res.status == IntelSourceStatus.UNKNOWN_OR_MISSING
        resilience_results.append({"feed": "NVD", "scenario": "HTTP 500", "result_status": res.status.value, "last_status": nvd_service.last_status})

    # 3. NVD Timeout
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = httpx.TimeoutException("Connection timed out")
        res = await nvd_service.fetch_cve("CVE-2021-44228", simulate_offline=False)
        assert res.status == IntelSourceStatus.UNKNOWN_OR_MISSING
        resilience_results.append({"feed": "NVD", "scenario": "Timeout", "result_status": res.status.value, "last_status": nvd_service.last_status})

    # 4. NVD Malformed Response Resilience Check
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = httpx.Response(200, text="<html>Cloudflare Error</html>", request=httpx.Request("GET", "http://test"))
        crashed = False
        res = None
        try:
            res = await nvd_service.fetch_cve("CVE-2021-44228", simulate_offline=False)
        except json.JSONDecodeError:
            crashed = True
        assert crashed is False
        assert res is not None and res.status == IntelSourceStatus.UNKNOWN_OR_MISSING
        resilience_results.append({
            "feed": "NVD",
            "scenario": "HTTP 200 with HTML/Malformed Body",
            "crashes_unhandled": crashed,
            "status": "gracefully_handled",
            "last_status": nvd_service.last_status
        })

async def test_epss_failures():
    print("[FAIL_TEST] Testing EPSS Failures...")
    # 1. EPSS 500
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = httpx.Response(500, text="Server Error", request=httpx.Request("GET", "http://test"))
        res = await epss_service.fetch_epss("CVE-2021-44228", simulate_offline=False)
        assert res.status == IntelSourceStatus.UNKNOWN_OR_MISSING
        assert res.epss_probability is None
        resilience_results.append({"feed": "EPSS", "scenario": "HTTP 500", "result_status": res.status.value})

    # 2. EPSS Absent Record (empty data array returns UNKNOWN_OR_MISSING per implementation)
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = httpx.Response(200, json={"status": "OK", "data": []}, request=httpx.Request("GET", "http://test"))
        res = await epss_service.fetch_epss("CVE-2026-99999", simulate_offline=False)
        assert res.status == IntelSourceStatus.UNKNOWN_OR_MISSING
        assert res.epss_probability is None
        resilience_results.append({
            "feed": "EPSS",
            "scenario": "Absent Record in FIRST.org",
            "result_status": res.status.value,
            "note": "Returns UNKNOWN_OR_MISSING, triggering provisional baseline scoring (3.0 pts)."
        })

    # 3. EPSS Malformed Response Resilience Check
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = httpx.Response(200, text="<html>502 Bad Gateway</html>", request=httpx.Request("GET", "http://test"))
        crashed = False
        res = None
        try:
            res = await epss_service.fetch_epss("CVE-2021-44228", simulate_offline=False)
        except json.JSONDecodeError:
            crashed = True
        assert crashed is False
        assert res is not None and res.status == IntelSourceStatus.UNKNOWN_OR_MISSING
        resilience_results.append({
            "feed": "EPSS",
            "scenario": "HTTP 200 with HTML/Malformed Body",
            "crashes_unhandled": crashed,
            "status": "gracefully_handled",
            "last_status": epss_service.last_status
        })

async def test_cisa_failures():
    print("[FAIL_TEST] Testing CISA KEV Failures...")
    # 1. KEV 500 Catalog Download Failure
    cisa_cache.delete(CATALOG_CACHE_KEY)
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = httpx.Response(500, text="Catalog Unavailable", request=httpx.Request("GET", "http://test"))
        res = await cisa_service.get_cisa_kev("CVE-2021-44228", simulate_offline=False)
        assert res.status == IntelSourceStatus.UNKNOWN_OR_MISSING
        assert res.is_known_exploited is None
        resilience_results.append({"feed": "CISA KEV", "scenario": "Catalog 500", "result_status": res.status.value})

    # 2. KEV Malformed Catalog (no vulnerabilities key)
    cisa_cache.delete(CATALOG_CACHE_KEY)
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = httpx.Response(200, json={"count": 0}, request=httpx.Request("GET", "http://test"))
        res = await cisa_service.get_cisa_kev("CVE-2021-44228", simulate_offline=False)
        assert res.status == IntelSourceStatus.UNKNOWN_OR_MISSING
        resilience_results.append({"feed": "CISA KEV", "scenario": "Malformed Catalog Schema", "result_status": res.status.value})

async def test_ai_provider_fallbacks():
    print("[FAIL_TEST] Testing AI Multi-Tier Fallback Chain...")
    from backend.schemas.intelligence import AggregatedIntel, NvdIntel, EpssIntel, CisaKevIntel
    explainer = BedrockExplainer()
    mock_intel = AggregatedIntel(
        cve_id="CVE-2021-44228",
        nvd=NvdIntel(cve_id="CVE-2021-44228", status=IntelSourceStatus.AVAILABLE, description="Log4j", cvss_version="3.1", cvss_base_score=10.0, cvss_severity="CRITICAL", cvss_vector_string=None, published_date=None, last_modified_date=None, references=[], weaknesses=[], fetched_at="2026-11-24", source_url="", is_simulated=False),
        epss=EpssIntel(cve_id="CVE-2021-44228", status=IntelSourceStatus.AVAILABLE, epss_probability=0.99, epss_percentile=1.0, model_date="2026-11-24", fetched_at="2026-11-24", source_url="", is_simulated=False),
        cisa_kev=CisaKevIntel(cve_id="CVE-2021-44228", status=IntelSourceStatus.AVAILABLE, is_known_exploited=True, vulnerability_name="Log4j", date_added=None, required_action=None, due_date=None, known_ransomware_use=None, notes=None, fetched_at="2026-11-24", source_url="", is_simulated=False),
        is_simulated=False
    )
    score = scoring_engine.calculate_risk(mock_intel, AssetCriticality.CRITICAL, InternetExposure.PUBLIC_FACING)

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = httpx.Response(500, text="NVIDIA Service Unavailable", request=httpx.Request("POST", "http://test"))
        with patch.object(explainer, "_get_client", return_value=None):
            rem = await explainer.generate_explanation("CVE-2021-44228", mock_intel, score, system_context="Prod")
            assert rem.is_fallback_deterministic is True
            assert rem.model_used == "deterministic-fallback-rules"
            resilience_results.append({
                "component": "AI Inference",
                "scenario": "NVIDIA 500 + Bedrock Unreachable",
                "recovered": True,
                "model_used": rem.model_used,
                "is_fallback": rem.is_fallback_deterministic
            })

def test_dynamodb_failure():
    print("[FAIL_TEST] Testing DynamoDB Failure Handling...")
    repo = DynamoDBAssessmentRepository.__new__(DynamoDBAssessmentRepository)
    mock_table = MagicMock()
    mock_table.put_item.side_effect = ClientError({"Error": {"Code": "AccessDeniedException", "Message": "User not authorized"}}, "PutItem")
    repo._table = mock_table
    repo.table_name = "VulnGuardAssessments"

    mock_resp = MagicMock()
    mock_resp.id = "vg-test"
    mock_resp.cve_id = "CVE-TEST"
    mock_resp.created_at = "2026-11-24"
    mock_resp.asset_criticality.value = "HIGH"
    mock_resp.internet_exposure.value = "PUBLIC_FACING"
    mock_resp.intelligence.nvd.cvss_base_score = 10.0
    mock_resp.intelligence.nvd.description = "Test"
    mock_resp.intelligence.nvd.cvss_version = "3.1"
    mock_resp.intelligence.nvd.fetched_at = "2026-11-24"
    mock_resp.intelligence.epss.epss_probability = 0.99
    mock_resp.intelligence.epss.epss_percentile = 0.99
    mock_resp.intelligence.epss.fetched_at = "2026-11-24"
    mock_resp.intelligence.cisa_kev.status.value = "AVAILABLE"
    mock_resp.intelligence.cisa_kev.is_known_exploited = True
    mock_resp.intelligence.cisa_kev.fetched_at = "2026-11-24"
    mock_resp.risk_score.total_score = 100.0
    mock_resp.risk_score.priority_level.value = "CRITICAL"
    mock_resp.risk_score.is_provisional = False
    mock_resp.risk_score.provisional_reasons = []
    mock_resp.remediation.executive_summary = "Test"
    mock_resp.remediation.model_used = "test"
    mock_resp.remediation.evidence_citations = []
    mock_resp.model_dump_json.return_value = "{}"

    raised = False
    try:
        repo.create_assessment(mock_resp)
    except DatabaseError as e:
        raised = True
        resilience_results.append({
            "component": "DynamoDB",
            "scenario": "AccessDeniedException",
            "handled_as_database_error": True,
            "error_msg": str(e)
        })
    assert raised is True

async def main():
    await test_nvd_failures()
    await test_epss_failures()
    await test_cisa_failures()
    await test_ai_provider_fallbacks()
    test_dynamodb_failure()

    with open("resilience_output.json", "w") as f:
        json.dump(resilience_results, f, indent=2)
    print("\n[FAIL_TEST] Resilience simulation suite executed and recorded.")

if __name__ == "__main__":
    asyncio.run(main())
