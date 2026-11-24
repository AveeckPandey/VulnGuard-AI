"""
VulnGuard AI - QA Test Scenarios: Pass, Fail, and Stress Tests
Comprehensive test suite covering:
1. Scenario 1 (PASS): Valid end-to-end vulnerability assessment with full assertions.
2. Scenario 2 (FAIL / Negative Validation): Submits malformed CVEs and invalid enums, asserting proper HTTP 422 rejection.
3. Scenario 3 (DELIBERATE FAIL): Demonstrative failing test case that triggers an explicit assertion failure when enabled.
4. Scenario 4 (STRESS): High-concurrency load test firing parallel requests to verify throughput, caching, and thread-safety.
"""
import os
import time
import asyncio
import pytest
import httpx
from httpx import ASGITransport

from backend.app.main import app
from backend.services.cache import nvd_cache, epss_cache


# =====================================================================
# 1. PASSED TEST CASE
# =====================================================================
def test_scenario_1_passed_assessment(client):
    """
    PASSED TEST CASE:
    Submits a valid, complete vulnerability assessment request for CVE-2021-44228.
    Verifies HTTP 201 Created, complete multi-source intelligence, deterministic risk scoring,
    and structured AI remediation output.
    """
    payload = {
        "cve_id": "CVE-2021-44228",
        "asset_criticality": "CRITICAL",
        "internet_exposure": "PUBLIC_FACING",
        "system_context": "Production edge API gateway running vulnerable Log4j 2.14.1",
        "simulate_offline": True,
    }

    response = client.post("/api/analyze", json=payload)

    # 1. HTTP Status Assertion
    assert response.status_code == 201, f"Expected 201 Created, got {response.status_code}: {response.text}"

    data = response.json()

    # 2. Identity and Input Integrity Assertions
    assert data["id"].startswith("vg-"), f"Expected ID prefix 'vg-', got: {data['id']}"
    assert data["cve_id"] == "CVE-2021-44228"
    assert data["asset_criticality"] == "CRITICAL"
    assert data["internet_exposure"] == "PUBLIC_FACING"

    # 3. Multi-Source Intelligence Assertions
    intel = data["intelligence"]
    assert intel["nvd"]["cvss_base_score"] == 10.0
    assert intel["nvd"]["cvss_severity"] == "CRITICAL"
    assert len(intel["nvd"]["references"]) > 0
    assert intel["epss"]["epss_probability"] > 0.90
    assert intel["cisa_kev"]["is_known_exploited"] is True

    # 4. Risk Prioritization Assertions
    risk = data["risk_score"]
    assert risk["total_score"] >= 90.0, f"Expected critical score >= 90, got: {risk['total_score']}"
    assert risk["priority_level"] == "CRITICAL"
    assert len(risk["components"]) == 5, f"Expected 5 score components, got {len(risk['components'])}"

    # 5. Remediation Plan Assertions
    remediation = data["remediation"]
    assert len(remediation["executive_summary"]) > 20
    assert len(remediation["technical_impact"]) > 20
    assert len(remediation["remediation_steps"]) >= 2
    assert len(remediation["mitigation_workarounds"]) >= 1

    print(f"\n[PASS TEST] Successfully verified assessment for {data['cve_id']} (Score: {risk['total_score']})")


# =====================================================================
# 2. FAILED TEST CASES (Negative Validation & Boundary Rejection)
# =====================================================================
@pytest.mark.parametrize("invalid_cve", [
    "NOT-A-CVE",
    "cve-2021-abc",
    "CVE-21-44228",
    "CVE-2021",
    "CVE-2021-",
    "<script>alert(1)</script>",
    "CVE-2021-44228; DROP TABLE assessments;",
])
def test_scenario_2_failed_invalid_cve_format(client, invalid_cve):
    """
    FAIL TEST CASE (Negative Input Validation):
    Submits invalid CVE identifiers and asserts the API correctly rejects them
    with HTTP 422 Unprocessable Content, enforcing the standard regex pattern.
    """
    payload = {
        "cve_id": invalid_cve,
        "asset_criticality": "HIGH",
        "internet_exposure": "INTERNAL",
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 422, f"Expected 422 for invalid CVE '{invalid_cve}', got: {response.status_code}"

    error_data = response.json()
    assert "error" in error_data or "detail" in error_data


def test_scenario_2_failed_invalid_enums(client):
    """
    FAIL TEST CASE (Schema Type Safety):
    Submits invalid asset_criticality and internet_exposure values, asserting strict enum rejection.
    """
    payload = {
        "cve_id": "CVE-2021-44228",
        "asset_criticality": "EXTREME_DANGER",  # Invalid enum value
        "internet_exposure": "AIR_GAPPED",       # Invalid enum value
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 422, f"Expected 422 for invalid enums, got: {response.status_code}"


# =====================================================================
# 3. DELIBERATE FAILING TEST (Demonstrates Red FAILED State in Pytest)
# =====================================================================
def test_scenario_3_deliberate_failure_demonstration(client):
    """
    DELIBERATE FAILING TEST:
    Explicitly designed to FAIL an assertion to demonstrate how QA test runners
    surface an unexpected regression or logic mismatch.
    Activated when RUN_DELIBERATE_FAIL=1 is set, otherwise skipped.
    """
    if os.getenv("RUN_DELIBERATE_FAIL") != "1":
        pytest.skip("Set RUN_DELIBERATE_FAIL=1 to observe this test fail intentionally.")

    payload = {
        "cve_id": "CVE-2021-44228",
        "asset_criticality": "CRITICAL",
        "internet_exposure": "PUBLIC_FACING",
        "simulate_offline": True,
    }
    response = client.post("/api/analyze", json=payload)
    data = response.json()

    # Intentional impossible assertion: Log4Shell should NEVER be scored as 0.0 (LOW)
    expected_score = 0.0
    actual_score = data["risk_score"]["total_score"]
    assert actual_score == expected_score, (
        f"[DEMO INTENTIONAL FAILURE] Expected risk score to be {expected_score} (LOW), "
        f"but received {actual_score} (CRITICAL). This simulates a bug detection!"
    )


# =====================================================================
# 4. STRESS TEST CASE (Concurrent Load & Throughput)
# =====================================================================
@pytest.mark.asyncio
async def test_scenario_4_stress_concurrent_load():
    """
    STRESS TEST CASE:
    Fires 20 concurrent assessment requests simultaneously to test:
    1. Async event loop concurrency and non-blocking I/O.
    2. Rate limiter and in-memory cache acceleration under load.
    3. Thread-safety and UUID uniqueness under concurrency.
    4. Absence of 500 Internal Server Errors under burst load.
    """
    concurrency_count = 20
    cve_id = "CVE-2021-44228"

    payload = {
        "cve_id": cve_id,
        "asset_criticality": "HIGH",
        "internet_exposure": "PUBLIC_FACING",
        "system_context": "Concurrency benchmark worker thread",
        "simulate_offline": True,
    }

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as async_client:
        start_time = time.perf_counter()

        # Fire concurrent requests in parallel
        tasks = [
            async_client.post("/api/analyze", json=payload)
            for _ in range(concurrency_count)
        ]
        responses = await asyncio.gather(*tasks)

        total_duration = time.perf_counter() - start_time

    # Assertions
    status_codes = [r.status_code for r in responses]
    success_count = sum(1 for code in status_codes if code == 201)
    failed_count = len(responses) - success_count

    assert failed_count == 0, f"Expected 0 failed requests under stress, got {failed_count} failures."
    assert success_count == concurrency_count, f"Expected {concurrency_count} successes, got {success_count}."

    # Verify ID uniqueness across all concurrent responses
    ids = [r.json()["id"] for r in responses]
    unique_ids = set(ids)
    assert len(unique_ids) == concurrency_count, "Detected duplicate assessment IDs under concurrency!"

    # Calculate and print performance metrics
    rps = concurrency_count / total_duration if total_duration > 0 else 0
    avg_latency_ms = (total_duration / concurrency_count) * 1000.0

    print(f"\n[STRESS TEST] Concurrency: {concurrency_count} requests")
    print(f"[STRESS TEST] Total Duration: {total_duration:.3f}s")
    print(f"[STRESS TEST] Throughput: {rps:.1f} requests/sec")
    print(f"[STRESS TEST] Avg Latency: {avg_latency_ms:.2f} ms/req")
    print(f"[STRESS TEST] Unique IDs verified: {len(unique_ids)}/{concurrency_count}")
