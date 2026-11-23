"""
VulnGuard AI - Live End-to-End Validation Script
Executes live assessments against running server for CVE-2021-44228 and CVE-2023-34362.
"""
import httpx
import json

def run_e2e_verification():
    client = httpx.Client(base_url="http://127.0.0.1:8000", timeout=45.0)

    print("=================================================================")
    print("TEST 1: Live Triage of Log4Shell (CVE-2021-44228)")
    print("=================================================================")
    res1 = client.post("/api/analyze", json={
        "cve_id": "CVE-2021-44228",
        "asset_criticality": "CRITICAL",
        "internet_exposure": "PUBLIC_FACING",
        "system_context": "Core Payment Ingress Gateway",
        "simulate_offline": False
    })
    print(f"HTTP Status: {res1.status_code}")
    assert res1.status_code == 201, f"Failed: {res1.text}"
    d1 = res1.json()
    print(f"Assessment ID      : {d1['id']}")
    print(f"CVE ID             : {d1['cve_id']}")
    print(f"CVSS Base Score    : {d1['intelligence']['nvd']['cvss_base_score']} ({d1['intelligence']['nvd']['cvss_severity']})")
    print(f"CVSS Vector        : {d1['intelligence']['nvd']['cvss_vector_string']}")
    print(f"EPSS Probability   : {d1['intelligence']['epss']['epss_probability']} (Percentile: {d1['intelligence']['epss']['epss_percentile']})")
    print(f"CISA KEV Listed    : {d1['intelligence']['cisa_kev']['is_known_exploited']}")
    print(f"Vulnerability Name : {d1['intelligence']['cisa_kev']['vulnerability_name']}")
    print(f"Calculated Score   : {d1['risk_score']['total_score']}/100 ({d1['risk_score']['priority_level']})")
    print(f"Inference Model    : {d1['remediation']['model_used']}")
    print(f"Execution Latency  : {d1['execution_time_ms']} ms")
    assert d1["intelligence"]["cisa_kev"]["is_known_exploited"] is True
    assert d1["risk_score"]["priority_level"] == "CRITICAL"
    assert d1["risk_score"]["total_score"] >= 85.0

    print("\n=================================================================")
    print("TEST 2: Live Triage of MOVEit Transfer (CVE-2023-34362)")
    print("=================================================================")
    res2 = client.post("/api/analyze", json={
        "cve_id": "CVE-2023-34362",
        "asset_criticality": "HIGH",
        "internet_exposure": "PUBLIC_FACING",
        "system_context": "MOVEit Transfer SFTP Cluster",
        "simulate_offline": False
    })
    print(f"HTTP Status: {res2.status_code}")
    assert res2.status_code == 201, f"Failed: {res2.text}"
    d2 = res2.json()
    print(f"Assessment ID      : {d2['id']}")
    print(f"CVE ID             : {d2['cve_id']}")
    print(f"CVSS Base Score    : {d2['intelligence']['nvd']['cvss_base_score']} ({d2['intelligence']['nvd']['cvss_severity']})")
    print(f"EPSS Probability   : {d2['intelligence']['epss']['epss_probability']}")
    print(f"CISA KEV Listed    : {d2['intelligence']['cisa_kev']['is_known_exploited']}")
    print(f"Calculated Score   : {d2['risk_score']['total_score']}/100 ({d2['risk_score']['priority_level']})")
    print(f"Inference Model    : {d2['remediation']['model_used']}")
    print(f"Execution Latency  : {d2['execution_time_ms']} ms")
    assert d2["intelligence"]["cisa_kev"]["is_known_exploited"] is True
    assert d2["risk_score"]["total_score"] >= 85.0

    print("\n=================================================================")
    print("TEST 3: Assessment Retrieval from Repository")
    print("=================================================================")
    aid = d1["id"]
    get_res = client.get(f"/api/assessments/{aid}")
    assert get_res.status_code == 200
    retrieved = get_res.json()
    assert retrieved["id"] == aid
    assert retrieved["cve_id"] == "CVE-2021-44228"
    print(f"Successfully retrieved assessment {aid} from repository.")

    print("\n=================================================================")
    print("TEST 4: Assessment History Listing")
    print("=================================================================")
    hist_res = client.get("/api/assessments?limit=10")
    assert hist_res.status_code == 200
    history_items = hist_res.json()
    assert len(history_items) >= 2
    cves_in_history = [h["cve_id"] for h in history_items]
    print(f"History contains {len(history_items)} items. Recent CVEs: {cves_in_history[:5]}")
    assert "CVE-2021-44228" in cves_in_history
    assert "CVE-2023-34362" in cves_in_history

    print("\n=================================================================")
    print("TEST 5: Invalid Input Validation (Malformed CVE format)")
    print("=================================================================")
    bad_res = client.post("/api/analyze", json={"cve_id": "INVALID-NOT-A-CVE"})
    print(f"HTTP Status: {bad_res.status_code}")
    assert bad_res.status_code == 422
    print(f"Validation Error Response: {bad_res.json()}")

    print("\n=================================================================")
    print("ALL LIVE END-TO-END VERIFICATION CHECKS PASSED SUCCESSFULLY!")
    print("=================================================================")

if __name__ == "__main__":
    run_e2e_verification()
