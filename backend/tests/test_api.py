"""
VulnGuard AI - REST API Endpoint Integration Tests
Validates FastAPI endpoints, request validation, error responses, and database retrieval.
"""
from fastapi.testclient import TestClient


def test_health_check_endpoint(client: TestClient):
    """GET /health must return 200 OK with system status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "VulnGuard AI"
    assert data["database_backend"] == "sqlite"


def test_analyze_cve_endpoint(client: TestClient):
    """POST /api/analyze must process assessment and persist to database."""
    payload = {
        "cve_id": "CVE-2021-44228",
        "asset_criticality": "HIGH",
        "internet_exposure": "PUBLIC_FACING",
        "system_context": "Core Payment API Gateway",
        "simulate_offline": True
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 201
    data = response.json()

    assert data["cve_id"] == "CVE-2021-44228"
    assert "id" in data
    assert data["id"].startswith("vg-")
    assert data["risk_score"]["priority_level"] == "CRITICAL"
    assert data["risk_score"]["total_score"] >= 85.0
    assert len(data["remediation"]["remediation_steps"]) > 0

    # Test retrieval by ID
    assessment_id = data["id"]
    get_res = client.get(f"/api/assessments/{assessment_id}")
    assert get_res.status_code == 200
    retrieved = get_res.json()
    assert retrieved["id"] == assessment_id
    assert retrieved["cve_id"] == "CVE-2021-44228"


def test_list_assessments_history(client: TestClient):
    """GET /api/assessments must return history of saved assessments."""
    # Create two assessments
    for cve in ["CVE-2021-44228", "CVE-2023-38606"]:
        client.post("/api/analyze", json={
            "cve_id": cve,
            "asset_criticality": "MEDIUM",
            "internet_exposure": "INTERNAL",
            "simulate_offline": True
        })

    response = client.get("/api/assessments?limit=10")
    assert response.status_code == 200
    items = response.json()
    assert len(items) >= 2
    cves = [item["cve_id"] for item in items]
    assert "CVE-2021-44228" in cves
    assert "CVE-2023-38606" in cves


def test_invalid_cve_format_validation(client: TestClient):
    """Invalid CVE ID pattern should return HTTP 422 Unprocessable Entity."""
    response = client.post("/api/analyze", json={
        "cve_id": "INVALID-FORMAT",
        "asset_criticality": "LOW",
        "internet_exposure": "INTERNAL"
    })
    assert response.status_code == 422


def test_assessment_not_found_returns_404(client: TestClient):
    """GET /api/assessments/{nonexistent_id} must return 404."""
    response = client.get("/api/assessments/vg-nonexistent-12345")
    assert response.status_code == 404


def test_threat_intel_status_endpoint(client: TestClient):
    """GET /api/threat-intel/status must report operational feeds."""
    response = client.get("/api/threat-intel/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"
    assert "nist_nvd" in data["feeds"]
    assert "first_epss" in data["feeds"]


def test_analyze_cve_whitespace_and_lowercase_normalization(client: TestClient):
    """CVE with leading/trailing spaces and lowercase is normalized to uppercase."""
    response = client.post("/api/analyze", json={
        "cve_id": "   cve-2021-44228   ",
        "asset_criticality": "MEDIUM",
        "internet_exposure": "INTERNAL",
        "simulate_offline": True
    })
    assert response.status_code == 201
    assert response.json()["cve_id"] == "CVE-2021-44228"


def test_invalid_criticality_or_exposure_returns_422(client: TestClient):
    """Invalid enum values for criticality or exposure must return 422."""
    res1 = client.post("/api/analyze", json={
        "cve_id": "CVE-2021-44228",
        "asset_criticality": "EXTREME",
        "internet_exposure": "INTERNAL"
    })
    assert res1.status_code == 422

    res2 = client.post("/api/analyze", json={
        "cve_id": "CVE-2021-44228",
        "asset_criticality": "HIGH",
        "internet_exposure": "DMZ_NOT_SUPPORTED"
    })
    assert res2.status_code == 422


def test_assessments_query_limit_boundary(client: TestClient):
    """Query parameter limit boundary: ge=1, le=100. limit=0 or 101 must fail with 422."""
    res_low = client.get("/api/assessments?limit=0")
    assert res_low.status_code == 422

    res_high = client.get("/api/assessments?limit=101")
    assert res_high.status_code == 422

    res_valid = client.get("/api/assessments?limit=5")
    assert res_valid.status_code == 200


def test_empty_request_body_returns_422(client: TestClient):
    """POST /api/analyze with empty JSON body must return 422."""
    res = client.post("/api/analyze", json={})
    assert res.status_code == 422
