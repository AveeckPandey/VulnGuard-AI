"""
VulnGuard AI - Multi-Tenant Workspace & Security Isolation Tests
Verifies that:
1. User A and User B analyzing the same CVE with different system contexts cannot
   list, retrieve, count, or infer each other's assessments.
2. Direct lookup of another user's assessment ID returns 404 (fails closed).
3. Personal workspace summary metrics reflect only the authenticated tenant's data.
4. Unauthenticated or invalid token requests receive HTTP 401 when auth is enforced.
5. Legacy unassigned records are quarantined from normal user tenant queries.
"""
from fastapi.testclient import TestClient
from backend.core.config import settings
from backend.schemas.assessment import AssessmentResponse, AiRemediation
from backend.schemas.risk import AssetCriticality, InternetExposure, PriorityLevel, RiskScoreBreakdown, ScoreComponent
from backend.schemas.intelligence import AggregatedIntel, NvdIntel, EpssIntel, CisaKevIntel, IntelSourceStatus
from database.factory import get_repository


USER_A_TOKEN = "user-a-edge-token"
USER_B_TOKEN = "user-b-core-token"

USER_A_HEADERS = {"Authorization": f"Bearer {USER_A_TOKEN}"}
USER_B_HEADERS = {"Authorization": f"Bearer {USER_B_TOKEN}"}


def test_two_users_analyzing_same_cve_strict_isolation(client: TestClient):
    """
    Two users analyze the same CVE with different contexts.
    Verifies that neither user can see, count, or retrieve the other's assessment.
    """
    cve_id = "CVE-2021-44228"

    # User A analyzes CVE-2021-44228 in critical edge context
    res_a = client.post(
        "/api/analyze",
        headers=USER_A_HEADERS,
        json={
            "cve_id": cve_id,
            "asset_criticality": "CRITICAL",
            "internet_exposure": "PUBLIC_FACING",
            "system_context": "User A Public Kubernetes Ingress Gateway",
            "simulate_offline": True,
        },
    )
    assert res_a.status_code == 201
    data_a = res_a.json()
    id_a = data_a["id"]
    assert data_a["owner_user_id"] == "usr-a-edge-analyst"
    assert data_a["risk_score"]["priority_level"] == "CRITICAL"

    # User B analyzes the SAME CVE-2021-44228 in low internal context
    res_b = client.post(
        "/api/analyze",
        headers=USER_B_HEADERS,
        json={
            "cve_id": cve_id,
            "asset_criticality": "LOW",
            "internet_exposure": "INTERNAL",
            "system_context": "User B Sandboxed Offline Dev Sandbox",
            "simulate_offline": True,
        },
    )
    assert res_b.status_code == 201
    data_b = res_b.json()
    id_b = data_b["id"]
    assert data_b["owner_user_id"] == "usr-b-core-analyst"
    assert id_a != id_b

    # 1. User A lists assessments: must see ONLY id_a, never id_b
    list_a = client.get("/api/assessments?limit=50", headers=USER_A_HEADERS)
    assert list_a.status_code == 200
    items_a = list_a.json()
    assert len(items_a) == 1
    assert items_a[0]["id"] == id_a
    assert items_a[0]["owner_user_id"] == "usr-a-edge-analyst"
    assert not any(item["id"] == id_b for item in items_a)

    # 2. User B lists assessments: must see ONLY id_b, never id_a
    list_b = client.get("/api/assessments?limit=50", headers=USER_B_HEADERS)
    assert list_b.status_code == 200
    items_b = list_b.json()
    assert len(items_b) == 1
    assert items_b[0]["id"] == id_b
    assert items_b[0]["owner_user_id"] == "usr-b-core-analyst"
    assert not any(item["id"] == id_a for item in items_b)

    # 3. Cross-Tenant ID Direct Access Prevention:
    # User A tries to fetch User B's assessment ID -> must return 404 (not found, zero information leak)
    cross_a_to_b = client.get(f"/api/assessments/{id_b}", headers=USER_A_HEADERS)
    assert cross_a_to_b.status_code == 404

    # User B tries to fetch User A's assessment ID -> must return 404
    cross_b_to_a = client.get(f"/api/assessments/{id_a}", headers=USER_B_HEADERS)
    assert cross_b_to_a.status_code == 404

    # 4. Personal Workspace summary isolation
    ws_a = client.get("/api/user/workspace", headers=USER_A_HEADERS)
    assert ws_a.status_code == 200
    ws_a_data = ws_a.json()
    assert ws_a_data["user_id"] == "usr-a-edge-analyst"
    assert ws_a_data["total_assessments"] == 1
    assert ws_a_data["priority_distribution"]["CRITICAL"] == 1
    assert len(ws_a_data["recent_assessments"]) == 1
    assert ws_a_data["recent_assessments"][0]["id"] == id_a

    ws_b = client.get("/api/user/workspace", headers=USER_B_HEADERS)
    assert ws_b.status_code == 200
    ws_b_data = ws_b.json()
    assert ws_b_data["user_id"] == "usr-b-core-analyst"
    assert ws_b_data["total_assessments"] == 1
    assert len(ws_b_data["recent_assessments"]) == 1
    assert ws_b_data["recent_assessments"][0]["id"] == id_b


def test_paginated_user_isolation(client: TestClient):
    """Verifies that pagination endpoints strictly return only the user's assessments."""
    # User A creates 2 assessments
    for cve in ["CVE-2021-44228", "CVE-2024-3094"]:
        client.post(
            "/api/analyze",
            headers=USER_A_HEADERS,
            json={
                "cve_id": cve,
                "asset_criticality": "HIGH",
                "internet_exposure": "PUBLIC_FACING",
                "simulate_offline": True,
            },
        )

    # User B creates 1 assessment
    client.post(
        "/api/analyze",
        headers=USER_B_HEADERS,
        json={
            "cve_id": "CVE-2023-34362",
            "asset_criticality": "MEDIUM",
            "internet_exposure": "INTERNAL",
            "simulate_offline": True,
        },
    )

    # User A queries paged endpoint
    paged_a = client.get("/api/assessments/paged?limit=10", headers=USER_A_HEADERS)
    assert paged_a.status_code == 200
    paged_a_data = paged_a.json()
    assert paged_a_data["count"] == 2
    assert len(paged_a_data["items"]) == 2
    for item in paged_a_data["items"]:
        assert item["owner_user_id"] == "usr-a-edge-analyst"

    # User B queries paged endpoint
    paged_b = client.get("/api/assessments/paged?limit=10", headers=USER_B_HEADERS)
    assert paged_b.status_code == 200
    paged_b_data = paged_b.json()
    assert paged_b_data["count"] == 1
    assert paged_b_data["items"][0]["owner_user_id"] == "usr-b-core-analyst"


def test_authentication_enforcement_and_unauthorized_rejection(client: TestClient):
    """Verifies that unauthenticated or invalid tokens receive HTTP 401 when REQUIRE_AUTH is true."""
    original_require_auth = settings.REQUIRE_AUTH
    try:
        settings.REQUIRE_AUTH = True

        # Unauthenticated POST /api/analyze fails with 401
        res_no_auth = client.post(
            "/api/analyze",
            json={
                "cve_id": "CVE-2021-44228",
                "asset_criticality": "HIGH",
                "internet_exposure": "PUBLIC_FACING",
                "simulate_offline": True,
            },
        )
        assert res_no_auth.status_code == 401

        # Unauthenticated GET /api/assessments fails with 401
        res_list_no_auth = client.get("/api/assessments")
        assert res_list_no_auth.status_code == 401

        # Unauthenticated GET /api/user/workspace fails with 401
        res_ws_no_auth = client.get("/api/user/workspace")
        assert res_ws_no_auth.status_code == 401

        # Invalid token fails with 401
        res_invalid = client.get(
            "/api/assessments",
            headers={"Authorization": "Bearer invalid-tampered-token-12345"},
        )
        assert res_invalid.status_code == 401

    finally:
        settings.REQUIRE_AUTH = original_require_auth


def test_legacy_unassigned_records_quarantine(client: TestClient):
    """
    Verifies that unassigned legacy records (owner_user_id is None)
    are quarantined and never surfaced in user-scoped queries.
    """
    repo = get_repository()

    # Create a legacy assessment without owner_user_id
    legacy_assessment = AssessmentResponse(
        id="vg-legacy-unassigned-001",
        cve_id="CVE-2020-0001",
        risk_score=RiskScoreBreakdown(
            total_score=50.0,
            priority_level=PriorityLevel.MEDIUM,
            components=[
                ScoreComponent(
                    name="CVSS Base Score",
                    raw_value=5.0,
                    normalized_score=50.0,
                    weight=0.30,
                    weighted_contribution=15.0,
                    description="CVSS 5.0",
                )
            ],
            summary="Legacy score",
        ),
        intelligence=AggregatedIntel(
            cve_id="CVE-2020-0001",
            nvd=NvdIntel(
                cve_id="CVE-2020-0001",
                status=IntelSourceStatus.AVAILABLE,
                description="Legacy sample CVE",
                cvss_version="3.1",
                cvss_base_score=5.0,
                cvss_severity="MEDIUM",
                cvss_vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                weaknesses=["CWE-200"],
                fetched_at="2026-11-20T00:00:00Z",
                source_url="https://nvd.nist.gov",
            ),
            epss=EpssIntel(
                cve_id="CVE-2020-0001",
                status=IntelSourceStatus.AVAILABLE,
                epss_probability=0.01,
                epss_percentile=0.5,
                fetched_at="2026-11-20T00:00:00Z",
                source_url="https://epss.cyentia.com",
            ),
            cisa_kev=CisaKevIntel(
                cve_id="CVE-2020-0001",
                status=IntelSourceStatus.CONFIRMED_NEGATIVE,
                is_known_exploited=False,
                fetched_at="2026-11-20T00:00:00Z",
                source_url="https://cisa.gov",
            ),
        ),
        remediation=AiRemediation(
            executive_summary="Legacy assessment",
            technical_impact="Low impact",
            exploitation_assessment="Unlikely",
            remediation_steps=["Upgrade package"],
            mitigation_workarounds=["Network ACLs"],
            evidence_citations=["https://nvd.nist.gov"],
            model_used="legacy-mock",
        ),
        asset_criticality=AssetCriticality.MEDIUM,
        internet_exposure=InternetExposure.INTERNAL,
        system_context="Old legacy system",
        created_at="2026-11-20T00:00:00Z",
        execution_time_ms=120.0,
        owner_user_id=None,  # Legacy record
    )

    repo.save_assessment(legacy_assessment)

    # User A queries assessments: legacy record must NOT be returned
    res_a = client.get("/api/assessments?limit=50", headers=USER_A_HEADERS)
    assert res_a.status_code == 200
    items_a = res_a.json()
    assert not any(item["id"] == "vg-legacy-unassigned-001" for item in items_a)

    # User A attempts direct get by ID: must return 404 (quarantined)
    get_legacy = client.get("/api/assessments/vg-legacy-unassigned-001", headers=USER_A_HEADERS)
    assert get_legacy.status_code == 404
