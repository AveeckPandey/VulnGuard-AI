"""
VulnGuard AI - Phase 3 LangGraph Workflow & Node Isolation Tests
Tests each node independently and tests the complete compiled StateGraph.
Verifies state transitions, error resilience, evidence propagation, and lack of loops.
"""
import pytest
from unittest.mock import patch, AsyncMock
from backend.agents.nodes.intelligence import intelligence_collection_node
from backend.agents.nodes.prioritization import risk_prioritization_node
from backend.agents.nodes.explanation import ai_explanation_node
from backend.agents.graph import vulnguard_graph, execute_assessment
from backend.agents.state import VulnGuardState
from backend.schemas.assessment import AssessmentRequest
from backend.schemas.risk import AssetCriticality, InternetExposure, PriorityLevel
from backend.schemas.intelligence import IntelSourceStatus
from backend.tests.fixtures.simulated_intel import SIMULATED_CVE_FIXTURES


@pytest.mark.asyncio
async def test_node1_intelligence_collection_isolation():
    """Tests intelligence_collection_node independently."""
    state: VulnGuardState = {
        "cve_id": "CVE-2021-44228",
        "simulate_offline": True,
        "asset_criticality": AssetCriticality.HIGH,
        "internet_exposure": InternetExposure.PUBLIC_FACING,
    }

    result = await intelligence_collection_node(state)
    assert "intelligence" in result
    intel = result["intelligence"]
    assert intel.cve_id == "CVE-2021-44228"
    assert intel.nvd.cvss_base_score == 10.0
    assert intel.epss.epss_probability > 0.90
    assert intel.cisa_kev.is_known_exploited is True


@pytest.mark.asyncio
async def test_node1_resilience_to_feed_crash():
    """Tests that Node 1 catches unexpected feed exceptions and returns controlled partial intelligence."""
    state: VulnGuardState = {
        "cve_id": "CVE-2021-44228",
        "simulate_offline": False,
        "asset_criticality": AssetCriticality.HIGH,
        "internet_exposure": InternetExposure.PUBLIC_FACING,
    }

    # Simulate NVD throwing unexpected RuntimeError
    with patch("backend.services.nvd_service.nvd_service.fetch_cve", side_effect=RuntimeError("NVD service crashed")):
        result = await intelligence_collection_node(state)
        assert "intelligence" in result
        intel = result["intelligence"]
        # NVD should be marked as UNKNOWN_OR_MISSING rather than failing the whole node
        assert intel.nvd.status == IntelSourceStatus.UNKNOWN_OR_MISSING


@pytest.mark.asyncio
async def test_node2_risk_prioritization_isolation():
    """Tests risk_prioritization_node independently."""
    from backend.tests.test_scorer import build_mock_intel

    mock_intel = build_mock_intel(cvss=9.8, epss_prob=0.85, is_kev=True)
    state: VulnGuardState = {
        "cve_id": "CVE-2021-44228",
        "intelligence": mock_intel,
        "asset_criticality": AssetCriticality.CRITICAL,
        "internet_exposure": InternetExposure.PUBLIC_FACING,
    }

    result = await risk_prioritization_node(state)
    assert "risk_score" in result
    score = result["risk_score"]
    assert score.priority_level == PriorityLevel.CRITICAL
    assert score.total_score >= 85.0
    assert len(score.components) == 5


@pytest.mark.asyncio
async def test_node3_explanation_isolation():
    """Tests ai_explanation_node independently with deterministic rules fallback."""
    from backend.tests.test_scorer import build_mock_intel
    from backend.services.scorer import scoring_engine

    mock_intel = build_mock_intel(cvss=10.0, epss_prob=0.95, is_kev=True)
    risk_score = scoring_engine.calculate_risk(
        intel=mock_intel,
        criticality=AssetCriticality.HIGH,
        exposure=InternetExposure.PUBLIC_FACING,
    )

    state: VulnGuardState = {
        "cve_id": "CVE-2021-44228",
        "intelligence": mock_intel,
        "risk_score": risk_score,
        "system_context": "Production Auth Edge",
        "simulate_offline": True,
    }

    result = await ai_explanation_node(state)
    assert "remediation" in result
    remediation = result["remediation"]
    assert "CVE-2021-44228" in remediation.executive_summary
    assert len(remediation.remediation_steps) >= 3
    assert len(remediation.evidence_citations) >= 3


@pytest.mark.asyncio
async def test_full_compiled_stategraph_pipeline():
    """Tests the entire compiled LangGraph StateGraph pipeline from START to END."""
    initial_state: VulnGuardState = {
        "cve_id": "CVE-2023-38606",
        "asset_criticality": AssetCriticality.MEDIUM,
        "internet_exposure": InternetExposure.INTERNAL,
        "system_context": "Internal macOS development fleet",
        "simulate_offline": True,
    }

    final_state = await vulnguard_graph.ainvoke(initial_state)

    # 1. Intelligence preserved
    assert "intelligence" in final_state
    assert final_state["intelligence"].cve_id == "CVE-2023-38606"

    # 2. Risk scoring computed
    assert "risk_score" in final_state
    assert final_state["risk_score"].total_score > 0

    # 3. Remediation synthesized
    assert "remediation" in final_state
    assert final_state["remediation"].model_used is not None
