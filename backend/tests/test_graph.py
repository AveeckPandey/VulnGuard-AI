"""
VulnGuard AI - LangGraph Workflow Integration Tests
Validates the 3-node assessment graph end-to-end.
"""
import pytest
from backend.agents.graph import execute_assessment
from backend.schemas.assessment import AssessmentRequest
from backend.schemas.risk import AssetCriticality, InternetExposure, PriorityLevel


@pytest.mark.asyncio
async def test_langgraph_workflow_execution():
    """Executes the full 3-node LangGraph workflow in simulated mode."""
    request = AssessmentRequest(
        cve_id="CVE-2021-44228",
        asset_criticality=AssetCriticality.HIGH,
        internet_exposure=InternetExposure.PUBLIC_FACING,
        system_context="Publicly accessible Apache Web server",
        simulate_offline=True,
    )

    assessment = await execute_assessment(request)

    # 1. Verify Node 1: Intelligence
    assert assessment.intelligence is not None
    assert assessment.intelligence.cve_id == "CVE-2021-44228"
    assert assessment.intelligence.nvd.cvss_base_score == 10.0
    assert assessment.intelligence.cisa_kev.is_known_exploited is True

    # 2. Verify Node 2: Risk Prioritization
    assert assessment.risk_score is not None
    assert assessment.risk_score.total_score >= 85.0
    assert assessment.risk_score.priority_level == PriorityLevel.CRITICAL
    assert len(assessment.risk_score.components) == 5

    # 3. Verify Node 3: AI Explanation & Remediation
    assert assessment.remediation is not None
    assert "CVE-2021-44228" in assessment.remediation.executive_summary
    assert len(assessment.remediation.remediation_steps) >= 3
    assert len(assessment.remediation.mitigation_workarounds) >= 2
    assert assessment.remediation.is_fallback_deterministic is True
    assert assessment.remediation.model_used == "deterministic-fallback-rules"

    # Execution time recorded
    assert assessment.execution_time_ms > 0
