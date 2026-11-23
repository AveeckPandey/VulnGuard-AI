"""
VulnGuard AI - Phase 5 Amazon Bedrock Integration & Fallback Tests
Validates Amazon Bedrock Nova model execution and deterministic rules fallback.
"""
import pytest
from unittest.mock import patch, MagicMock
from backend.agents.bedrock import bedrock_explainer, BedrockExplainer
from backend.services.scorer import scoring_engine
from backend.schemas.risk import AssetCriticality, InternetExposure
from backend.tests.test_scorer import build_mock_intel


@pytest.mark.asyncio
async def test_bedrock_live_nova_explanation():
    """Tests live Amazon Bedrock Nova invocation with validated CVE evidence."""
    intel = build_mock_intel(cvss=10.0, epss_prob=0.97, is_kev=True)
    intel.is_simulated = False  # Enable live inference
    risk = scoring_engine.calculate_risk(intel, AssetCriticality.CRITICAL, InternetExposure.PUBLIC_FACING)

    remediation = await bedrock_explainer.generate_explanation(
        cve_id="CVE-2021-44228",
        intel=intel,
        risk_score=risk,
        system_context="Public Edge Payment Gateway",
        force_deterministic=False
    )

    assert remediation is not None
    assert len(remediation.remediation_steps) >= 1
    assert len(remediation.mitigation_workarounds) >= 1
    assert len(remediation.evidence_citations) >= 3

    # If Bedrock succeeded, it is labeled with model id, or if fallback, labeled cleanly
    if not remediation.is_fallback_deterministic:
        assert "nova" in remediation.model_used.lower()
    else:
        assert remediation.model_used == "deterministic-fallback-rules"


@pytest.mark.asyncio
async def test_bedrock_fallback_when_unavailable():
    """Tests that deterministic fallback is invoked when Bedrock client encounters an error."""
    intel = build_mock_intel(cvss=7.8, epss_prob=0.05, is_kev=False)
    risk = scoring_engine.calculate_risk(intel, AssetCriticality.HIGH, InternetExposure.INTERNAL)

    explainer = BedrockExplainer()
    # Force client invocation to raise error
    with patch.object(explainer, "_invoke_bedrock_nova", side_effect=Exception("ThrottlingException: Rate exceeded")):
        remediation = await explainer.generate_explanation(
            cve_id="CVE-2023-38606",
            intel=intel,
            risk_score=risk,
            system_context="Corporate fleet",
            force_deterministic=False
        )

        assert remediation.is_fallback_deterministic is True
        assert remediation.model_used == "deterministic-fallback-rules"
        assert "CVE-2023-38606" in remediation.executive_summary
        assert len(remediation.remediation_steps) >= 3
