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


@pytest.mark.asyncio
async def test_xz_version_guardrail_remediation():
    """
    Validates BUG-04 fix: XZ Utils (CVE-2024-3094) version remediation guardrails.
    Ensures neither vulnerable version 5.6.1 nor ambiguous 'post-5.6.0' advice is ever recommended.
    """
    explainer = BedrockExplainer()
    intel = build_mock_intel(cvss=10.0, epss_prob=0.91, is_kev=False)
    risk = scoring_engine.calculate_risk(intel, AssetCriticality.CRITICAL, InternetExposure.PUBLIC_FACING)

    # 1. Prompt instructions check
    prompt = explainer._build_prompt("CVE-2024-3094", intel, risk, "Production Linux Host")
    assert "CRITICAL REMEDIATION & VERSIONING GUARDRAILS" in prompt
    assert "CVE-2024-3094" in prompt
    assert "5.6.1" in prompt
    assert "5.4.6" in prompt

    # 2. Output guardrail interceptor check across all 5 schema fields
    bad_data = {
        "executive_summary": "Critical vulnerability identified in liblzma. We recommend upgrading to 5.6.1 immediately.",
        "technical_impact": "Malicious code injected via M4 macros. Deploying version 5.6.1 resolves this impact.",
        "exploitation_assessment": "High probability of exploitation. Systems should patch to post-5.6.0 releases.",
        "remediation_steps": [
            "Upgrade XZ Utils to a patched version (post 5.6.0) immediately.",
            "Alternatively upgrade to 5.6.1 if available."
        ],
        "mitigation_workarounds": [
            "Isolate hosts after 5.6.0",
            "Switch to 5.6.1 in staging"
        ]
    }
    exec_summary, tech_impact, exploit_assess, guarded_steps, guarded_mits = explainer._guard_ai_output("CVE-2024-3094", bad_data)

    # Verify all 5 fields neutralized the bad recommendations
    assert "upgrading to 5.6.1" not in exec_summary.lower()
    assert "5.4.6" in exec_summary or "5.6.2" in exec_summary

    assert "deploying version 5.6.1" not in tech_impact.lower()
    assert "5.4.6" in tech_impact or "5.6.2" in tech_impact

    assert "post-5.6.0" not in exploit_assess.lower()
    assert "5.4.6" in exploit_assess or "5.6.2" in exploit_assess

    for s in guarded_steps:
        assert "post 5.6.0" not in s.lower()
        assert "upgrade to 5.6.1" not in s.lower()
        assert "5.4.6" in s or "5.6.2" in s

    for m in guarded_mits:
        assert "after 5.6.0" not in m.lower()
        assert "switch to 5.6.1" not in m.lower()
        assert "5.4.6" in m

    # 3. Verification that correct/safe mentions of 5.6.1 are NOT replaced
    safe_data = {
        "executive_summary": "CVE-2024-3094 affects XZ Utils 5.6.0 and 5.6.1. Avoid version 5.6.1 and downgrade to 5.4.6.",
        "technical_impact": "Versions 5.6.0 and 5.6.1 contain an upstream supply chain backdoor affecting OpenSSH sshd.",
        "exploitation_assessment": "Active testing in distributions. Do not deploy 5.6.0 or 5.6.1 under any circumstances.",
        "remediation_steps": [
            "Downgrade packages immediately to uncompromised 5.4.6 (avoid 5.6.1)."
        ],
        "mitigation_workarounds": [
            "Isolate all hosts that installed tainted 5.6.0 or 5.6.1."
        ]
    }
    s_exec, s_tech, s_exploit, s_steps, s_mits = explainer._guard_ai_output("CVE-2024-3094", safe_data)
    assert "Avoid version 5.6.1" in s_exec
    assert "5.6.0 and 5.6.1 contain an upstream supply chain backdoor" in s_tech
    assert "Do not deploy 5.6.0 or 5.6.1" in s_exploit
    assert "(avoid 5.6.1)" in s_steps[0]
    assert "tainted 5.6.0 or 5.6.1" in s_mits[0]

    # 4. Deterministic remediation check
    det_remediation = explainer._build_deterministic_remediation(
        "CVE-2024-3094", intel, risk, "Edge Server", is_fallback=True
    )
    assert any("Downgrade XZ Utils to known uncompromised version 5.4.6" in s for s in det_remediation.remediation_steps)
    assert not any("upgrade to 5.6.1" in s.lower() or "post 5.6.0" in s.lower() or "post-5.6.0" in s.lower() for s in det_remediation.remediation_steps)


@pytest.mark.asyncio
async def test_nvidia_nemotron_five_field_guardrail():
    """
    Validates that the NVIDIA Nemotron AI path applies the five-field guardrail
    across executive_summary, technical_impact, exploitation_assessment,
    remediation_steps, and mitigation_workarounds.
    """
    import json
    explainer = BedrockExplainer()
    intel = build_mock_intel(cvss=10.0, epss_prob=0.91, is_kev=False)
    risk = scoring_engine.calculate_risk(intel, AssetCriticality.CRITICAL, InternetExposure.PUBLIC_FACING)

    # Raw model JSON containing unsafe recommendations across narrative and list fields
    model_json = {
        "executive_summary": "Critical vulnerability identified in liblzma. We recommend upgrading to 5.6.1 immediately.",
        "technical_impact": "Malicious code injected via M4 macros. Deploying version 5.6.1 resolves this impact.",
        "exploitation_assessment": "High probability of exploitation. Systems should patch to post-5.6.0 releases.",
        "remediation_steps": [
            "Upgrade XZ Utils to 5.6.1 immediately."
        ],
        "mitigation_workarounds": [
            "Switch to 5.6.1 in staging environments."
        ]
    }
    raw_response = {
        "choices": [
            {
                "message": {
                    "content": f"```json\n{json.dumps(model_json)}\n```"
                }
            }
        ]
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = raw_response

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        remediation = await explainer._invoke_nvidia_nemotron(
            cve_id="CVE-2024-3094",
            intel=intel,
            risk_score=risk,
            system_context="Edge Server",
            api_key="nvapi-test-key"
        )

        assert remediation.model_used == "nvidia/nemotron-3.5-bolt-e4b"
        # Assert narrative fields were sanitized
        assert "upgrading to 5.6.1" not in remediation.executive_summary.lower()
        assert "5.4.6" in remediation.executive_summary or "5.6.2" in remediation.executive_summary

        assert "deploying version 5.6.1" not in remediation.technical_impact.lower()
        assert "5.4.6" in remediation.technical_impact or "5.6.2" in remediation.technical_impact

        assert "post-5.6.0" not in remediation.exploitation_assessment.lower()
        assert "5.4.6" in remediation.exploitation_assessment or "5.6.2" in remediation.exploitation_assessment

        # Assert list fields were sanitized
        for s in remediation.remediation_steps:
            assert "upgrade to 5.6.1" not in s.lower()
            assert "5.4.6" in s or "5.6.2" in s

        for m in remediation.mitigation_workarounds:
            assert "switch to 5.6.1" not in m.lower()
            assert "5.4.6" in m

