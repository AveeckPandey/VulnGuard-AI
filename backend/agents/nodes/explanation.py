"""
VulnGuard AI - AI Explanation Node
Node 3 in the LangGraph assessment workflow.
Invokes Amazon Bedrock Nova (or deterministic fallback) to produce evidence-grounded remediation.
"""
from backend.core.logging import logger
from backend.agents.state import VulnGuardState
from backend.agents.bedrock import bedrock_explainer


async def ai_explanation_node(state: VulnGuardState) -> VulnGuardState:
    """Generates executive summary, technical impact, exploitation assessment, and remediation."""
    cve_id = state["cve_id"]
    intel = state["intelligence"]
    risk_score = state["risk_score"]
    system_context = state.get("system_context")
    simulate_offline = state.get("simulate_offline", False)

    logger.info(f"[LangGraph Node 3] Generating remediation explanation for {cve_id}")

    remediation = await bedrock_explainer.generate_explanation(
        cve_id=cve_id,
        intel=intel,
        risk_score=risk_score,
        system_context=system_context,
        force_deterministic=simulate_offline,
    )

    logger.info(f"[LangGraph Node 3] Explanation complete using model: '{remediation.model_used}' (fallback={remediation.is_fallback_deterministic})")
    return {"remediation": remediation}
