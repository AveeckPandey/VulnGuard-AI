"""
VulnGuard AI - Risk Prioritization Node
Node 2 in the LangGraph assessment workflow.
Executes the deterministic 0-100 cybersecurity prioritization scoring engine.
"""
from backend.core.logging import logger
from backend.agents.state import VulnGuardState
from backend.services.scorer import scoring_engine


async def risk_prioritization_node(state: VulnGuardState) -> VulnGuardState:
    """Calculates deterministic composite risk score and factor contributions."""
    cve_id = state["cve_id"]
    intel = state["intelligence"]
    criticality = state["asset_criticality"]
    exposure = state["internet_exposure"]

    logger.info(f"[LangGraph Node 2] Calculating risk priority for {cve_id} (Crit: {criticality}, Expo: {exposure})")

    risk_score = scoring_engine.calculate_risk(
        intel=intel,
        criticality=criticality,
        exposure=exposure,
    )

    logger.info(f"[LangGraph Node 2] Completed risk score: {risk_score.total_score} ({risk_score.priority_level.value})")
    return {"risk_score": risk_score}
