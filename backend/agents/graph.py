"""
VulnGuard AI - LangGraph StateGraph Workflow
Constructs the 3-node assessment execution graph:
START -> intel_collection -> risk_prioritization -> ai_explanation -> END
"""
import uuid
import time
from datetime import datetime, timezone
from langgraph.graph import StateGraph, START, END

from backend.core.logging import logger
from backend.agents.state import VulnGuardState
from backend.agents.nodes.intelligence import intelligence_collection_node
from backend.agents.nodes.prioritization import risk_prioritization_node
from backend.agents.nodes.explanation import ai_explanation_node
from backend.schemas.assessment import AssessmentRequest, AssessmentResponse


def build_assessment_graph():
    """Builds and compiles the 3-node LangGraph workflow."""
    workflow = StateGraph(VulnGuardState)

    workflow.add_node("intel_collection", intelligence_collection_node)
    workflow.add_node("risk_prioritization", risk_prioritization_node)
    workflow.add_node("ai_explanation", ai_explanation_node)

    workflow.add_edge(START, "intel_collection")
    workflow.add_edge("intel_collection", "risk_prioritization")
    workflow.add_edge("risk_prioritization", "ai_explanation")
    workflow.add_edge("ai_explanation", END)

    return workflow.compile()


vulnguard_graph = build_assessment_graph()


async def execute_assessment(request: AssessmentRequest) -> AssessmentResponse:
    """Executes the full LangGraph pipeline and returns the validated AssessmentResponse."""
    start_time = time.monotonic()
    assessment_id = f"vg-{uuid.uuid4().hex[:12]}"
    created_at = datetime.now(timezone.utc).isoformat()

    logger.info(f"[Workflow] Starting assessment {assessment_id} for {request.cve_id}")

    initial_state: VulnGuardState = {
        "cve_id": request.cve_id,
        "asset_criticality": request.asset_criticality,
        "internet_exposure": request.internet_exposure,
        "system_context": request.system_context,
        "simulate_offline": request.simulate_offline,
        "errors": [],
    }

    # Execute LangGraph workflow asynchronously
    final_state = await vulnguard_graph.ainvoke(initial_state)

    duration_ms = round((time.monotonic() - start_time) * 1000.0, 2)

    response = AssessmentResponse(
        id=assessment_id,
        cve_id=request.cve_id,
        asset_criticality=request.asset_criticality,
        internet_exposure=request.internet_exposure,
        system_context=request.system_context,
        intelligence=final_state["intelligence"],
        risk_score=final_state["risk_score"],
        remediation=final_state["remediation"],
        created_at=created_at,
        execution_time_ms=duration_ms,
    )

    logger.info(f"[Workflow] Completed assessment {assessment_id} in {duration_ms}ms (Score: {response.risk_score.total_score})")
    return response
