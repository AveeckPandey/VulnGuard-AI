"""
VulnGuard AI - LangGraph State Definition
Defines the shared state dictionary passed across the assessment graph nodes.
"""
from typing import TypedDict, Optional, List, Dict, Any
from backend.schemas.risk import AssetCriticality, InternetExposure, RiskScoreBreakdown
from backend.schemas.intelligence import AggregatedIntel
from backend.schemas.assessment import AiRemediation


class VulnGuardState(TypedDict, total=False):
    """LangGraph workflow state schema."""
    cve_id: str
    asset_criticality: AssetCriticality
    internet_exposure: InternetExposure
    system_context: Optional[str]
    simulate_offline: bool
    intelligence: Optional[AggregatedIntel]
    risk_score: Optional[RiskScoreBreakdown]
    remediation: Optional[AiRemediation]
    errors: List[str]
