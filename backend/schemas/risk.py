"""
VulnGuard AI - Risk Scoring Schemas
Defines enumerations, scoring component breakdowns, and priority models.
"""
from enum import Enum
from typing import List, Optional, Any
from pydantic import BaseModel, Field


class AssetCriticality(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class InternetExposure(str, Enum):
    INTERNAL = "INTERNAL"
    PUBLIC_FACING = "PUBLIC_FACING"


class PriorityLevel(str, Enum):
    CRITICAL = "CRITICAL"  # 85 - 100
    HIGH = "HIGH"          # 70 - 84
    MEDIUM = "MEDIUM"      # 40 - 69
    LOW = "LOW"            # 0 - 39


class ScoreComponent(BaseModel):
    name: str = Field(..., description="Factor name (e.g. CVSS Severity, EPSS Probability)")
    raw_value: Any = Field(..., description="Raw input value before normalization")
    normalized_score: float = Field(..., ge=0.0, le=100.0, description="Normalized score on 0-100 scale")
    weight: float = Field(..., ge=0.0, le=1.0, description="Weight factor (e.g. 0.30)")
    weighted_contribution: float = Field(..., description="Calculated contribution to total score")
    description: str = Field(..., description="Explanation of how the score was calculated")


class RiskScoreBreakdown(BaseModel):
    total_score: float = Field(..., ge=0.0, le=100.0, description="Final composite score (0-100)")
    priority_level: PriorityLevel = Field(..., description="Categorized priority")
    is_provisional: bool = Field(False, description="True if key intelligence was missing or estimated")
    provisional_reasons: List[str] = Field(default_factory=list, description="Reasons for provisional status")
    components: List[ScoreComponent] = Field(..., description="Detailed contribution of each factor")
    summary: str = Field(..., description="Human-readable synthesis of the scoring rationale")
    formula_disclaimer: str = Field(
        default="Custom portfolio heuristic scoring model (CVSS 30%, EPSS 30%, KEV 20%, Criticality 10%, Exposure 10%). Not an official NIST/CISA risk standard.",
        description="Notice clarifying this is a custom scoring heuristic."
    )
