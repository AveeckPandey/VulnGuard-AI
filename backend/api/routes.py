"""
VulnGuard AI - REST API Routes
Implements endpoints for vulnerability triage, assessment lookup, and history retrieval.
"""
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from backend.core.logging import logger
from backend.core.exceptions import AssessmentNotFoundError, InvalidCVEFormatError
from backend.schemas.assessment import (
    AssessmentRequest,
    AssessmentResponse,
    AssessmentSummary,
)
from backend.agents.graph import execute_assessment
from backend.api.deps import get_db_repo
from database.interface import AssessmentRepository
from backend.services.cache import nvd_cache, epss_cache, cisa_cache
from backend.services.cisa_service import CATALOG_CACHE_KEY

router = APIRouter(prefix="/api", tags=["Vulnerability Assessment"])


@router.post(
    "/analyze",
    response_model=AssessmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Analyze CVE & Prioritize Risk",
    description="Executes the 3-node LangGraph intelligence pipeline to gather CVE threat intel, compute risk priority, and generate AI remediation."
)
async def analyze_vulnerability(
    request: AssessmentRequest,
    repo: AssessmentRepository = Depends(get_db_repo)
) -> AssessmentResponse:
    try:
        # 1. Execute 3-Node LangGraph Pipeline
        assessment = await execute_assessment(request)

        # 2. Persist to active repository backend (DynamoDB / SQLite)
        repo.save(assessment)

        return assessment
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(val_err))
    except Exception as exc:
        logger.error(f"[API] Error analyzing {request.cve_id}: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to complete vulnerability analysis: {str(exc)}"
        )


@router.get(
    "/assessments/{assessment_id}",
    response_model=AssessmentResponse,
    summary="Get Assessment Details",
    description="Retrieves a complete completed vulnerability assessment by its unique ID."
)
async def get_assessment(
    assessment_id: str,
    repo: AssessmentRepository = Depends(get_db_repo)
) -> AssessmentResponse:
    assessment = repo.get_by_id(assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment with ID '{assessment_id}' was not found."
        )
    return assessment


@router.get(
    "/assessments",
    response_model=List[AssessmentSummary],
    summary="List Assessment History",
    description="Retrieves a chronological list of recent vulnerability assessments."
)
async def list_assessments(
    limit: int = Query(default=20, ge=1, le=100, description="Max number of items to return"),
    repo: AssessmentRepository = Depends(get_db_repo)
) -> List[AssessmentSummary]:
    return repo.list_recent(limit=limit)


@router.get(
    "/threat-intel/status",
    summary="Threat Intelligence Feeds Status",
    description="Returns current caching and synchronization status of upstream threat intelligence feeds."
)
async def get_intel_status() -> Dict[str, Any]:
    cisa_catalog = cisa_cache.get(CATALOG_CACHE_KEY)
    cisa_count = len(cisa_catalog) if cisa_catalog else 0

    return {
        "status": "operational",
        "feeds": {
            "nist_nvd": {
                "name": "NIST National Vulnerability Database API 2.0",
                "cached_items": nvd_cache.size(),
                "ttl_hours": 12,
            },
            "first_epss": {
                "name": "FIRST.org Exploit Prediction Scoring System",
                "cached_items": epss_cache.size(),
                "ttl_hours": 24,
            },
            "cisa_kev": {
                "name": "CISA Known Exploited Vulnerabilities Catalog",
                "catalog_loaded": cisa_count > 0,
                "known_exploited_cves_count": cisa_count,
                "ttl_hours": 6,
            }
        }
    }
