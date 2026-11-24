"""
VulnGuard AI - REST API Routes
Implements endpoints for vulnerability triage, assessment lookup, and history retrieval.
"""
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from backend.core.logging import logger
from backend.core.exceptions import IntelligenceNotFoundError, ThreatIntelFetchError
from backend.schemas.assessment import (
    AssessmentRequest,
    AssessmentResponse,
    AssessmentSummary,
    PaginatedAssessmentsResponse,
)
from backend.agents.graph import execute_assessment
from backend.api.deps import get_db_repo, get_current_user, verify_analysis_access
from database.interface import AssessmentRepository
from backend.services.cache import nvd_cache, epss_cache, cisa_cache
from backend.services.cisa_service import CATALOG_CACHE_KEY, cisa_service
from backend.services.nvd_service import nvd_service
from backend.services.epss_service import epss_service
from backend.core.config import settings

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
    repo: AssessmentRepository = Depends(get_db_repo),
    user: Dict[str, Any] = Depends(get_current_user),
) -> AssessmentResponse:
    try:
        owner = user.get("sub", "unassigned")

        # 1. Execute 3-Node LangGraph Pipeline scoped to authenticated user
        assessment = await execute_assessment(request, owner_user_id=owner)

        # 2. Persist to active repository backend (DynamoDB / SQLite) scoped to owner
        repo.save(assessment, owner_user_id=owner)

        return assessment
    except IntelligenceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=exc.message) from exc
    except ThreatIntelFetchError as exc:
        raise HTTPException(status_code=503, detail=exc.message) from exc
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(val_err))
    except Exception as exc:
        logger.error(f"[API] Error analyzing {request.cve_id}: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to complete vulnerability analysis: {str(exc)}"
        )


@router.get(
    "/assessments/paged",
    response_model=PaginatedAssessmentsResponse,
    summary="List Assessment History (Paginated)",
    description="Retrieves paginated assessments scoped to the authenticated user with explicit counts and cursor."
)
async def list_assessments_paged(
    limit: int = Query(default=20, ge=1, le=100, description="Max number of items to return"),
    cursor: Optional[str] = Query(default=None, description="Pagination cursor"),
    repo: AssessmentRepository = Depends(get_db_repo),
    user: Dict[str, Any] = Depends(get_current_user),
) -> PaginatedAssessmentsResponse:
    owner = user.get("sub", "unassigned")
    items, next_cursor = repo.list_recent_assessments(owner_user_id=owner, limit=limit, last_evaluated_key=cursor)
    return PaginatedAssessmentsResponse(
        items=items,
        count=len(items),
        next_cursor=next_cursor,
        has_more=bool(next_cursor),
    )


@router.get(
    "/assessments",
    response_model=List[AssessmentSummary],
    summary="List Assessment History",
    description="Retrieves a chronological list of assessments scoped strictly to the authenticated user."
)
async def list_assessments(
    limit: int = Query(default=20, ge=1, le=100, description="Max number of items to return"),
    cursor: Optional[str] = Query(default=None, description="Pagination cursor"),
    repo: AssessmentRepository = Depends(get_db_repo),
    user: Dict[str, Any] = Depends(get_current_user),
) -> List[AssessmentSummary]:
    owner = user.get("sub", "unassigned")
    items, _ = repo.list_recent_assessments(owner_user_id=owner, limit=limit, last_evaluated_key=cursor)
    return items


@router.get(
    "/assessments/{assessment_id}",
    response_model=AssessmentResponse,
    summary="Get Assessment Details",
    description="Retrieves a complete vulnerability assessment by ID, strictly verifying ownership."
)
async def get_assessment(
    assessment_id: str,
    repo: AssessmentRepository = Depends(get_db_repo),
    user: Dict[str, Any] = Depends(get_current_user),
) -> AssessmentResponse:
    owner = user.get("sub", "unassigned")
    assessment = repo.get_by_id(assessment_id, owner_user_id=owner)
    if not assessment:
        # Consistently return 404 so existence under another user is not leaked
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment with ID '{assessment_id}' was not found in your workspace."
        )
    return assessment


@router.get(
    "/user/workspace",
    summary="User Workspace Summary & Telemetry",
    description="Returns aggregate metrics, recent triage items, and priority distributions for the signed-in user."
)
async def get_user_workspace(
    repo: AssessmentRepository = Depends(get_db_repo),
    user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    owner = user.get("sub", "unassigned")
    items, _ = repo.list_recent_assessments(owner_user_id=owner, limit=100)

    priorities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for item in items:
        p_name = item.priority_level.value if hasattr(item.priority_level, "value") else str(item.priority_level)
        if p_name.upper() in priorities:
            priorities[p_name.upper()] += 1

    return {
        "user_id": owner,
        "email": user.get("email"),
        "client_type": user.get("client_type"),
        "total_assessments": len(items),
        "recent_assessments": items[:10],
        "priority_distribution": priorities,
    }


@router.get(
    "/threat-intel/status",
    summary="Threat Intelligence Feeds Status",
    description="Returns current caching and synchronization status of upstream threat intelligence feeds."
)
async def get_intel_status() -> Dict[str, Any]:
    cisa_catalog = cisa_cache.get(CATALOG_CACHE_KEY)
    cisa_count = len(cisa_catalog) if cisa_catalog else 0

    nvd_status = nvd_service.last_status
    epss_status = epss_service.last_status
    cisa_status = cisa_service.last_status if cisa_count > 0 else (
        "uninitialized" if cisa_service.last_status == "operational" else cisa_service.last_status
    )

    # Compute overall status dynamically based on real feed health
    statuses = [nvd_status, epss_status, cisa_status]
    if any(s in ("dns_resolution_failed", "unreachable", "degraded", "rate_limited") for s in statuses):
        overall_status = "degraded"
    else:
        overall_status = "operational"

    return {
        "status": overall_status,
        "feeds": {
            "nist_nvd": {
                "name": "NIST National Vulnerability Database API 2.0",
                "status": nvd_status,
                "authenticated": bool(settings.get_nvd_api_key()),
                "rate_limit_tier": f"{settings.nvd_rate_limit_calls} req / {int(settings.nvd_rate_limit_period)}s",
                "last_error": nvd_service.last_error,
                "last_check": nvd_service.last_check_time,
                "cached_items": nvd_cache.size(),
                "ttl_hours": settings.NVD_CACHE_TTL_HOURS,
            },
            "first_epss": {
                "name": "FIRST.org Exploit Prediction Scoring System",
                "status": epss_status,
                "last_error": epss_service.last_error,
                "last_check": epss_service.last_check_time,
                "cached_items": epss_cache.size(),
                "ttl_hours": settings.EPSS_CACHE_TTL_HOURS,
            },
            "cisa_kev": {
                "name": "CISA Known Exploited Vulnerabilities Catalog",
                "status": cisa_status,
                "catalog_loaded": cisa_count > 0,
                "known_exploited_cves_count": cisa_count,
                "last_error": cisa_service.last_error,
                "last_check": cisa_service.last_check_time,
                "ttl_hours": settings.CISA_CACHE_TTL_HOURS,
            }
        }
    }
