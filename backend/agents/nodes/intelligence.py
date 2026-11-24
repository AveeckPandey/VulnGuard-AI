"""
VulnGuard AI - Intelligence Collection Node
Node 1 in the LangGraph assessment workflow.
Queries NIST NVD, FIRST EPSS, and CISA KEV concurrently and aggregates results.
"""
import asyncio
from backend.core.logging import logger
from backend.core.exceptions import IntelligenceNotFoundError, ThreatIntelFetchError
from backend.agents.state import VulnGuardState
from backend.schemas.intelligence import AggregatedIntel, IntelSourceStatus
from backend.services.nvd_service import nvd_service
from backend.services.epss_service import epss_service
from backend.services.cisa_service import cisa_service


async def intelligence_collection_node(state: VulnGuardState) -> VulnGuardState:
    """Collects multi-source cybersecurity threat intelligence for the target CVE."""
    cve_id = state["cve_id"]
    simulate_offline = state.get("simulate_offline", False)
    logger.info(f"[LangGraph Node 1] Initiating intelligence collection for {cve_id} (offline={simulate_offline})")

    # Fetch all 3 feeds concurrently
    nvd_task = nvd_service.fetch_cve(cve_id, simulate_offline=simulate_offline)
    epss_task = epss_service.fetch_epss(cve_id, simulate_offline=simulate_offline)
    cisa_task = cisa_service.get_cisa_kev(cve_id, simulate_offline=simulate_offline)

    results = await asyncio.gather(
        nvd_task, epss_task, cisa_task, return_exceptions=True
    )

    nvd_res = results[0] if not isinstance(results[0], Exception) else nvd_service._build_unavailable(cve_id)
    epss_res = results[1] if not isinstance(results[1], Exception) else epss_service._build_unavailable(cve_id)
    cisa_res = results[2] if not isinstance(results[2], Exception) else cisa_service._build_unavailable(cve_id)

    if any(isinstance(r, Exception) for r in results):
        logger.warning(f"[LangGraph Node 1] Upstream exception caught in one or more feeds for {cve_id}; returning controlled partial intelligence.")

    if not simulate_offline and all(feed.status != IntelSourceStatus.AVAILABLE for feed in (nvd_res, epss_res, cisa_res)):
        if nvd_res.status == IntelSourceStatus.CONFIRMED_NEGATIVE:
            raise IntelligenceNotFoundError(f"No published intelligence found for {cve_id}.")
        raise ThreatIntelFetchError(f"Unable to verify {cve_id} with the upstream intelligence services. Retry later.")

    is_simulated = (
        simulate_offline or
        nvd_res.is_simulated or
        epss_res.is_simulated or
        cisa_res.is_simulated
    )

    aggregated = AggregatedIntel(
        cve_id=cve_id,
        nvd=nvd_res,
        epss=epss_res,
        cisa_kev=cisa_res,
        is_simulated=is_simulated,
    )

    logger.info(f"[LangGraph Node 1] Completed intelligence collection for {cve_id}")
    return {"intelligence": aggregated}
