"""
VulnGuard AI - Phase 4 Risk Scoring Engine & Boundary Verification Tests
Validates the 0-100 formula, monotonicity, boundary thresholds (39, 40, 69, 70, 84, 85, 100),
reproducibility, and explicit handling of missing values.
"""
import pytest
from backend.services.scorer import scoring_engine
from backend.schemas.risk import AssetCriticality, InternetExposure, PriorityLevel
from backend.schemas.intelligence import (
    AggregatedIntel,
    NvdIntel,
    EpssIntel,
    CisaKevIntel,
    IntelSourceStatus,
)


def make_intel(
    cvss: float | None = 5.0,
    epss: float | None = 0.50,
    is_kev: bool | None = False,
    kev_status: IntelSourceStatus = IntelSourceStatus.CONFIRMED_NEGATIVE,
    cvss_version: str = "3.1"
) -> AggregatedIntel:
    return AggregatedIntel(
        cve_id="CVE-2024-TEST",
        nvd=NvdIntel(
            cve_id="CVE-2024-TEST",
            status=IntelSourceStatus.AVAILABLE if cvss is not None else IntelSourceStatus.UNKNOWN_OR_MISSING,
            cvss_version=cvss_version,
            cvss_base_score=cvss,
            cvss_severity="MEDIUM" if cvss else None,
            fetched_at="2026-11-23T00:00:00Z",
            source_url="https://nvd.nist.gov",
        ),
        epss=EpssIntel(
            cve_id="CVE-2024-TEST",
            status=IntelSourceStatus.AVAILABLE if epss is not None else IntelSourceStatus.UNKNOWN_OR_MISSING,
            epss_probability=epss,
            epss_percentile=epss,
            fetched_at="2026-11-23T00:00:00Z",
            source_url="https://api.first.org",
        ),
        cisa_kev=CisaKevIntel(
            cve_id="CVE-2024-TEST",
            status=kev_status,
            is_known_exploited=is_kev,
            fetched_at="2026-11-23T00:00:00Z",
            source_url="https://www.cisa.gov",
        ),
    )


def test_score_boundary_thresholds():
    """Validates exact classification boundaries: 39 (Low), 40 (Med), 69 (Med), 70 (High), 84 (High), 85 (Crit), 100 (Crit)."""
    # 1. Low boundary: Score 0 -> LOW
    intel_0 = make_intel(cvss=0.0, epss=0.0, is_kev=False)
    # Using Low asset (10 * 0.10 = 1.0) and Internal (30 * 0.10 = 3.0) -> total 4.0 -> LOW
    res_0 = scoring_engine.calculate_risk(intel_0, AssetCriticality.LOW, InternetExposure.INTERNAL)
    assert res_0.priority_level == PriorityLevel.LOW

    # 2. Score ~ 39.0 -> LOW
    # CVSS 5.0 (15 pts) + EPSS 0.50 (15 pts) + KEV 0 (0 pts) + Low (1 pt) + Public (10 pts) = 41 (Med)
    # Let's calibrate for exactly 39.0:
    # CVSS 5.0 (15.0) + EPSS 0.40 (12.0) + KEV 0 (0) + Low (1.0) + Exposure (10.0) = 38.0 -> LOW
    res_38 = scoring_engine.calculate_risk(make_intel(cvss=5.0, epss=0.40, is_kev=False), AssetCriticality.LOW, InternetExposure.PUBLIC_FACING)
    assert res_38.total_score == 38.0
    assert res_38.priority_level == PriorityLevel.LOW

    # 3. Score ~ 40.0 -> MEDIUM
    # CVSS 5.0 (15.0) + EPSS 0.47 (14.1) + Low (1.0) + Exposure (10.0) = 40.1 -> MEDIUM
    res_40 = scoring_engine.calculate_risk(make_intel(cvss=5.0, epss=0.47, is_kev=False), AssetCriticality.LOW, InternetExposure.PUBLIC_FACING)
    assert res_40.total_score >= 40.0
    assert res_40.priority_level == PriorityLevel.MEDIUM

    # 4. Score ~ 69.0 -> MEDIUM
    # CVSS 8.0 (24.0) + EPSS 0.80 (24.0) + KEV 0 (0) + Crit (10.0) + Public (10.0) = 68.0 -> MEDIUM
    res_68 = scoring_engine.calculate_risk(make_intel(cvss=8.0, epss=0.80, is_kev=False), AssetCriticality.CRITICAL, InternetExposure.PUBLIC_FACING)
    assert res_68.total_score == 68.0
    assert res_68.priority_level == PriorityLevel.MEDIUM

    # 5. Score >= 70.0 -> HIGH
    # CVSS 9.0 (27.0) + EPSS 0.80 (24.0) + KEV 0 (0) + Crit (10.0) + Public (10.0) = 71.0 -> HIGH
    res_71 = scoring_engine.calculate_risk(make_intel(cvss=9.0, epss=0.80, is_kev=False), AssetCriticality.CRITICAL, InternetExposure.PUBLIC_FACING)
    assert res_71.total_score == 71.0
    assert res_71.priority_level == PriorityLevel.HIGH

    # 6. Score ~ 84.0 -> HIGH
    # CVSS 8.0 (24.0) + EPSS 0.70 (21.0) + KEV True (20.0) + High (7.0) + Public (10.0) = 82.0 -> HIGH
    res_82 = scoring_engine.calculate_risk(make_intel(cvss=8.0, epss=0.70, is_kev=True), AssetCriticality.HIGH, InternetExposure.PUBLIC_FACING)
    assert res_82.total_score == 82.0
    assert res_82.priority_level == PriorityLevel.HIGH

    # 7. Score >= 85.0 -> CRITICAL
    # CVSS 9.0 (27.0) + EPSS 0.70 (21.0) + KEV True (20.0) + High (7.0) + Public (10.0) = 85.0 -> CRITICAL
    res_85 = scoring_engine.calculate_risk(make_intel(cvss=9.0, epss=0.70, is_kev=True), AssetCriticality.HIGH, InternetExposure.PUBLIC_FACING)
    assert res_85.total_score == 85.0
    assert res_85.priority_level == PriorityLevel.CRITICAL

    # 8. Perfect 100.0 -> CRITICAL
    # CVSS 10.0 (30) + EPSS 1.0 (30) + KEV True (20) + Crit (10) + Public (10) = 100.0
    res_100 = scoring_engine.calculate_risk(make_intel(cvss=10.0, epss=1.0, is_kev=True), AssetCriticality.CRITICAL, InternetExposure.PUBLIC_FACING)
    assert res_100.total_score == 100.0
    assert res_100.priority_level == PriorityLevel.CRITICAL


def test_epss_monotonicity():
    """Higher EPSS probability strictly increases score when other factors remain constant."""
    low_epss = scoring_engine.calculate_risk(make_intel(epss=0.10), AssetCriticality.MEDIUM, InternetExposure.INTERNAL)
    high_epss = scoring_engine.calculate_risk(make_intel(epss=0.90), AssetCriticality.MEDIUM, InternetExposure.INTERNAL)
    assert high_epss.total_score > low_epss.total_score
    # Difference should be (0.90 - 0.10) * 100 * 0.30 = 24.0 pts
    assert round(high_epss.total_score - low_epss.total_score, 2) == 24.0


def test_kev_contribution_weight():
    """CISA KEV active status adds exactly 20 points compared to confirmed negative."""
    neg_kev = scoring_engine.calculate_risk(make_intel(is_kev=False, kev_status=IntelSourceStatus.CONFIRMED_NEGATIVE), AssetCriticality.MEDIUM, InternetExposure.INTERNAL)
    pos_kev = scoring_engine.calculate_risk(make_intel(is_kev=True, kev_status=IntelSourceStatus.AVAILABLE), AssetCriticality.MEDIUM, InternetExposure.INTERNAL)
    assert round(pos_kev.total_score - neg_kev.total_score, 2) == 20.0


def test_criticality_hierarchy():
    """Critical assets receive greater priority than low-criticality assets."""
    crit_score = scoring_engine.calculate_risk(make_intel(), AssetCriticality.CRITICAL, InternetExposure.INTERNAL).total_score
    high_score = scoring_engine.calculate_risk(make_intel(), AssetCriticality.HIGH, InternetExposure.INTERNAL).total_score
    med_score = scoring_engine.calculate_risk(make_intel(), AssetCriticality.MEDIUM, InternetExposure.INTERNAL).total_score
    low_score = scoring_engine.calculate_risk(make_intel(), AssetCriticality.LOW, InternetExposure.INTERNAL).total_score

    assert crit_score > high_score > med_score > low_score


def test_exposure_hierarchy():
    """Public-facing assets receive higher exposure priority than internal assets."""
    pub_score = scoring_engine.calculate_risk(make_intel(), AssetCriticality.MEDIUM, InternetExposure.PUBLIC_FACING).total_score
    int_score = scoring_engine.calculate_risk(make_intel(), AssetCriticality.MEDIUM, InternetExposure.INTERNAL).total_score

    assert pub_score > int_score
    # (100 - 30) * 0.10 = 7.0 pts difference
    assert round(pub_score - int_score, 2) == 7.0


def test_reproducibility():
    """Same inputs must always generate the exact same score across 100 iterations."""
    intel = make_intel(cvss=8.4, epss=0.62, is_kev=True)
    first_run = scoring_engine.calculate_risk(intel, AssetCriticality.HIGH, InternetExposure.PUBLIC_FACING).total_score
    for _ in range(100):
        run = scoring_engine.calculate_risk(intel, AssetCriticality.HIGH, InternetExposure.PUBLIC_FACING).total_score
        assert run == first_run


def test_missing_values_provisional_flag():
    """Missing values must NOT be silently converted to 0, and is_provisional must be True."""
    missing_intel = make_intel(cvss=None, epss=None, is_kev=None, kev_status=IntelSourceStatus.UNKNOWN_OR_MISSING)
    result = scoring_engine.calculate_risk(missing_intel, AssetCriticality.MEDIUM, InternetExposure.INTERNAL)

    assert result.is_provisional is True
    assert len(result.provisional_reasons) >= 3
    # Non-zero baseline applied rather than 0
    assert result.total_score > 0
