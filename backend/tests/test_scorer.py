"""
VulnGuard AI - Deterministic Risk Scorer Unit Tests
Verifies the 0-100 formula, component weighting, and priority tier classifications.
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


def build_mock_intel(
    cvss: float | None = 10.0,
    epss_prob: float | None = 0.90,
    epss_pct: float | None = 0.99,
    is_kev: bool = True,
    kev_status: IntelSourceStatus = IntelSourceStatus.AVAILABLE,
) -> AggregatedIntel:
    return AggregatedIntel(
        cve_id="CVE-2021-44228",
        nvd=NvdIntel(
            cve_id="CVE-2021-44228",
            status=IntelSourceStatus.AVAILABLE if cvss is not None else IntelSourceStatus.UNKNOWN_OR_MISSING,
            description="Remote Code Execution",
            cvss_version="3.1",
            cvss_base_score=cvss,
            cvss_severity="CRITICAL" if cvss and cvss >= 9.0 else "MEDIUM",
            fetched_at="2026-11-23T00:00:00Z",
            source_url="https://nvd.nist.gov",
            is_simulated=True,
        ),
        epss=EpssIntel(
            cve_id="CVE-2021-44228",
            status=IntelSourceStatus.AVAILABLE if epss_prob is not None else IntelSourceStatus.UNKNOWN_OR_MISSING,
            epss_probability=epss_prob,
            epss_percentile=epss_pct,
            fetched_at="2026-11-23T00:00:00Z",
            source_url="https://api.first.org",
            is_simulated=True,
        ),
        cisa_kev=CisaKevIntel(
            cve_id="CVE-2021-44228",
            status=kev_status,
            is_known_exploited=is_kev,
            fetched_at="2026-11-23T00:00:00Z",
            source_url="https://www.cisa.gov",
            is_simulated=True,
        ),
        is_simulated=True,
    )


def test_critical_risk_score_calculation():
    """Critical test: CVSS 10.0, EPSS 0.95, KEV=True, Critical Asset, Public Facing."""
    intel = build_mock_intel(cvss=10.0, epss_prob=0.95, is_kev=True)
    breakdown = scoring_engine.calculate_risk(
        intel=intel,
        criticality=AssetCriticality.CRITICAL,
        exposure=InternetExposure.PUBLIC_FACING,
    )

    # Calculation:
    # CVSS: 100 * 0.30 = 30.0
    # EPSS: 95 * 0.30 = 28.5
    # KEV: 100 * 0.20 = 20.0
    # Criticality: 100 * 0.10 = 10.0
    # Exposure: 100 * 0.10 = 10.0
    # Total = 30.0 + 28.5 + 20.0 + 10.0 + 10.0 = 98.5
    assert breakdown.total_score == 98.5
    assert breakdown.priority_level == PriorityLevel.CRITICAL
    assert breakdown.is_provisional is False
    assert len(breakdown.components) == 5


def test_low_risk_score_calculation():
    """Low risk test: CVSS 2.0, EPSS 0.001, KEV=False (Confirmed negative), Low Asset, Internal."""
    intel = build_mock_intel(
        cvss=2.0,
        epss_prob=0.001,
        is_kev=False,
        kev_status=IntelSourceStatus.CONFIRMED_NEGATIVE,
    )
    breakdown = scoring_engine.calculate_risk(
        intel=intel,
        criticality=AssetCriticality.LOW,
        exposure=InternetExposure.INTERNAL,
    )

    # Calculation:
    # CVSS: 20 * 0.30 = 6.0
    # EPSS: 0.10 * 0.30 = 0.03
    # KEV: 0 * 0.20 = 0.0
    # Criticality: 10 * 0.10 = 1.0
    # Exposure: 30 * 0.10 = 3.0
    # Total = 6.0 + 0.03 + 0.0 + 1.0 + 3.0 = 10.03
    assert breakdown.total_score < 40.0
    assert breakdown.priority_level == PriorityLevel.LOW
    assert breakdown.is_provisional is False


def test_provisional_flag_when_data_missing():
    """Provisional test: Missing CVSS and EPSS should mark assessment as provisional with reasons."""
    intel = build_mock_intel(
        cvss=None,
        epss_prob=None,
        is_kev=False,
        kev_status=IntelSourceStatus.UNKNOWN_OR_MISSING,
    )
    breakdown = scoring_engine.calculate_risk(
        intel=intel,
        criticality=AssetCriticality.MEDIUM,
        exposure=InternetExposure.INTERNAL,
    )

    assert breakdown.is_provisional is True
    assert len(breakdown.provisional_reasons) >= 2


def test_epss_probability_used_not_percentile():
    """Verifies that EPSS probability (e.g. 0.05 = 5 pts) is used, NOT percentile (0.95 = 95 pts)."""
    intel = build_mock_intel(
        cvss=5.0,
        epss_prob=0.05,    # 5% probability
        epss_pct=0.95,     # 95th percentile
        is_kev=False,
        kev_status=IntelSourceStatus.CONFIRMED_NEGATIVE,
    )
    breakdown = scoring_engine.calculate_risk(
        intel=intel,
        criticality=AssetCriticality.LOW,
        exposure=InternetExposure.INTERNAL,
    )

    # EPSS component normalized score should be 5.0 (from 0.05 * 100), NOT 95.0
    epss_comp = next(c for c in breakdown.components if "EPSS" in c.name)
    assert epss_comp.normalized_score == 5.0
    assert epss_comp.weighted_contribution == 1.5  # 5.0 * 0.30
