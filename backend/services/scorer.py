"""
VulnGuard AI - Deterministic Risk Prioritization Engine
Implements the 0-100 weighted cybersecurity scoring model:
- CVSS Severity: 30%
- EPSS Exploitation Probability: 30%
- CISA KEV Exploitation Status: 20%
- Asset Criticality: 10%
- Internet Exposure: 10%

Classifications:
- Critical: 85 - 100
- High: 70 - 84
- Medium: 40 - 69
- Low: 0 - 39
"""
from typing import List
from backend.schemas.risk import (
    AssetCriticality,
    InternetExposure,
    PriorityLevel,
    ScoreComponent,
    RiskScoreBreakdown,
)
from backend.schemas.intelligence import AggregatedIntel, IntelSourceStatus


class RiskScoringEngine:
    """Calculates deterministic composite risk score and prioritization breakdown."""

    CRITICALITY_MAP = {
        AssetCriticality.CRITICAL: 100.0,
        AssetCriticality.HIGH: 70.0,
        AssetCriticality.MEDIUM: 40.0,
        AssetCriticality.LOW: 10.0,
    }

    EXPOSURE_MAP = {
        InternetExposure.PUBLIC_FACING: 100.0,
        InternetExposure.INTERNAL: 30.0,
    }

    def calculate_risk(
        self,
        intel: AggregatedIntel,
        criticality: AssetCriticality,
        exposure: InternetExposure,
    ) -> RiskScoreBreakdown:
        provisional_reasons: List[str] = []
        is_provisional = False

        # 1. CVSS Component (30%)
        cvss_raw = intel.nvd.cvss_base_score
        if cvss_raw is not None:
            cvss_norm = round(min(100.0, max(0.0, cvss_raw * 10.0)), 2)
            cvss_desc = f"CVSS base score {cvss_raw}/10.0 normalized to {cvss_norm}/100"
        else:
            cvss_norm = 50.0  # Conservative median default
            is_provisional = True
            provisional_reasons.append("NVD CVSS score is missing or unpublished; estimated median baseline 5.0 (50/100).")
            cvss_desc = "Unpublished CVSS; provisional median score applied."

        cvss_contrib = round(cvss_norm * 0.30, 2)
        cvss_comp = ScoreComponent(
            name="CVSS Severity",
            raw_value=cvss_raw if cvss_raw is not None else "Missing",
            normalized_score=cvss_norm,
            weight=0.30,
            weighted_contribution=cvss_contrib,
            description=cvss_desc,
        )

        # 2. EPSS Probability Component (30%)
        # Note: Must use EPSS probability, not percentile
        epss_raw = intel.epss.epss_probability
        if epss_raw is not None:
            epss_norm = round(min(100.0, max(0.0, epss_raw * 100.0)), 2)
            epss_desc = f"FIRST EPSS probability {epss_raw:.4f} ({epss_raw*100:.2f}%) normalized to {epss_norm}/100"
        else:
            epss_norm = 10.0  # Conservative baseline
            is_provisional = True
            provisional_reasons.append("FIRST EPSS probability is unavailable; estimated baseline applied.")
            epss_desc = "Unavailable EPSS; provisional 10/100 applied."

        epss_contrib = round(epss_norm * 0.30, 2)
        epss_comp = ScoreComponent(
            name="EPSS Exploitation Probability",
            raw_value=f"{epss_raw:.4f}" if epss_raw is not None else "Missing",
            normalized_score=epss_norm,
            weight=0.30,
            weighted_contribution=epss_contrib,
            description=epss_desc,
        )

        # 3. CISA KEV Component (20%)
        if intel.cisa_kev.is_known_exploited:
            kev_norm = 100.0
            kev_desc = "Confirmed active in-the-wild exploitation listed in CISA KEV catalog (100/100)."
            kev_raw = True
        elif intel.cisa_kev.status == IntelSourceStatus.CONFIRMED_NEGATIVE:
            kev_norm = 0.0
            kev_desc = "Confirmed NOT present in CISA KEV catalog (0/100)."
            kev_raw = False
        else:
            # Unknown or unreachable
            kev_norm = 30.0
            is_provisional = True
            provisional_reasons.append("CISA KEV catalog status could not be verified; provisional 30/100 applied.")
            kev_desc = "KEV verification inconclusive; provisional baseline applied."
            kev_raw = "Unknown"

        kev_contrib = round(kev_norm * 0.20, 2)
        kev_comp = ScoreComponent(
            name="CISA KEV In-The-Wild Exploitation",
            raw_value=kev_raw,
            normalized_score=kev_norm,
            weight=0.20,
            weighted_contribution=kev_contrib,
            description=kev_desc,
        )

        # 4. Asset Criticality Component (10%)
        crit_norm = self.CRITICALITY_MAP.get(criticality, 40.0)
        crit_contrib = round(crit_norm * 0.10, 2)
        crit_comp = ScoreComponent(
            name="Asset Business Criticality",
            raw_value=criticality.value,
            normalized_score=crit_norm,
            weight=0.10,
            weighted_contribution=crit_contrib,
            description=f"Operational criticality tier '{criticality.value}' scored at {crit_norm}/100.",
        )

        # 5. Internet Exposure Component (10%)
        expo_norm = self.EXPOSURE_MAP.get(exposure, 30.0)
        expo_contrib = round(expo_norm * 0.10, 2)
        expo_comp = ScoreComponent(
            name="Network Perimeter Exposure",
            raw_value=exposure.value,
            normalized_score=expo_norm,
            weight=0.10,
            weighted_contribution=expo_contrib,
            description=f"Perimeter exposure '{exposure.value}' scored at {expo_norm}/100.",
        )

        # Total Composite Calculation (Sum of weighted contributions)
        total = round(cvss_contrib + epss_contrib + kev_contrib + crit_contrib + expo_contrib, 2)
        total = min(100.0, max(0.0, total))

        # Classification Mapping
        if total >= 85.0:
            priority = PriorityLevel.CRITICAL
        elif total >= 70.0:
            priority = PriorityLevel.HIGH
        elif total >= 40.0:
            priority = PriorityLevel.MEDIUM
        else:
            priority = PriorityLevel.LOW

        # Generate summary synthesis
        summary = (
            f"Prioritization score: {total}/100 ({priority.value}). "
            f"Driven by CVSS contribution ({cvss_contrib} pts), EPSS exploitation probability ({epss_contrib} pts), "
            f"CISA KEV presence ({kev_contrib} pts), asset tier ({crit_contrib} pts), and exposure ({expo_contrib} pts)."
        )

        return RiskScoreBreakdown(
            total_score=total,
            priority_level=priority,
            is_provisional=is_provisional,
            provisional_reasons=provisional_reasons,
            components=[cvss_comp, epss_comp, kev_comp, crit_comp, expo_comp],
            summary=summary,
        )


scoring_engine = RiskScoringEngine()
