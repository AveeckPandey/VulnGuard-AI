"""
VulnGuard AI - Persistence Layer Tests
Validates create, read, and history query operations across SQLite and DynamoDB repositories.
"""
import pytest
from unittest.mock import MagicMock
from decimal import Decimal
from backend.schemas.assessment import AssessmentResponse, AiRemediation
from backend.schemas.risk import (
    AssetCriticality,
    InternetExposure,
    PriorityLevel,
    RiskScoreBreakdown,
    ScoreComponent,
)
from backend.schemas.intelligence import (
    AggregatedIntel,
    NvdIntel,
    EpssIntel,
    CisaKevIntel,
    IntelSourceStatus,
)
from database.sqlite_repo import SQLiteAssessmentRepository
from database.dynamodb_repo import DynamoDBAssessmentRepository, float_to_decimal
from database.factory import get_repository, reset_repository
from backend.core.exceptions import DatabaseError


def create_dummy_assessment(aid: str = "vg-test-001", cve: str = "CVE-2021-44228") -> AssessmentResponse:
    return AssessmentResponse(
        id=aid,
        cve_id=cve,
        asset_criticality=AssetCriticality.HIGH,
        internet_exposure=InternetExposure.PUBLIC_FACING,
        system_context="E-Commerce Payment Gateway",
        intelligence=AggregatedIntel(
            cve_id=cve,
            nvd=NvdIntel(
                cve_id=cve,
                status=IntelSourceStatus.AVAILABLE,
                description="Remote code execution vulnerability.",
                cvss_version="3.1",
                cvss_base_score=10.0,
                cvss_severity="CRITICAL",
                fetched_at="2026-11-23T00:00:00Z",
                source_url="https://nvd.nist.gov",
                is_simulated=True,
            ),
            epss=EpssIntel(
                cve_id=cve,
                status=IntelSourceStatus.AVAILABLE,
                epss_probability=0.9754,
                epss_percentile=0.9999,
                fetched_at="2026-11-23T00:00:00Z",
                source_url="https://api.first.org",
                is_simulated=True,
            ),
            cisa_kev=CisaKevIntel(
                cve_id=cve,
                status=IntelSourceStatus.AVAILABLE,
                is_known_exploited=True,
                vulnerability_name="Apache Log4j RCE",
                fetched_at="2026-11-23T00:00:00Z",
                source_url="https://www.cisa.gov",
                is_simulated=True,
            ),
            is_simulated=True,
        ),
        risk_score=RiskScoreBreakdown(
            total_score=98.5,
            priority_level=PriorityLevel.CRITICAL,
            is_provisional=False,
            provisional_reasons=[],
            components=[
                ScoreComponent(
                    name="CVSS Severity",
                    raw_value=10.0,
                    normalized_score=100.0,
                    weight=0.30,
                    weighted_contribution=30.0,
                    description="CVSS 10.0 normalized to 100",
                )
            ],
            summary="Critical threat level requiring immediate mitigation.",
        ),
        remediation=AiRemediation(
            executive_summary="Urgent patch required for Log4j2.",
            technical_impact="Unauthenticated remote attacker can execute arbitrary code.",
            exploitation_assessment="Active weaponization observed globally.",
            remediation_steps=["Upgrade to Log4j 2.17.1 or higher."],
            mitigation_workarounds=["Set log4j2.formatMsgNoLookups=true."],
            evidence_citations=["https://nvd.nist.gov", "https://www.cisa.gov"],
            model_used="deterministic-fallback-rules",
            is_fallback_deterministic=True,
        ),
        created_at="2026-11-23T12:00:00Z",
        execution_time_ms=45.2,
    )


def test_sqlite_save_and_retrieve(tmp_path):
    """Proves that completed assessments are saved and retrieved accurately in SQLite."""
    db_file = str(tmp_path / "test_repo.db")
    repo = SQLiteAssessmentRepository(db_path=db_file)

    assessment = create_dummy_assessment("vg-sql-100", "CVE-2021-44228")
    saved = repo.save(assessment, owner_user_id="test-user-a")
    assert saved.id == "vg-sql-100"

    retrieved = repo.get_by_id("vg-sql-100", owner_user_id="test-user-a")
    assert retrieved is not None
    assert retrieved.id == "vg-sql-100"
    assert retrieved.cve_id == "CVE-2021-44228"
    assert retrieved.risk_score.priority_level == PriorityLevel.CRITICAL
    assert retrieved.risk_score.total_score == 98.5
    assert retrieved.intelligence.nvd.cvss_base_score == 10.0
    assert retrieved.intelligence.cisa_kev.is_known_exploited is True
    assert len(retrieved.remediation.remediation_steps) == 1
    assert repo.get_by_id("vg-sql-100", owner_user_id="test-user-b") is None


def test_sqlite_history_listing(tmp_path):
    """Proves that recent assessments can be queried chronologically."""
    db_file = str(tmp_path / "test_history.db")
    repo = SQLiteAssessmentRepository(db_path=db_file)

    # Save multiple assessments
    repo.save(create_dummy_assessment("vg-1", "CVE-2021-44228"), owner_user_id="test-user-a")
    repo.save(create_dummy_assessment("vg-2", "CVE-2023-38606"), owner_user_id="test-user-a")

    history = repo.list_recent(owner_user_id="test-user-a", limit=10)
    assert len(history) == 2
    ids = [item.id for item in history]
    assert "vg-1" in ids
    assert "vg-2" in ids
    assert repo.list_recent(owner_user_id="test-user-b", limit=10) == []


def test_sqlite_save_cannot_reassign_existing_assessment(tmp_path):
    """A duplicate ID cannot overwrite another tenant's saved assessment."""
    import pytest
    from backend.core.exceptions import DatabaseError

    repo = SQLiteAssessmentRepository(db_path=str(tmp_path / "isolation.db"))
    repo.save(create_dummy_assessment("vg-shared"), owner_user_id="test-user-a")
    with pytest.raises(DatabaseError):
        repo.save(create_dummy_assessment("vg-shared"), owner_user_id="test-user-b")
    assert repo.get_by_id("vg-shared", owner_user_id="test-user-b") is None
    assert repo.get_by_id("vg-shared", owner_user_id="test-user-a") is not None


def test_dynamodb_repository_save_and_get():
    """Validates DynamoDB Boto3 repository with mocked DynamoDB Table."""
    mock_resource = MagicMock()
    mock_table = MagicMock()
    mock_resource.Table.return_value = mock_table

    repo = DynamoDBAssessmentRepository(
        table_name="vulnguard_assessments",
        boto3_resource=mock_resource
    )

    assessment = create_dummy_assessment("vg-dyn-001", "CVE-2021-44228")
    repo.save(assessment)

    # Verify put_item was called with Decimal for numerical attributes
    mock_table.put_item.assert_called_once()
    put_args = mock_table.put_item.call_args[1]["Item"]
    assert put_args["id"] == "vg-dyn-001"
    assert put_args["entity_type"] == "ASSESSMENT"
    assert isinstance(put_args["total_score"], Decimal)
    assert put_args["total_score"] == Decimal("98.5")

    # Mock get_item return
    mock_table.get_item.return_value = {
        "Item": {
            "id": "vg-dyn-001",
            "full_data": assessment.model_dump_json()
        }
    }
    retrieved = repo.get_by_id("vg-dyn-001")
    assert retrieved is not None
    assert retrieved.id == "vg-dyn-001"
    assert retrieved.cve_id == "CVE-2021-44228"


def test_float_to_decimal_conversion():
    """Proves float values are correctly converted to Decimal for DynamoDB serialization."""
    data = {"score": 98.5, "nested": [1.5, 2.5]}
    converted = float_to_decimal(data)
    assert isinstance(converted["score"], Decimal)
    assert isinstance(converted["nested"][0], Decimal)
