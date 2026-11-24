"""
VulnGuard AI - Live AWS DynamoDB Integration Verification
Tests real persistence, retrieval, conditional writes, and GSI queries against real AWS DynamoDB table 'VulnGuardAssessments'.
"""
import os
import pytest
import boto3
import time
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from database.dynamodb_repo import DynamoDBAssessmentRepository
from backend.tests.test_persistence import create_dummy_assessment
from backend.core.exceptions import DatabaseError
from backend.schemas.risk import PriorityLevel


def wait_for_gsi_record(query_fn, assessment_id, timeout_seconds=20):
    """DynamoDB GSIs are eventually consistent; poll until the record is visible."""
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if any(item.id == assessment_id for item in query_fn()):
            return True
        time.sleep(0.5)
    return False


@pytest.mark.skipif(os.getenv("QA_LIVE_DYNAMO") != "1", reason="requires live AWS DynamoDB access")
@pytest.mark.asyncio
async def test_live_aws_dynamodb_crud_and_gsis():
    """Live verification against real AWS DynamoDB table VulnGuardAssessments."""
    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
    table = dynamodb.Table("VulnGuardAssessments")
    table.load()
    assert table.table_status == "ACTIVE"

    repo = DynamoDBAssessmentRepository(
        table_name="VulnGuardAssessments",
        region_name="us-east-1"
    )

    test_aid = f"vg-live-{uuid.uuid4().hex[:8]}"
    assessment = create_dummy_assessment(test_aid, "CVE-2021-44228")
    # Sort keys use created_at, so use the current time to ensure this record
    # ranks within the top-10 window even after the table accumulates history.
    assessment.created_at = datetime.now(timezone.utc).isoformat()

    # 1. Test create_assessment (Conditional PutItem)
    created = repo.create_assessment(assessment)
    assert created.id == test_aid

    # 2. Test get_assessment_by_id
    retrieved = repo.get_assessment_by_id(test_aid)
    assert retrieved is not None
    assert retrieved.id == test_aid
    assert retrieved.cve_id == "CVE-2021-44228"
    assert retrieved.risk_score.total_score == 98.5
    assert retrieved.risk_score.priority_level == PriorityLevel.CRITICAL
    assert retrieved.intelligence.nvd.cvss_base_score == 10.0
    assert retrieved.intelligence.cisa_kev.is_known_exploited is True

    # 3. Test conditional write prevents duplicate
    with pytest.raises(DatabaseError) as exc_info:
        repo.create_assessment(assessment)
    assert "already exists in DynamoDB" in str(exc_info.value)

    # 4. Test HistoryIndex query
    history = repo.list_recent_assessments(limit=10)
    assert len(history) >= 1
    assert wait_for_gsi_record(lambda: repo.list_recent_assessments(limit=10), test_aid) is True

    # 5. Test CveHistoryIndex query
    cve_history = repo.list_assessments_by_cve("CVE-2021-44228", limit=10)
    assert len(cve_history) >= 1
    assert wait_for_gsi_record(
        lambda: repo.list_assessments_by_cve("CVE-2021-44228", limit=10), test_aid
    ) is True

    print(f"LIVE AWS DYNAMODB TEST SUCCESS: Verified {test_aid} in VulnGuardAssessments!")
