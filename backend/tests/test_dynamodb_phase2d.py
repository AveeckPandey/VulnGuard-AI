"""
VulnGuard AI - Phase 2D Amazon DynamoDB Unit & Edge Case Tests
Validates Boto3 DynamoDB repository, Decimal serialization, conditional writes,
HistoryIndex and CveHistoryIndex queries, pagination, duplicate prevention, and AWS error handling.
"""
import pytest
import json
from unittest.mock import MagicMock
from decimal import Decimal
from botocore.exceptions import ClientError, BotoCoreError

from database.dynamodb_repo import (
    DynamoDBAssessmentRepository,
    float_to_decimal,
    decimal_to_float,
)
from database.factory import get_repository, reset_repository
from backend.core.config import settings
from backend.core.exceptions import DatabaseError
from backend.schemas.assessment import AssessmentResponse
from backend.schemas.risk import PriorityLevel
from backend.tests.test_persistence import create_dummy_assessment


def test_dynamodb_serialization_roundtrip():
    """Validates recursive Decimal serialization and deserialization."""
    raw_payload = {
        "score": 98.75,
        "metrics": {"cvss": 10.0, "epss": 0.9754},
        "flags": [1.5, 2.5, "verified"],
        "count": 42
    }
    converted = float_to_decimal(raw_payload)
    assert isinstance(converted["score"], Decimal)
    assert isinstance(converted["metrics"]["cvss"], Decimal)
    assert isinstance(converted["flags"][0], Decimal)
    assert converted["count"] == 42

    restored = decimal_to_float(converted)
    assert restored["score"] == 98.75
    assert restored["metrics"]["cvss"] == 10.0
    assert restored["metrics"]["epss"] == 0.9754
    assert restored["flags"][0] == 1.5


def test_dynamodb_create_assessment_conditional_write():
    """Validates assessment creation with conditional check and required DynamoDB attributes."""
    mock_resource = MagicMock()
    mock_table = MagicMock()
    mock_resource.Table.return_value = mock_table

    repo = DynamoDBAssessmentRepository(
        table_name="VulnGuardAssessments",
        boto3_resource=mock_resource
    )

    assessment = create_dummy_assessment("vg-dyn-101", "CVE-2021-44228")
    saved = repo.create_assessment(assessment)
    assert saved.id == "vg-dyn-101"

    mock_table.put_item.assert_called_once()
    kwargs = mock_table.put_item.call_args[1]
    item = kwargs["Item"]

    # Verify primary and GSI keys
    assert item["assessment_id"] == "vg-dyn-101"
    assert item["entity_type"] == "ASSESSMENT"
    assert item["cve_id"] == "CVE-2021-44228"
    assert "sort_key" in item
    assert item["sort_key"] == f"{assessment.created_at}#vg-dyn-101"

    # Verify specified attributes
    assert isinstance(item["risk_score"], Decimal)
    assert item["risk_score"] == Decimal("98.5")
    assert item["risk_classification"] == "CRITICAL"
    assert "cve_description" in item
    assert "source_timestamps" in item
    assert item["source_timestamps"]["nvd"] == "2026-11-23T00:00:00Z"

    # Verify conditional write expression
    assert "attribute_not_exists(assessment_id)" in kwargs["ConditionExpression"]


def test_dynamodb_duplicate_assessment_prevented():
    """Proves conditional write prevents accidental overwrites when assessment_id exists."""
    mock_resource = MagicMock()
    mock_table = MagicMock()
    mock_resource.Table.return_value = mock_table

    # Simulate ConditionalCheckFailedException
    error_response = {"Error": {"Code": "ConditionalCheckFailedException", "Message": "The conditional request failed"}}
    mock_table.put_item.side_effect = ClientError(error_response, "PutItem")

    repo = DynamoDBAssessmentRepository(
        table_name="VulnGuardAssessments",
        boto3_resource=mock_resource
    )

    assessment = create_dummy_assessment("vg-duplicate-001", "CVE-2021-44228")
    with pytest.raises(DatabaseError) as exc_info:
        repo.create_assessment(assessment)

    assert "already exists" in str(exc_info.value)


def test_dynamodb_get_assessment_by_id_found_and_missing():
    """Validates get_assessment_by_id for both existing and missing records."""
    mock_resource = MagicMock()
    mock_table = MagicMock()
    mock_resource.Table.return_value = mock_table

    assessment = create_dummy_assessment("vg-found-001", "CVE-2021-44228")
    mock_table.get_item.return_value = {
        "Item": {
            "assessment_id": "vg-found-001",
            "full_data": assessment.model_dump_json()
        }
    }

    repo = DynamoDBAssessmentRepository(
        table_name="VulnGuardAssessments",
        boto3_resource=mock_resource
    )

    # Found
    retrieved = repo.get_assessment_by_id("vg-found-001")
    assert retrieved is not None
    assert retrieved.id == "vg-found-001"
    assert retrieved.cve_id == "CVE-2021-44228"

    # Missing
    mock_table.get_item.return_value = {}
    missing = repo.get_assessment_by_id("vg-nonexistent-999")
    assert missing is None


def test_dynamodb_chronological_history_query():
    """Validates chronological history query using HistoryIndex."""
    mock_resource = MagicMock()
    mock_table = MagicMock()
    mock_resource.Table.return_value = mock_table

    mock_table.query.return_value = {
        "Items": [
            {
                "assessment_id": "vg-2",
                "cve_id": "CVE-2023-34362",
                "risk_classification": "CRITICAL",
                "risk_score": Decimal("96.38"),
                "cvss_score": Decimal("9.8"),
                "epss_probability": Decimal("0.9993"),
                "is_known_exploited": True,
                "asset_criticality": "HIGH",
                "internet_exposure": "PUBLIC_FACING",
                "created_at": "2026-11-23T12:05:00Z"
            },
            {
                "assessment_id": "vg-1",
                "cve_id": "CVE-2021-44228",
                "risk_classification": "CRITICAL",
                "risk_score": Decimal("100.0"),
                "cvss_score": Decimal("10.0"),
                "epss_probability": Decimal("0.9999"),
                "is_known_exploited": True,
                "asset_criticality": "CRITICAL",
                "internet_exposure": "PUBLIC_FACING",
                "created_at": "2026-11-23T12:00:00Z"
            }
        ]
    }

    repo = DynamoDBAssessmentRepository(table_name="VulnGuardAssessments", boto3_resource=mock_resource)
    history = repo.list_recent_assessments(limit=10)

    assert len(history) == 2
    assert history[0].id == "vg-2"
    assert history[0].cve_id == "CVE-2023-34362"
    assert history[0].priority_level == PriorityLevel.CRITICAL
    assert history[1].id == "vg-1"
    mock_table.query.assert_called_once()
    query_args = mock_table.query.call_args[1]
    assert query_args["IndexName"] == "HistoryIndex"
    assert query_args["ScanIndexForward"] is False


def test_dynamodb_per_cve_history_query():
    """Validates per-CVE history query using CveHistoryIndex."""
    mock_resource = MagicMock()
    mock_table = MagicMock()
    mock_resource.Table.return_value = mock_table

    mock_table.query.return_value = {
        "Items": [
            {
                "assessment_id": "vg-cve-001",
                "cve_id": "CVE-2021-44228",
                "risk_classification": "CRITICAL",
                "risk_score": Decimal("100.0"),
                "cvss_score": Decimal("10.0"),
                "epss_probability": Decimal("0.9999"),
                "is_known_exploited": True,
                "asset_criticality": "HIGH",
                "internet_exposure": "PUBLIC_FACING",
                "created_at": "2026-11-23T12:00:00Z"
            }
        ]
    }

    repo = DynamoDBAssessmentRepository(table_name="VulnGuardAssessments", boto3_resource=mock_resource)
    items = repo.list_assessments_by_cve("CVE-2021-44228", limit=5)

    assert len(items) == 1
    assert items[0].cve_id == "CVE-2021-44228"
    mock_table.query.assert_called_once()
    query_args = mock_table.query.call_args[1]
    assert query_args["IndexName"] == "CveHistoryIndex"
    assert query_args["ExpressionAttributeValues"][":cid"] == "CVE-2021-44228"


def test_dynamodb_pagination_with_last_evaluated_key():
    """Validates that ExclusiveStartKey is forwarded when last_evaluated_key is provided."""
    mock_resource = MagicMock()
    mock_table = MagicMock()
    mock_resource.Table.return_value = mock_table
    mock_table.query.return_value = {"Items": []}

    repo = DynamoDBAssessmentRepository(table_name="VulnGuardAssessments", boto3_resource=mock_resource)
    start_key = json.dumps({"assessment_id": "vg-last-key", "sort_key": "2026-11-23#vg-last-key"})
    repo.list_recent_assessments(limit=5, last_evaluated_key=start_key)

    query_args = mock_table.query.call_args[1]
    assert "ExclusiveStartKey" in query_args
    assert query_args["ExclusiveStartKey"]["assessment_id"] == "vg-last-key"


def test_dynamodb_permission_access_denied_failure():
    """Proves AccessDeniedException is cleanly caught and raises DatabaseError."""
    mock_resource = MagicMock()
    mock_table = MagicMock()
    mock_resource.Table.return_value = mock_table

    error_response = {"Error": {"Code": "AccessDeniedException", "Message": "User is not authorized to perform dynamodb:GetItem"}}
    mock_table.get_item.side_effect = ClientError(error_response, "GetItem")

    repo = DynamoDBAssessmentRepository(table_name="VulnGuardAssessments", boto3_resource=mock_resource)
    with pytest.raises(DatabaseError) as exc_info:
        repo.get_assessment_by_id("vg-test-error")
    assert "DynamoDB get failed" in str(exc_info.value)


def test_dynamodb_temporary_service_failure():
    """Proves transient AWS service errors (e.g. 500) raise DatabaseError and never silently switch."""
    mock_resource = MagicMock()
    mock_table = MagicMock()
    mock_resource.Table.return_value = mock_table

    error_response = {"Error": {"Code": "InternalServerError", "Message": "Internal service error"}}
    mock_table.put_item.side_effect = ClientError(error_response, "PutItem")

    repo = DynamoDBAssessmentRepository(table_name="VulnGuardAssessments", boto3_resource=mock_resource)
    assessment = create_dummy_assessment("vg-err-500", "CVE-2021-44228")

    with pytest.raises(DatabaseError) as exc_info:
        repo.create_assessment(assessment)
    assert "DynamoDB operation failed" in str(exc_info.value)


def test_factory_never_silently_switches_to_sqlite():
    """Proves factory does NOT fall back to SQLite when DATABASE_BACKEND=dynamodb is configured."""
    reset_repository()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(settings, "DATABASE_BACKEND", "dynamodb")
        # Ensure that get_repository instantiates DynamoDBAssessmentRepository
        repo = get_repository()
        assert isinstance(repo, DynamoDBAssessmentRepository)
    reset_repository()
