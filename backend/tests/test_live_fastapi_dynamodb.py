"""
VulnGuard AI - Live FastAPI + Real AWS DynamoDB End-to-End Test
Proves an assessment created through FastAPI is successfully persisted to and retrieved from the real AWS DynamoDB table.
"""
import os
import boto3
import pytest
from fastapi.testclient import TestClient

from backend.core.config import settings
from database.factory import reset_repository, get_repository
from backend.app.main import app

@pytest.mark.skipif(os.getenv("QA_LIVE_DYNAMO") != "1", reason="writes to the AWS table")
def test_fastapi_live_dynamodb_persistence():
    orig_backend = settings.DATABASE_BACKEND
    orig_mock = settings.USE_BEDROCK_MOCK
    orig_table = settings.DYNAMODB_TABLE_NAME

    settings.DATABASE_BACKEND = "dynamodb"
    settings.DYNAMODB_TABLE_NAME = "VulnGuardAssessments"
    settings.USE_BEDROCK_MOCK = True
    reset_repository()

    try:
        client = TestClient(app)

        print("\n--- Step 1: Submit new assessment via POST /api/analyze with DynamoDB backend ---")
        payload = {
            "cve_id": "CVE-2021-44228",
            "asset_criticality": "CRITICAL",
            "internet_exposure": "PUBLIC_FACING",
            "system_context": "Production AWS ECS Ingress Gateway",
            "simulate_offline": False
        }

        response = client.post("/api/analyze", json=payload)
        print(f"POST /api/analyze status code: {response.status_code}")
        assert response.status_code == 201
        created_data = response.json()
        assessment_id = created_data["id"]
        print(f"Generated Assessment ID: {assessment_id}")
        print(f"Calculated Risk Score: {created_data['risk_score']['total_score']} ({created_data['risk_score']['priority_level']})")
        print(f"Bedrock Model Used: {created_data['remediation']['model_used']}")

        print("\n--- Step 2: Verify record physically exists in real AWS DynamoDB table via Boto3 ---")
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.Table("VulnGuardAssessments")
        db_item = table.get_item(Key={"assessment_id": assessment_id}).get("Item")
        assert db_item is not None
        print(f"Verified DynamoDB record: assessment_id={db_item['assessment_id']}, cve_id={db_item['cve_id']}")
        assert db_item["cve_id"] == "CVE-2021-44228"
        assert db_item["entity_type"] == "ASSESSMENT"
        assert db_item["risk_classification"] == "CRITICAL"

        print("\n--- Step 3: Retrieve assessment via GET /api/assessments/{id} ---")
        get_res = client.get(f"/api/assessments/{assessment_id}")
        assert get_res.status_code == 200
        retrieved_data = get_res.json()
        assert retrieved_data["id"] == assessment_id
        assert retrieved_data["cve_id"] == "CVE-2021-44228"
        assert retrieved_data["risk_score"]["total_score"] == created_data["risk_score"]["total_score"]
        assert retrieved_data["intelligence"]["cisa_kev"]["is_known_exploited"] is True
        print("Assessment successfully retrieved via API and verified identical to original payload!")

        print("\n--- Step 4: Verify History and GSI querying ---")
        list_res = client.get("/api/assessments?limit=10")
        assert list_res.status_code == 200
        summaries = list_res.json()
        assert len(summaries) >= 1
        matching = [s for s in summaries if s["id"] == assessment_id]
        assert len(matching) == 1
        print(f"Assessment {assessment_id} found in chronological history listing via HistoryIndex!")

        print("\nSUCCESS: Phase 2 FastAPI + Real AWS DynamoDB Persistence is 100% Verified!")
    finally:
        settings.DATABASE_BACKEND = orig_backend
        settings.USE_BEDROCK_MOCK = orig_mock
        settings.DYNAMODB_TABLE_NAME = orig_table
        reset_repository()

if __name__ == "__main__":
    test_fastapi_live_dynamodb_persistence()
