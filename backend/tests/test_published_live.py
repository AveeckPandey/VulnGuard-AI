"""Explicit live acceptance gates. Each gate is independently selectable."""
import os

import boto3
import httpx
import pytest

from backend.agents.bedrock import bedrock_explainer
from backend.agents.nodes.intelligence import intelligence_collection_node
from backend.api.deps import get_db_repo
from backend.app.main import app
from backend.core.config import settings
from backend.schemas.risk import AssetCriticality, InternetExposure
from backend.services.scorer import scoring_engine
from backend.tests.test_published_cves import SAMPLES, analyze, check_score, feeds, inference
from database.dynamodb_repo import DynamoDBAssessmentRepository


@pytest.mark.skipif(os.getenv("QA_LIVE_FEEDS") != "1", reason="requires public feeds and configured AWS table")
@pytest.mark.parametrize("cve", sorted(SAMPLES))
def test_live_assessment(client, monkeypatch, cve, inference):
    """Compare the assessment with the raw responses actually delivered by the providers."""
    raw = {}
    http_get = httpx.AsyncClient.get

    async def capture(client, url, **kwargs):
        response = await http_get(client, url, **kwargs)
        if response.status_code == 200:
            raw[url] = response.json()
        return response

    monkeypatch.setattr(httpx.AsyncClient, "get", capture)
    repo = DynamoDBAssessmentRepository()
    monkeypatch.setitem(app.dependency_overrides, get_db_repo, lambda: repo)
    res = analyze(client, cve)
    assert res.status_code == 201, (res.status_code, res.json(), list(raw))
    data = res.json()
    intel = data["intelligence"]
    source, = raw[settings.NVD_BASE_URL]["vulnerabilities"]
    nvd = source["cve"]
    assert nvd["id"] == cve and not intel["is_simulated"]
    assert intel["nvd"]["description"] in [row["value"] for row in nvd["descriptions"]]
    metrics = nvd.get("metrics", {})
    score = next((metrics[k][0]["cvssData"]["baseScore"] for k in
                  ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2") if metrics.get(k)), None)
    assert intel["nvd"]["cvss_base_score"] == score
    row, = raw[settings.EPSS_BASE_URL]["data"]
    p = float(row["epss"])
    assert row["cve"] == cve and intel["epss"]["epss_probability"] == p
    assert intel["epss"]["epss_percentile"] == float(row["percentile"])
    listed = any(v["cveID"] == cve for v in raw[settings.CISA_KEV_URL]["vulnerabilities"])
    assert intel["cisa_kev"]["is_known_exploited"] is listed
    check_score(data["risk_score"], score, p, listed)
    prompt, = inference
    assert cve in prompt and intel["nvd"]["description"] in prompt and f"{p:.4f}" in prompt
    assert client.get("/api/assessments/" + data["id"]).json() == data


@pytest.mark.skipif(os.getenv("QA_LIVE_DYNAMO") != "1", reason="writes to configured AWS table")
@pytest.mark.parametrize("cve", sorted(SAMPLES))
def test_aws_roundtrip_independently(client, monkeypatch, cve, feeds):
    """Use recorded source fields and deterministic remediation to isolate real AWS persistence."""
    table = boto3.resource("dynamodb", region_name=settings.AWS_REGION).Table(settings.DYNAMODB_TABLE_NAME)
    repo = DynamoDBAssessmentRepository()
    monkeypatch.setitem(app.dependency_overrides, get_db_repo, lambda: repo)
    # Clearly label the source replay in the persisted QA record.
    res = client.post("/api/analyze", json={"cve_id": cve, "simulate_offline": False,
                      "system_context": "QA source replay / DynamoDB acceptance check"})
    assert res.status_code == 201, (res.status_code, res.json())
    data = res.json()
    item = table.get_item(Key={"assessment_id": data["id"]}, ConsistentRead=True)["Item"]
    assert item["cve_id"] == cve
    assert client.get("/api/assessments/" + data["id"]).json() == data


@pytest.mark.skipif(os.getenv("QA_ONE_NVIDIA") != "1", reason="one explicitly authorized NVIDIA call")
@pytest.mark.asyncio
async def test_one_nvidia_request(feeds):
    """One actual completion attempt with public OpenSSH evidence; no retry or alternative model."""
    cve = "CVE-2024-6387"
    intel = (await intelligence_collection_node({"cve_id": cve, "simulate_offline": False}))["intelligence"]
    score = scoring_engine.calculate_risk(intel, AssetCriticality.HIGH, InternetExposure.PUBLIC_FACING)
    assert settings.get_nvidia_api_key(), "NVIDIA credential unavailable"
    result = await bedrock_explainer._invoke_nvidia_nemotron(cve, intel, score, "OpenSSH QA validation")
    assert result.model_used == settings.NVIDIA_MODEL_ID and not result.is_fallback_deterministic
    assert result.remediation_steps and result.technical_impact and result.exploitation_assessment
    assert "openssh" in " ".join([result.executive_summary, result.technical_impact, *result.remediation_steps]).lower()
