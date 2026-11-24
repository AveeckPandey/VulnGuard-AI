"""Assessment acceptance tests. Only HTTP and the AWS endpoint are doubled."""
import copy
import io
import json
from secrets import randbelow
from pathlib import Path
from unittest.mock import AsyncMock

import boto3
import httpx
import pytest
from botocore.awsrequest import AWSResponse

from backend.agents.bedrock import bedrock_explainer
from backend.api.deps import get_db_repo
from backend.app.main import app
from backend.core.config import settings
from backend.services.nvd_service import nvd_service
from database.dynamodb_repo import DynamoDBAssessmentRepository

SAMPLES = json.loads((Path(__file__).parent / "fixtures/published_cves.json").read_text(encoding="utf-8"))
UNKNOWN = "CVE-2099-9876543"
MODEL_REPLY = {
    "executive_summary": "QA model response",
    "technical_impact": "Review affected installations.",
    "exploitation_assessment": "Refer to the supplied evidence.",
    "remediation_steps": ["Review the vendor advisory."],
    "mitigation_workarounds": ["Restrict access to affected services."],
}


class ResponseBody(io.BytesIO):
    def stream(self):
        yield self.read()


@pytest.fixture
def dynamo(monkeypatch):
    """Exercise actual boto3 marshalling and repository code without an AWS write."""
    resource = boto3.resource("dynamodb", region_name="us-east-1",
                              aws_access_key_id="testing", aws_secret_access_key="testing")
    items = {}

    def respond(request, **kwargs):
        operation = request.headers["X-Amz-Target"].decode().split(".")[-1]
        payload = json.loads(request.body)
        assert payload["TableName"] == "QA"
        if operation == "PutItem":
            item = payload["Item"]
            key = item["assessment_id"]["S"]
            assert "attribute_not_exists(assessment_id)" in payload["ConditionExpression"]
            assert key not in items
            items[key] = item
            result = {}
        elif operation == "GetItem":
            key = payload["Key"]["assessment_id"]["S"]
            result = {"Item": items[key]} if key in items else {}
        elif operation == "Query":
            result = {"Items": list(items.values())}
        else:
            raise AssertionError(operation)
        return AWSResponse(request.url, 200, {}, ResponseBody(json.dumps(result).encode()))

    resource.meta.client.meta.events.register("before-send.dynamodb", respond)
    repo = DynamoDBAssessmentRepository(table_name="QA", boto3_resource=resource)
    monkeypatch.setitem(app.dependency_overrides, get_db_repo, lambda: repo)
    return items


@pytest.fixture
def feeds(monkeypatch):
    """Replay reduced, dated fields from the official sources at the HTTP boundary."""
    samples = copy.deepcopy(SAMPLES)
    state = {"samples": samples, "fail": set(), "requests": []}

    async def fetch(client, url, *, params=None, **kwargs):
        state["requests"].append((url, params))
        if url in state["fail"]:
            return httpx.Response(503)
        if url == settings.NVD_BASE_URL:
            cve = params["cveId"]
            sample = samples.get(cve)
            rows = []
            if sample:
                metrics = {sample["metric"]: [{"cvssData": sample["cvssData"]}]} if sample["cvssData"] else {}
                rows.append({"cve": {
                    "id": cve, "published": sample["published"], "metrics": metrics,
                    "descriptions": [{"lang": "en", "value": sample["description"]}],
                    "references": [{"url": sample["reference"]}],
                    "weaknesses": [{"description": [{"value": sample.get("weakness")}]}],
                }})
            return httpx.Response(200, json={"vulnerabilities": rows, "totalResults": len(rows)})
        if url == settings.EPSS_BASE_URL:
            sample = samples.get(params["cve"])
            return httpx.Response(200, json={"data": [sample["epss"]] if sample and sample["epss"] else []})
        assert url == settings.CISA_KEV_URL
        entries = [s["kev"] for s in samples.values() if s["kev"]]
        return httpx.Response(200, json={"vulnerabilities": entries, "count": len(entries)})

    monkeypatch.setattr(httpx.AsyncClient, "get", fetch)
    monkeypatch.setattr(nvd_service.rate_limiter, "acquire", AsyncMock())
    return state


@pytest.fixture
def inference(monkeypatch):
    calls = []
    model_json = json.dumps(MODEL_REPLY)

    async def post(client, url, *, json, **kwargs):
        assert url == "https://integrate.api.nvidia.com/v1/chat/completions"
        assert json["model"] == settings.NVIDIA_MODEL_ID
        calls.append(json["messages"][-1]["content"])
        return httpx.Response(200, json={"choices": [{"message": {"content": model_json}}]})

    monkeypatch.setattr(settings, "NVIDIA_API_KEY", "qa-local")
    monkeypatch.setattr(settings, "USE_BEDROCK_MOCK", False)
    monkeypatch.setattr(httpx.AsyncClient, "post", post)
    monkeypatch.setattr(bedrock_explainer, "_get_client", lambda: None)
    monkeypatch.setattr(settings, "AWS_BEARER_TOKEN_BEDROCK", "")
    return calls


def analyze(client, cve):
    return client.post("/api/analyze", json={"cve_id": cve, "asset_criticality": "HIGH",
                       "internet_exposure": "PUBLIC_FACING", "system_context": "QA validation",
                       "simulate_offline": False})


def check_score(risk, cvss, probability, kev):
    # HIGH asset = 7 points, public exposure = 10. Round each normalized factor before weighting.
    expected = [round((cvss if cvss is not None else 5) * 3, 2),
                round(round(100 * (probability if probability is not None else 0.1), 2) * 0.3, 2),
                {True: 20, False: 0, None: 6}[kev], 7, 10]
    assert [c["weighted_contribution"] for c in risk["components"]] == expected
    total = round(sum(expected), 2)
    assert risk["total_score"] == total
    assert risk["priority_level"] == ("CRITICAL" if total >= 85 else "HIGH" if total >= 70 else
                                      "MEDIUM" if total >= 40 else "LOW")
    assert risk["is_provisional"] == (None in (cvss, probability, kev))


@pytest.mark.parametrize("cve", sorted(SAMPLES))
def test_published(client, cve, feeds, inference, dynamo):
    sample = SAMPLES[cve]
    response = analyze(client, " " + cve.lower() + " ")
    assert response.status_code == 201, response.text
    record = response.json()
    assert (settings.NVD_BASE_URL, {"cveId": cve}) in feeds["requests"]
    assert (settings.EPSS_BASE_URL, {"cve": cve}) in feeds["requests"]
    assert (settings.CISA_KEV_URL, None) in feeds["requests"]
    intel = record["intelligence"]
    assert record["cve_id"] == intel["cve_id"] == cve and not intel["is_simulated"]
    nvd, epss, kev = (intel[k] for k in ("nvd", "epss", "cisa_kev"))
    assert nvd["status"] == epss["status"] == "AVAILABLE"
    assert nvd["description"] == sample["description"] and nvd["published_date"] == sample["published"]
    metric = sample["cvssData"]
    assert (nvd["cvss_base_score"], nvd["cvss_vector_string"]) == (metric.get("baseScore"), metric.get("vectorString"))
    probability, percentile = (float(sample["epss"][k]) for k in ("epss", "percentile"))
    assert (epss["epss_probability"], epss["epss_percentile"], epss["model_date"]) == (
        probability, percentile, sample["epss"]["date"])
    listed = bool(sample["kev"])
    assert kev["is_known_exploited"] is listed
    assert kev["status"] == ("AVAILABLE" if listed else "CONFIRMED_NEGATIVE")
    check_score(record["risk_score"], metric.get("baseScore"), probability, listed)
    prompt, = inference
    for evidence in (cve, sample["description"], metric.get("vectorString", "CVSS version: Unknown"), sample["reference"],
                     f"{probability:.4f}", f"{percentile:.4f}", "QA validation",
                     "YES (listed" if listed else "NO (not listed", str(record["risk_score"]["total_score"])):
        assert evidence in prompt
    if listed and "requiredAction" in sample["kev"]:
        assert sample["kev"]["requiredAction"] in prompt
    assert record["remediation"]["executive_summary"] == MODEL_REPLY["executive_summary"]
    assert not record["remediation"]["is_fallback_deterministic"]
    assert sample["reference"] in record["remediation"]["evidence_citations"]
    assert dynamo[record["id"]]["cve_id"] == {"S": cve}
    read = client.get("/api/assessments/" + record["id"])
    assert read.status_code == 200 and read.json() == record
    print(f"{cve} | {record['id']} | {record['risk_score']['total_score']} | {record['risk_score']['priority_level']}")


@pytest.mark.parametrize("cve, expected", [(UNKNOWN, 404), ("CVE-2099-123456789", 404),
                                          ("CVE-24-6387", 422), ("CVE-2024-１２３４", 422)])
def test_invalid_or_absent(client, feeds, inference, dynamo, cve, expected):
    assert analyze(client, cve).status_code == expected
    assert bool(feeds["requests"]) == (expected == 404)
    assert not inference and not dynamo


@pytest.mark.parametrize("case", ["no_cvss", "epss_missing", "kev_outage", "all_down"])
def test_incomplete_evidence(client, feeds, inference, dynamo, case):
    cve = "CVE-2024-6387"
    sample = feeds["samples"][cve]
    if case == "no_cvss":
        sample["cvssData"] = {}
    elif case == "epss_missing":
        sample["epss"] = None
    elif case == "kev_outage":
        feeds["fail"].add(settings.CISA_KEV_URL)
    else:
        feeds["fail"].update([settings.NVD_BASE_URL, settings.EPSS_BASE_URL, settings.CISA_KEV_URL])
    response = analyze(client, cve)
    if case == "all_down":
        assert response.status_code == 503 and not inference and not dynamo
        return
    assert response.status_code == 201
    data = response.json()
    intel = data["intelligence"]
    cvss = None if case == "no_cvss" else 8.1
    epss = None if case == "epss_missing" else float(sample["epss"]["epss"])
    listed = None if case == "kev_outage" else False
    assert intel["nvd"]["status"] == "AVAILABLE"
    assert intel["nvd"]["cvss_base_score"] == cvss
    assert intel["epss"]["epss_probability"] == epss
    assert intel["cisa_kev"]["is_known_exploited"] is listed
    if case == "kev_outage":
        assert "Unknown (catalog unavailable)" in inference[0]
    check_score(data["risk_score"], cvss, epss, listed)
    assert client.get("/api/assessments/" + data["id"]).json() == data


def test_new_upstream_record_without_preset(client, feeds, inference, dynamo):
    """Publish a previously absent random test ID upstream, then investigate it again."""
    cve = f"CVE-2099-{100000000 + randbelow(900000000)}"
    assert analyze(client, cve).status_code == 404
    sample = copy.deepcopy(SAMPLES["CVE-2024-6387"])
    sample.update(description=f"New upstream description for {cve}", metric="cvssMetricV40",
                  cvssData={"baseScore": 6.4, "version": "4.0", "baseSeverity": "MEDIUM"},
                  epss={"cve": cve, "epss": "0.04", "percentile": "0.89", "date": "2026-11-23"})
    feeds["samples"][cve] = sample
    response = analyze(client, cve)
    assert response.status_code == 201
    data = response.json()
    check_score(data["risk_score"], 6.4, 0.04, False)
    prompt, = inference
    assert sample["description"] in prompt and "CVSS version: 4.0" in prompt
    assert client.get("/api/assessments/" + data["id"]).json() == data


@pytest.mark.parametrize("fault", ["wrong_nvd_id", "wrong_epss_id", "invalid_catalog"])
def test_bad_upstream_payload(client, monkeypatch, feeds, inference, dynamo, fault):
    cve = "CVE-2024-6387"
    original_get = httpx.AsyncClient.get

    async def damaged(client, url, **kwargs):
        response = await original_get(client, url, **kwargs)
        data = response.json()
        if fault == "wrong_nvd_id" and url == settings.NVD_BASE_URL:
            data["vulnerabilities"][0]["cve"]["id"] = "CVE-2021-44228"
        elif fault == "wrong_epss_id" and url == settings.EPSS_BASE_URL:
            data["data"][0]["cve"] = "CVE-2021-44228"
        elif fault == "invalid_catalog" and url == settings.CISA_KEV_URL:
            data = {"count": 2000, "vulnerabilities": []}
        return httpx.Response(200, json=data)

    monkeypatch.setattr(httpx.AsyncClient, "get", damaged)
    response = analyze(client, cve)
    assert response.status_code == 201
    data = response.json()
    source = {"wrong_nvd_id": "nvd", "wrong_epss_id": "epss", "invalid_catalog": "cisa_kev"}[fault]
    assert data["intelligence"][source]["status"] == "UNKNOWN_OR_MISSING"
    assert data["risk_score"]["is_provisional"]
    if fault == "invalid_catalog":
        assert data["intelligence"]["cisa_kev"]["is_known_exploited"] is None
