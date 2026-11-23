"""
VulnGuard AI - Amazon DynamoDB Repository
Implements production persistence for vulnerability assessments using Boto3.
Enforces partition keys (assessment_id), GSIs for fast history & per-CVE queries,
conditional writes preventing accidental overwrites, pagination support, and Decimal conversion.
"""
import json
import boto3
from decimal import Decimal
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from botocore.exceptions import ClientError, BotoCoreError

from backend.core.config import settings
from backend.core.logging import logger
from backend.core.exceptions import DatabaseError
from backend.schemas.assessment import AssessmentResponse, AssessmentSummary
from backend.schemas.risk import AssetCriticality, InternetExposure, PriorityLevel
from database.interface import AssessmentRepository


def float_to_decimal(obj: Any) -> Any:
    """Recursively converts float values to Decimal for DynamoDB serialization."""
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: float_to_decimal(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [float_to_decimal(x) for x in obj]
    return obj


def decimal_to_float(obj: Any) -> Any:
    """Recursively converts Decimal values back to float/int."""
    if isinstance(obj, Decimal):
        return float(obj) if "." in str(obj) else int(obj)
    if isinstance(obj, dict):
        return {k: decimal_to_float(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [decimal_to_float(x) for x in obj]
    return obj


class DynamoDBAssessmentRepository(AssessmentRepository):
    """Production AWS DynamoDB implementation of AssessmentRepository."""

    def __init__(
        self,
        table_name: Optional[str] = None,
        region_name: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        boto3_resource=None
    ):
        self.table_name = table_name or settings.DYNAMODB_TABLE_NAME
        self.region_name = region_name or settings.AWS_REGION
        self.endpoint_url = endpoint_url

        if boto3_resource is not None:
            self._dynamodb = boto3_resource
        else:
            kwargs: Dict[str, Any] = {"region_name": self.region_name}
            if self.endpoint_url:
                kwargs["endpoint_url"] = self.endpoint_url
            self._dynamodb = boto3.resource("dynamodb", **kwargs)

        self._table = self._dynamodb.Table(self.table_name)
        logger.info(f"[DynamoDB] Initialized repository for table '{self.table_name}' in region '{self.region_name}'")

    def create_assessment(self, assessment: AssessmentResponse) -> AssessmentResponse:
        """Stores a newly completed assessment in DynamoDB using conditional write."""
        try:
            cvss = assessment.intelligence.nvd.cvss_base_score
            epss_p = assessment.intelligence.epss.epss_probability
            epss_pct = assessment.intelligence.epss.epss_percentile
            kev_intel = assessment.intelligence.cisa_kev
            nvd_intel = assessment.intelligence.nvd
            now_iso = datetime.now(timezone.utc).isoformat()
            sort_key_val = f"{assessment.created_at}#{assessment.id}"

            item: Dict[str, Any] = {
                # Primary Partition Key
                "assessment_id": assessment.id,
                # Backward-compatibility alias
                "id": assessment.id,
                # GSI 1 Partition Key & Sort Key
                "entity_type": "ASSESSMENT",
                "sort_key": sort_key_val,
                # GSI 2 Partition Key
                "cve_id": assessment.cve_id,
                # Vulnerability & Threat Intelligence Fields
                "cve_description": nvd_intel.description,
                "cvss_score": Decimal(str(cvss)) if cvss is not None else None,
                "cvss_version": nvd_intel.cvss_version,
                "epss_probability": Decimal(str(epss_p)) if epss_p is not None else None,
                "epss_percentile": Decimal(str(epss_pct)) if epss_pct is not None else None,
                "kev_status": kev_intel.status.value,
                "is_known_exploited": kev_intel.is_known_exploited,
                # Environmental Context
                "asset_criticality": assessment.asset_criticality.value,
                "internet_exposure": assessment.internet_exposure.value,
                # Scoring & Classification
                "risk_score": Decimal(str(assessment.risk_score.total_score)),
                "total_score": Decimal(str(assessment.risk_score.total_score)),
                "risk_classification": assessment.risk_score.priority_level.value,
                "priority_level": assessment.risk_score.priority_level.value,
                "is_provisional": assessment.risk_score.is_provisional,
                "provisional_reasons": assessment.risk_score.provisional_reasons,
                # AI Remediation
                "ai_explanation": assessment.remediation.executive_summary[:1000],
                "model_used": assessment.remediation.model_used,
                "intelligence_sources": assessment.remediation.evidence_citations,
                "source_timestamps": {
                    "nvd": nvd_intel.fetched_at,
                    "epss": assessment.intelligence.epss.fetched_at,
                    "cisa": kev_intel.fetched_at,
                },
                # Full lossless payload & Timestamps
                "full_data": assessment.model_dump_json(),
                "created_at": assessment.created_at,
                "updated_at": now_iso,
            }

            # Remove None values because DynamoDB rejects null attribute values for sparse indexes
            cleaned_item = {k: v for k, v in item.items() if v is not None}

            # Enforce conditional write preventing accidental overwrites
            self._table.put_item(
                Item=cleaned_item,
                ConditionExpression="attribute_not_exists(assessment_id) AND attribute_not_exists(id)"
            )
            logger.info(f"[DynamoDB] Successfully created assessment {assessment.id} for {assessment.cve_id}")
            return assessment

        except ClientError as err:
            error_code = err.response.get("Error", {}).get("Code", "")
            if error_code == "ConditionalCheckFailedException":
                logger.warning(f"[DynamoDB] Duplicate assessment overwrite prevented for {assessment.id}")
                raise DatabaseError(f"Assessment with ID '{assessment.id}' already exists in DynamoDB. Overwrites are prohibited.") from err
            logger.error(f"[DynamoDB] PutItem failed for assessment {assessment.id}: {err}", exc_info=True)
            raise DatabaseError(f"DynamoDB operation failed: {str(err)}") from err
        except BotoCoreError as b_err:
            logger.error(f"[DynamoDB] BotoCoreError for assessment {assessment.id}: {b_err}", exc_info=True)
            raise DatabaseError(f"DynamoDB connection failed: {str(b_err)}") from b_err

    def get_assessment_by_id(self, assessment_id: str) -> Optional[AssessmentResponse]:
        """Retrieves an assessment item by primary key (assessment_id)."""
        try:
            # First try assessment_id partition key
            response = self._table.get_item(Key={"assessment_id": assessment_id})
            item = response.get("Item")

            # Fallback to id partition key for legacy records
            if not item:
                try:
                    response = self._table.get_item(Key={"id": assessment_id})
                    item = response.get("Item")
                except ClientError:
                    pass

            if not item:
                return None

            full_json = item.get("full_data")
            if full_json:
                data = json.loads(full_json)
                return AssessmentResponse.model_validate(data)

            return None
        except (ClientError, BotoCoreError) as err:
            logger.error(f"[DynamoDB] GetItem failed for ID {assessment_id}: {err}", exc_info=True)
            raise DatabaseError(f"DynamoDB get failed: {str(err)}") from err

    def list_recent_assessments(
        self, limit: int = 20, last_evaluated_key: Optional[str] = None
    ) -> List[AssessmentSummary]:
        """Queries recent assessments using the HistoryIndex GSI (entity_type='ASSESSMENT')."""
        try:
            query_kwargs: Dict[str, Any] = {
                "IndexName": "HistoryIndex",
                "KeyConditionExpression": "entity_type = :etype",
                "ExpressionAttributeValues": {":etype": "ASSESSMENT"},
                "ScanIndexForward": False,  # Chronological DESC
                "Limit": limit,
            }
            if last_evaluated_key:
                try:
                    query_kwargs["ExclusiveStartKey"] = json.loads(last_evaluated_key)
                except Exception:
                    pass

            try:
                response = self._table.query(**query_kwargs)
                items = response.get("Items", [])
            except ClientError as gsi_err:
                logger.warning(f"[DynamoDB] HistoryIndex query failed ({gsi_err.response.get('Error', {}).get('Code')}), falling back to Scan.")
                scan_kwargs: Dict[str, Any] = {"Limit": limit}
                if last_evaluated_key:
                    try:
                        scan_kwargs["ExclusiveStartKey"] = json.loads(last_evaluated_key)
                    except Exception:
                        pass
                response = self._table.scan(**scan_kwargs)
                items = response.get("Items", [])
                items.sort(key=lambda x: str(x.get("sort_key") or x.get("created_at", "")), reverse=True)
                items = items[:limit]

            return self._items_to_summaries(items)

        except (ClientError, BotoCoreError) as err:
            logger.error(f"[DynamoDB] Query recent assessments failed: {err}", exc_info=True)
            raise DatabaseError(f"DynamoDB query failed: {str(err)}") from err

    def list_assessments_by_cve(
        self, cve_id: str, limit: int = 20, last_evaluated_key: Optional[str] = None
    ) -> List[AssessmentSummary]:
        """Queries assessments for a specific CVE using the CveHistoryIndex GSI."""
        clean_cve = cve_id.strip().upper()
        try:
            query_kwargs: Dict[str, Any] = {
                "IndexName": "CveHistoryIndex",
                "KeyConditionExpression": "cve_id = :cid",
                "ExpressionAttributeValues": {":cid": clean_cve},
                "ScanIndexForward": False,  # Chronological DESC
                "Limit": limit,
            }
            if last_evaluated_key:
                try:
                    query_kwargs["ExclusiveStartKey"] = json.loads(last_evaluated_key)
                except Exception:
                    pass

            try:
                response = self._table.query(**query_kwargs)
                items = response.get("Items", [])
            except ClientError as gsi_err:
                logger.warning(f"[DynamoDB] CveHistoryIndex query failed ({gsi_err.response.get('Error', {}).get('Code')}), using Scan fallback.")
                scan_kwargs: Dict[str, Any] = {
                    "FilterExpression": "cve_id = :cid",
                    "ExpressionAttributeValues": {":cid": clean_cve},
                    "Limit": limit,
                }
                response = self._table.scan(**scan_kwargs)
                items = response.get("Items", [])
                items.sort(key=lambda x: str(x.get("sort_key") or x.get("created_at", "")), reverse=True)
                items = items[:limit]

            return self._items_to_summaries(items)

        except (ClientError, BotoCoreError) as err:
            logger.error(f"[DynamoDB] Query assessments for {clean_cve} failed: {err}", exc_info=True)
            raise DatabaseError(f"DynamoDB query by CVE failed: {str(err)}") from err

    def _items_to_summaries(self, items: List[Dict[str, Any]]) -> List[AssessmentSummary]:
        summaries: List[AssessmentSummary] = []
        for item in items:
            aid = item.get("assessment_id") or item.get("id", "")
            cvss_raw = item.get("cvss_score") or item.get("cvss_base_score")
            epss_raw = item.get("epss_probability")
            p_level = item.get("risk_classification") or item.get("priority_level", "LOW")
            score_val = float(item.get("risk_score") or item.get("total_score", 0.0))

            kev_val = item.get("is_known_exploited")
            is_kev_bool = bool(kev_val) if kev_val is not None else None

            summaries.append(AssessmentSummary(
                id=aid,
                cve_id=item["cve_id"],
                priority_level=PriorityLevel(p_level),
                total_score=score_val,
                cvss_base_score=float(cvss_raw) if cvss_raw is not None else None,
                epss_probability=float(epss_raw) if epss_raw is not None else None,
                is_known_exploited=is_kev_bool,
                asset_criticality=AssetCriticality(item.get("asset_criticality", "MEDIUM")),
                internet_exposure=InternetExposure(item.get("internet_exposure", "INTERNAL")),
                created_at=item.get("created_at", ""),
            ))
        return summaries

    # Backward-compatible aliases
    def save(self, assessment: AssessmentResponse) -> AssessmentResponse:
        return self.create_assessment(assessment)

    def get_by_id(self, assessment_id: str) -> Optional[AssessmentResponse]:
        return self.get_assessment_by_id(assessment_id)

    def list_recent(self, limit: int = 20) -> List[AssessmentSummary]:
        return self.list_recent_assessments(limit=limit)
