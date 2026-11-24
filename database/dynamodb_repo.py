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

    def create_assessment(
        self, assessment: AssessmentResponse, owner_user_id: Optional[str] = None
    ) -> AssessmentResponse:
        """Stores a newly completed assessment in DynamoDB scoped to owner_user_id using conditional write."""
        try:
            effective_owner = owner_user_id or assessment.owner_user_id or "LEGACY_UNASSIGNED"
            assessment.owner_user_id = effective_owner

            cvss = assessment.intelligence.nvd.cvss_base_score
            epss_p = assessment.intelligence.epss.epss_probability
            epss_pct = assessment.intelligence.epss.epss_percentile
            kev_intel = assessment.intelligence.cisa_kev
            nvd_intel = assessment.intelligence.nvd
            now_iso = datetime.now(timezone.utc).isoformat()
            sort_key_val = f"{assessment.created_at}#{assessment.id}"
            user_cve_key = f"{effective_owner}#{assessment.cve_id.strip().upper()}"

            item: Dict[str, Any] = {
                # Primary Partition Key
                "assessment_id": assessment.id,
                # Backward-compatibility alias
                "id": assessment.id,
                # Multi-Tenant User Partitioning
                "owner_user_id": effective_owner,
                "user_cve_id": user_cve_key,
                # Sort Key
                "sort_key": sort_key_val,
                # Legacy GSI 1 Partition Key (retained for backward compatibility only)
                "entity_type": "ASSESSMENT",
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
            logger.info(f"[DynamoDB] Successfully created assessment {assessment.id} for {assessment.cve_id} (owner={effective_owner})")
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

    def get_assessment_by_id(
        self, assessment_id: str, owner_user_id: Optional[str] = None
    ) -> Optional[AssessmentResponse]:
        """
        Retrieves an assessment item by primary key, strictly verifying ownership.
        Returns None if record does not belong to owner_user_id, preventing cross-tenant leakage.
        """
        try:
            # First try assessment_id partition key
            response = self._table.get_item(Key={"assessment_id": assessment_id}, ConsistentRead=True)
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

            # Enforce strict ownership boundary
            item_owner = item.get("owner_user_id")
            if owner_user_id is not None:
                if not item_owner or item_owner != owner_user_id:
                    logger.warning(
                        f"[Security] Cross-tenant access denied: User '{owner_user_id}' requested assessment '{assessment_id}' owned by '{item_owner}'"
                    )
                    return None

            full_json = item.get("full_data")
            if full_json:
                data = json.loads(full_json)
                if item_owner and not data.get("owner_user_id"):
                    data["owner_user_id"] = item_owner
                return AssessmentResponse.model_validate(data)

            return None
        except (ClientError, BotoCoreError) as err:
            logger.error(f"[DynamoDB] GetItem failed for ID {assessment_id}: {err}", exc_info=True)
            raise DatabaseError(f"DynamoDB get failed: {str(err)}") from err

    def list_recent_assessments(
        self, owner_user_id: str, limit: int = 20, last_evaluated_key: Optional[str] = None
    ) -> Tuple[List[AssessmentSummary], Optional[str]]:
        """
        Queries recent assessments for a specific user using UserHistoryIndex.
        Fails visibly if index is missing; never falls back to a global table scan.
        """
        try:
            query_kwargs: Dict[str, Any] = {
                "IndexName": "UserHistoryIndex",
                "KeyConditionExpression": "owner_user_id = :uid",
                "ExpressionAttributeValues": {":uid": owner_user_id},
                "ScanIndexForward": False,  # Chronological DESC
                "Limit": limit,
            }
            if last_evaluated_key:
                try:
                    query_kwargs["ExclusiveStartKey"] = json.loads(last_evaluated_key)
                except Exception:
                    pass

            response = self._table.query(**query_kwargs)
            items = response.get("Items", [])
            lek = response.get("LastEvaluatedKey")
            next_cursor = json.dumps(decimal_to_float(lek)) if lek else None
            return self._items_to_summaries(items), next_cursor

        except (ClientError, BotoCoreError) as err:
            logger.error(f"[DynamoDB] Query UserHistoryIndex for user '{owner_user_id}' failed: {err}", exc_info=True)
            raise DatabaseError(f"DynamoDB query failed on UserHistoryIndex: {str(err)}") from err

    def list_assessments_by_cve(
        self, cve_id: str, owner_user_id: str, limit: int = 20, last_evaluated_key: Optional[str] = None
    ) -> List[AssessmentSummary]:
        """
        Queries assessments for a specific CVE for a specific user using UserCveHistoryIndex.
        Fails visibly if index is missing; never falls back to a global table scan.
        """
        clean_cve = cve_id.strip().upper()
        user_cve_key = f"{owner_user_id}#{clean_cve}"
        try:
            query_kwargs: Dict[str, Any] = {
                "IndexName": "UserCveHistoryIndex",
                "KeyConditionExpression": "user_cve_id = :ucid",
                "ExpressionAttributeValues": {":ucid": user_cve_key},
                "ScanIndexForward": False,  # Chronological DESC
                "Limit": limit,
            }
            if last_evaluated_key:
                try:
                    query_kwargs["ExclusiveStartKey"] = json.loads(last_evaluated_key)
                except Exception:
                    pass

            response = self._table.query(**query_kwargs)
            items = response.get("Items", [])
            return self._items_to_summaries(items)

        except (ClientError, BotoCoreError) as err:
            logger.error(f"[DynamoDB] Query UserCveHistoryIndex for '{clean_cve}' user '{owner_user_id}' failed: {err}", exc_info=True)
            raise DatabaseError(f"DynamoDB query failed on UserCveHistoryIndex: {str(err)}") from err

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
                owner_user_id=item.get("owner_user_id"),
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

    # Use the owner-aware convenience methods inherited from AssessmentRepository.
