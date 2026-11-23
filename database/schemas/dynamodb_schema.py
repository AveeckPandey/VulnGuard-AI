"""
VulnGuard AI - DynamoDB Schema Creation Utility
Provides programmatic table creation and schema validation for development and setup scripts.
"""
from typing import Any, Dict
from botocore.exceptions import ClientError
from backend.core.logging import logger
from backend.core.config import settings


def get_table_schema(table_name: str = "VulnGuardAssessments") -> Dict[str, Any]:
    """Returns the DynamoDB table creation specification with On-Demand billing and GSIs."""
    return {
        "TableName": table_name,
        "BillingMode": "PAY_PER_REQUEST",
        "KeySchema": [
            {"AttributeName": "assessment_id", "KeyType": "HASH"}
        ],
        "AttributeDefinitions": [
            {"AttributeName": "assessment_id", "AttributeType": "S"},
            {"AttributeName": "entity_type", "AttributeType": "S"},
            {"AttributeName": "cve_id", "AttributeType": "S"},
            {"AttributeName": "sort_key", "AttributeType": "S"},
        ],
        "GlobalSecondaryIndexes": [
            {
                "IndexName": "HistoryIndex",
                "KeySchema": [
                    {"AttributeName": "entity_type", "KeyType": "HASH"},
                    {"AttributeName": "sort_key", "KeyType": "RANGE"}
                ],
                "Projection": {"ProjectionType": "ALL"}
            },
            {
                "IndexName": "CveHistoryIndex",
                "KeySchema": [
                    {"AttributeName": "cve_id", "KeyType": "HASH"},
                    {"AttributeName": "sort_key", "KeyType": "RANGE"}
                ],
                "Projection": {"ProjectionType": "ALL"}
            }
        ]
    }


def create_table_if_not_exists(dynamodb_resource, table_name: str = "VulnGuardAssessments") -> Any:
    """Creates the DynamoDB table if it does not already exist."""
    try:
        table = dynamodb_resource.Table(table_name)
        table.load()
        logger.info(f"[DynamoDB Schema] Table '{table_name}' already exists (Status: {table.table_status})")
        return table
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            logger.info(f"[DynamoDB Schema] Creating table '{table_name}'...")
            params = get_table_schema(table_name)
            table = dynamodb_resource.create_table(**params)
            table.wait_until_exists()
            logger.info(f"[DynamoDB Schema] Table '{table_name}' successfully created and active.")
            return table
        else:
            raise
