"""
VulnGuard AI - DynamoDB Global Secondary Index Deployment & Verification Script
Updates existing pre-created DynamoDB tables to add UserHistoryIndex and UserCveHistoryIndex.
Waits until both GSIs reach 'ACTIVE' state before switching production read patterns.

Usage:
    python scripts/update_dynamodb_indexes.py --table-name VulnGuardAssessments --region us-east-1
    python scripts/update_dynamodb_indexes.py --dry-run
"""
import sys
import time
import argparse
import boto3
from botocore.exceptions import ClientError


def get_gsi_definitions():
    return [
        {
            "IndexName": "UserHistoryIndex",
            "KeySchema": [
                {"AttributeName": "owner_user_id", "KeyType": "HASH"},
                {"AttributeName": "sort_key", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        },
        {
            "IndexName": "UserCveHistoryIndex",
            "KeySchema": [
                {"AttributeName": "user_cve_id", "KeyType": "HASH"},
                {"AttributeName": "sort_key", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        },
    ]


def ensure_user_indexes(table_name: str, region: str, dry_run: bool = False, wait: bool = True):
    print(f"\n=======================================================")
    print(f" VulnGuard DynamoDB GSI Provisioning & Verification")
    print(f" Target Table: {table_name} ({region})")
    print(f" Dry-Run: {dry_run}")
    print(f"=======================================================\n")

    client = boto3.client("dynamodb", region_name=region)

    try:
        desc = client.describe_table(TableName=table_name)
    except ClientError as e:
        print(f"[Error] Could not reach table '{table_name}': {e}")
        sys.exit(1)

    existing_gsis = {gsi["IndexName"]: gsi["IndexStatus"] for gsi in desc["Table"].get("GlobalSecondaryIndexes", [])}
    print(f"[Status] Existing Global Secondary Indexes: {existing_gsis or 'None'}")

    # Required attribute definitions for the new GSIs
    required_attr_defs = [
        {"AttributeName": "owner_user_id", "AttributeType": "S"},
        {"AttributeName": "user_cve_id", "AttributeType": "S"},
        {"AttributeName": "sort_key", "AttributeType": "S"},
    ]
    target_gsis = get_gsi_definitions()

    for gsi in target_gsis:
        index_name = gsi["IndexName"]
        if index_name in existing_gsis:
            status = existing_gsis[index_name]
            print(f"[Check] Index '{index_name}' already exists with status: {status}")
            continue

        print(f"[Action] Provisioning new GSI: '{index_name}'...")
        if dry_run:
            print(f"  [DRY RUN] Would issue UpdateTable for '{index_name}' with Hash Key '{gsi['KeySchema'][0]['AttributeName']}'")
            continue

        # AWS DynamoDB allows adding only ONE GSI per UpdateTable call on existing tables
        # UpdateTable needs definitions for every key in the new GSI, including
        # keys already defined by an existing index.
        key_attrs = [
            attr for attr in required_attr_defs
            if attr["AttributeName"] in [k["AttributeName"] for k in gsi["KeySchema"]]
        ]

        update_kwargs = {
            "TableName": table_name,
            "GlobalSecondaryIndexUpdates": [{"Create": gsi}],
        }
        update_kwargs["AttributeDefinitions"] = key_attrs

        try:
            client.update_table(**update_kwargs)
            print(f"[Success] Issued Create request for '{index_name}'. DynamoDB is backfilling index.")
            # Wait for this GSI to become ACTIVE before creating the next one (DynamoDB constraint)
            if wait:
                print(f"[Wait] Waiting for '{index_name}' to reach 'ACTIVE' state before continuing...")
                while True:
                    time.sleep(10)
                    t_desc = client.describe_table(TableName=table_name)
                    gsi_status = next(
                        (g["IndexStatus"] for g in t_desc["Table"].get("GlobalSecondaryIndexes", []) if g["IndexName"] == index_name),
                        "UNKNOWN"
                    )
                    print(f"  Status of '{index_name}': {gsi_status}")
                    if gsi_status == "ACTIVE":
                        break
                    if gsi_status in ("CREATING", "UPDATING"):
                        continue
                    if gsi_status in ("DELETING", "FAILED"):
                        print(f"[Error] Index '{index_name}' entered unexpected status: {gsi_status}")
                        sys.exit(1)

        except ClientError as update_err:
            print(f"[Error] Failed to update table for '{index_name}': {update_err}")
            sys.exit(1)

    print("\n[Complete] All user-scoped GSIs verified. Sparse indexing ensures legacy ownerless records remain quarantined.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy and verify VulnGuard User GSIs in DynamoDB")
    parser.add_argument("--table-name", default="VulnGuardAssessments", help="DynamoDB table name")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without modifying AWS")
    parser.add_argument("--no-wait", action="store_true", help="Do not wait for GSIs to reach ACTIVE")
    args = parser.parse_args()

    ensure_user_indexes(
        table_name=args.table_name,
        region=args.region,
        dry_run=args.dry_run,
        wait=not args.no_wait,
    )
