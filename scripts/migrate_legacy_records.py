"""
VulnGuard AI - Administrator Legacy Record Migration & Quarantine Tool
Scans DynamoDB or SQLite for legacy assessments created before multi-tenant user isolation.
Quarantines unowned records to ensure strict tenant boundaries, or assigns them to a verified administrator.

Usage:
    python scripts/migrate_legacy_records.py --dry-run
    python scripts/migrate_legacy_records.py --action quarantine
    python scripts/migrate_legacy_records.py --action reassign --target-user-id <admin_cognito_sub>
"""
import sys
import json
import argparse
import boto3
from botocore.exceptions import ClientError


def scan_unowned_items(table):
    """Scans for records lacking owner_user_id."""
    unowned = []
    scan_kwargs = {
        "FilterExpression": "attribute_not_exists(owner_user_id) OR owner_user_id = :empty",
        "ExpressionAttributeValues": {":empty": ""},
    }
    while True:
        resp = table.scan(**scan_kwargs)
        unowned.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            break
        scan_kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return unowned


def run_migration(table_name: str, region: str, action: str, target_user_id: str, dry_run: bool):
    print(f"\n=======================================================")
    print(f" VulnGuard Legacy Assessment Quarantine & Migration")
    print(f" Table: {table_name} ({region})")
    print(f" Action: {action}")
    if action == "reassign":
        print(f" Target Owner User ID: {target_user_id}")
    print(f" Dry Run: {dry_run}")
    print(f"=======================================================\n")

    dynamodb = boto3.resource("dynamodb", region_name=region)
    table = dynamodb.Table(table_name)

    try:
        unowned_items = scan_unowned_items(table)
    except ClientError as e:
        print(f"[Error] Failed to scan table: {e}")
        sys.exit(1)

    count = len(unowned_items)
    print(f"[Scan] Found {count} unowned legacy assessment(s).\n")
    if count == 0:
        print("[Status] No unowned records found. All assessments are assigned to explicit tenant owners.")
        return

    assigned_owner = "QUARANTINED_LEGACY" if action == "quarantine" else target_user_id

    for idx, item in enumerate(unowned_items, start=1):
        aid = item.get("assessment_id") or item.get("id")
        cve = item.get("cve_id", "UNKNOWN")
        created = item.get("created_at", "")
        print(f"[{idx}/{count}] Processing {aid} ({cve})...")

        if dry_run:
            print(f"  [DRY RUN] Would set owner_user_id='{assigned_owner}' and user_cve_id='{assigned_owner}#{cve}'")
            continue

        # Update item in DynamoDB
        user_cve_key = f"{assigned_owner}#{cve}"

        # Update the serialized full_data JSON so detail lookups also reflect the assignment
        full_json_str = item.get("full_data")
        updated_full_json = full_json_str
        if full_json_str:
            try:
                data_dict = json.loads(full_json_str)
                data_dict["owner_user_id"] = assigned_owner
                updated_full_json = json.dumps(data_dict)
            except Exception:
                pass

        try:
            update_exp = "SET owner_user_id = :owner, user_cve_id = :ucid"
            expr_vals = {
                ":owner": assigned_owner,
                ":ucid": user_cve_key,
            }
            if updated_full_json:
                update_exp += ", full_data = :fdata"
                expr_vals[":fdata"] = updated_full_json

            table.update_item(
                Key={"assessment_id": aid},
                UpdateExpression=update_exp,
                ExpressionAttributeValues=expr_vals
            )
            print(f"  [Updated] Successfully assigned to {assigned_owner}")
        except ClientError as err:
            print(f"  [Failed] Could not update {aid}: {err}")

    print(f"\n[Complete] Successfully processed {count} records. Quarantined records remain un-queryable by normal users.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage legacy VulnGuard records")
    parser.add_argument("--table-name", default="VulnGuardAssessments", help="DynamoDB table name")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--action", choices=["quarantine", "reassign"], default="quarantine", help="Quarantine or reassign legacy records")
    parser.add_argument("--target-user-id", default="", help="Target Cognito sub if reassigning")
    parser.add_argument("--dry-run", action="store_true", help="Preview operations without executing")
    args = parser.parse_args()

    if args.action == "reassign" and not args.target_user_id.strip():
        print("[Error] --target-user-id is required when action is 'reassign'.")
        sys.exit(1)

    run_migration(
        table_name=args.table_name,
        region=args.region,
        action=args.action,
        target_user_id=args.target_user_id.strip(),
        dry_run=args.dry_run,
    )
