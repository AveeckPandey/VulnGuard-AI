# VulnGuard AI — Database Architecture & Persistence Layer

This directory defines the persistence tier for the **VulnGuard AI — AI-Powered CVE Intelligence & Vulnerability Prioritization Platform**.

---

## 1. Architecture Overview: Dual-Backend Repository Pattern

VulnGuard AI employs a strict **Repository Pattern** defined in `interface.py` to decouple business logic from the database storage engine.

```
                      +-----------------------------+
                      |    AssessmentRepository     |
                      |         (Interface)         |
                      +--------------+--------------+
                                     |
                 +-------------------+-------------------+
                 |                                       |
  +--------------v--------------+         +--------------v--------------+
  |  SQLiteAssessmentRepository |         | DynamoDBAssessmentRepository|
  |         (Local Dev)         |         |        (Production)         |
  +-----------------------------+         +-----------------------------+
```

### Backend Selection
The storage backend is chosen explicitly via the `DATABASE_BACKEND` environment variable:
- `DATABASE_BACKEND=sqlite` (Default for local development and CI/CD).
- `DATABASE_BACKEND=dynamodb` (Production AWS deployment).

> **Production Safety Guarantee:** VulnGuard AI **never** silently switches to SQLite if DynamoDB connection fails in production. Misconfigurations immediately fail fast with an actionable `DatabaseError`.

---

## 2. Amazon DynamoDB Table Specification

- **Table Name:** `VulnGuardAssessments` (Configurable via `DYNAMODB_TABLE_NAME`)
- **Billing Mode:** `PAY_PER_REQUEST` (On-Demand capacity — zero cost when idle, auto-scaling up to thousands of concurrent requests).
- **Encryption at Rest:** Enabled (KMS SSE).
- **Point-In-Time Recovery:** Enabled.

### Primary Key
| Attribute | Key Type | Type | Description |
|---|---|---|---|
| `assessment_id` | HASH (Partition Key) | String (`S`) | Assessment unique identifier (e.g., `vg-a1b2c3d4e5f6`) |

### Global Secondary Indexes (GSIs)
1. **`HistoryIndex`** (For fast chronological listing of recent assessments across all systems):
   - **Partition Key (`HASH`):** `entity_type` (String, static value `"ASSESSMENT"`)
   - **Sort Key (`RANGE`):** `sort_key` (String, formatted as `<created_at>#<assessment_id>`)
   - **Projection:** `ALL`
2. **`CveHistoryIndex`** (For rapid chronological lookup of past assessments for a specific CVE):
   - **Partition Key (`HASH`):** `cve_id` (String, e.g., `CVE-2021-44228`)
   - **Sort Key (`RANGE`):** `sort_key` (String, formatted as `<created_at>#<assessment_id>`)
   - **Projection:** `ALL`

---

## 3. Data Attributes & Serialization

DynamoDB requires `Decimal` types for numerical values (Boto3 rejects Python `float`). The repository automates lossless type conversion via `float_to_decimal` and `decimal_to_float`.

| Field Name | Type | Notes |
|---|---|---|
| `assessment_id` | String | Unique ID (`id` also retained for backward compatibility) |
| `cve_id` | String | CVE Identifier |
| `entity_type` | String | Static `"ASSESSMENT"` for GSI partition |
| `sort_key` | String | `<created_at>#<assessment_id>` for deterministic GSI sorting |
| `risk_classification` | String | `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` (`priority_level` alias) |
| `risk_score` | Number (`Decimal`) | 0.0 to 100.0 (`total_score` alias retained) |
| `cvss_base_score` | Number (`Decimal`) | CVSS base severity (0.0 - 10.0) |
| `epss_probability` | Number (`Decimal`) | EPSS exploitation probability (0.0 - 1.0) |
| `is_known_exploited` | Boolean | True if listed in CISA KEV (explicit null if feed unavailable) |
| `asset_criticality` | String | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `internet_exposure` | String | `INTERNAL`, `PUBLIC_FACING` |
| `remediation_summary` | String | Executive summary narrative |
| `evidence_citations` | List[String] | Links to NVD, EPSS, CISA KEV sources |
| `full_data` | String (JSON) | Complete Pydantic `AssessmentResponse` serialized payload |
| `created_at` | String | ISO 8601 UTC timestamp |

---

## 4. Security & AWS IAM Roles

**Never commit AWS access keys or secrets to source control.**
- **AWS Environments (Lambda / ECS / EC2):** Automatically leverages IAM Execution Roles.
- **Local Testing:** Leverages standard AWS CLI profiles (`~/.aws/credentials`) or environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`).

See `infrastructure/dynamodb_iam_policy.json` for the least-privilege IAM policy.

---

## 5. Local Database (SQLite)

When `DATABASE_BACKEND=sqlite`, the application creates a lightweight local database at `SQLITE_DB_PATH` (defaults to `./vulnguard.db`). This requires zero Docker or AWS dependencies, ensuring that offline unit and integration tests run in milliseconds.

---

## 6. Infrastructure as Code (SAM & CloudFormation)

The infrastructure definition in `infrastructure/template.yaml` provisions:
1. `VulnGuardAssessmentsTable`: DynamoDB table with PAY_PER_REQUEST, encryption, PITR, and GSIs.
2. `VulnGuardHttpApi`: Amazon API Gateway HTTP API (v2) with CORS scoped to `https://vulnguard.buildwithaveeck.com` and `http://localhost:5173`.
3. `VulnGuardApiFunction`: AWS Lambda (Python 3.12, 512MB, 29s timeout) running the Mangum FastAPI adapter with least-privilege IAM policies.

### Deployment Commands
```bash
# Validate template syntax
aws cloudformation validate-template --template-body file://database/infrastructure/template.yaml

# Deploy via SAM
cd database/infrastructure
sam build
sam deploy --guided --stack-name vulnguard-ai-backend
```
