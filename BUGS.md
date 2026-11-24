# VulnGuard AI — Severity-Ranked Bug & Defect Register

This register details all defects, vulnerabilities, and architectural inconsistencies identified during the deep, evidence-based audit conducted on November 24, 2026.

---

### BUG-01 (HIGH / AppSec): Unauthenticated Paid AI & DynamoDB Write Endpoint
- **Severity:** HIGH (Production Deployment Blocker)
- **User Impact:** Any anonymous visitor or automated script on the public internet can send unauthenticated `POST /api/analyze` requests directly to `https://0n159e640h.execute-api.us-east-1.amazonaws.com`. Each request invokes paid NVIDIA Nemotron-3.5-bolt inference and executes a conditional write to Amazon DynamoDB table `VulnGuardAssessments`. This creates an immediate vulnerability to API quota depletion, cloud bill inflation (Denial of Wallet), and database pollution. Note that a frontend CAPTCHA alone does not protect direct API calls.
- **Affected Files:**
  - `backend/api/routes.py` (lines 26-57)
  - `database/infrastructure/template.yaml` (lines 36-54, 90-103)
- **Reproduction Steps:**
  1. Open a terminal on an external network with no AWS credentials, API keys, or session tokens.
  2. Execute:
     ```bash
     curl -i -X POST "https://0n159e640h.execute-api.us-east-1.amazonaws.com/api/analyze" \
       -H "Content-Type: application/json" \
       -d '{"cve_id":"CVE-2024-6387","asset_criticality":"HIGH","internet_exposure":"PUBLIC_FACING","system_context":"Public Probe"}'
     ```
  3. Observe HTTP `201 Created` returned with live NVIDIA Nemotron output and a newly persisted DynamoDB assessment ID (e.g., `vg-6c8195c7afee`).
- **Concrete Evidence:**
  - Automated audit harness confirmed unauthenticated invocation (`evidence/live_api_results.json`).
  - No authorization middleware, API key header validation, or OAuth/JWT token checks exist in `backend/app/main.py` or `backend/api/routes.py`.
- **Confirmed Cause:** API Gateway HTTP API v2 route is configured with `Auth: None` and FastAPI declares no security dependencies on `/api/analyze`.
- **Recommended Fix:**
  - Implement an API Key or JWT Authorizer in AWS API Gateway HTTP API (`VulnGuardHttpApi` in `template.yaml`).
  - Enforce server-side rate limits / throttling quotas at API Gateway (e.g. 10 requests/minute per client IP).
- **Verification Test:** Submit an unauthenticated `POST /api/analyze` and verify HTTP `401 Unauthorized` is returned.

---

### BUG-02 (HIGH / AppSec): Overprivileged IAM User `vulnguard` Assigned `AdministratorAccess`
- **Severity:** HIGH (Cloud Security Posture Defect)
- **User Impact:** The IAM user `vulnguard` (AWS Account `608379566260`) whose credentials reside in local developer environments has `AdministratorAccess` and redundant full-access policies attached. Any workstation credential compromise grants full administrative control of the entire AWS account.
- **Affected Resources:** AWS IAM User `vulnguard`
- **Reproduction Steps:**
  1. Run `aws iam list-attached-user-policies --user-name vulnguard`.
  2. Inspect the attached policy list.
- **Concrete Evidence:**
  ```json
  [
    {"PolicyName": "AmazonDynamoDBFullAccesswithDataPipeline"},
    {"PolicyName": "AdministratorAccess"},
    {"PolicyName": "AmazonDynamoDBFullAccess"},
    {"PolicyName": "AmazonBedrockFullAccess"},
    {"PolicyName": "AmazonDynamoDBFullAccess_v2"}
  ]
  ```
- **Confirmed Cause:** Permissive policies and full admin rights were granted during initial bootstrap rather than creating scoped IAM policies.
- **Recommended Fix:**
  1. **Do not remove `AdministratorAccess` immediately** without testing, as doing so abruptly could break deployment pipelines or operations.
  2. Prepare and test a narrowly scoped replacement policy that grants only the exact required actions (avoiding broad wildcards like `dynamodb:*`):
     - DynamoDB: `dynamodb:PutItem`, `dynamodb:GetItem`, `dynamodb:Query`, `dynamodb:Scan`, `dynamodb:DescribeTable` restricted to `arn:aws:dynamodb:us-east-1:608379566260:table/VulnGuardAssessments*`.
     - Bedrock: `bedrock:InvokeModel` restricted to `arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-*`.
     - SSM Parameter Store: `ssm:GetParameter`, `ssm:GetParameters` restricted to `arn:aws:ssm:us-east-1:608379566260:parameter/vulnguard/*`.
     - CloudWatch Logs: `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`.
  3. Validate SAM deployment and test runs with the replacement policy active, then safely detach `AdministratorAccess`.
- **Verification Test:** Re-run `aws iam list-attached-user-policies` and verify `AdministratorAccess` is detached while application deployment and tests remain fully functional.

---

### BUG-03 (HIGH / Reliability): Unhandled `JSONDecodeError` Bypasses Feed Retries in NVD & EPSS Services
- **Severity:** HIGH (Service-Level Resilience & Retry Bypass Defect)
- **User Impact:** When upstream intelligence feeds (NIST NVD or FIRST EPSS) return HTTP 200 with non-JSON text (such as HTML error pages, Cloudflare challenge pages, or proxy gateway errors), `response.json()` raises an unhandled `json.decoder.JSONDecodeError`.
  - **Service-Level Impact:** Because the exception handler in `nvd_service.py` and `epss_service.py` only catches `httpx.RequestError`, this exception immediately aborts the retry loop on attempt 1, bypassing the intended exponential backoff retries and failing to update `self.last_status = "degraded"`.
  - **API-Level Impact:** In the LangGraph assessment pipeline, `asyncio.gather(..., return_exceptions=True)` intercepts the `JSONDecodeError` and converts the failed feed to `_build_unavailable(cve_id)` (`status = UNKNOWN_OR_MISSING`). If other feeds succeed, the API returns **HTTP 201 Created** with provisional scoring (`is_provisional = true`). However, if all feeds return non-JSON text, the API raises `ThreatIntelFetchError`, which produces **HTTP 503 Service Unavailable** (not HTTP 500). Any standalone caller of the service module crashes with an unhandled exception.
- **Affected Files:**
  - `backend/services/nvd_service.py` (line 72)
  - `backend/services/epss_service.py` (line 58)
- **Reproduction Steps:**
  1. Mock upstream NVD API returning HTTP 200 with body `"<html><body>Cloudflare Challenge</body></html>"`.
  2. Invoke `nvd_service.fetch_cve("CVE-2021-44228")`.
  3. Observe immediate exit with `json.decoder.JSONDecodeError` on attempt 1, without executing retry attempts 2 or 3.
- **Concrete Evidence:** Verified in local resilience simulation (`evidence/resilience_simulations.json`).
- **Confirmed Cause:** `response.json()` is invoked inside a `try` block that catches only `httpx.RequestError`. `JSONDecodeError` inherits from `ValueError`, not `RequestError`.
- **Recommended Fix:**
  Wrap `response.json()` inside `try...except (json.JSONDecodeError, ValueError):` within the retry loop:
  ```python
  try:
      raw_json = response.json()
  except (json.JSONDecodeError, ValueError) as json_err:
      self.last_status = "degraded"
      self.last_error = f"Malformed upstream JSON: {str(json_err)[:100]}"
      logger.warning(f"[NVD] Malformed non-JSON response on attempt {attempt + 1}: {json_err}")
      if attempt < max_retries - 1:
          await asyncio.sleep(calculate_backoff_with_jitter(attempt))
          continue
      return self._build_unavailable(cve_id)
  ```
- **Verification Test:** Mock an HTTP 200 HTML response; verify the service completes all 3 retries with backoff and gracefully returns `UNKNOWN_OR_MISSING` without uncaught exceptions.

---

### BUG-04 (MEDIUM / AI Guidance): Vulnerable Version Recommendation for XZ Utils (`CVE-2024-3094`)
- **Severity:** MEDIUM (AI Safety & Remediation Guidance Defect)
- **User Impact:** For `CVE-2024-3094` (the XZ Utils backdoor), live NVIDIA Nemotron AI generated remediation guidance stating:
  > *"Upgrade XZ Utils to a patched version (post 5.6.0) immediately, as detailed in vendor advisories (e.g., Red Hat)."*
  Both versions 5.6.0 and 5.6.1 were compromised by the backdoor author. Recommending a "post-5.6.0" version implies version 5.6.1 is safe, which directly contradicts official CISA and vendor advisories (which mandated downgrading to 5.4.6 or upgrading to clean releases 5.6.2+). Relying solely on plausible-sounding version recommendations creates acute operational risk.
- **Affected Files:**
  - `backend/agents/bedrock.py` (lines 83-110, prompt instructions)
- **Reproduction Steps:**
  1. Triage `CVE-2024-3094` through the live API (`POST /api/analyze`).
  2. Inspect `remediation.remediation_steps[0]`.
- **Concrete Evidence:** Recorded in live QA assessment `vg-4b54b48cea7f` and previous audit `vg-3482c26725f7`:
  `"remediation_steps": ["Upgrade XZ Utils to a patched version (post 5.6.0) immediately..."]`
- **Confirmed Cause:** The prompt passes the raw NVD description (`"starting with version 5.6.0"`) without grounding instructions that require validating patch versions against official vendor errata.
- **Recommended Fix:** Add strict prompt guardrails in `_build_prompt`:
  > *"Validate all remediation versions against official vendor errata. Never extrapolate patch version numbers from vulnerability descriptions. When specific safe versions are not explicitly confirmed in vendor advisories, instruct the analyst to consult official distribution errata rather than asserting version numbers."*
- **Verification Test:** Re-run triage on `CVE-2024-3094` and verify remediation does not recommend version 5.6.1 or ambiguous "post-5.6.0" strings.

---

### BUG-05 (MEDIUM / Frontend Defect): Duplicate CWE Weaknesses Cause React Key Collisions & Carryover
- **Severity:** MEDIUM (Frontend Reconciliation & UI Defect)
- **User Impact:** Upstream NIST NVD responses frequently include duplicate CWE entries (e.g., `["CWE-89", "CWE-89"]` for MOVEit, `["CWE-125", "CWE-125"]` for Heartbleed, `["CWE-787", "CWE-787"]` for libwebp). Because the backend does not deduplicate CWEs, and the frontend maps them using `key={cwe}`, React logs `Encountered two children with the same key` warnings. During rapid triage transitions, this corrupts React virtual DOM reconciliation, causing stale CWE tags from previous assessments to carry over or persist.
- **Affected Files:**
  - `backend/services/nvd_service.py` (lines 167-173)
  - `frontend/src/components/dashboard/ThreatIntelCards.tsx` (lines 58-68)
- **Reproduction Steps:**
  1. Analyze `CVE-2023-34362` (MOVEit).
  2. Inspect the returned JSON payload: `weaknesses` contains `["CWE-89", "CWE-89"]`.
  3. Open browser developer console while analyzing MOVEit; observe React duplicate key warning.
  4. Rapidly switch from Log4j (`CWE-20`, `CWE-400`, `CWE-502`, `CWE-917`) to XZ Utils (`CWE-506`); observe stale tag rendering artifacts.
- **Concrete Evidence:**
  - Live API JSON output for MOVEit: `"weaknesses": ["CWE-89", "CWE-89"]` (`evidence/live_api_results.json`).
  - Frontend code in `ThreatIntelCards.tsx:62`:
    ```tsx
    {nvd.weaknesses.map((cwe) => (
      <span key={cwe} ...>{cwe}</span>
    ))}
    ```
- **Confirmed Cause:**
  1. Backend `nvd_service.py` loops over all NVD weaknesses (Primary and Secondary sources) and appends values without calling `list(dict.fromkeys(weaknesses))`.
  2. Frontend `ThreatIntelCards.tsx` uses raw `key={cwe}` rather than a composite key `key={`${cwe}-${index}`}` or deduplicating the array.
- **Recommended Fix:**
  - Backend: `weaknesses = list(dict.fromkeys(weaknesses))` in `_parse_nvd_response()`.
  - Frontend: `Array.from(new Set(nvd.weaknesses)).map((cwe, idx) => <span key={`${cwe}-${idx}`} ...>{cwe}</span>)`.
- **Verification Test:** Triage MOVEit and verify `weaknesses` contains only `["CWE-89"]` with zero browser console key collision warnings.

---

### BUG-06 (MEDIUM / Deployment Sync): Production Vercel Bundle Desynchronization
- **Severity:** MEDIUM (Deployment Integrity Defect)
- **User Impact:** The live public website `https://vulnguard.buildwithaveeck.com` is running an older bundle (`index-DmYX-hSm.js`) that still contains the deprecated `performInitialAnalysis()` function. Every time a user visits or reloads the dashboard, it silently fires an automatic `POST /api/analyze` for `CVE-2021-44228`. In contrast, the local repository working tree has already removed this call in uncommitted changes to `frontend/src/App.tsx`.
- **Affected Files:**
  - `frontend/src/App.tsx` (uncommitted unstaged changes)
  - Deployed Vercel CDN asset `https://vulnguard.buildwithaveeck.com/assets/index-DmYX-hSm.js`
- **Reproduction Steps:**
  1. Fetch `https://vulnguard.buildwithaveeck.com/assets/index-DmYX-hSm.js`.
  2. Search for `cve_id:"CVE-2021-44228"`.
  3. Observe `M.useEffect(()=>{I(),T(),R()},[])` where `R` is the automated analysis function.
- **Concrete Evidence:** Verified via Node.js script inspection of live bundle (`evidence/live_api_results.json`).
- **Confirmed Cause:** Code improvements made in the local repository were never committed to git or deployed to Vercel.
- **Recommended Fix:** Commit verified changes in `frontend/src/App.tsx` and deploy a fresh build to Vercel.
- **Verification Test:** Load `https://vulnguard.buildwithaveeck.com` with network inspector open; verify zero `POST /api/analyze` requests fire on initial mount.

---

### BUG-07 (LOW / Cosmetic & UX): Hardcoded `http://127.0.0.1:8000` & Static Telemetry in Settings
- **Severity:** LOW (Misleading UI Telemetry)
- **User Impact:** When a user accesses the live website through `https://vulnguard.buildwithaveeck.com`, the Settings panel displays a literal string "Local Endpoint: http://127.0.0.1:8000" and static hardcoded AI badges ("ACTIVE", "STANDBY", "READY"). This leads users to mistakenly believe the public website is reliant on their local machine.
- **Affected Files:**
  - `frontend/src/components/settings/SettingsPanel.tsx` (lines 107-109, 185-218)
- **Reproduction Steps:**
  1. Navigate to `https://vulnguard.buildwithaveeck.com/` in an incognito window.
  2. Click "Settings" in the sidebar.
  3. Under "FastAPI Core Backend", inspect "Local Endpoint".
- **Concrete Evidence:**
  `frontend/src/components/settings/SettingsPanel.tsx:108`:
  ```tsx
  <span className="font-mono text-slate-400 text-[11px]">http://127.0.0.1:8000</span>
  ```
- **Confirmed Cause:** Static strings were hardcoded in the JSX rather than reading `import.meta.env.VITE_API_BASE_URL` or dynamic server metadata.
- **Recommended Fix:**
  Replace static string with:
  ```tsx
  <span className="font-mono text-slate-400 text-[11px]">
    {import.meta.env.VITE_API_BASE_URL || 'Direct API Gateway'}
  </span>
  ```
- **Verification Test:** Open Settings on the deployed website; verify it shows the AWS API Gateway URL or "Cloud Production" rather than `http://127.0.0.1:8000`.

---

### BUG-08 (LOW / UI State): Transient "Backend Unreachable" Flash on Initial Load
- **Severity:** LOW (UI State Flicker)
- **User Impact:** On initial page load, the top header briefly flashes an alarming red "Offline / Backend Unreachable" indicator before switching to green "API Online" once `/health` completes.
- **Affected Files:**
  - `frontend/src/components/layout/Header.tsx` (line 28)
  - `frontend/src/App.tsx` (lines 41, 56)
- **Reproduction Steps:**
  1. Open `https://vulnguard.buildwithaveeck.com/` in an incognito browser.
  2. Observe the top right status icon during the first 500-800ms of loading.
- **Concrete Evidence:**
  In `Header.tsx`:
  ```tsx
  const isHealthy = systemHealth === 'healthy';
  ```
  In `App.tsx`:
  ```tsx
  const [systemHealth, setSystemHealth] = useState<any>(null);
  ```
- **Confirmed Cause:** While the initial `/health` request is in flight, `systemHealth` is `null`. `isHealthy` evaluates `null === 'healthy'` as `false`, immediately applying the offline styles before the request finishes.
- **Recommended Fix:** Introduce an explicit loading state: `const isConnecting = systemHealth === null;` and display a neutral pulse ("Connecting...") instead of the red "Offline / Backend Unreachable" badge.
- **Verification Test:** Reload page and verify neutral loading state appears during network latency.

---

### BUG-09 (LOW / UI Accuracy): Assessment History Count Misrepresented
- **Severity:** LOW (Data Accuracy Defect)
- **User Impact:** The Assessment History tab displays "Total Assessments (50)" when fetching recent records. In reality, DynamoDB contains 71+ records, and 50 is merely the hardcoded query `limit` parameter passed to `apiClient.listAssessments(50)`.
- **Affected Files:**
  - `frontend/src/App.tsx` (line 68)
  - `frontend/src/components/history/AssessmentHistoryTable.tsx`
- **Reproduction Steps:**
  1. Open History tab.
  2. Observe table header showing "Total Assessments (50)".
  3. Query DynamoDB via AWS CLI: `ItemCount` is 71.
- **Confirmed Cause:** UI labels the fetched page array length as "Total Assessments" rather than "Recent Assessments (Limit 50)".
- **Recommended Fix:** Change UI label to "Recent Assessments (showing up to 50)" or expose a `/api/assessments/stats` count endpoint.
- **Verification Test:** Verify table header displays "Recent Assessments (50)".

---

### BUG-10 (LOW / Environment): Missing `playwright` in `frontend/package.json`
- **Severity:** LOW (Test Suite Environment Defect)
- **User Impact:** Executing the Playwright browser regression test `python -m pytest backend/tests/test_published_browser.py` fails with `Cannot find module 'playwright'` because `playwright` is not declared in `frontend/package.json`.
- **Affected Files:** `frontend/package.json`
- **Reproduction Steps:**
  1. Set `$env:QA_BROWSER = '1'`.
  2. Run `python -m pytest backend/tests/test_published_browser.py`.
  3. Observe Node.js error: `Error: Cannot find module 'playwright' Require stack: ... frontend/tests/published-cve.cjs`.
- **Confirmed Cause:** `playwright` was omitted from `devDependencies`.
- **Recommended Fix:** Add `"playwright": "^1.49.0"` to `devDependencies` in `frontend/package.json`.
- **Verification Test:** Run `npm test` or `pytest backend/tests/test_published_browser.py` and verify Playwright imports successfully.
