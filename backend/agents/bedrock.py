"""
VulnGuard AI - Amazon Bedrock Nova Integration & Deterministic Fallback
Integrates Amazon Bedrock for grounded AI remediation explanations.
Gracefully falls back to a deterministic rules-based generator if AWS Bedrock is offline/unavailable.
"""
import json
import re
import boto3
from botocore.exceptions import ClientError, BotoCoreError, NoCredentialsError
from typing import Dict, Any, List, Tuple
from backend.core.config import settings
from backend.core.logging import logger
from backend.schemas.assessment import AiRemediation
from backend.schemas.intelligence import AggregatedIntel, IntelSourceStatus
from backend.schemas.risk import RiskScoreBreakdown, PriorityLevel


class BedrockExplainer:
    """Invokes Amazon Bedrock Nova model for evidence-grounded vulnerability explanations."""

    def __init__(self):
        self._client = None
        self._client_init_failed = False

    def _get_client(self):
        if self._client is None and not self._client_init_failed:
            try:
                self._client = boto3.client(
                    "bedrock-runtime",
                    region_name=settings.AWS_REGION
                )
            except Exception as e:
                logger.warning(f"[Bedrock] Could not initialize boto3 bedrock-runtime client: {e}")
                self._client_init_failed = True
        return self._client

    async def generate_explanation(
        self,
        cve_id: str,
        intel: AggregatedIntel,
        risk_score: RiskScoreBreakdown,
        system_context: str | None = None,
        force_deterministic: bool = False
    ) -> AiRemediation:
        """Generates evidence-grounded AI remediation or deterministic fallback."""

        # 1. Deterministic Mode if explicitly configured or requested
        if force_deterministic or settings.USE_BEDROCK_MOCK or intel.is_simulated:
            logger.info(f"[Bedrock] Generating deterministic explanation for {cve_id} (simulated/offline mode).")
            return self._build_deterministic_remediation(cve_id, intel, risk_score, system_context)

        # 2. Priority 1: NVIDIA Nemotron AI (if configured via env or SSM)
        api_key = settings.get_nvidia_api_key()
        if api_key:
            try:
                return await self._invoke_nvidia_nemotron(cve_id, intel, risk_score, system_context, api_key=api_key)
            except Exception as nvd_err:
                logger.warning(f"[NVIDIA Nemotron] API invocation failed ({nvd_err}). Trying fallback/Bedrock.")

        # 3. Priority 2: Amazon Bedrock Nova
        client = self._get_client()
        if client is not None or settings.AWS_BEARER_TOKEN_BEDROCK:
            try:
                return await self._invoke_bedrock_nova(cve_id, intel, risk_score, system_context)
            except (ClientError, BotoCoreError, NoCredentialsError) as aws_err:
                logger.warning(f"[Bedrock] AWS Bedrock unavailable ({type(aws_err).__name__}: {aws_err}). Falling back to deterministic rules.")
            except Exception as err:
                logger.warning(f"[Bedrock] Unexpected error invoking Bedrock: {err}. Falling back to deterministic rules.")

        # 4. Deterministic Fallback
        return self._build_deterministic_remediation(
            cve_id, intel, risk_score, system_context, is_fallback=True
        )

    async def _invoke_nvidia_nemotron(
        self,
        cve_id: str,
        intel: AggregatedIntel,
        risk_score: RiskScoreBreakdown,
        system_context: str | None,
        api_key: str | None = None
    ) -> AiRemediation:
        """Invokes NVIDIA Nemotron API for evidence-grounded vulnerability remediation."""
        prompt = self._build_prompt(cve_id, intel, risk_score, system_context)
        active_key = api_key or settings.get_nvidia_api_key()

        import httpx
        url = "https://integrate.api.nvidia.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {active_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        payload = {
            "model": settings.NVIDIA_MODEL_ID,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are VulnGuard AI, a senior cybersecurity expert. Analyze the vulnerability data and output ONLY "
                        "a valid JSON object matching the requested schema with no surrounding prose or markdown formatting."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "max_tokens": 1024,
            "temperature": 0.1
        }

        async with httpx.AsyncClient(timeout=35.0) as http_client:
            resp = await http_client.post(url, headers=headers, json=payload)
            if resp.status_code != 200:
                raise RuntimeError(f"NVIDIA API returned status {resp.status_code}: {resp.text}")

            result = resp.json()
            output_text = result["choices"][0]["message"].get("content")
            if not output_text:
                raise RuntimeError("NVIDIA Nemotron returned empty content.")

            cleaned = output_text.strip()
            if "```json" in cleaned:
                cleaned = cleaned.split("```json")[1].split("```")[0].strip()
            elif "```" in cleaned:
                cleaned = cleaned.split("```")[1].split("```")[0].strip()

            data = json.loads(cleaned)
            citations = self._build_citations(intel)
            exec_summary, tech_impact, exploit_assess, steps, mitigations = self._guard_ai_output(cve_id, data)

            logger.info(f"[NVIDIA Nemotron] Successfully generated AI remediation roadmap for {cve_id}")
            return AiRemediation(
                executive_summary=exec_summary,
                technical_impact=tech_impact,
                exploitation_assessment=exploit_assess,
                remediation_steps=steps,
                mitigation_workarounds=mitigations,
                evidence_citations=citations,
                model_used=settings.NVIDIA_MODEL_ID,
                is_fallback_deterministic=False,
            )

    async def _invoke_bedrock_nova(
        self,
        cve_id: str,
        intel: AggregatedIntel,
        risk_score: RiskScoreBreakdown,
        system_context: str | None
    ) -> AiRemediation:
        """Calls Amazon Bedrock Nova Lite/Pro model with strict evidence grounding."""
        prompt = self._build_prompt(cve_id, intel, risk_score, system_context)

        body = {
            "messages": [
                {
                    "role": "user",
                    "content": [{"text": prompt}]
                }
            ],
            "inferenceConfig": {
                "max_new_tokens": 1500,
                "temperature": 0.1,
                "top_p": 0.9
            }
        }

        output_text = None

        # Option A: Direct invocation via AWS Bedrock Bearer Token / API Key
        if settings.AWS_BEARER_TOKEN_BEDROCK:
            try:
                import httpx
                url = f"https://bedrock-runtime.{settings.AWS_REGION}.amazonaws.com/model/{settings.BEDROCK_MODEL_ID}/invoke"
                headers = {
                    "Authorization": f"Bearer {settings.AWS_BEARER_TOKEN_BEDROCK}",
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }
                async with httpx.AsyncClient(timeout=25.0) as http_client:
                    resp = await http_client.post(url, headers=headers, json=body)
                    if resp.status_code == 200:
                        response_body = resp.json()
                        output_text = response_body["output"]["message"]["content"][0]["text"]
                        logger.info(f"[Bedrock] Successfully invoked Nova via Bearer token API key.")
                    else:
                        logger.warning(f"[Bedrock Bearer] API returned status {resp.status_code}: {resp.text[:120]}")
            except Exception as bearer_err:
                logger.warning(f"[Bedrock Bearer] Error calling Bedrock via Bearer token: {bearer_err}")

        # Option B: Standard Boto3 SigV4 invocation
        if output_text is None and self._client is not None:
            import asyncio
            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self._client.invoke_model(
                    modelId=settings.BEDROCK_MODEL_ID,
                    body=json.dumps(body),
                    contentType="application/json",
                    accept="application/json"
                )
            )
            response_body = json.loads(response["body"].read().decode("utf-8"))
            output_text = response_body["output"]["message"]["content"][0]["text"]

        if output_text is None:
            raise RuntimeError("Bedrock invocation returned no output text.")

        # Parse JSON from model output
        try:
            # Look for JSON codeblock or bare JSON
            cleaned = output_text.strip()
            if "```json" in cleaned:
                cleaned = cleaned.split("```json")[1].split("```")[0].strip()
            elif "```" in cleaned:
                cleaned = cleaned.split("```")[1].split("```")[0].strip()

            data = json.loads(cleaned)
            citations = self._build_citations(intel)
            exec_summary, tech_impact, exploit_assess, steps, mitigations = self._guard_ai_output(cve_id, data)

            return AiRemediation(
                executive_summary=exec_summary,
                technical_impact=tech_impact,
                exploitation_assessment=exploit_assess,
                remediation_steps=steps,
                mitigation_workarounds=mitigations,
                evidence_citations=citations,
                model_used=settings.BEDROCK_MODEL_ID,
                is_fallback_deterministic=False,
            )
        except Exception as parse_err:
            logger.warning(f"[Bedrock] Could not parse Bedrock JSON output: {parse_err}. Content: {output_text[:150]}")
            # Use deterministic synthesis rather than failing
            return self._build_deterministic_remediation(
                cve_id, intel, risk_score, system_context, is_fallback=True
            )

    def _is_unsafe_xz_guidance(self, text: str) -> bool:
        """
        Evaluates whether text affirmatively recommends compromised XZ versions (5.6.0, 5.6.1, post-5.6.0)
        or claims they are safe/clean. Returns False if 5.6.0/5.6.1 are mentioned strictly in a negative,
        warning, or avoidance context (e.g., 'avoid 5.6.1', 'do not deploy 5.6.0 or 5.6.1', '5.6.0 and 5.6.1 are compromised').
        """
        lower = text.lower()

        # 1. Ambiguous post-5.6.0 recommendations without explicit negative warnings
        if re.search(r'\b(?:post|after|above|greater than|later than)[-\s]+5\.6\.0\b', lower):
            if not re.search(r'\b(?:do not|don\'t|never|avoid|refrain|compromis|malicious|backdoor)\b.*\b(?:post|after|above)[-\s]+5\.6\.0\b', lower):
                return True

        # 2. Check for mentions of 5.6.0 or 5.6.1
        if not re.search(r'\b5\.6\.[01]\b', lower):
            return False

        # 3. Explicit action verbs instructing upgrade/install/deploy/use of 5.6.0 or 5.6.1 without negation
        # Example matches: "upgrade to 5.6.1", "deploying version 5.6.1", "recommend 5.6.1", "migrate to 5.6.1"
        action_match = re.search(
            r'\b(?:upgrade|upgrading|update|updating|patch|patching|install|installing|deploy|deploying|recommend|recommending|recommendation|switch|switching|migrate|migrating|use|using|adopt|adopting|target|targeting|move to)\b'
            r'[\s\w,:-]*?\b(?:to\s+|version\s+|release\s+)?5\.6\.[01]\b',
            lower
        )
        if action_match:
            # Check if this action verb was preceded by a negation like "do not", "never", "avoid", "refrain from"
            match_start = action_match.start()
            prefix = lower[max(0, match_start - 30):match_start]
            if not re.search(r'\b(?:do not|don\'t|never|avoid|refrain from|caution against)\s*$', prefix.strip()):
                return True

        # 4. Assertions that 5.6.0 or 5.6.1 is safe, fixed, or clean
        if re.search(r'\b5\.6\.[01]\b[^.!?\n]*\b(?:safe|clean|fixed|unaffected|patched|resolved|resolves|remediated|uncompromised)\b', lower):
            # Check if negated
            if not re.search(r'\b(?:not|never|unproven|neither)\b[^.!?\n]*\b5\.6\.[01]\b', lower):
                return True

        # 5. Sentence-level analysis: in each sentence mentioning 5.6.0 or 5.6.1, ensure there is a clear warning indicator
        # Note: Do not split on standalone decimals in version numbers (e.g., 5.6.1)
        sentences = re.split(r'(?<=[!?])\s+|(?<=\.)\s+(?=[A-Za-z])|\n+', lower)
        for s in sentences:
            if re.search(r'\b5\.6\.[01]\b', s):
                warning_keywords = [
                    "do not", "don't", "never", "avoid", "refrain", "compromis", "backdoor",
                    "vulnerab", "affect", "impact", "malicious", "tainted", "insecure", "downgrade",
                    "isolate", "remove", "revert", "replace", "flaw"
                ]
                if not any(kw in s for kw in warning_keywords):
                    # Sentence mentions 5.6.0 or 5.6.1 without any warning/negative qualifier
                    return True

        return False

    def _sanitize_text_field(self, text: str) -> str:
        """Sanitizes free-text fields (summary, impact, exploitation) to neutralize unsafe XZ guidance."""
        if not self._is_unsafe_xz_guidance(text):
            return text

        # Replace offending sentences with official vendor/CISA downgrade guidance
        sentences = re.split(r'(?<=[!?])\s+|(?<=\.)\s+(?=[A-Za-z])|\n+', text)
        guarded = []
        replaced_any = False
        for s in sentences:
            if self._is_unsafe_xz_guidance(s):
                guarded.append(
                    "Official vendor and CISA guidance mandates downgrading XZ Utils to known uncompromised version 5.4.6 "
                    "or upgrading to verified clean releases (5.6.2+), as versions 5.6.0 and 5.6.1 were both compromised with a malicious backdoor."
                )
                replaced_any = True
            else:
                guarded.append(s)

        if not replaced_any:
            guarded.append(
                "Per CISA and distribution advisories, downgrade XZ Utils to uncompromised 5.4.6 or clean 5.6.2+ (do not deploy 5.6.0 or 5.6.1)."
            )

        return " ".join(guarded)

    def _sanitize_steps(self, steps: List[str]) -> List[str]:
        """Sanitizes remediation steps list for XZ Utils CVE-2024-3094."""
        guarded = []
        for step in steps:
            if self._is_unsafe_xz_guidance(step):
                guarded.append(
                    "Downgrade XZ Utils to known uncompromised version 5.4.6 or upgrade to verified clean releases "
                    "(5.6.2+) per official vendor and CISA guidance (do not deploy 5.6.0 or 5.6.1)."
                )
            else:
                guarded.append(step)
        return guarded

    def _sanitize_mitigations(self, mitigations: List[str]) -> List[str]:
        """Sanitizes mitigation workarounds list for XZ Utils CVE-2024-3094."""
        guarded = []
        for mit in mitigations:
            if self._is_unsafe_xz_guidance(mit):
                guarded.append(
                    "Immediately isolate hosts running xz/liblzma 5.6.0 or 5.6.1 and replace with distribution packages "
                    "reverted to uncompromised 5.4.6."
                )
            else:
                guarded.append(mit)
        return guarded

    def _guard_ai_output(
        self,
        cve_id: str,
        data: dict
    ) -> Tuple[str, str, str, List[str], List[str]]:
        """
        Enforces strict vendor errata version guardrails across ALL AI output fields:
        executive_summary, technical_impact, exploitation_assessment, remediation_steps,
        and mitigation_workarounds.
        """
        exec_summary = data.get("executive_summary", "Security analysis completed.")
        tech_impact = data.get("technical_impact", "Technical impact documented.")
        exploit_assess = data.get("exploitation_assessment", "Exploitation assessed.")
        steps = data.get("remediation_steps", ["Apply latest security patches from vendor."])
        mitigations = data.get("mitigation_workarounds", ["Enforce network segmentation and egress filtering."])

        if cve_id.upper() == "CVE-2024-3094":
            exec_summary = self._sanitize_text_field(exec_summary)
            tech_impact = self._sanitize_text_field(tech_impact)
            exploit_assess = self._sanitize_text_field(exploit_assess)
            steps = self._sanitize_steps(steps)
            mitigations = self._sanitize_mitigations(mitigations)

        return exec_summary, tech_impact, exploit_assess, steps, mitigations

    def _guard_remediation_versions(
        self, cve_id: str, steps: List[str], mitigations: List[str]
    ) -> Tuple[List[str], List[str]]:
        """
        Backwards-compatible interface for remediation steps and mitigations.
        """
        if cve_id.upper() == "CVE-2024-3094":
            return self._sanitize_steps(steps), self._sanitize_mitigations(mitigations)
        return steps, mitigations

    def _build_prompt(
        self,
        cve_id: str,
        intel: AggregatedIntel,
        risk_score: RiskScoreBreakdown,
        system_context: str | None
    ) -> str:
        kev_text = "Unknown (catalog unavailable)"
        if intel.cisa_kev.is_known_exploited is True:
            kev_text = "YES (listed in KEV)"
        elif intel.cisa_kev.is_known_exploited is False:
            kev_text = "NO (not listed in KEV)"
        epss_prob = f"{intel.epss.epss_probability:.4f}" if intel.epss.epss_probability is not None else "Unknown"
        epss_pct = f"{intel.epss.epss_percentile:.4f}" if intel.epss.epss_percentile is not None else "Unknown"

        return f"""You are VulnGuard AI, an expert Tier-3 cybersecurity vulnerability triage engine.
Analyze the following evidence for {cve_id} and return ONLY a valid JSON object matching the requested schema.

EVIDENCE DATA:
- CVE ID: {cve_id}
- CVSS version: {intel.nvd.cvss_version or 'Unknown'}, score: {intel.nvd.cvss_base_score} ({intel.nvd.cvss_severity})
- CVSS Vector: {intel.nvd.cvss_vector_string}
- NVD Description: {intel.nvd.description}
- CWE Weaknesses: {', '.join(intel.nvd.weaknesses) if intel.nvd.weaknesses else 'Not specified'}
- FIRST EPSS Exploitation Probability: {epss_prob} (Percentile: {epss_pct})
- CISA KEV In-the-Wild Status: {kev_text}
- CISA required action: {intel.cisa_kev.required_action or 'Not supplied'}
- NVD references: {', '.join(intel.nvd.references) or 'Not supplied'}
- Priority Classification: {risk_score.priority_level.value} (Composite Score: {risk_score.total_score}/100)
- System Context: {system_context or 'Standard corporate server/application'}

CRITICAL REMEDIATION & VERSIONING GUARDRAILS:
1. Validate all remediation versions against official vendor errata and CISA advisories.
2. Never extrapolate or guess patch version numbers from vulnerability descriptions.
3. For CVE-2024-3094 (XZ Utils), versions 5.6.0 and 5.6.1 were BOTH compromised. Do NOT recommend version 5.6.1 or ambiguous "post-5.6.0" strings. Mandate downgrading to 5.4.6 or clean releases (5.6.2+) per official vendor and CISA guidance.
4. When specific safe versions are not explicitly confirmed in official vendor advisories, instruct the analyst to consult official distribution errata rather than asserting unconfirmed version numbers.
5. Never recommend an affected or compromised version under any circumstances.

Respond ONLY with valid JSON using this exact schema:
{{
  "executive_summary": "Concise 2-3 sentence overview for security leadership explaining risk and urgency.",
  "technical_impact": "Detailed breakdown of the vulnerability mechanics, attack vector, and potential business disruption.",
  "exploitation_assessment": "Analysis combining EPSS probability and KEV status to evaluate real-world likelihood of exploitation.",
  "remediation_steps": [
    "Step 1: Specific patching or upgrade action",
    "Step 2: Configuration hardening"
  ],
  "mitigation_workarounds": [
    "Compensating control 1",
    "Compensating control 2"
  ]
}}"""

    def _build_deterministic_remediation(
        self,
        cve_id: str,
        intel: AggregatedIntel,
        risk_score: RiskScoreBreakdown,
        system_context: str | None,
        is_fallback: bool = False
    ) -> AiRemediation:
        """Deterministic, evidence-grounded remediation generated through rule heuristics."""
        cvss = intel.nvd.cvss_base_score if intel.nvd.cvss_base_score is not None else "N/A"
        sev = intel.nvd.cvss_severity or "UNKNOWN"
        is_kev = intel.cisa_kev.is_known_exploited
        epss_p = intel.epss.epss_probability
        epss_pct = intel.epss.epss_percentile

        # Executive Summary
        if is_kev:
            urgency = "IMMEDIATE EMERGENCY ACTION REQUIRED: Active weaponization and exploitation in the wild have been confirmed by CISA."
        elif risk_score.priority_level == PriorityLevel.CRITICAL:
            urgency = "HIGH URGENCY: Critical severity threat requiring rapid remediation within 24-48 hours."
        elif risk_score.priority_level == PriorityLevel.HIGH:
            urgency = "ELEVATED CONCERN: Substantial risk to operations; remediation recommended during the current sprint cycle."
        else:
            urgency = "STANDARD MONITORING: Manageable risk level; schedule patching according to standard vulnerability management cadence."

        exec_summary = (
            f"{cve_id} has been triaged with a composite risk score of {risk_score.total_score}/100 ({risk_score.priority_level.value}). "
            f"{urgency} The vulnerability carries a CVSS score of {cvss} ({sev})."
        )

        # Technical Impact
        desc = intel.nvd.description or "No description provided by upstream source."
        cwes = ", ".join(intel.nvd.weaknesses) if intel.nvd.weaknesses else "General security flaw"
        context_note = f" Target environment context: '{system_context}'." if system_context else ""
        tech_impact = (
            f"Vulnerability mechanism affects {cwes}. {desc}{context_note} "
            f"Attack vector vector string: {intel.nvd.cvss_vector_string or 'Standard remote network exposure'}."
        )

        # Exploitation Assessment
        if epss_p is not None:
            rank = f" ({epss_pct*100:.1f}th percentile)" if epss_pct is not None else ""
            epss_str = f"EPSS estimates an exploitation probability of {epss_p * 100:.2f}%{rank}."
        else:
            epss_str = "EPSS model data is currently unrecorded for this vulnerability."

        if is_kev:
            kev_str = f"CISA KEV officially lists this CVE ({intel.cisa_kev.vulnerability_name or cve_id}) as actively exploited."
            if intel.cisa_kev.required_action:
                kev_str += f" Required action: {intel.cisa_kev.required_action}."
        elif intel.cisa_kev.status == IntelSourceStatus.CONFIRMED_NEGATIVE:
            kev_str = "This CVE was absent from the retrieved CISA KEV catalog."
        else:
            kev_str = "KEV status is unknown or pending catalog sync."

        exploit_assessment = f"{epss_str} {kev_str}"

        # Remediation Steps
        remediation_steps = [
            f"Apply official security updates and vendor patches addressing {cve_id}.",
            "Verify all package dependencies and container images for vulnerable library versions.",
            "Conduct automated vulnerability rescans to validate patch efficacy across affected hosts.",
        ]
        if cve_id == "CVE-2024-3094":
            remediation_steps.insert(
                0,
                "Downgrade XZ Utils to known uncompromised version 5.4.6 or upgrade to clean vendor releases (5.6.2+) "
                "per CISA and distribution errata (do not deploy 5.6.0 or 5.6.1)."
            )
        elif intel.cisa_kev.required_action:
            remediation_steps.insert(0, f"CISA KEV Mandate: {intel.cisa_kev.required_action}")

        # Mitigation Workarounds
        mitigations = [
            "Implement network segmentation and restrict untrusted ingress access to affected services.",
            "Deploy Web Application Firewall (WAF) or Network IDS/IPS signatures targeting exploit payloads.",
            "Enforce least-privilege service account credentials to contain lateral movement in case of compromise.",
            "Enable heightened audit logging and SIEM alerting for anomalous process execution.",
        ]

        citations = self._build_citations(intel)
        model_name = "deterministic-fallback-rules"

        return AiRemediation(
            executive_summary=exec_summary,
            technical_impact=tech_impact,
            exploitation_assessment=exploit_assessment,
            remediation_steps=remediation_steps,
            mitigation_workarounds=mitigations,
            evidence_citations=citations,
            model_used=model_name,
            is_fallback_deterministic=True,
        )

    def _build_citations(self, intel: AggregatedIntel) -> List[str]:
        citations = [
            f"NIST NVD: {intel.nvd.source_url}",
            f"FIRST.org EPSS: {intel.epss.source_url}",
            f"CISA KEV Catalog: {intel.cisa_kev.source_url}",
        ]
        citations.extend(intel.nvd.references[:4])
        return citations


bedrock_explainer = BedrockExplainer()
