"""
VulnGuard AI - Offline Demonstration Intelligence
Explicitly labeled as SIMULATED data for offline testing, CI/CD, and demo runs.
"""
from typing import Dict, Any

SIMULATED_CVE_FIXTURES: Dict[str, Dict[str, Any]] = {
    "CVE-2021-44228": {
        "nvd": {
            "cve_id": "CVE-2021-44228",
            "status": "SIMULATED",
            "description": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
            "cvss_version": "3.1",
            "cvss_base_score": 10.0,
            "cvss_severity": "CRITICAL",
            "cvss_vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "published_date": "2021-12-10T10:15:00.000",
            "last_modified_date": "2023-11-07T03:39:00.000",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                "https://logging.apache.org/log4j/2.x/security.html"
            ],
            "weaknesses": ["CWE-502", "CWE-400"],
            "fetched_at": "2026-11-23T00:00:00Z",
            "source_url": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228",
            "is_simulated": True
        },
        "epss": {
            "cve_id": "CVE-2021-44228",
            "status": "SIMULATED",
            "epss_probability": 0.97542,
            "epss_percentile": 0.99988,
            "model_date": "2026-11-22",
            "fetched_at": "2026-11-23T00:00:00Z",
            "source_url": "https://api.first.org/data/v1/epss?cve=CVE-2021-44228",
            "is_simulated": True
        },
        "cisa_kev": {
            "cve_id": "CVE-2021-44228",
            "status": "SIMULATED",
            "is_known_exploited": True,
            "vulnerability_name": "Apache Log4j2 Remote Code Execution Vulnerability",
            "date_added": "2021-12-10",
            "required_action": "Apply immediate updates per vendor instructions or discontinue use.",
            "due_date": "2021-12-24",
            "known_ransomware_use": "Known",
            "notes": "Widely observed in weaponized automated botnets and ransomware attacks.",
            "fetched_at": "2026-11-23T00:00:00Z",
            "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "is_simulated": True
        }
    },
    "CVE-2023-38606": {
        "nvd": {
            "cve_id": "CVE-2023-38606",
            "status": "SIMULATED",
            "description": "An app may be able to modify sensitive kernel state. Apple is aware of a report that this issue may have been actively exploited against versions of iOS released before iOS 15.7.1.",
            "cvss_version": "3.1",
            "cvss_base_score": 7.8,
            "cvss_severity": "HIGH",
            "cvss_vector_string": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "published_date": "2023-07-24T22:15:00.000",
            "last_modified_date": "2023-08-01T14:48:00.000",
            "references": ["https://support.apple.com/kb/HT213841"],
            "weaknesses": ["CWE-284"],
            "fetched_at": "2026-11-23T00:00:00Z",
            "source_url": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-38606",
            "is_simulated": True
        },
        "epss": {
            "cve_id": "CVE-2023-38606",
            "status": "SIMULATED",
            "epss_probability": 0.01520,
            "epss_percentile": 0.85410,
            "model_date": "2026-11-22",
            "fetched_at": "2026-11-23T00:00:00Z",
            "source_url": "https://api.first.org/data/v1/epss?cve=CVE-2023-38606",
            "is_simulated": True
        },
        "cisa_kev": {
            "cve_id": "CVE-2023-38606",
            "status": "SIMULATED",
            "is_known_exploited": True,
            "vulnerability_name": "Apple Multiple Products Kernel State Modification Vulnerability",
            "date_added": "2023-07-25",
            "required_action": "Apply mitigations per vendor instructions or discontinue use.",
            "due_date": "2023-08-15",
            "known_ransomware_use": "Unknown",
            "notes": "Targeted spyware attack vector.",
            "fetched_at": "2026-11-23T00:00:00Z",
            "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "is_simulated": True
        }
    },
    "CVE-2024-3094": {
        "nvd": {
            "cve_id": "CVE-2024-3094",
            "status": "SIMULATED",
            "description": "Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file.",
            "cvss_version": "3.1",
            "cvss_base_score": 10.0,
            "cvss_severity": "CRITICAL",
            "cvss_vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "published_date": "2024-03-29T21:15:00.000",
            "last_modified_date": "2024-04-02T13:15:00.000",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"],
            "weaknesses": ["CWE-506"],
            "fetched_at": "2026-11-23T00:00:00Z",
            "source_url": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094",
            "is_simulated": True
        },
        "epss": {
            "cve_id": "CVE-2024-3094",
            "status": "SIMULATED",
            "epss_probability": 0.00280,
            "epss_percentile": 0.45000,
            "model_date": "2026-11-22",
            "fetched_at": "2026-11-23T00:00:00Z",
            "source_url": "https://api.first.org/data/v1/epss?cve=CVE-2024-3094",
            "is_simulated": True
        },
        "cisa_kev": {
            "cve_id": "CVE-2024-3094",
            "status": "CONFIRMED_NEGATIVE",
            "is_known_exploited": False,
            "vulnerability_name": None,
            "date_added": None,
            "required_action": None,
            "due_date": None,
            "known_ransomware_use": None,
            "notes": "Not cataloged in CISA KEV as widespread active exploitation in the wild was averted before release.",
            "fetched_at": "2026-11-23T00:00:00Z",
            "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "is_simulated": True
        }
    }
}
