"""
VulnGuard AI - Threat Intelligence Schemas
Defines structured data models for NVD, EPSS, and CISA KEV sources.
"""
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class IntelSourceStatus(str, Enum):
    AVAILABLE = "AVAILABLE"                      # Data successfully fetched from live source
    CONFIRMED_NEGATIVE = "CONFIRMED_NEGATIVE"    # Checked live source, confirmed negative (e.g. NOT in KEV)
    UNKNOWN_OR_MISSING = "UNKNOWN_OR_MISSING"    # Data missing from upstream, pending analysis, or unreachable
    SIMULATED = "SIMULATED"                      # Offline test fixture / demo data


class NvdIntel(BaseModel):
    cve_id: str
    status: IntelSourceStatus = IntelSourceStatus.AVAILABLE
    description: Optional[str] = None
    cvss_version: Optional[str] = None
    cvss_base_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    cvss_vector_string: Optional[str] = None
    published_date: Optional[str] = None
    last_modified_date: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    weaknesses: List[str] = Field(default_factory=list, description="CWE IDs")
    fetched_at: str
    source_url: str
    is_simulated: bool = False


class EpssIntel(BaseModel):
    cve_id: str
    status: IntelSourceStatus = IntelSourceStatus.AVAILABLE
    epss_probability: Optional[float] = Field(None, description="Exploitation probability (0.0 to 1.0)")
    epss_percentile: Optional[float] = Field(None, description="Percentile relative to all CVEs (0.0 to 1.0)")
    model_date: Optional[str] = None
    fetched_at: str
    source_url: str
    is_simulated: bool = False


class CisaKevIntel(BaseModel):
    cve_id: str
    status: IntelSourceStatus = IntelSourceStatus.AVAILABLE
    is_known_exploited: Optional[bool] = Field(None, description="True if actively exploited in the wild, False if confirmed negative, None if unknown/unreachable")
    vulnerability_name: Optional[str] = None
    date_added: Optional[str] = None
    required_action: Optional[str] = None
    due_date: Optional[str] = None
    known_ransomware_use: Optional[str] = None
    notes: Optional[str] = None
    fetched_at: str
    source_url: str
    is_simulated: bool = False


class AggregatedIntel(BaseModel):
    cve_id: str
    nvd: NvdIntel
    epss: EpssIntel
    cisa_kev: CisaKevIntel
    is_simulated: bool = False
