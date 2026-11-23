"""
VulnGuard AI - Core Configuration Module
Handles environment variables and application settings using Pydantic Settings.
"""
from typing import List, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
import json
import os


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application Settings
    APP_NAME: str = "VulnGuard AI"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    PORT: int = 8000
    HOST: str = "0.0.0.0"

    # CORS
    CORS_ORIGINS: Union[List[str], str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://vulnguard.buildwithaveeck.com",
    ]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    # NIST NVD Threat Intelligence
    NVD_API_KEY: str = ""
    NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_CACHE_TTL_HOURS: int = 12
    NVD_TIMEOUT_SECONDS: float = 15.0

    @property
    def nvd_rate_limit_calls(self) -> int:
        """50 calls per 30s with key, 5 calls per 30s without key."""
        return 50 if self.NVD_API_KEY.strip() else 5

    @property
    def nvd_rate_limit_period(self) -> float:
        """30 seconds window."""
        return 30.0

    # FIRST EPSS Threat Intelligence
    EPSS_BASE_URL: str = "https://api.first.org/data/v1/epss"
    EPSS_CACHE_TTL_HOURS: int = 24
    EPSS_TIMEOUT_SECONDS: float = 10.0

    # CISA KEV Threat Intelligence
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    CISA_CACHE_TTL_HOURS: int = 6
    CISA_TIMEOUT_SECONDS: float = 20.0

    # Database Backend
    DATABASE_BACKEND: str = "sqlite"  # 'sqlite' or 'dynamodb'
    SQLITE_DB_PATH: str = "./vulnguard.db"
    DYNAMODB_TABLE_NAME: str = "VulnGuardAssessments"

    # AWS & Amazon Bedrock
    AWS_REGION: str = "us-east-1"
    BEDROCK_MODEL_ID: str = "amazon.nova-lite-v1:0"
    USE_BEDROCK_MOCK: bool = False
    AWS_BEARER_TOKEN_BEDROCK: str = ""

    # NVIDIA Nemotron AI
    NVIDIA_API_KEY: str = ""
    NVIDIA_MODEL_ID: str = "nvidia/nemotron-3.5-bolt-e4b"


settings = Settings()
