"""
VulnGuard AI - Core Configuration Module
Handles environment variables and application settings using Pydantic Settings.
"""
import warnings
warnings.filterwarnings("ignore", message=".*Core Pydantic V1 functionality.*")

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
        "https://vulnguard-ai.buildwithaveeck.com",
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

    # API Security & Authentication
    REQUIRE_AUTH: bool = False
    API_KEY: str = ""
    SSM_API_KEY_PARAM: str = "/vulnguard/api_key"

    # Amazon Cognito User Pools (Multi-tenant User Identity)
    COGNITO_USER_POOL_ID: str = ""
    COGNITO_APP_CLIENT_ID: str = ""
    COGNITO_DOMAIN: str = ""

    # Machine-to-Machine (M2M) Service Account Authentication
    M2M_API_KEY: str = ""
    SSM_M2M_API_KEY_PARAM: str = "/vulnguard/m2m_api_key"

    @property
    def is_auth_required(self) -> bool:
        """Authentication is required in production or when explicitly configured via REQUIRE_AUTH."""
        return self.REQUIRE_AUTH or self.ENVIRONMENT == "production"

    @property
    def cognito_issuer(self) -> str:
        """Returns standard Cognito OIDC issuer URL."""
        if self.COGNITO_USER_POOL_ID:
            return f"https://cognito-idp.{self.AWS_REGION}.amazonaws.com/{self.COGNITO_USER_POOL_ID}"
        return ""

    def get_api_key(self) -> str:
        """Returns API key from environment variable or AWS SSM Parameter Store (cached)."""
        if self.API_KEY.strip():
            return self.API_KEY.strip()
        
        global _CACHED_SSM_API_KEY
        if _CACHED_SSM_API_KEY:
            return _CACHED_SSM_API_KEY
            
        try:
            import boto3
            ssm = boto3.client("ssm", region_name=self.AWS_REGION)
            response = ssm.get_parameter(Name=self.SSM_API_KEY_PARAM, WithDecryption=True)
            _CACHED_SSM_API_KEY = response["Parameter"]["Value"].strip()
            return _CACHED_SSM_API_KEY
        except Exception:
            return ""

    def get_m2m_api_key(self) -> str:
        """Returns M2M service key from environment or AWS SSM Parameter Store."""
        if self.M2M_API_KEY.strip():
            return self.M2M_API_KEY.strip()
        try:
            import boto3
            ssm = boto3.client("ssm", region_name=self.AWS_REGION)
            response = ssm.get_parameter(Name=self.SSM_M2M_API_KEY_PARAM, WithDecryption=True)
            return response["Parameter"]["Value"].strip()
        except Exception:
            return ""

    # NIST NVD Threat Intelligence
    NVD_API_KEY: str = ""
    SSM_NVD_API_KEY_PARAM: str = "/vulnguard/nvd_api_key"
    NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_CACHE_TTL_HOURS: int = 12
    NVD_TIMEOUT_SECONDS: float = 15.0

    def get_nvd_api_key(self) -> str:
        """Returns the NVD API key from environment variable or AWS SSM Parameter Store (cached)."""
        if self.NVD_API_KEY.strip():
            return self.NVD_API_KEY.strip()
        
        global _CACHED_SSM_NVD_KEY
        if _CACHED_SSM_NVD_KEY:
            return _CACHED_SSM_NVD_KEY
            
        try:
            import boto3
            ssm = boto3.client("ssm", region_name=self.AWS_REGION)
            response = ssm.get_parameter(Name=self.SSM_NVD_API_KEY_PARAM, WithDecryption=True)
            _CACHED_SSM_NVD_KEY = response["Parameter"]["Value"].strip()
            return _CACHED_SSM_NVD_KEY
        except Exception:
            return ""

    @property
    def nvd_rate_limit_calls(self) -> int:
        """50 calls per 30s with key, 5 calls per 30s without key."""
        return 50 if self.get_nvd_api_key().strip() else 5

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
    SSM_NVIDIA_API_KEY_PARAM: str = "/vulnguard/nvidia_api_key"

    def get_nvidia_api_key(self) -> str:
        """Returns the NVIDIA API key from environment variable or AWS SSM Parameter Store (cached)."""
        if self.NVIDIA_API_KEY.strip():
            return self.NVIDIA_API_KEY.strip()
        
        # Check global module-level cache
        global _CACHED_SSM_NVIDIA_KEY
        if _CACHED_SSM_NVIDIA_KEY:
            return _CACHED_SSM_NVIDIA_KEY
            
        try:
            import boto3
            ssm = boto3.client("ssm", region_name=self.AWS_REGION)
            response = ssm.get_parameter(Name=self.SSM_NVIDIA_API_KEY_PARAM, WithDecryption=True)
            _CACHED_SSM_NVIDIA_KEY = response["Parameter"]["Value"].strip()
            return _CACHED_SSM_NVIDIA_KEY
        except Exception:
            return ""


_CACHED_SSM_NVIDIA_KEY: str = ""
_CACHED_SSM_NVD_KEY: str = ""
_CACHED_SSM_API_KEY: str = ""

settings = Settings()
