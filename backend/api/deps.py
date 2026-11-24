"""
VulnGuard AI - API Dependencies
Dependency injection for FastAPI endpoints.
"""
import hmac
from typing import Optional, Dict, Any
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from database.interface import AssessmentRepository
from database.factory import get_repository
from backend.core.config import settings
from backend.core.logging import logger

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


def get_db_repo() -> AssessmentRepository:
    """Dependency provider for database repository."""
    return get_repository()


async def verify_analysis_access(
    api_key: Optional[str] = Security(api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> Dict[str, Any]:
    """
    Authentication dependency for paid AI & assessment generation endpoints (/api/analyze).
    Protects against anonymous denial-of-wallet, quota depletion, and unauthorized execution.
    Fails closed when production credentials are missing.
    """
    configured_key = settings.get_api_key().strip()
    token = api_key or (bearer.credentials if bearer else None)

    # Enforce strict authentication in production or when explicitly required
    if settings.is_auth_required:
        # Fail closed: never allow anonymous requests or accept arbitrary tokens if key cannot be loaded
        if not configured_key:
            logger.critical("[Security] Authentication required but server API key is unconfigured in SSM/environment. Failing closed.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authentication service misconfigured: missing server credential.",
            )

        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required for analysis endpoint. Provide a valid 'X-API-Key' or 'Authorization: Bearer <token>' header.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(token, configured_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key or bearer credentials.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return {"authenticated": True, "token": token, "user": "authenticated-client"}

    # Development / local testing fallback (when REQUIRE_AUTH is False and ENVIRONMENT != "production")
    if token and configured_key:
        if not hmac.compare_digest(token, configured_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key or bearer credentials.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return {"authenticated": True, "token": token, "user": "dev-client"}

    return {"authenticated": bool(token), "token": token or None, "user": "dev-anonymous"}


