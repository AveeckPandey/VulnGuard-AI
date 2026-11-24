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

"""
VulnGuard AI - API Dependencies & Multi-Tenant Identity Verification
Implements strict Cognito JWT validation, M2M service authentication, and user workspace isolation.
"""
import hmac
import time
from typing import Optional, Dict, Any
from fastapi import Depends, HTTPException, Security, Request, status
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
import jwt
from jwt import PyJWKClient, PyJWTError

from database.interface import AssessmentRepository
from database.factory import get_repository
from backend.core.config import settings
from backend.core.logging import logger

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
service_key_header = APIKeyHeader(name="X-Service-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)

# Cached PyJWKClient instance for Cognito User Pools
_CACHED_JWKS_CLIENT: Optional[PyJWKClient] = None
_CACHED_JWKS_ISSUER: Optional[str] = None


def get_jwks_client() -> Optional[PyJWKClient]:
    """Returns or initializes a cached PyJWKClient for the configured Cognito User Pool."""
    global _CACHED_JWKS_CLIENT, _CACHED_JWKS_ISSUER
    issuer = settings.cognito_issuer
    if not issuer:
        return None
    if _CACHED_JWKS_CLIENT is None or _CACHED_JWKS_ISSUER != issuer:
        jwks_url = f"{issuer}/.well-known/jwks.json"
        _CACHED_JWKS_CLIENT = PyJWKClient(jwks_url, cache_keys=True, lifespan=3600)
        _CACHED_JWKS_ISSUER = issuer
    return _CACHED_JWKS_CLIENT


def get_db_repo() -> AssessmentRepository:
    """Dependency provider for database repository."""
    return get_repository()


async def get_current_user(
    request: Request,
    bearer: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    api_key: Optional[str] = Security(api_key_header),
    service_key: Optional[str] = Security(service_key_header),
) -> Dict[str, Any]:
    """
    Validates user or service identity for all protected endpoints.
    Enforces that user workspace reads and writes are derived strictly from verified credentials.

    Priority:
    1. Edge JWT Authorizer Claims (API Gateway HTTP API v2 requestContext)
    2. Verified Cognito User Pool Bearer Token (Authorization: Bearer <JWT>)
    3. Authenticated M2M Service Account (X-Service-Key / X-API-Key matching M2M credential)
    4. Development/Testing mock token handlers
    """
    # ---------------------------------------------------------
    # 1. Edge API Gateway JWT Authorizer Context
    # ---------------------------------------------------------
    # When deployed behind AWS API Gateway HTTP API v2 with a JWT Authorizer,
    # API Gateway validates the token signature/claims at the perimeter and populates requestContext.
    aws_event = request.scope.get("aws.event", {})
    if isinstance(aws_event, dict):
        jwt_authorizer = aws_event.get("requestContext", {}).get("authorizer", {}).get("jwt", {})
        claims = jwt_authorizer.get("claims", {})
        if claims and claims.get("sub"):
            sub = claims["sub"].strip()
            return {
                "sub": sub,
                "client_type": "cognito_user",
                "email": claims.get("email"),
                "username": claims.get("cognito:username") or claims.get("username"),
                "is_service": False,
            }

    # ---------------------------------------------------------
    # 2. Machine-to-Machine (M2M) Service Account Authentication
    # ---------------------------------------------------------
    active_m2m_key = service_key or api_key
    configured_m2m = settings.get_m2m_api_key().strip() or settings.get_api_key().strip()

    # Fail-closed check if strict auth is required but server has no credential configured
    if settings.is_auth_required and not settings.COGNITO_USER_POOL_ID and not configured_m2m:
        logger.critical("[Security] Strict authentication required but neither Cognito nor M2M credentials configured. Failing closed.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service misconfigured: missing server credential.",
        )

    if active_m2m_key:
        if configured_m2m and hmac.compare_digest(active_m2m_key.strip(), configured_m2m):
            # Assigned immutable service partition ID; caller cannot select or spoof owner
            return {
                "sub": "m2m:pipeline-runner",
                "client_type": "service_account",
                "is_service": True,
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key or service credential.",
                headers={"WWW-Authenticate": "ApiKey"},
            )

    # ---------------------------------------------------------
    # 3. Cognito User Pools Bearer Token (JWT)
    # ---------------------------------------------------------
    token = bearer.credentials.strip() if bearer else None
    if token:
        # Check for live Cognito verification if User Pool is configured
        issuer = settings.cognito_issuer
        jwks_client = get_jwks_client()

        if issuer and jwks_client:
            try:
                signing_key = jwks_client.get_signing_key_from_jwt(token)
                claims = jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=["RS256"],
                    issuer=issuer,
                    options={
                        "verify_exp": True,
                        "verify_iss": True,
                        "verify_signature": True,
                    }
                )

                # Validate token_use and client_id
                token_use = claims.get("token_use")
                if token_use not in ("access", "id"):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid token: 'token_use' must be 'access' or 'id'.",
                        headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
                    )

                client_id = claims.get("client_id") if token_use == "access" else claims.get("aud")
                if settings.COGNITO_APP_CLIENT_ID and client_id != settings.COGNITO_APP_CLIENT_ID:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid token: intended audience / client_id mismatch.",
                        headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
                    )

                sub = claims.get("sub")
                if not sub:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid token: missing subject claim.",
                        headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
                    )

                return {
                    "sub": sub.strip(),
                    "client_type": "cognito_user",
                    "email": claims.get("email"),
                    "username": claims.get("cognito:username") or claims.get("username"),
                    "is_service": False,
                }
            except (PyJWTError, Exception) as jwt_err:
                logger.warning(f"[Auth] Cognito token validation failed: {jwt_err}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Invalid Cognito authentication token: {str(jwt_err)}",
                    headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
                )

        # In testing or local development without live Cognito reachable,
        # support standard simulated test tokens and HS256 / unverified test tokens
        if settings.ENVIRONMENT in ("testing", "development"):
            # Check for simulated test tokens
            try:
                unverified = jwt.decode(token, options={"verify_signature": False})
                if unverified.get("sub"):
                    # Check expiration if present
                    exp = unverified.get("exp")
                    if exp and exp < time.time():
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Authentication token has expired.",
                            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
                        )
                    # Check issuer if present
                    if issuer and unverified.get("iss") and unverified.get("iss") != issuer:
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Token issuer does not match configured Cognito user pool.",
                            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
                        )
                    return {
                        "sub": unverified["sub"].strip(),
                        "client_type": "test_user",
                        "is_service": False,
                    }
            except PyJWTError:
                pass

            # Support direct demo analyst personas and test bearer identifiers
            if token.startswith("user-a"):
                return {
                    "sub": "usr-a-edge-analyst",
                    "email": "analyst-a@vulnguard.io",
                    "username": "Analyst A (Edge Ops)",
                    "client_type": "demo_analyst",
                    "is_service": False,
                }
            if token.startswith("user-b"):
                return {
                    "sub": "usr-b-core-analyst",
                    "email": "analyst-b@vulnguard.io",
                    "username": "Analyst B (Core Sec)",
                    "client_type": "demo_analyst",
                    "is_service": False,
                }

            if token.startswith("test-") or token.startswith("user-"):
                sub_name = token.replace("-token", "").strip()
                return {
                    "sub": f"sub:{sub_name}",
                    "client_type": "test_user",
                    "is_service": False,
                }

            # Backward-compatible API key bearer matching
            server_key = settings.get_api_key().strip()
            if server_key and hmac.compare_digest(token, server_key):
                return {
                    "sub": "m2m:pipeline-runner",
                    "client_type": "service_account",
                    "is_service": True,
                }

        # If a bearer token was explicitly provided but could not be validated, reject with 401
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )

    # ---------------------------------------------------------
    # 4. Unauthenticated / Rejection
    # ---------------------------------------------------------
    if settings.is_auth_required:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide a valid Cognito 'Authorization: Bearer <token>' or service key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Anonymous development fallback (non-production and REQUIRE_AUTH=False)
    return {
        "sub": "dev-anonymous-user",
        "client_type": "dev_anonymous",
        "is_service": False,
    }


# Backward-compatible alias
async def verify_analysis_access(
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Alias for get_current_user maintaining backwards compatibility across routes."""
    return user


