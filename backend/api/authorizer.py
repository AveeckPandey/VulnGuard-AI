"""
VulnGuard AI - AWS API Gateway Lambda Request Authorizer
Validates Authorization (Bearer) and X-API-Key headers for protected routes (e.g. /api/analyze).
Returns Simple Response format: {"isAuthorized": bool, "context": {...}}.
"""
import os
import hmac
from typing import Dict, Any
import boto3
from backend.core.logging import logger

_CACHED_KEY = None


def get_expected_key() -> str:
    """Retrieves the expected API key from environment or SSM Parameter Store."""
    global _CACHED_KEY
    if _CACHED_KEY:
        return _CACHED_KEY

    # Check env var first
    key = os.getenv("API_KEY", "").strip()
    if key:
        _CACHED_KEY = key
        return _CACHED_KEY

    # Retrieve from SSM Parameter Store
    param_name = os.getenv("SSM_API_KEY_PARAM", "/vulnguard/api_key")
    region = os.getenv("AWS_REGION", "us-east-1")
    try:
        ssm = boto3.client("ssm", region_name=region)
        resp = ssm.get_parameter(Name=param_name, WithDecryption=True)
        _CACHED_KEY = resp["Parameter"]["Value"].strip()
        return _CACHED_KEY
    except Exception as exc:
        logger.error(f"[Authorizer] Failed to load key from SSM parameter {param_name}: {exc}")
        return ""


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    API Gateway HTTP API Payload Format 2.0 Simple Authorizer handler.
    Fails closed if the server key is missing or client credentials are invalid.
    """
    headers = event.get("headers") or {}

    # Case-insensitive header lookup
    raw_headers = {k.lower(): v for k, v in headers.items()}
    token = raw_headers.get("x-api-key")
    if not token and "authorization" in raw_headers:
        auth_header = raw_headers["authorization"].strip()
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
        else:
            token = auth_header

    expected_key = get_expected_key()

    # Fail closed if server has no configured key or client supplied no token
    if not expected_key or not token:
        logger.warning("[Authorizer] Access denied: missing expected key or request token (failing closed).")
        return {"isAuthorized": False, "context": {"error": "unauthorized"}}

    is_authorized = hmac.compare_digest(token, expected_key)
    if is_authorized:
        return {
            "isAuthorized": True,
            "context": {
                "user": "authenticated-client",
                "auth_method": "api_key"
            }
        }

    logger.warning("[Authorizer] Access denied: token mismatch.")
    return {"isAuthorized": False, "context": {"error": "invalid_credentials"}}
