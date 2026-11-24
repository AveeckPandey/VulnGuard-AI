"""
VulnGuard AI - FastAPI Application Entry Point
Configures routes, CORS middleware, exception handlers, and AWS Lambda Mangum handler.
"""
import warnings
warnings.filterwarnings("ignore", message=".*Core Pydantic V1 functionality.*")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="starlette")

from datetime import datetime, timezone
from contextlib import asynccontextmanager
from functools import lru_cache
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
from mangum import Mangum

from backend.core.config import settings
from backend.core.logging import logger
from backend.core.exceptions import VulnGuardException
from backend.api.routes import router as api_router
from database.factory import get_repository


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize services and warm up caches if needed."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} (Env: {settings.ENVIRONMENT})")
    # Initialize repository schema
    try:
        get_repository()
    except Exception as e:
        logger.warning(f"Database initialization warning: {e}")
    yield
    logger.info("Shutting down VulnGuard AI application.")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI-Powered CVE Intelligence & Deterministic Vulnerability Prioritization Platform",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# CORS Middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


# Global Exception Handlers
@app.exception_handler(VulnGuardException)
async def domain_exception_handler(request: Request, exc: VulnGuardException):
    logger.warning(f"Domain exception on {request.url.path}: {exc.message}")
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": type(exc).__name__,
            "message": exc.message,
            "details": exc.details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning(f"Validation failure on {request.url.path}: {exc.errors()}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "ValidationError",
            "message": "Input validation failed. Please check field formats.",
            "details": jsonable_encoder(exc.errors()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "InternalServerError",
            "message": "An unexpected error occurred while processing the request.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


# Health check endpoint
@app.get(
    "/health",
    tags=["System"],
    summary="Service Health Check",
    description="Returns service availability, active environment, and configured database backend."
)
async def health_check():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "environment": settings.ENVIRONMENT,
        "version": settings.APP_VERSION,
        "database_backend": settings.DATABASE_BACKEND,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# Include API routes
app.include_router(api_router)

# Construct the Lambda adapter only inside Lambda. Eager construction creates an
# asyncio event loop on import and can block the local Windows test runner.
@lru_cache(maxsize=1)
def _lambda_adapter() -> Mangum:
    return Mangum(app, lifespan="off")


def handler(event, context):
    return _lambda_adapter()(event, context)
