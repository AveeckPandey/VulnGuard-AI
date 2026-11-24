"""
VulnGuard AI - Pytest Configuration and Shared Fixtures
"""
import sys
import os
import warnings
warnings.filterwarnings("ignore", message=".*Core Pydantic V1 functionality.*")
warnings.filterwarnings("ignore", category=DeprecationWarning)

import pytest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Set test environment variables
os.environ["ENVIRONMENT"] = "testing"
os.environ["DEBUG"] = "true"
os.environ["DATABASE_BACKEND"] = "sqlite"
os.environ["SQLITE_DB_PATH"] = str(PROJECT_ROOT / "test_vulnguard.db")
os.environ["USE_BEDROCK_MOCK"] = "true"

from fastapi.testclient import TestClient
from backend.app.main import app
from backend.services.cache import nvd_cache, epss_cache, cisa_cache
from database.factory import reset_repository, get_repository


@pytest.fixture(autouse=True)
def clean_state():
    """Cleans up cache and test database before each test."""
    nvd_cache.clear()
    epss_cache.clear()
    cisa_cache.clear()
    reset_repository()
    test_db = Path(os.environ["SQLITE_DB_PATH"])
    if test_db.exists():
        try:
            test_db.unlink()
        except Exception:
            pass
    yield
    reset_repository()
    if test_db.exists():
        try:
            test_db.unlink()
        except Exception:
            pass


@pytest.fixture
def client():
    """Provides a synchronous FastAPI TestClient."""
    with TestClient(app) as test_client:
        yield test_client
