"""
VulnGuard AI - Database Factory
Instantiates the designated repository backend based on explicit DATABASE_BACKEND configuration.
Never silently falls back between backends.
"""
from typing import Optional
from backend.core.config import settings
from backend.core.logging import logger
from backend.core.exceptions import DatabaseError
from database.interface import AssessmentRepository
from database.sqlite_repo import SQLiteAssessmentRepository


_repo_instance: Optional[AssessmentRepository] = None


def get_repository() -> AssessmentRepository:
    """Returns the singleton repository instance based on configuration."""
    global _repo_instance
    if _repo_instance is None:
        backend = settings.DATABASE_BACKEND.lower().strip()
        if backend == "sqlite":
            logger.info("[Database Factory] Selected backend: SQLite")
            _repo_instance = SQLiteAssessmentRepository()
        elif backend == "dynamodb":
            logger.info("[Database Factory] Selected backend: Amazon DynamoDB")
            from database.dynamodb_repo import DynamoDBAssessmentRepository
            _repo_instance = DynamoDBAssessmentRepository()
        else:
            raise DatabaseError(f"Unsupported DATABASE_BACKEND: '{settings.DATABASE_BACKEND}'. Must be 'sqlite' or 'dynamodb'.")
    return _repo_instance


def reset_repository() -> None:
    """Resets the repository singleton (used during tests)."""
    global _repo_instance
    _repo_instance = None
