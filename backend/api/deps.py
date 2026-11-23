"""
VulnGuard AI - API Dependencies
Dependency injection for FastAPI endpoints.
"""
from fastapi import Depends
from database.interface import AssessmentRepository
from database.factory import get_repository


def get_db_repo() -> AssessmentRepository:
    """Dependency provider for database repository."""
    return get_repository()
