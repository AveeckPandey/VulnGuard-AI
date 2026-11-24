"""
VulnGuard AI - Database Repository Interface
Abstract base class defining persistence operations for vulnerability assessments.
Supports both primary method names and backward-compatible aliases.
"""
from abc import ABC, abstractmethod
from typing import Optional, List, Tuple, Any
from backend.schemas.assessment import AssessmentResponse, AssessmentSummary


class AssessmentRepository(ABC):
    """Abstract interface for multi-tenant, user-isolated assessment persistence."""

    @abstractmethod
    def create_assessment(
        self, assessment: AssessmentResponse, owner_user_id: Optional[str] = None
    ) -> AssessmentResponse:
        """Stores a newly completed assessment scoped to the owner_user_id."""
        pass

    @abstractmethod
    def get_assessment_by_id(
        self, assessment_id: str, owner_user_id: Optional[str] = None
    ) -> Optional[AssessmentResponse]:
        """
        Retrieves an assessment by primary key, strictly validating ownership.
        Returns None if record does not belong to owner_user_id.
        """
        pass

    @abstractmethod
    def list_recent_assessments(
        self, owner_user_id: str, limit: int = 20, last_evaluated_key: Optional[str] = None
    ) -> Tuple[List[AssessmentSummary], Optional[str]]:
        """Queries recent assessments for a specific user using UserHistoryIndex."""
        pass

    @abstractmethod
    def list_assessments_by_cve(
        self, cve_id: str, owner_user_id: str, limit: int = 20, last_evaluated_key: Optional[str] = None
    ) -> List[AssessmentSummary]:
        """Queries assessments for a specific CVE for a specific user using UserCveHistoryIndex."""
        pass

    # Owner-aware convenience aliases
    def save(
        self, assessment: AssessmentResponse, owner_user_id: Optional[str] = None
    ) -> AssessmentResponse:
        return self.create_assessment(assessment, owner_user_id=owner_user_id)

    def get_by_id(
        self, assessment_id: str, owner_user_id: Optional[str] = None
    ) -> Optional[AssessmentResponse]:
        return self.get_assessment_by_id(assessment_id, owner_user_id=owner_user_id)

    def list_recent(
        self, owner_user_id: str, limit: int = 20, last_evaluated_key: Optional[str] = None
    ) -> List[AssessmentSummary]:
        items, _ = self.list_recent_assessments(owner_user_id=owner_user_id, limit=limit, last_evaluated_key=last_evaluated_key)
        return items
