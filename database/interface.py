"""
VulnGuard AI - Database Repository Interface
Abstract base class defining persistence operations for vulnerability assessments.
Supports both primary method names and backward-compatible aliases.
"""
from abc import ABC, abstractmethod
from typing import Optional, List, Tuple, Any
from backend.schemas.assessment import AssessmentResponse, AssessmentSummary


class AssessmentRepository(ABC):
    """Abstract interface for assessment persistence."""

    @abstractmethod
    def create_assessment(self, assessment: AssessmentResponse) -> AssessmentResponse:
        """Stores a newly completed assessment using conditional write to prevent overwriting."""
        pass

    @abstractmethod
    def get_assessment_by_id(self, assessment_id: str) -> Optional[AssessmentResponse]:
        """Retrieves an assessment by its primary partition key (assessment_id)."""
        pass

    @abstractmethod
    def list_recent_assessments(
        self, limit: int = 20, last_evaluated_key: Optional[str] = None
    ) -> List[AssessmentSummary]:
        """Queries recent assessments chronologically using the History GSI."""
        pass

    @abstractmethod
    def list_assessments_by_cve(
        self, cve_id: str, limit: int = 20, last_evaluated_key: Optional[str] = None
    ) -> List[AssessmentSummary]:
        """Queries assessments for a specific CVE chronologically using the CVE History GSI."""
        pass

    # Backward-compatible convenience aliases
    def save(self, assessment: AssessmentResponse) -> AssessmentResponse:
        return self.create_assessment(assessment)

    def get_by_id(self, assessment_id: str) -> Optional[AssessmentResponse]:
        return self.get_assessment_by_id(assessment_id)

    def list_recent(self, limit: int = 20) -> List[AssessmentSummary]:
        return self.list_recent_assessments(limit=limit)
