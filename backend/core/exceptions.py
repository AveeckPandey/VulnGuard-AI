"""
VulnGuard AI - Domain Exceptions
Custom exception hierarchy for clean error handling across API and agents.
"""


class VulnGuardException(Exception):
    """Base exception for all VulnGuard domain errors."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class InvalidCVEFormatError(VulnGuardException):
    """Raised when an invalid CVE ID format is passed (must be CVE-YYYY-NNNN+)."""
    pass


class ThreatIntelFetchError(VulnGuardException):
    """Raised when an external threat intelligence provider fails to respond."""
    pass


class RateLimitExceededError(VulnGuardException):
    """Raised when upstream API (e.g. NVD) rate limit is exhausted."""
    pass


class IntelligenceNotFoundError(VulnGuardException):
    """Raised when a CVE is not found in NIST NVD or other primary sources."""
    pass


class ModelInferenceError(VulnGuardException):
    """Raised when Amazon Bedrock inference encounters an unrecoverable failure."""
    pass


class DatabaseError(VulnGuardException):
    """Raised when repository storage encounters an issue."""
    pass


class AssessmentNotFoundError(VulnGuardException):
    """Raised when an assessment ID is not found in the database."""
    pass
