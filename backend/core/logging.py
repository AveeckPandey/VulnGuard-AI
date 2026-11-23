"""
VulnGuard AI - Structured Logging Module
Provides production-ready JSON and formatted logging.
"""
import logging
import sys
import json
from datetime import datetime, timezone
from backend.core.config import settings


class JSONFormatter(logging.Formatter):
    """Formats log records as structured JSON for AWS CloudWatch and log aggregators."""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if hasattr(record, "cve_id"):
            log_data["cve_id"] = record.cve_id
        if hasattr(record, "assessment_id"):
            log_data["assessment_id"] = record.assessment_id
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_data)


def setup_logger(name: str = "vulnguard") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        if settings.ENVIRONMENT == "production":
            handler.setFormatter(JSONFormatter())
        else:
            fmt = "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s"
            handler.setFormatter(logging.Formatter(fmt))
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
    return logger


logger = setup_logger("vulnguard")
