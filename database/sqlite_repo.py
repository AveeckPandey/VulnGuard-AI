"""
VulnGuard AI - SQLite Local Database Repository
Provides zero-dependency local storage for assessments and investigation history.
Implements the AssessmentRepository interface with full parity to DynamoDB operations.
"""
import sqlite3
import json
import os
import threading
from typing import Optional, List, Tuple
from backend.core.config import settings
from backend.core.logging import logger
from backend.core.exceptions import DatabaseError
from backend.schemas.assessment import AssessmentResponse, AssessmentSummary
from backend.schemas.risk import AssetCriticality, InternetExposure, PriorityLevel
from database.interface import AssessmentRepository


class SQLiteAssessmentRepository(AssessmentRepository):
    """Local development database using standard library SQLite."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or settings.SQLITE_DB_PATH
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initializes tables and indexes, applying schema migrations if needed."""
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS assessments (
                        id TEXT PRIMARY KEY,
                        cve_id TEXT NOT NULL,
                        owner_user_id TEXT,
                        priority_level TEXT NOT NULL,
                        total_score REAL NOT NULL,
                        cvss_base_score REAL,
                        epss_probability REAL,
                        is_known_exploited INTEGER,
                        asset_criticality TEXT NOT NULL,
                        internet_exposure TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        full_data TEXT NOT NULL
                    )
                """)
                # Automatic column migration if table was created in an earlier schema version
                cursor = conn.execute("PRAGMA table_info(assessments)")
                cols = [c[1] for c in cursor.fetchall()]
                if "owner_user_id" not in cols:
                    conn.execute("ALTER TABLE assessments ADD COLUMN owner_user_id TEXT")

                conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_id ON assessments(cve_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON assessments(created_at DESC)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_owner_created ON assessments(owner_user_id, created_at DESC)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_owner_cve ON assessments(owner_user_id, cve_id, created_at DESC)")
                conn.commit()
        logger.info(f"[Database] Initialized SQLite repository at {self.db_path}")

    def create_assessment(
        self, assessment: AssessmentResponse, owner_user_id: Optional[str] = None
    ) -> AssessmentResponse:
        effective_owner = owner_user_id if owner_user_id is not None else assessment.owner_user_id
        assessment.owner_user_id = effective_owner
        full_json = assessment.model_dump_json()
        cvss = assessment.intelligence.nvd.cvss_base_score
        epss = assessment.intelligence.epss.epss_probability
        kev_val = assessment.intelligence.cisa_kev.is_known_exploited
        is_kev = 1 if kev_val is True else (0 if kev_val is False else None)

        with self._lock:
            with self._get_connection() as conn:
                # Check for existing record
                cursor = conn.execute("SELECT id FROM assessments WHERE id = ?", (assessment.id,))
                if cursor.fetchone():
                    raise DatabaseError(f"Assessment '{assessment.id}' already exists in SQLite.")

                conn.execute("""
                    INSERT INTO assessments (
                        id, cve_id, owner_user_id, priority_level, total_score,
                        cvss_base_score, epss_probability, is_known_exploited,
                        asset_criticality, internet_exposure, created_at, full_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    assessment.id,
                    assessment.cve_id,
                    effective_owner,
                    assessment.risk_score.priority_level.value,
                    assessment.risk_score.total_score,
                    cvss,
                    epss,
                    is_kev,
                    assessment.asset_criticality.value,
                    assessment.internet_exposure.value,
                    assessment.created_at,
                    full_json
                ))
                conn.commit()

        logger.info(f"[Database] Persisted assessment {assessment.id} for {assessment.cve_id} (owner={effective_owner}, SQLite)")
        return assessment

    def get_assessment_by_id(
        self, assessment_id: str, owner_user_id: Optional[str] = None
    ) -> Optional[AssessmentResponse]:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT full_data, owner_user_id FROM assessments WHERE id = ?", (assessment_id,))
                row = cursor.fetchone()
                if not row:
                    return None

                # Strict ownership check
                item_owner = row["owner_user_id"]
                if owner_user_id is not None:
                    if not item_owner or item_owner != owner_user_id:
                        logger.warning(
                            f"[Security SQLite] Access denied: User '{owner_user_id}' requested assessment '{assessment_id}' owned by '{item_owner}'"
                        )
                        return None

                data = json.loads(row["full_data"])
                if item_owner and not data.get("owner_user_id"):
                    data["owner_user_id"] = item_owner
                return AssessmentResponse.model_validate(data)

    def list_recent_assessments(
        self, owner_user_id: str, limit: int = 20, last_evaluated_key: Optional[str] = None
    ) -> Tuple[List[AssessmentSummary], Optional[str]]:
        offset = int(last_evaluated_key) if last_evaluated_key and last_evaluated_key.isdigit() else 0
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute("""
                    SELECT id, cve_id, owner_user_id, priority_level, total_score,
                           cvss_base_score, epss_probability, is_known_exploited,
                           asset_criticality, internet_exposure, created_at
                    FROM assessments
                    WHERE owner_user_id = ?
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?
                """, (owner_user_id, limit, offset))
                rows = cursor.fetchall()
                items = self._rows_to_summaries(rows)
                next_cursor = str(offset + limit) if len(items) == limit else None
                return items, next_cursor

    def list_assessments_by_cve(
        self, cve_id: str, owner_user_id: str, limit: int = 20, last_evaluated_key: Optional[str] = None
    ) -> List[AssessmentSummary]:
        clean_cve = cve_id.strip().upper()
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute("""
                    SELECT id, cve_id, owner_user_id, priority_level, total_score,
                           cvss_base_score, epss_probability, is_known_exploited,
                           asset_criticality, internet_exposure, created_at
                    FROM assessments
                    WHERE cve_id = ? AND owner_user_id = ?
                    ORDER BY created_at DESC
                    LIMIT ?
                """, (clean_cve, owner_user_id, limit))
                rows = cursor.fetchall()
                return self._rows_to_summaries(rows)

    def _rows_to_summaries(self, rows: list) -> List[AssessmentSummary]:
        summaries = []
        for row in rows:
            is_kev_val = row["is_known_exploited"]
            is_kev = bool(is_kev_val) if is_kev_val is not None else None
            summaries.append(AssessmentSummary(
                id=row["id"],
                cve_id=row["cve_id"],
                owner_user_id=row["owner_user_id"],
                priority_level=PriorityLevel(row["priority_level"]),
                total_score=row["total_score"],
                cvss_base_score=row["cvss_base_score"],
                epss_probability=row["epss_probability"],
                is_known_exploited=is_kev,
                asset_criticality=AssetCriticality(row["asset_criticality"]),
                internet_exposure=InternetExposure(row["internet_exposure"]),
                created_at=row["created_at"],
            ))
        return summaries

    # Backward-compatible convenience aliases
    def save(
        self, assessment: AssessmentResponse, owner_user_id: Optional[str] = None
    ) -> AssessmentResponse:
        return self.create_assessment(assessment, owner_user_id=owner_user_id)

    def save_assessment(
        self, assessment: AssessmentResponse, owner_user_id: Optional[str] = None
    ) -> AssessmentResponse:
        return self.save(assessment, owner_user_id=owner_user_id)

    def get_by_id(
        self, assessment_id: str, owner_user_id: Optional[str] = None
    ) -> Optional[AssessmentResponse]:
        return self.get_assessment_by_id(assessment_id, owner_user_id=owner_user_id)

    # list_recent is inherited and requires an owner_user_id.
