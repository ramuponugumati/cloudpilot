"""Scan job manager — in-memory job store for tracking background scans."""
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any


class ScanJobStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ScanJob:
    id: str
    status: ScanJobStatus
    skill_names: list[str]
    created_at: str
    completed_at: Optional[str] = None
    results: Optional[list] = None
    org_results: Optional[dict] = None
    error: Optional[str] = None


class JobStore:
    """In-memory scan job storage."""

    def __init__(self):
        self._jobs: dict[str, ScanJob] = {}

    def create(self, skill_names: list[str]) -> ScanJob:
        job_id = str(uuid.uuid4())
        job = ScanJob(
            id=job_id,
            status=ScanJobStatus.PENDING,
            skill_names=skill_names,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._jobs[job_id] = job
        return job

    def get(self, job_id: str) -> Optional[ScanJob]:
        return self._jobs.get(job_id)

    def update(self, job_id: str, **kwargs) -> None:
        job = self._jobs.get(job_id)
        if not job:
            return
        for key, value in kwargs.items():
            if hasattr(job, key):
                setattr(job, key, value)
        if kwargs.get("status") in (ScanJobStatus.COMPLETED, ScanJobStatus.FAILED):
            job.completed_at = datetime.now(timezone.utc).isoformat()

    def list_all(self) -> list[ScanJob]:
        return sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)
