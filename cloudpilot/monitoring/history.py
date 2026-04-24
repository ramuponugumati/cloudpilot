"""Scan History Store — persists scan results to JSON files for trend analysis."""
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_HISTORY_DIR = os.environ.get("CLOUDPILOT_HISTORY_DIR", ".cloudpilot/history")


@dataclass
class ScanRecord:
    """A single scan execution record."""
    id: str
    timestamp: str
    trigger: str  # "scheduled" | "manual" | "api"
    suite: str  # suite name or "custom"
    skills_run: list[str] = field(default_factory=list)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    total_impact: float = 0.0
    duration_seconds: float = 0.0
    findings: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    account_id: str = ""
    regions: list[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)

    def summary_dict(self):
        """Compact summary without full findings (for listing)."""
        d = asdict(self)
        d.pop("findings", None)
        return d


class ScanHistoryStore:
    """File-based scan history with JSON persistence."""

    def __init__(self, history_dir: str = DEFAULT_HISTORY_DIR):
        self._dir = Path(history_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._index_file = self._dir / "index.json"
        self._index: list[dict] = self._load_index()

    def _load_index(self) -> list[dict]:
        if self._index_file.exists():
            try:
                return json.loads(self._index_file.read_text())
            except (json.JSONDecodeError, OSError):
                logger.warning("Corrupted history index, starting fresh")
        return []

    def _save_index(self):
        self._index_file.write_text(json.dumps(self._index, indent=2, default=str))

    def record_scan(self, suite: str, skills_run: list[str], findings: list[dict],
                    duration: float, trigger: str = "manual",
                    account_id: str = "", regions: list[str] = None) -> ScanRecord:
        """Record a completed scan and persist to disk."""
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        total_impact = 0.0
        for f in findings:
            sev = f.get("severity", "info")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            total_impact += f.get("monthly_impact", 0)

        record = ScanRecord(
            id=str(uuid.uuid4())[:8],
            timestamp=datetime.now(timezone.utc).isoformat(),
            trigger=trigger,
            suite=suite,
            skills_run=skills_run,
            total_findings=len(findings),
            critical_count=sev_counts["critical"],
            high_count=sev_counts["high"],
            medium_count=sev_counts["medium"],
            low_count=sev_counts["low"],
            info_count=sev_counts["info"],
            total_impact=round(total_impact, 2),
            duration_seconds=round(duration, 1),
            findings=findings[:100],  # Cap stored findings
            errors=[],
            account_id=account_id,
            regions=regions or [],
        )

        # Save full record
        record_file = self._dir / f"{record.id}.json"
        record_file.write_text(json.dumps(record.to_dict(), indent=2, default=str))

        # Update index
        self._index.insert(0, record.summary_dict())
        # Keep last 500 records in index
        self._index = self._index[:500]
        self._save_index()

        logger.info(f"Recorded scan {record.id}: {record.suite} — "
                    f"{record.total_findings} findings, {record.critical_count} critical")
        return record

    def get_record(self, record_id: str) -> Optional[ScanRecord]:
        """Load a full scan record by ID."""
        record_file = self._dir / f"{record_id}.json"
        if not record_file.exists():
            return None
        try:
            data = json.loads(record_file.read_text())
            return ScanRecord(**data)
        except Exception as e:
            logger.warning(f"Failed to load record {record_id}: {e}")
            return None

    def list_records(self, limit: int = 50, suite: str = None) -> list[dict]:
        """List scan summaries, optionally filtered by suite."""
        records = self._index
        if suite:
            records = [r for r in records if r.get("suite") == suite]
        return records[:limit]

    def get_trends(self, days: int = 30, suite: str = None) -> dict:
        """Compute trend data for charting — findings over time."""
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        records = [r for r in self._index if r.get("timestamp", "") >= cutoff]
        if suite:
            records = [r for r in records if r.get("suite") == suite]

        # Reverse to chronological order
        records = list(reversed(records))

        return {
            "period_days": days,
            "scan_count": len(records),
            "timestamps": [r["timestamp"] for r in records],
            "total_findings": [r.get("total_findings", 0) for r in records],
            "critical_counts": [r.get("critical_count", 0) for r in records],
            "high_counts": [r.get("high_count", 0) for r in records],
            "total_impacts": [r.get("total_impact", 0) for r in records],
            "suites": [r.get("suite", "") for r in records],
        }

    def clear(self):
        """Clear all history (for testing)."""
        import shutil
        if self._dir.exists():
            shutil.rmtree(self._dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._index = []
        self._save_index()
