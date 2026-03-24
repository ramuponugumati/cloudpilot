"""Local JSON-based persistent memory — fallback when AgentCore MemoryClient is unavailable.
Stores scan history, remediation log, and conversation context at ~/.cloudpilot/memory.json."""
import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ScanRecord:
    skill: str
    timestamp: str
    finding_count: int
    top_findings: list
    total_impact: float


@dataclass
class RemediationRecord:
    resource_id: str
    action: str
    success: bool
    timestamp: str
    region: str


class LocalMemoryStore:
    """JSON file persistent memory at ~/.cloudpilot/memory.json"""
    PATH = Path.home() / ".cloudpilot" / "memory.json"
    MAX_SCANS = 50
    MAX_REMEDIATIONS = 100

    def _load(self) -> dict:
        try:
            if self.PATH.exists():
                return json.loads(self.PATH.read_text())
        except Exception as e:
            logger.warning(f"Failed to load memory: {e}")
        return {"scans": [], "remediations": [], "sessions": []}

    def _save(self, data: dict):
        try:
            self.PATH.parent.mkdir(parents=True, exist_ok=True)
            self.PATH.write_text(json.dumps(data, indent=2, default=str))
        except Exception as e:
            logger.warning(f"Failed to save memory: {e}")

    def append_scan(self, record: ScanRecord):
        data = self._load()
        data["scans"].append(asdict(record))
        data["scans"] = data["scans"][-self.MAX_SCANS:]
        self._save(data)

    def append_remediation(self, record: RemediationRecord):
        data = self._load()
        data["remediations"].append(asdict(record))
        data["remediations"] = data["remediations"][-self.MAX_REMEDIATIONS:]
        self._save(data)

    def append_session_summary(self, summary: dict):
        data = self._load()
        data["sessions"].append(summary)
        data["sessions"] = data["sessions"][-20:]
        self._save(data)

    def get_scans(self, limit: int = 10) -> list:
        return self._load().get("scans", [])[-limit:]

    def get_remediations(self, limit: int = 20) -> list:
        return self._load().get("remediations", [])[-limit:]

    def build_context_prompt(self) -> str:
        """Build memory context string for system prompt injection."""
        data = self._load()
        lines = []
        scans = data.get("scans", [])[-5:]
        if scans:
            lines.append("Recent scans:")
            for s in scans:
                lines.append(f"  - {s['skill']}: {s['finding_count']} findings, "
                             f"${s['total_impact']:.2f}/mo impact ({s['timestamp'][:16]})")
        remediations = data.get("remediations", [])[-10:]
        if remediations:
            lines.append("Recent remediations:")
            for r in remediations:
                status = "✅" if r["success"] else "❌"
                lines.append(f"  - {status} {r['action']} on {r['resource_id']} in {r['region']} ({r['timestamp'][:16]})")
        return "\n".join(lines) if lines else ""
