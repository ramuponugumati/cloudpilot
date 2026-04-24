"""Scan Scheduler — runs suites on configurable cron schedules with history and notifications."""
import logging
import time
import threading
from typing import Optional

from cloudpilot.core import SkillRegistry
from cloudpilot.aws_client import get_regions, get_account_id
from cloudpilot.monitoring.history import ScanHistoryStore
from cloudpilot.monitoring.notifications import notify_scan_complete, NotificationConfig
import cloudpilot.skills  # auto-register

logger = logging.getLogger(__name__)

# Default suite definitions
SUITES = {
    "FinOps": ["cost-radar", "zombie-hunter", "costopt-intelligence", "database-optimizer"],
    "Security": ["security-posture", "data-security", "secrets-hygiene", "sg-chain-analyzer"],
    "Network": ["network-path-tracer", "connectivity-diagnoser", "network-topology", "dns-cert-manager"],
    "Platform": ["drift-detector", "eks-optimizer", "serverless-optimizer", "arch-diagram", "lifecycle-tracker"],
    "Resilience": ["resiliency-gaps", "backup-dr-posture", "blast-radius", "health-monitor", "capacity-planner"],
    "Governance": ["tag-enforcer", "quota-guardian", "multi-account-governance", "shadow-it-detector"],
    "Modernization": ["modernization-advisor", "event-analysis"],
}

# Default schedules (cron-like: hour, minute)
DEFAULT_SCHEDULES = {
    "Security": {"interval_hours": 6},
    "FinOps": {"interval_hours": 24},
    "Resilience": {"interval_hours": 24},
    "Governance": {"interval_hours": 24},
    "Network": {"interval_hours": 12},
    "Platform": {"interval_hours": 24},
    "Modernization": {"interval_hours": 168},  # weekly
}


def run_suite_scan(suite_name: str, skill_names: list[str],
                   regions: list[str], profile: str = None,
                   history: ScanHistoryStore = None,
                   notify_config: NotificationConfig = None,
                   trigger: str = "scheduled") -> dict:
    """Execute a suite scan, record history, and send notifications."""
    logger.info(f"Starting {trigger} scan: {suite_name} ({len(skill_names)} skills)")
    start = time.time()
    all_findings = []
    skills_run = []
    errors = []
    account_id = ""

    try:
        account_id = get_account_id(profile)
    except Exception:
        pass

    for skill_name in skill_names:
        skill = SkillRegistry.get(skill_name)
        if not skill:
            errors.append(f"Unknown skill: {skill_name}")
            continue
        try:
            result = skill.scan(regions, profile)
            findings = [f.to_dict() for f in result.findings]
            all_findings.extend(findings)
            skills_run.append(skill_name)
        except Exception as e:
            errors.append(f"{skill_name}: {e}")
            logger.warning(f"Skill {skill_name} failed: {e}")

    duration = time.time() - start

    # Record to history
    record = None
    if history:
        record = history.record_scan(
            suite=suite_name,
            skills_run=skills_run,
            findings=all_findings,
            duration=duration,
            trigger=trigger,
            account_id=account_id,
            regions=regions,
        )

    # Send notifications
    notified = []
    if record and notify_config:
        notified = notify_scan_complete(record, notify_config, profile)

    summary = {
        "suite": suite_name,
        "skills_run": skills_run,
        "total_findings": len(all_findings),
        "critical_count": sum(1 for f in all_findings if f.get("severity") == "critical"),
        "high_count": sum(1 for f in all_findings if f.get("severity") == "high"),
        "total_impact": round(sum(f.get("monthly_impact", 0) for f in all_findings), 2),
        "duration_seconds": round(duration, 1),
        "errors": errors,
        "record_id": record.id if record else None,
        "notified": notified,
    }
    logger.info(f"Completed {suite_name}: {summary['total_findings']} findings, "
                f"{summary['critical_count']} critical, {summary['duration_seconds']}s")
    return summary


class ScanScheduler:
    """Background scheduler that runs suite scans on intervals."""

    def __init__(self, profile: str = None, regions: list[str] = None,
                 history_dir: str = None, schedules: dict = None):
        self.profile = profile
        self.regions = regions or []
        self.history = ScanHistoryStore(history_dir) if history_dir else ScanHistoryStore()
        self.notify_config = NotificationConfig.from_env()
        self.schedules = schedules or dict(DEFAULT_SCHEDULES)
        self._timers: dict[str, threading.Timer] = {}
        self._running = False
        self._lock = threading.Lock()

    def start(self):
        """Start all scheduled scans."""
        if not self.regions:
            try:
                self.regions = get_regions(profile=self.profile)
            except Exception:
                self.regions = ["us-east-1"]

        self._running = True
        logger.info(f"Starting scheduler with {len(self.schedules)} suite schedules")

        for suite_name, schedule in self.schedules.items():
            if suite_name not in SUITES:
                logger.warning(f"Unknown suite in schedule: {suite_name}")
                continue
            interval = schedule.get("interval_hours", 24) * 3600
            self._schedule_suite(suite_name, interval)

        logger.info("Scheduler started. Press Ctrl+C to stop.")

    def _schedule_suite(self, suite_name: str, interval_seconds: float):
        """Schedule a suite to run at a fixed interval."""
        def _run():
            if not self._running:
                return
            try:
                skill_names = SUITES.get(suite_name, [])
                run_suite_scan(
                    suite_name, skill_names, self.regions, self.profile,
                    self.history, self.notify_config, trigger="scheduled",
                )
            except Exception as e:
                logger.error(f"Scheduled scan {suite_name} failed: {e}")
            finally:
                # Re-schedule
                if self._running:
                    self._schedule_suite(suite_name, interval_seconds)

        with self._lock:
            timer = threading.Timer(interval_seconds, _run)
            timer.daemon = True
            timer.name = f"cloudpilot-{suite_name}"
            self._timers[suite_name] = timer
            timer.start()

        hours = interval_seconds / 3600
        logger.info(f"Scheduled {suite_name}: every {hours:.0f}h")

    def run_now(self, suite_name: str) -> dict:
        """Trigger an immediate scan for a suite."""
        if suite_name not in SUITES:
            return {"error": f"Unknown suite: {suite_name}. Available: {list(SUITES.keys())}"}
        if not self.regions:
            try:
                self.regions = get_regions(profile=self.profile)
            except Exception:
                self.regions = ["us-east-1"]
        return run_suite_scan(
            suite_name, SUITES[suite_name], self.regions, self.profile,
            self.history, self.notify_config, trigger="manual",
        )

    def stop(self):
        """Stop all scheduled scans."""
        self._running = False
        with self._lock:
            for name, timer in self._timers.items():
                timer.cancel()
                logger.info(f"Cancelled schedule: {name}")
            self._timers.clear()
        logger.info("Scheduler stopped.")

    def get_status(self) -> dict:
        """Get current scheduler status."""
        return {
            "running": self._running,
            "schedules": {
                name: {"interval_hours": sched.get("interval_hours", 24)}
                for name, sched in self.schedules.items()
            },
            "active_timers": list(self._timers.keys()),
            "history_count": len(self.history.list_records(limit=1000)),
        }
