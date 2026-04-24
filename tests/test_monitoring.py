"""Tests for CloudPilot Continuous Monitoring — history, notifications, scheduler."""
import json
import os
import tempfile
import pytest
from unittest.mock import patch, MagicMock

from cloudpilot.monitoring.history import ScanHistoryStore, ScanRecord
from cloudpilot.monitoring.notifications import (
    should_notify, build_summary_message, NotificationConfig, notify_scan_complete,
    SEVERITY_ORDER,
)
from cloudpilot.monitoring.scheduler import SUITES, run_suite_scan


# --- History Store ---

class TestScanHistoryStore:

    def test_record_and_retrieve(self, tmp_path):
        store = ScanHistoryStore(str(tmp_path / "history"))
        findings = [
            {"severity": "critical", "skill": "security-posture", "title": "Open port", "monthly_impact": 0},
            {"severity": "high", "skill": "zombie-hunter", "title": "Idle EC2", "monthly_impact": 50},
            {"severity": "low", "skill": "zombie-hunter", "title": "Unused EIP", "monthly_impact": 3.5},
        ]
        record = store.record_scan("Security", ["security-posture"], findings, 2.5, trigger="manual")
        assert record.total_findings == 3
        assert record.critical_count == 1
        assert record.high_count == 1
        assert record.low_count == 1
        assert record.total_impact == 53.5

        # Retrieve by ID
        loaded = store.get_record(record.id)
        assert loaded is not None
        assert loaded.id == record.id
        assert loaded.total_findings == 3

    def test_list_records(self, tmp_path):
        store = ScanHistoryStore(str(tmp_path / "history"))
        store.record_scan("FinOps", ["cost-radar"], [{"severity": "low", "monthly_impact": 10}], 1.0)
        store.record_scan("Security", ["security-posture"], [{"severity": "high", "monthly_impact": 0}], 1.5)
        records = store.list_records(limit=10)
        assert len(records) == 2
        # Most recent first
        assert records[0]["suite"] == "Security"

    def test_list_records_filter_by_suite(self, tmp_path):
        store = ScanHistoryStore(str(tmp_path / "history"))
        store.record_scan("FinOps", ["cost-radar"], [], 1.0)
        store.record_scan("Security", ["security-posture"], [], 1.5)
        store.record_scan("FinOps", ["zombie-hunter"], [], 0.8)
        records = store.list_records(suite="FinOps")
        assert len(records) == 2
        assert all(r["suite"] == "FinOps" for r in records)

    def test_get_trends(self, tmp_path):
        store = ScanHistoryStore(str(tmp_path / "history"))
        store.record_scan("Security", ["security-posture"],
                          [{"severity": "critical", "monthly_impact": 0}], 1.0)
        store.record_scan("Security", ["security-posture"],
                          [{"severity": "high", "monthly_impact": 0}, {"severity": "low", "monthly_impact": 5}], 1.2)
        trends = store.get_trends(days=30, suite="Security")
        assert trends["scan_count"] == 2
        assert len(trends["total_findings"]) == 2
        assert trends["total_findings"] == [1, 2]  # chronological order

    def test_clear(self, tmp_path):
        store = ScanHistoryStore(str(tmp_path / "history"))
        store.record_scan("FinOps", ["cost-radar"], [], 1.0)
        assert len(store.list_records()) == 1
        store.clear()
        assert len(store.list_records()) == 0

    def test_nonexistent_record_returns_none(self, tmp_path):
        store = ScanHistoryStore(str(tmp_path / "history"))
        assert store.get_record("nonexistent") is None


# --- Notifications ---

class TestNotifications:

    def test_should_notify_critical_above_high(self):
        assert should_notify("critical", "high") is True

    def test_should_notify_high_at_high(self):
        assert should_notify("high", "high") is True

    def test_should_not_notify_medium_at_high(self):
        assert should_notify("medium", "high") is False

    def test_should_not_notify_low_at_high(self):
        assert should_notify("low", "high") is False

    def test_should_notify_medium_at_medium(self):
        assert should_notify("medium", "medium") is True

    def test_severity_order_is_correct(self):
        assert SEVERITY_ORDER["critical"] < SEVERITY_ORDER["high"]
        assert SEVERITY_ORDER["high"] < SEVERITY_ORDER["medium"]
        assert SEVERITY_ORDER["medium"] < SEVERITY_ORDER["low"]
        assert SEVERITY_ORDER["low"] < SEVERITY_ORDER["info"]

    def test_build_summary_message(self):
        record = ScanRecord(
            id="abc123", timestamp="2025-04-24T10:00:00Z", trigger="scheduled",
            suite="Security", skills_run=["security-posture"],
            total_findings=5, critical_count=2, high_count=1, medium_count=1, low_count=1,
            total_impact=100.0, duration_seconds=3.5,
            findings=[
                {"severity": "critical", "title": "Open port 22"},
                {"severity": "critical", "title": "Public S3 bucket"},
                {"severity": "high", "title": "Old IAM key"},
            ],
        )
        msg = build_summary_message(record)
        assert msg["suite"] == "Security"
        assert msg["total_findings"] == 5
        assert msg["critical_count"] == 2
        assert len(msg["top_findings"]) == 3
        assert "100.00" in msg["impact"]

    def test_notify_disabled_returns_empty(self):
        config = NotificationConfig(enabled=False)
        record = ScanRecord(
            id="x", timestamp="", trigger="manual", suite="FinOps",
            findings=[{"severity": "critical"}], critical_count=1,
        )
        result = notify_scan_complete(record, config)
        assert result == []

    def test_notify_below_threshold_skips(self):
        config = NotificationConfig(enabled=True, min_severity="critical")
        record = ScanRecord(
            id="x", timestamp="", trigger="manual", suite="FinOps",
            total_findings=3, critical_count=0, high_count=3,
            findings=[{"severity": "high"}, {"severity": "high"}, {"severity": "high"}],
        )
        result = notify_scan_complete(record, config)
        assert result == []


# --- Scheduler / Suite Runner ---

class TestSuiteRunner:

    def test_suites_have_valid_skills(self):
        """All skills referenced in SUITES must be registered."""
        from cloudpilot.core import SkillRegistry
        for suite_name, skills in SUITES.items():
            for skill_name in skills:
                assert SkillRegistry.get(skill_name) is not None, (
                    f"Suite {suite_name} references unregistered skill: {skill_name}")

    def test_run_suite_scan_records_history(self, tmp_path):
        """run_suite_scan should record to history store."""
        history = ScanHistoryStore(str(tmp_path / "history"))

        # Mock all skills to return empty results
        with patch("cloudpilot.monitoring.scheduler.SkillRegistry") as mock_reg:
            mock_skill = MagicMock()
            mock_skill.scan.return_value = MagicMock(findings=[], total_impact=0, critical_count=0)
            mock_reg.get.return_value = mock_skill

            with patch("cloudpilot.monitoring.scheduler.get_account_id", return_value="123456789012"):
                result = run_suite_scan(
                    "Security", ["security-posture"], ["us-east-1"],
                    history=history, trigger="test",
                )

        assert result["suite"] == "Security"
        assert result["record_id"] is not None
        records = history.list_records()
        assert len(records) == 1
        assert records[0]["suite"] == "Security"

    def test_run_suite_scan_handles_unknown_skill(self, tmp_path):
        """Unknown skills should be logged as errors, not crash."""
        history = ScanHistoryStore(str(tmp_path / "history"))
        with patch("cloudpilot.monitoring.scheduler.get_account_id", return_value="123"):
            result = run_suite_scan(
                "Custom", ["nonexistent-skill"], ["us-east-1"],
                history=history, trigger="test",
            )
        assert len(result["errors"]) == 1
        assert "nonexistent-skill" in result["errors"][0]
