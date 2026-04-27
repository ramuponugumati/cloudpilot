"""Tests for CloudPilot Real-time Monitoring — event model, severity mapping, buffer."""
import pytest
from cloudpilot.monitoring.realtime import (
    RealtimeEvent, RealtimeMonitor, HIGH_RISK_EVENTS,
    EVENT_CLOUDTRAIL, EVENT_HEALTH, EVENT_ALARM, EVENT_FINDING, EVENT_HEARTBEAT,
)


class TestRealtimeEvent:

    def test_event_to_dict(self):
        evt = RealtimeEvent(
            event_type=EVENT_CLOUDTRAIL, severity="high",
            title="TerminateInstances by admin",
            description="EC2 terminated", source="CloudTrail",
            region="us-east-1", resource_id="i-abc123",
        )
        d = evt.to_dict()
        assert d["event_type"] == "cloudtrail"
        assert d["severity"] == "high"
        assert d["title"] == "TerminateInstances by admin"
        assert d["region"] == "us-east-1"
        assert d["resource_id"] == "i-abc123"
        assert d["timestamp"]
        assert d["id"].startswith("cloudtrail-")

    def test_event_types_are_strings(self):
        for et in [EVENT_CLOUDTRAIL, EVENT_HEALTH, EVENT_ALARM, EVENT_FINDING, EVENT_HEARTBEAT]:
            assert isinstance(et, str)


class TestHighRiskEvents:

    def test_critical_events_exist(self):
        """Destructive operations should be critical."""
        assert HIGH_RISK_EVENTS["DeleteBucket"] == "critical"
        assert HIGH_RISK_EVENTS["DeleteDBInstance"] == "critical"
        assert HIGH_RISK_EVENTS["StopLogging"] == "critical"
        assert HIGH_RISK_EVENTS["DeleteTrail"] == "critical"
        assert HIGH_RISK_EVENTS["ScheduleKeyDeletion"] == "critical"

    def test_high_events_exist(self):
        """Privilege escalation and security changes should be high."""
        assert HIGH_RISK_EVENTS["TerminateInstances"] == "high"
        assert HIGH_RISK_EVENTS["AttachRolePolicy"] == "high"
        assert HIGH_RISK_EVENTS["PutBucketAcl"] == "high"

    def test_all_events_have_valid_severity(self):
        valid = {"critical", "high", "medium", "low", "info"}
        for event_name, severity in HIGH_RISK_EVENTS.items():
            assert severity in valid, f"{event_name} has invalid severity: {severity}"


class TestRealtimeMonitor:

    def test_buffer_caps_at_max(self):
        monitor = RealtimeMonitor()
        monitor._max_buffer = 5
        for i in range(10):
            evt = RealtimeEvent("test", "info", f"Event {i}")
            monitor._event_buffer.append(evt.to_dict())
            if len(monitor._event_buffer) > monitor._max_buffer:
                monitor._event_buffer = monitor._event_buffer[-monitor._max_buffer:]
        assert len(monitor._event_buffer) == 5
        assert monitor._event_buffer[0]["title"] == "Event 5"

    def test_default_poll_interval(self):
        monitor = RealtimeMonitor()
        assert monitor.poll_interval == 60

    def test_default_regions(self):
        monitor = RealtimeMonitor()
        assert monitor.regions == ["us-east-1"]

    def test_stop_sets_running_false(self):
        monitor = RealtimeMonitor()
        monitor._running = True
        monitor.stop()
        assert monitor._running is False

    def test_unregister_removes_client(self):
        monitor = RealtimeMonitor()
        fake_ws = object()
        monitor._clients.add(fake_ws)
        assert len(monitor._clients) == 1
        monitor.unregister(fake_ws)
        assert len(monitor._clients) == 0

    def test_unregister_nonexistent_is_safe(self):
        monitor = RealtimeMonitor()
        monitor.unregister(object())  # Should not raise
        assert len(monitor._clients) == 0
