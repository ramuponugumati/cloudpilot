"""Real-time monitoring — polls CloudTrail, Health Dashboard, and CloudWatch alarms,
pushes events to connected WebSocket clients."""
import asyncio
import json
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# Event types
EVENT_CLOUDTRAIL = "cloudtrail"
EVENT_HEALTH = "health"
EVENT_ALARM = "alarm"
EVENT_FINDING = "finding"
EVENT_HEARTBEAT = "heartbeat"


class RealtimeEvent:
    """A real-time monitoring event."""
    def __init__(self, event_type: str, severity: str, title: str,
                 description: str = "", source: str = "", region: str = "",
                 resource_id: str = "", metadata: dict = None):
        self.event_type = event_type
        self.severity = severity
        self.title = title
        self.description = description
        self.source = source
        self.region = region
        self.resource_id = resource_id
        self.metadata = metadata or {}
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.id = f"{event_type}-{int(time.time()*1000)}"

    def to_dict(self):
        return {
            "id": self.id, "event_type": self.event_type,
            "severity": self.severity, "title": self.title,
            "description": self.description, "source": self.source,
            "region": self.region, "resource_id": self.resource_id,
            "metadata": self.metadata, "timestamp": self.timestamp,
        }


# High-risk CloudTrail events to watch for
HIGH_RISK_EVENTS = {
    "ConsoleLogin": "info",
    "StopInstances": "medium",
    "TerminateInstances": "high",
    "DeleteBucket": "critical",
    "DeleteDBInstance": "critical",
    "DeleteStack": "high",
    "PutBucketPolicy": "high",
    "CreateAccessKey": "medium",
    "AttachUserPolicy": "high",
    "AttachRolePolicy": "high",
    "CreateRole": "medium",
    "AuthorizeSecurityGroupIngress": "medium",
    "RunInstances": "info",
    "CreateStack": "info",
    "DeleteSecurityGroup": "high",
    "ModifyDBInstance": "medium",
    "PutBucketAcl": "high",
    "DeactivateMFADevice": "critical",
    "DeleteTrail": "critical",
    "StopLogging": "critical",
    "DisableKey": "high",
    "ScheduleKeyDeletion": "critical",
}


class RealtimeMonitor:
    """Polls AWS for real-time events and broadcasts to WebSocket clients."""

    def __init__(self, profile: str = None, regions: list[str] = None,
                 poll_interval: int = 60):
        self.profile = profile
        self.regions = regions or ["us-east-1"]
        self.poll_interval = poll_interval
        self._clients: set = set()  # WebSocket connections
        self._running = False
        self._last_poll: dict[str, str] = {}  # region -> last event timestamp
        self._event_buffer: list[dict] = []  # Recent events for new clients
        self._max_buffer = 100

    async def register(self, websocket):
        """Register a new WebSocket client and send buffered events."""
        self._clients.add(websocket)
        logger.info(f"WebSocket client connected ({len(self._clients)} total)")
        # Send recent events buffer
        for event in self._event_buffer[-20:]:
            try:
                await websocket.send_json(event)
            except Exception:
                pass

    def unregister(self, websocket):
        """Remove a disconnected WebSocket client."""
        self._clients.discard(websocket)
        logger.info(f"WebSocket client disconnected ({len(self._clients)} total)")

    async def broadcast(self, event: RealtimeEvent):
        """Send an event to all connected clients."""
        data = event.to_dict()
        self._event_buffer.append(data)
        if len(self._event_buffer) > self._max_buffer:
            self._event_buffer = self._event_buffer[-self._max_buffer:]

        dead = set()
        for ws in self._clients:
            try:
                await ws.send_json(data)
            except Exception:
                dead.add(ws)
        self._clients -= dead

    async def start(self):
        """Start the polling loop."""
        self._running = True
        logger.info(f"Real-time monitor started: {len(self.regions)} regions, {self.poll_interval}s interval")
        while self._running:
            try:
                await self._poll_all()
            except Exception as e:
                logger.error(f"Poll error: {e}")
            # Heartbeat
            await self.broadcast(RealtimeEvent(
                EVENT_HEARTBEAT, "info", "Heartbeat",
                description=f"Monitoring {len(self.regions)} regions, {len(self._clients)} clients",
                metadata={"clients": len(self._clients), "regions": self.regions},
            ))
            await asyncio.sleep(self.poll_interval)

    def stop(self):
        self._running = False

    async def _poll_all(self):
        """Poll all event sources across regions."""
        for region in self.regions:
            await self._poll_cloudtrail(region)
            await self._poll_health(region)
            await self._poll_alarms(region)

    async def _poll_cloudtrail(self, region: str):
        """Poll CloudTrail for high-risk events in the last poll interval."""
        try:
            from cloudpilot.aws_client import get_client
            ct = get_client("cloudtrail", region, self.profile)
            start_time = datetime.now(timezone.utc) - timedelta(seconds=self.poll_interval + 30)

            # Only look up events we care about
            events = []
            try:
                resp = ct.lookup_events(
                    StartTime=start_time,
                    MaxResults=50,
                )
                events = resp.get("Events", [])
            except Exception as e:
                logger.debug(f"CloudTrail lookup in {region}: {e}")
                return

            for event in events:
                event_name = event.get("EventName", "")
                if event_name not in HIGH_RISK_EVENTS:
                    continue

                severity = HIGH_RISK_EVENTS[event_name]
                username = event.get("Username", "unknown")
                event_time = event.get("EventTime", "")
                resources = event.get("Resources", [])
                resource_id = resources[0].get("ResourceName", "") if resources else ""

                await self.broadcast(RealtimeEvent(
                    event_type=EVENT_CLOUDTRAIL,
                    severity=severity,
                    title=f"{event_name} by {username}",
                    description=f"{event_name} performed by {username} in {region}",
                    source="CloudTrail",
                    region=region,
                    resource_id=resource_id,
                    metadata={
                        "event_name": event_name,
                        "username": username,
                        "event_time": str(event_time),
                        "resources": [r.get("ResourceName", "") for r in resources],
                    },
                ))
        except Exception as e:
            logger.debug(f"CloudTrail poll {region}: {e}")

    async def _poll_health(self, region: str):
        """Poll AWS Health Dashboard for active events."""
        try:
            from cloudpilot.aws_client import get_client
            health = get_client("health", "us-east-1", self.profile)  # Health is global

            now = datetime.now(timezone.utc)
            start = now - timedelta(seconds=self.poll_interval + 60)

            try:
                resp = health.describe_events(
                    filter={
                        "startTimes": [{"from": start}],
                        "eventStatusCodes": ["open", "upcoming"],
                    },
                    maxResults=10,
                )
            except Exception:
                return

            for event in resp.get("events", []):
                svc = event.get("service", "unknown")
                status = event.get("statusCode", "unknown")
                category = event.get("eventTypeCategory", "")
                severity = "high" if category == "issue" else "medium" if category == "scheduledChange" else "info"

                await self.broadcast(RealtimeEvent(
                    event_type=EVENT_HEALTH,
                    severity=severity,
                    title=f"AWS Health: {svc} — {status}",
                    description=event.get("eventTypeCode", ""),
                    source="AWS Health",
                    region=event.get("region", "global"),
                    metadata={
                        "service": svc,
                        "status": status,
                        "category": category,
                        "event_arn": event.get("arn", ""),
                    },
                ))
        except Exception as e:
            logger.debug(f"Health poll: {e}")

    async def _poll_alarms(self, region: str):
        """Poll CloudWatch for alarms in ALARM state."""
        try:
            from cloudpilot.aws_client import get_client
            cw = get_client("cloudwatch", region, self.profile)

            try:
                resp = cw.describe_alarms(StateValue="ALARM", MaxRecords=20)
            except Exception:
                return

            for alarm in resp.get("MetricAlarms", []):
                name = alarm.get("AlarmName", "")
                state_updated = alarm.get("StateUpdatedTimestamp")
                if state_updated:
                    # Only report alarms that changed state recently
                    if isinstance(state_updated, datetime):
                        age = (datetime.now(timezone.utc) - state_updated.replace(tzinfo=timezone.utc)).total_seconds()
                    else:
                        age = self.poll_interval + 1  # Include it
                    if age > self.poll_interval + 60:
                        continue

                await self.broadcast(RealtimeEvent(
                    event_type=EVENT_ALARM,
                    severity="high",
                    title=f"CloudWatch ALARM: {name}",
                    description=alarm.get("AlarmDescription", ""),
                    source="CloudWatch",
                    region=region,
                    resource_id=name,
                    metadata={
                        "alarm_name": name,
                        "metric": alarm.get("MetricName", ""),
                        "namespace": alarm.get("Namespace", ""),
                        "threshold": alarm.get("Threshold"),
                        "comparison": alarm.get("ComparisonOperator", ""),
                    },
                ))
        except Exception as e:
            logger.debug(f"CloudWatch alarms poll {region}: {e}")
