"""Notification system — Slack, Teams, SNS, and generic webhook alerts."""
import json
import logging
import os
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class NotificationConfig:
    """Notification channel configuration."""
    slack_webhook_url: str = ""
    teams_webhook_url: str = ""
    sns_topic_arn: str = ""
    generic_webhook_url: str = ""
    min_severity: str = "high"  # Only notify for this severity and above
    enabled: bool = True

    @classmethod
    def from_env(cls) -> "NotificationConfig":
        return cls(
            slack_webhook_url=os.environ.get("CLOUDPILOT_SLACK_WEBHOOK", ""),
            teams_webhook_url=os.environ.get("CLOUDPILOT_TEAMS_WEBHOOK", ""),
            sns_topic_arn=os.environ.get("CLOUDPILOT_SNS_TOPIC", ""),
            generic_webhook_url=os.environ.get("CLOUDPILOT_WEBHOOK_URL", ""),
            min_severity=os.environ.get("CLOUDPILOT_NOTIFY_SEVERITY", "high"),
            enabled=os.environ.get("CLOUDPILOT_NOTIFICATIONS", "true").lower() == "true",
        )


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def should_notify(finding_severity: str, min_severity: str) -> bool:
    """Check if a finding severity meets the notification threshold."""
    return SEVERITY_ORDER.get(finding_severity, 4) <= SEVERITY_ORDER.get(min_severity, 1)


def build_summary_message(scan_record) -> dict:
    """Build a notification message from a scan record."""
    sev_line = " | ".join([
        f"{SEVERITY_EMOJI.get(s, '⚪')} {s.upper()}: {getattr(scan_record, f'{s}_count', 0)}"
        for s in ["critical", "high", "medium", "low"]
        if getattr(scan_record, f"{s}_count", 0) > 0
    ])

    impact_str = f"${scan_record.total_impact:,.2f}/mo" if scan_record.total_impact > 0 else "—"

    top_findings = []
    for f in scan_record.findings[:5]:
        emoji = SEVERITY_EMOJI.get(f.get("severity", "info"), "⚪")
        top_findings.append(f"{emoji} {f.get('title', 'Unknown')}")

    return {
        "suite": scan_record.suite,
        "trigger": scan_record.trigger,
        "total_findings": scan_record.total_findings,
        "critical_count": scan_record.critical_count,
        "high_count": scan_record.high_count,
        "severity_line": sev_line,
        "impact": impact_str,
        "duration": f"{scan_record.duration_seconds:.1f}s",
        "top_findings": top_findings,
        "timestamp": scan_record.timestamp,
        "scan_id": scan_record.id,
    }


def send_slack(webhook_url: str, scan_record) -> bool:
    """Send a Slack notification via incoming webhook."""
    msg = build_summary_message(scan_record)
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"☁️✈️ CloudPilot — {msg['suite']} Scan Complete"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Findings:* {msg['total_findings']}"},
                {"type": "mrkdwn", "text": f"*Impact:* {msg['impact']}"},
                {"type": "mrkdwn", "text": f"*Duration:* {msg['duration']}"},
                {"type": "mrkdwn", "text": f"*Trigger:* {msg['trigger']}"},
            ]
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": msg["severity_line"] or "No findings above threshold"}
        },
    ]
    if msg["top_findings"]:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Top Findings:*\n" + "\n".join(msg["top_findings"])}
        })

    payload = json.dumps({"blocks": blocks}).encode("utf-8")
    return _post_webhook(webhook_url, payload, "Slack")


def send_teams(webhook_url: str, scan_record) -> bool:
    """Send a Microsoft Teams notification via incoming webhook."""
    msg = build_summary_message(scan_record)
    card = {
        "@type": "MessageCard",
        "summary": f"CloudPilot {msg['suite']} Scan",
        "themeColor": "dc2626" if msg["critical_count"] > 0 else "059669",
        "title": f"☁️✈️ CloudPilot — {msg['suite']} Scan Complete",
        "sections": [{
            "facts": [
                {"name": "Findings", "value": str(msg["total_findings"])},
                {"name": "Severity", "value": msg["severity_line"] or "Clean"},
                {"name": "Impact", "value": msg["impact"]},
                {"name": "Duration", "value": msg["duration"]},
                {"name": "Trigger", "value": msg["trigger"]},
            ],
            "text": "\n".join(msg["top_findings"]) if msg["top_findings"] else "No critical findings.",
        }],
    }
    payload = json.dumps(card).encode("utf-8")
    return _post_webhook(webhook_url, payload, "Teams")


def send_sns(topic_arn: str, scan_record, profile: str = None) -> bool:
    """Publish scan summary to an SNS topic."""
    try:
        import boto3
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        region = topic_arn.split(":")[3] if ":" in topic_arn else "us-east-1"
        sns = session.client("sns", region_name=region)
        msg = build_summary_message(scan_record)
        subject = f"CloudPilot {msg['suite']}: {msg['total_findings']} findings"
        if msg["critical_count"] > 0:
            subject += f" ({msg['critical_count']} CRITICAL)"
        body = (
            f"Suite: {msg['suite']}\n"
            f"Findings: {msg['total_findings']}\n"
            f"Severity: {msg['severity_line']}\n"
            f"Impact: {msg['impact']}\n"
            f"Duration: {msg['duration']}\n\n"
            f"Top Findings:\n" + "\n".join(msg["top_findings"])
        )
        sns.publish(TopicArn=topic_arn, Subject=subject[:100], Message=body)
        logger.info(f"SNS notification sent to {topic_arn}")
        return True
    except Exception as e:
        logger.error(f"SNS notification failed: {e}")
        return False


def send_generic_webhook(webhook_url: str, scan_record) -> bool:
    """Send scan results as JSON to a generic webhook endpoint."""
    msg = build_summary_message(scan_record)
    payload = json.dumps(msg).encode("utf-8")
    return _post_webhook(webhook_url, payload, "webhook")


def _post_webhook(url: str, payload: bytes, label: str) -> bool:
    """POST JSON payload to a webhook URL."""
    try:
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.info(f"{label} notification sent: {resp.status}")
            return resp.status < 300
    except Exception as e:
        logger.error(f"{label} notification failed: {e}")
        return False


def notify_scan_complete(scan_record, config: NotificationConfig = None,
                         profile: str = None) -> list[str]:
    """Send notifications to all configured channels. Returns list of channels notified."""
    if config is None:
        config = NotificationConfig.from_env()
    if not config.enabled:
        return []

    # Check if any findings meet the severity threshold
    dominated = any(
        should_notify(f.get("severity", "info"), config.min_severity)
        for f in scan_record.findings
    )
    # Always notify if there are critical findings, even if threshold is lower
    if not dominated and scan_record.critical_count == 0:
        logger.info(f"Scan {scan_record.id}: no findings above {config.min_severity} threshold, skipping notification")
        return []

    notified = []
    if config.slack_webhook_url:
        if send_slack(config.slack_webhook_url, scan_record):
            notified.append("slack")
    if config.teams_webhook_url:
        if send_teams(config.teams_webhook_url, scan_record):
            notified.append("teams")
    if config.sns_topic_arn:
        if send_sns(config.sns_topic_arn, scan_record, profile):
            notified.append("sns")
    if config.generic_webhook_url:
        if send_generic_webhook(config.generic_webhook_url, scan_record):
            notified.append("webhook")
    return notified
