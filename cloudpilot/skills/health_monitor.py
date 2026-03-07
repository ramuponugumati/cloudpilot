"""AWS Health Monitor — pull active Health events and correlate with infrastructure."""
import time
from datetime import datetime, timedelta, timezone
from cloudpilot.core import BaseSkill, SkillResult, Finding, Severity, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id


class HealthMonitorSkill(BaseSkill):
    name = "health-monitor"
    description = "Monitor AWS Health events, service disruptions, and scheduled maintenance affecting your resources"
    version = "0.1.0"

    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        findings = []
        errors = []
        acct = account_id or get_account_id(profile)

        # Check AWS Health events
        try:
            findings.extend(self._check_health_events(profile, regions))
        except Exception as e:
            errors.append(f"health-events: {e}")

        # Check Trusted Advisor checks
        try:
            findings.extend(self._check_trusted_advisor(profile))
        except Exception as e:
            errors.append(f"trusted-advisor: {e}")

        for f in findings:
            f.account_id = acct

        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=time.time() - start,
            accounts_scanned=1, regions_scanned=len(regions), errors=errors,
        )

    def _check_health_events(self, profile, regions):
        findings = []
        try:
            health = get_client("health", "us-east-1", profile)
            now = datetime.now(timezone.utc)
            week_ago = now - timedelta(days=7)

            # Get open and upcoming events
            resp = health.describe_events(
                filter={
                    "eventStatusCodes": ["open", "upcoming", "closed"],
                    "startTimes": [{"from": week_ago}],
                },
                maxResults=50,
            )

            for event in resp.get("events", []):
                arn = event.get("arn", "")
                svc = event.get("service", "")
                category = event.get("eventTypeCategory", "")
                status = event.get("statusCode", "")
                region = event.get("region", "global")

                # Skip if not in our scanned regions
                if region != "global" and region not in regions:
                    continue

                # Map category to severity
                if category == "issue":
                    sev = Severity.HIGH if status == "open" else Severity.MEDIUM
                elif category == "scheduledChange":
                    sev = Severity.MEDIUM
                elif category == "accountNotification":
                    sev = Severity.LOW
                else:
                    sev = Severity.INFO

                # Get event details
                desc = ""
                try:
                    detail_resp = health.describe_event_details(eventArns=[arn])
                    for detail in detail_resp.get("successfulSet", []):
                        desc = detail.get("eventDescription", {}).get("latestDescription", "")[:200]
                except Exception:
                    pass

                # Get affected resources
                affected = []
                try:
                    aff_resp = health.describe_affected_entities(filter={"eventArns": [arn]}, maxResults=10)
                    affected = [e.get("entityValue", "") for e in aff_resp.get("entities", [])]
                except Exception:
                    pass

                title_prefix = {"issue": "⚠ Service issue", "scheduledChange": "📅 Scheduled change", "accountNotification": "📢 Notification"}.get(category, "Health event")

                findings.append(Finding(
                    skill=self.name,
                    title=f"{title_prefix}: {svc} ({status})",
                    severity=sev, region=region,
                    resource_id=", ".join(affected[:3]) if affected else svc,
                    description=desc or f"{category} for {svc} in {region}",
                    recommended_action="Review event details in AWS Health Dashboard" if category == "issue" else "Plan for upcoming change",
                    metadata={
                        "event_arn": arn, "service": svc, "category": category,
                        "status": status, "affected_resources": affected,
                    },
                ))

        except health.exceptions.SubscriptionRequiredException:
            # Business/Enterprise support required for Health API
            findings.append(Finding(
                skill=self.name,
                title="AWS Health API requires Business/Enterprise Support",
                severity=Severity.INFO, region="global",
                description="Upgrade to Business or Enterprise Support to access AWS Health events via API",
                recommended_action="Consider upgrading AWS Support plan for proactive health monitoring",
            ))
        except Exception:
            pass
        return findings

    def _check_trusted_advisor(self, profile):
        findings = []
        try:
            ta = get_client("support", "us-east-1", profile)
            checks = ta.describe_trusted_advisor_checks(language="en").get("checks", [])

            # Focus on high-impact categories
            priority_categories = {"cost_optimizing", "security", "fault_tolerance", "performance"}
            for check in checks:
                if check.get("category") not in priority_categories:
                    continue
                try:
                    result = ta.describe_trusted_advisor_check_result(checkId=check["id"], language="en")
                    status = result.get("result", {}).get("status", "ok")
                    if status in ("warning", "error"):
                        resources_flagged = len(result.get("result", {}).get("flaggedResources", []))
                        if resources_flagged == 0:
                            continue
                        sev = Severity.HIGH if status == "error" else Severity.MEDIUM
                        cat_map = {"cost_optimizing": "Cost", "security": "Security", "fault_tolerance": "Reliability", "performance": "Performance"}
                        findings.append(Finding(
                            skill=self.name,
                            title=f"Trusted Advisor: {check['name']}",
                            severity=sev, region="global",
                            resource_id=check["id"],
                            description=f"[{cat_map.get(check['category'], check['category'])}] {resources_flagged} resources flagged — {check.get('description', '')[:100]}",
                            recommended_action="Review in Trusted Advisor console",
                            metadata={"check_id": check["id"], "category": check["category"], "status": status, "flagged_count": resources_flagged},
                        ))
                except Exception:
                    pass
        except Exception:
            pass  # Trusted Advisor requires Business/Enterprise support
        return findings


SkillRegistry.register(HealthMonitorSkill())
