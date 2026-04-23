"""Shadow IT Detector — pattern deviation detection, unapproved resource types,
change tracking via CloudTrail, cost anomaly correlation."""
import logging
import time
from datetime import datetime, timezone, timedelta

from cloudpilot.core import BaseSkill, Finding, Severity, SkillResult, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions

logger = logging.getLogger(__name__)

# Approved instance families (configurable)
DEFAULT_APPROVED_FAMILIES = {"t3", "t4g", "m5", "m6i", "m7g", "c5", "c6i", "c7g", "r5", "r6i", "r7g"}
# Services that are commonly unapproved in enterprise environments
FLAGGED_SERVICES = {"lightsail", "workspaces", "appstream"}


class ShadowITDetectorSkill(BaseSkill):
    name = "shadow-it-detector"
    description = "Pattern deviation detection, unapproved resources, change tracking"
    version = "0.1.0"

    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        acct = account_id or get_account_id(profile)
        approved_families = kwargs.get("approved_families", DEFAULT_APPROVED_FAMILIES)
        region_results = parallel_regions(
            lambda r, p: self._collect(r, p), regions, profile=profile)
        data = self._merge(region_results)
        # CloudTrail is global — collect recent events
        self._collect_cloudtrail(data, profile)
        findings = self._run_checks(data, approved_families)
        for f in findings:
            f.account_id = acct
        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=time.time() - start,
            accounts_scanned=1, regions_scanned=len(regions),
            errors=data.get("errors", []))

    def _collect(self, region, profile=None):
        data = {"instances": [], "errors": [], "region": region}
        try:
            ec2 = get_client("ec2", region, profile)
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
                for res in page.get("Reservations", []):
                    for inst in res.get("Instances", []):
                        tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                        data["instances"].append({
                            "id": inst["InstanceId"],
                            "name": tags.get("Name", ""),
                            "type": inst.get("InstanceType", ""),
                            "launch_time": inst["LaunchTime"].isoformat() if hasattr(inst.get("LaunchTime", ""), "isoformat") else "",
                            "tags": tags, "region": region,
                        })
        except Exception as e:
            logger.warning("EC2 in %s: %s", region, e)
            data["errors"].append(f"ec2 in {region}: {e}")
        return data

    def _collect_cloudtrail(self, data, profile):
        data.setdefault("recent_events", [])
        try:
            ct = get_client("cloudtrail", "us-east-1", profile)
            end = datetime.now(timezone.utc)
            start = end - timedelta(days=7)
            events = ct.lookup_events(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "RunInstances"}],
                StartTime=start, EndTime=end, MaxResults=50,
            ).get("Events", [])
            for ev in events:
                data["recent_events"].append({
                    "event_name": ev.get("EventName", ""),
                    "username": ev.get("Username", ""),
                    "event_time": ev.get("EventTime", "").isoformat() if hasattr(ev.get("EventTime", ""), "isoformat") else "",
                    "resources": [r.get("ResourceName", "") for r in ev.get("Resources", [])],
                })
        except Exception as e:
            logger.warning("CloudTrail: %s", e)
            data["errors"].append(f"cloudtrail: {e}")

    def _merge(self, results):
        merged = {"instances": [], "recent_events": [], "errors": []}
        for rd in (results if isinstance(results, list) else []):
            if isinstance(rd, dict):
                for k in ("instances", "errors"):
                    merged[k].extend(rd.get(k, []))
        return merged

    def _run_checks(self, data, approved_families):
        findings = []
        for checker in [
            lambda d: self._check_unapproved_types(d, approved_families),
            self._check_untagged_instances,
            self._check_recent_launches,
        ]:
            try:
                findings.extend(checker(data))
            except Exception as e:
                logger.warning("Checker failed: %s", e)
        return findings

    def _check_unapproved_types(self, data, approved_families):
        """Flag instances using non-approved instance families."""
        findings = []
        for inst in data.get("instances", []):
            family = inst.get("type", "").split(".")[0] if "." in inst.get("type", "") else ""
            if family and family not in approved_families:
                findings.append(Finding(
                    skill=self.name,
                    title=f"Unapproved instance type: {inst['id']}",
                    severity=Severity.MEDIUM, resource_id=inst["id"],
                    region=inst["region"],
                    description=f"EC2 {inst['id']} ({inst['name']}) uses {inst['type']} — family '{family}' is not in approved list",
                    recommended_action="Migrate to an approved instance family or request an exception",
                    metadata={"instance_id": inst["id"], "instance_type": inst["type"],
                              "family": family, "approved_families": sorted(approved_families)}))
        return findings

    def _check_untagged_instances(self, data):
        """Flag instances without Environment or Team tags — potential shadow IT."""
        findings = []
        for inst in data.get("instances", []):
            tags = inst.get("tags", {})
            if "Environment" not in tags and "Team" not in tags:
                findings.append(Finding(
                    skill=self.name,
                    title=f"Untagged instance (shadow IT risk): {inst['id']}",
                    severity=Severity.HIGH, resource_id=inst["id"],
                    region=inst["region"],
                    description=f"EC2 {inst['id']} ({inst['name']}) has no Environment or Team tag — may be shadow IT",
                    recommended_action="Tag the instance or investigate its origin",
                    metadata={"instance_id": inst["id"], "instance_name": inst.get("name", ""),
                              "existing_tags": list(tags.keys())}))
        return findings

    def _check_recent_launches(self, data):
        """Flag recent RunInstances events for visibility."""
        findings = []
        events = data.get("recent_events", [])
        if len(events) > 20:
            findings.append(Finding(
                skill=self.name,
                title=f"High instance launch activity: {len(events)} launches in 7 days",
                severity=Severity.MEDIUM,
                description=f"{len(events)} RunInstances events in the last 7 days — review for unauthorized launches",
                recommended_action="Review CloudTrail events and verify all launches are authorized",
                metadata={"event_count": len(events),
                          "users": list(set(e.get("username", "") for e in events))}))
        return findings


SkillRegistry.register(ShadowITDetectorSkill())
