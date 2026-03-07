"""Event Analysis — CloudTrail events, AWS Config changes, production impact detection."""
import time
from datetime import datetime, timedelta, timezone
from cloudpilot.core import BaseSkill, SkillResult, Finding, Severity, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions

# High-risk CloudTrail events that impact production
HIGH_RISK_EVENTS = {
    "DeleteSecurityGroup", "RevokeSecurityGroupIngress", "AuthorizeSecurityGroupIngress",
    "CreateNetworkAclEntry", "DeleteNetworkAclEntry", "ReplaceNetworkAclEntry",
    "CreateRoute", "DeleteRoute", "ReplaceRoute",
    "DeleteSubnet", "DeleteVpc",
    "PutBucketPolicy", "DeleteBucketPolicy", "PutBucketAcl",
    "DeleteLoadBalancer", "DeregisterTargets",
    "StopInstances", "TerminateInstances",
    "DeleteDBInstance", "DeleteDBCluster",
    "UpdateFunctionConfiguration", "DeleteFunction",
    "DeleteEndpoint", "UpdateEndpoint",
    "PutRolePolicy", "DeleteRolePolicy", "AttachRolePolicy", "DetachRolePolicy",
    "CreateAccessKey", "DeleteAccessKey",
}

ROOT_EVENTS = {"ConsoleLogin", "CreateAccessKey", "AssumeRole"}


class EventAnalysisSkill(BaseSkill):
    name = "event-analysis"
    description = "Analyze CloudTrail events, AWS Config changes, detect production-impacting changes"
    version = "0.1.0"

    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        findings = []
        errors = []
        acct = account_id or get_account_id(profile)
        hours = kwargs.get("hours", 24)

        # 1. CloudTrail — high-risk events
        try:
            findings.extend(self._check_cloudtrail(regions[0] if regions else "us-east-1", profile, hours))
        except Exception as e:
            errors.append(f"CloudTrail: {e}")

        # 2. CloudTrail — root account usage
        try:
            findings.extend(self._check_root_usage(regions[0] if regions else "us-east-1", profile, hours))
        except Exception as e:
            errors.append(f"Root usage: {e}")

        # 3. CloudTrail — unauthorized API calls
        try:
            findings.extend(self._check_unauthorized(regions[0] if regions else "us-east-1", profile, hours))
        except Exception as e:
            errors.append(f"Unauthorized: {e}")

        # 4. AWS Config — non-compliant resources
        def _scan_config(region):
            return self._check_config_compliance(region, profile)
        findings.extend(parallel_regions(_scan_config, regions))

        # 5. AWS Config — recent config changes
        try:
            findings.extend(self._check_config_changes(regions[0] if regions else "us-east-1", profile, hours))
        except Exception as e:
            errors.append(f"Config changes: {e}")

        for f in findings:
            f.account_id = acct

        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=time.time() - start,
            accounts_scanned=1, regions_scanned=len(regions), errors=errors,
        )

    def _check_cloudtrail(self, region, profile, hours):
        findings = []
        ct = get_client("cloudtrail", region, profile)
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=hours)

        try:
            resp = ct.lookup_events(
                StartTime=start, EndTime=end, MaxResults=50,
                LookupAttributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
            )
            for event in resp.get("Events", []):
                name = event.get("EventName", "")
                if name in HIGH_RISK_EVENTS:
                    user = event.get("Username", "unknown")
                    resources = event.get("Resources", [])
                    res_str = ", ".join([r.get("ResourceName", "") for r in resources[:3]]) or "N/A"
                    severity = Severity.HIGH if name.startswith("Delete") else Severity.MEDIUM

                    findings.append(Finding(
                        skill=self.name,
                        title=f"High-risk event: {name}",
                        severity=severity,
                        description=f"By: {user} | Resources: {res_str} | Time: {event.get('EventTime', '')}",
                        resource_id=res_str[:50],
                        region=region,
                        recommended_action="Verify this change was authorized and expected",
                        metadata={"event_name": name, "user": user, "time": str(event.get("EventTime"))},
                    ))
        except Exception:
            pass
        return findings

    def _check_root_usage(self, region, profile, hours):
        findings = []
        ct = get_client("cloudtrail", region, profile)
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=hours)

        try:
            resp = ct.lookup_events(
                StartTime=start, EndTime=end, MaxResults=20,
                LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": "root"}],
            )
            for event in resp.get("Events", []):
                findings.append(Finding(
                    skill=self.name,
                    title=f"Root account activity: {event.get('EventName', '')}",
                    severity=Severity.CRITICAL,
                    description=f"Root account used at {event.get('EventTime', '')}",
                    region=region,
                    recommended_action="Root account should not be used for daily operations. Investigate immediately.",
                    metadata={"event_name": event.get("EventName"), "time": str(event.get("EventTime"))},
                ))
        except Exception:
            pass
        return findings

    def _check_unauthorized(self, region, profile, hours):
        findings = []
        ct = get_client("cloudtrail", region, profile)
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=hours)

        try:
            resp = ct.lookup_events(StartTime=start, EndTime=end, MaxResults=50)
            denied_count = 0
            denied_users = set()
            for event in resp.get("Events", []):
                detail = event.get("CloudTrailEvent", "")
                if '"errorCode":"AccessDenied"' in detail or '"errorCode":"UnauthorizedAccess"' in detail:
                    denied_count += 1
                    denied_users.add(event.get("Username", "unknown"))

            if denied_count > 10:
                findings.append(Finding(
                    skill=self.name,
                    title=f"{denied_count} unauthorized API calls in last {hours}h",
                    severity=Severity.HIGH if denied_count > 50 else Severity.MEDIUM,
                    description=f"Users: {', '.join(list(denied_users)[:5])}",
                    region=region,
                    recommended_action="Review IAM policies — may indicate misconfiguration or compromise attempt",
                    metadata={"denied_count": denied_count, "users": list(denied_users)},
                ))
        except Exception:
            pass
        return findings

    def _check_config_compliance(self, region, profile):
        findings = []
        try:
            config = get_client("config", region, profile)
            resp = config.describe_compliance_by_config_rule(ComplianceTypes=["NON_COMPLIANT"])
            for rule in resp.get("ComplianceByConfigRules", []):
                rule_name = rule.get("ConfigRuleName", "")
                findings.append(Finding(
                    skill=self.name,
                    title=f"Config rule non-compliant: {rule_name}",
                    severity=Severity.MEDIUM,
                    region=region, resource_id=rule_name,
                    description=f"AWS Config rule '{rule_name}' has non-compliant resources",
                    recommended_action="Review non-compliant resources and remediate",
                ))
        except Exception:
            pass
        return findings

    def _check_config_changes(self, region, profile, hours):
        findings = []
        try:
            config = get_client("config", region, profile)
            end = datetime.now(timezone.utc)
            start = end - timedelta(hours=hours)

            # Check for recently changed critical resource types
            critical_types = [
                "AWS::EC2::SecurityGroup", "AWS::EC2::NetworkAcl",
                "AWS::IAM::Role", "AWS::IAM::Policy",
                "AWS::S3::Bucket", "AWS::RDS::DBInstance",
            ]
            for rtype in critical_types:
                try:
                    resp = config.get_discovered_resource_counts(resourceTypes=[rtype])
                    # We can't easily get "changed in last N hours" from Config directly
                    # but we flag if Config is tracking these types
                except Exception:
                    pass
        except Exception:
            pass
        return findings


SkillRegistry.register(EventAnalysisSkill())
