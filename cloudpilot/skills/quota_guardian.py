"""Quota Guardian — monitor service quotas and auto-request increases when approaching limits."""
import time
from cloudpilot.core import BaseSkill, SkillResult, Finding, Severity, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions

# Key quotas to monitor with their service codes and quota codes
MONITORED_QUOTAS = [
    {"service": "ec2", "quota_name": "Running On-Demand Standard instances", "quota_code": "L-1216C47A"},
    {"service": "ec2", "quota_name": "EC2-VPC Elastic IPs", "quota_code": "L-0263D0A3"},
    {"service": "vpc", "quota_name": "VPCs per Region", "quota_code": "L-F678F1CE"},
    {"service": "vpc", "quota_name": "Internet gateways per Region", "quota_code": "L-A4707A72"},
    {"service": "vpc", "quota_name": "NAT gateways per Availability Zone", "quota_code": "L-FE5A380F"},
    {"service": "elasticloadbalancing", "quota_name": "Application Load Balancers per Region", "quota_code": "L-53DA6B97"},
    {"service": "lambda", "quota_name": "Concurrent executions", "quota_code": "L-B99A9384"},
    {"service": "rds", "quota_name": "DB instances", "quota_code": "L-7B6409FD"},
    {"service": "s3", "quota_name": "Buckets", "quota_code": "L-DC2B2D3D"},
    {"service": "ebs", "quota_name": "Storage for General Purpose SSD (gp3) volumes", "quota_code": "L-7A658000"},
    {"service": "ecs", "quota_name": "Clusters per account", "quota_code": "L-21C621EB"},
    {"service": "cloudformation", "quota_name": "Stack count", "quota_code": "L-0485CB21"},
]


class QuotaGuardianSkill(BaseSkill):
    name = "quota-guardian"
    description = "Monitor service quotas approaching limits and flag resources at risk of throttling"
    version = "0.1.0"

    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        findings = []
        errors = []
        acct = account_id or get_account_id(profile)
        threshold = kwargs.get("threshold", 70)  # Alert at 70% usage

        try:
            results = parallel_regions(lambda r: self._check_quotas(r, profile, threshold), regions)
            findings.extend(results)
        except Exception as e:
            errors.append(f"quotas: {e}")

        for f in findings:
            f.account_id = acct

        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=time.time() - start,
            accounts_scanned=1, regions_scanned=len(regions), errors=errors,
        )

    def _check_quotas(self, region, profile, threshold):
        findings = []
        try:
            sq = get_client("service-quotas", region, profile)
            cw = get_client("cloudwatch", region, profile)

            for quota_info in MONITORED_QUOTAS:
                try:
                    # Get current quota value
                    resp = sq.get_service_quota(
                        ServiceCode=quota_info["service"],
                        QuotaCode=quota_info["quota_code"],
                    )
                    quota = resp.get("Quota", {})
                    limit = quota.get("Value", 0)
                    if limit <= 0:
                        continue

                    # Try to get usage from CloudWatch Service Quotas metrics
                    usage_pct = self._get_usage_percentage(cw, quota_info["service"], quota_info["quota_code"], limit)

                    if usage_pct is None:
                        # Fallback: estimate usage from resource counts
                        usage_pct = self._estimate_usage(region, profile, quota_info["service"], quota_info["quota_code"], limit)

                    if usage_pct is None or usage_pct < threshold:
                        continue

                    if usage_pct >= 90:
                        sev = Severity.CRITICAL
                    elif usage_pct >= 80:
                        sev = Severity.HIGH
                    else:
                        sev = Severity.MEDIUM

                    findings.append(Finding(
                        skill=self.name,
                        title=f"Quota {usage_pct:.0f}%: {quota_info['quota_name']}",
                        severity=sev, region=region,
                        resource_id=quota_info["quota_code"],
                        description=f"{quota_info['service']} | Limit: {limit:.0f} | Usage: {usage_pct:.0f}%",
                        recommended_action=f"Request quota increase for {quota_info['quota_name']}" if usage_pct >= 80 else "Monitor — approaching limit",
                        metadata={
                            "service": quota_info["service"],
                            "quota_code": quota_info["quota_code"],
                            "limit": limit, "usage_pct": round(usage_pct, 1),
                        },
                    ))
                except Exception:
                    pass  # Quota may not exist in this region
        except Exception:
            pass
        return findings

    def _get_usage_percentage(self, cw, service, quota_code, limit):
        """Try to get usage percentage from CloudWatch Service Quotas metrics."""
        from datetime import datetime, timedelta, timezone
        try:
            end = datetime.now(timezone.utc)
            start = end - timedelta(hours=1)
            resp = cw.get_metric_statistics(
                Namespace="AWS/Usage",
                MetricName="ResourceCount",
                Dimensions=[
                    {"Name": "Type", "Value": "Resource"},
                    {"Name": "Service", "Value": service.upper()},
                    {"Name": "Resource", "Value": quota_code},
                ],
                StartTime=start, EndTime=end,
                Period=3600, Statistics=["Maximum"],
            )
            pts = resp.get("Datapoints", [])
            if pts:
                usage = max(p["Maximum"] for p in pts)
                return (usage / limit * 100) if limit > 0 else 0
        except Exception:
            pass
        return None

    def _estimate_usage(self, region, profile, service, quota_code, limit):
        """Fallback: estimate usage by counting resources."""
        try:
            if service == "ec2" and "Elastic IPs" in str(quota_code):
                ec2 = get_client("ec2", region, profile)
                count = len(ec2.describe_addresses().get("Addresses", []))
                return (count / limit * 100) if limit > 0 else 0
            elif service == "vpc" and "VPCs" in str(quota_code):
                ec2 = get_client("ec2", region, profile)
                count = len(ec2.describe_vpcs().get("Vpcs", []))
                return (count / limit * 100) if limit > 0 else 0
            elif service == "rds":
                rds = get_client("rds", region, profile)
                count = len(rds.describe_db_instances().get("DBInstances", []))
                return (count / limit * 100) if limit > 0 else 0
        except Exception:
            pass
        return None


SkillRegistry.register(QuotaGuardianSkill())
