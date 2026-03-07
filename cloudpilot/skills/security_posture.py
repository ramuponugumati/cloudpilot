"""Security Posture — GuardDuty, Security Hub, public resources, IAM issues."""
import time
from datetime import datetime, timedelta, timezone
from cloudpilot.core import BaseSkill, SkillResult, Finding, Severity, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions

SEVERITY_MAP = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "INFORMATIONAL": Severity.INFO}

CONTROL_REMEDIATION = {
    "CIS.1.4": "Enable MFA on root account",
    "CIS.1.5": "Enable MFA on IAM users with console access",
    "CIS.1.10": "Enable MFA for IAM users with console password",
    "CIS.2.1": "Enable CloudTrail in all regions",
    "CIS.2.6": "Enable S3 bucket access logging on CloudTrail bucket",
    "CIS.2.7": "Enable CloudTrail log file validation",
    "CIS.2.9": "Enable VPC Flow Logs in all VPCs",
    "CIS.3.1": "Create CloudWatch log metric filter for unauthorized API calls",
    "CIS.4.1": "Restrict SSH access in security groups",
    "CIS.4.2": "Restrict RDP access in security groups",
    "S3.1": "Enable S3 Block Public Access at account level",
    "S3.2": "S3 buckets should prohibit public read access",
    "S3.5": "S3 buckets should require SSL",
    "EC2.2": "VPC default security group should restrict all traffic",
    "EC2.19": "Security groups should not allow unrestricted access to high risk ports",
    "IAM.1": "IAM policies should not allow full * administrative privileges",
    "IAM.4": "IAM root user access key should not exist",
    "RDS.1": "RDS snapshots should be private",
    "RDS.2": "RDS instances should prohibit public access",
    "RDS.3": "RDS instances should have encryption at rest enabled",
}


class SecurityPostureSkill(BaseSkill):
    name = "security-posture"
    description = "GuardDuty, Security Hub, public resources, open ports, IAM risks"
    version = "0.2.0"

    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        findings = []
        errors = []
        acct = account_id or get_account_id(profile)

        # 1. GuardDuty findings
        def _scan_guardduty(region):
            return self._check_guardduty(region, profile)
        findings.extend(parallel_regions(_scan_guardduty, regions))

        # 2. Public S3 buckets (global)
        try:
            findings.extend(self._check_public_s3(profile))
        except Exception as e:
            errors.append(f"S3: {e}")

        # 3. Public security groups
        def _scan_sgs(region):
            return self._check_open_sgs(region, profile)
        findings.extend(parallel_regions(_scan_sgs, regions))

        # 4. IAM access keys older than 90 days
        try:
            findings.extend(self._check_old_access_keys(profile))
        except Exception as e:
            errors.append(f"IAM: {e}")

        # 5. Security Hub findings
        def _scan_sechub(region):
            return self._check_security_hub(region, profile)
        try:
            findings.extend(parallel_regions(_scan_sechub, regions))
        except Exception as e:
            errors.append(f"SecurityHub: {e}")

        for f in findings:
            f.account_id = acct

        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=time.time() - start,
            accounts_scanned=1, regions_scanned=len(regions), errors=errors,
        )

    def _check_guardduty(self, region, profile):
        findings = []
        try:
            gd = get_client("guardduty", region, profile)
            detectors = gd.list_detectors().get("DetectorIds", [])
            if not detectors:
                return []
            detector_id = detectors[0]
            criteria = {"Criterion": {"severity": {"Gte": 4}, "service.archived": {"Eq": ["false"]}}}
            finding_ids = gd.list_findings(
                DetectorId=detector_id, FindingCriteria=criteria, MaxResults=20
            ).get("FindingIds", [])
            if not finding_ids:
                return []
            details = gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids).get("Findings", [])
            for d in details:
                sev = Severity.CRITICAL if d["Severity"] >= 8 else Severity.HIGH if d["Severity"] >= 5 else Severity.MEDIUM
                findings.append(Finding(
                    skill=self.name, title=d.get("Title", "GuardDuty Finding"),
                    severity=sev, region=region,
                    description=d.get("Description", "")[:200],
                    resource_id=d.get("Resource", {}).get("ResourceType", ""),
                    recommended_action="Investigate and remediate per GuardDuty recommendation",
                    metadata={"type": d.get("Type"), "severity_score": d["Severity"]},
                ))
        except Exception:
            pass
        return findings

    def _check_public_s3(self, profile):
        findings = []
        try:
            s3 = get_client("s3", "us-east-1", profile)
            s3control = get_client("s3control", "us-east-1", profile)
            buckets = s3.list_buckets().get("Buckets", [])
            for bucket in buckets[:50]:
                name = bucket["Name"]
                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        if grantee.get("URI", "").endswith("AllUsers") or grantee.get("URI", "").endswith("AuthenticatedUsers"):
                            findings.append(Finding(
                                skill=self.name, title=f"Public S3 bucket: {name}",
                                severity=Severity.CRITICAL, resource_id=name,
                                description=f"Bucket has public ACL grant: {grant.get('Permission')}",
                                recommended_action="Remove public access or enable Block Public Access",
                            ))
                except Exception:
                    pass
        except Exception:
            pass
        return findings

    def _check_open_sgs(self, region, profile):
        findings = []
        try:
            ec2 = get_client("ec2", region, profile)
            sgs = ec2.describe_security_groups(
                Filters=[{"Name": "ip-permission.cidr", "Values": ["0.0.0.0/0"]}]
            ).get("SecurityGroups", [])
            for sg in sgs:
                for perm in sg.get("IpPermissions", []):
                    port = perm.get("FromPort", 0)
                    if port in (22, 3389, 3306, 5432, 27017):
                        name = sg.get("GroupName", "")
                        findings.append(Finding(
                            skill=self.name,
                            title=f"Open port {port} to 0.0.0.0/0: {sg['GroupId']}",
                            severity=Severity.HIGH, region=region,
                            resource_id=sg["GroupId"],
                            description=f"SG '{name}' allows inbound on port {port} from anywhere",
                            recommended_action="Restrict source IP range",
                        ))
        except Exception:
            pass
        return findings

    def _check_old_access_keys(self, profile, max_age_days=90):
        findings = []
        try:
            iam = get_client("iam", "us-east-1", profile)
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    keys = iam.list_access_keys(UserName=user["UserName"]).get("AccessKeyMetadata", [])
                    for key in keys:
                        if key["Status"] != "Active":
                            continue
                        age = (datetime.now(timezone.utc) - key["CreateDate"]).days
                        if age > max_age_days:
                            findings.append(Finding(
                                skill=self.name,
                                title=f"Old access key: {user['UserName']} ({age} days)",
                                severity=Severity.MEDIUM,
                                resource_id=key["AccessKeyId"],
                                description=f"Access key for {user['UserName']} is {age} days old",
                                recommended_action="Rotate or deactivate the access key",
                                metadata={"user": user["UserName"], "age_days": age},
                            ))
        except Exception:
            pass
        return findings

    def _check_security_hub(self, region, profile):
        findings = []
        try:
            sh = get_client("securityhub", region, profile)
            resp = sh.get_findings(
                Filters={
                    "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}, {"Value": "NOTIFIED", "Comparison": "EQUALS"}],
                    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                    "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
                },
                MaxResults=100,
                SortCriteria=[{"Field": "SeverityLabel", "SortOrder": "desc"}],
            )
            controls_seen = {}
            for f in resp.get("Findings", []):
                control_id = f.get("Compliance", {}).get("SecurityControlId", "") or f.get("GeneratorId", "").split("/")[-1]
                sev_label = f.get("Severity", {}).get("Label", "INFORMATIONAL")
                title = f.get("Title", "")
                resource_id = ""
                resources = f.get("Resources", [])
                if resources:
                    resource_id = resources[0].get("Id", "").split("/")[-1]
                if control_id not in controls_seen:
                    controls_seen[control_id] = {"title": title, "severity": sev_label, "resources": [], "count": 0}
                controls_seen[control_id]["count"] += 1
                if len(controls_seen[control_id]["resources"]) < 5:
                    controls_seen[control_id]["resources"].append(resource_id)

            for control_id, info in controls_seen.items():
                sev = SEVERITY_MAP.get(info["severity"], Severity.INFO)
                remediation = CONTROL_REMEDIATION.get(control_id, "Review in Security Hub console")
                resource_list = ", ".join(info["resources"][:3])
                if info["count"] > 3:
                    resource_list += f" (+{info['count']-3} more)"
                findings.append(Finding(
                    skill=self.name,
                    title=f"SecHub {control_id}: {info['title'][:55]}",
                    severity=sev, region=region,
                    resource_id=resource_list,
                    description=f"{info['count']} resource(s) failing this control",
                    recommended_action=remediation,
                    metadata={"control_id": control_id, "failing_count": info["count"], "resources": info["resources"]},
                ))
        except Exception:
            pass
        return findings


SkillRegistry.register(SecurityPostureSkill())
