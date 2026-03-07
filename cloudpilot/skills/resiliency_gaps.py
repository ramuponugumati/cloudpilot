"""Resiliency Gaps — WAFR-aligned checks across all 6 pillars."""
import time
from cloudpilot.core import BaseSkill, SkillResult, Finding, Severity, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions


class ResiliencyGapsSkill(BaseSkill):
    name = "resiliency-gaps"
    description = "WAFR-aligned resiliency checks: reliability, security, performance, cost, ops, sustainability"
    version = "0.1.0"

    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        findings = []
        errors = []
        acct = account_id or get_account_id(profile)

        checks = [
            # Reliability pillar
            ("reliability", self._check_single_az_rds),
            ("reliability", self._check_single_az_elb),
            ("reliability", self._check_no_backups),
            ("reliability", self._check_no_autoscaling),
            # Security pillar
            ("security", self._check_unencrypted_ebs),
            ("security", self._check_unencrypted_rds),
            ("security", self._check_no_vpc_flow_logs),
            # Performance pillar
            ("performance", self._check_old_gen_instances),
            # Operational Excellence
            ("ops", self._check_missing_alarms),
            ("ops", self._check_no_tags),
            # Sustainability pillar
            ("sustainability", self._check_graviton_eligible),
            ("sustainability", self._check_oversized_instances),
        ]

        for pillar, check_fn in checks:
            try:
                results = parallel_regions(lambda r: check_fn(r, profile), regions)
                for f in results:
                    f.metadata["wafr_pillar"] = pillar
                findings.extend(results)
            except Exception as e:
                errors.append(f"{pillar}: {e}")

        for f in findings:
            f.account_id = acct

        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=time.time() - start,
            accounts_scanned=1, regions_scanned=len(regions), errors=errors,
        )

    # === RELIABILITY PILLAR ===

    def _check_single_az_rds(self, region, profile):
        findings = []
        try:
            rds = get_client("rds", region, profile)
            for db in rds.describe_db_instances().get("DBInstances", []):
                if db["DBInstanceStatus"] != "available":
                    continue
                if not db.get("MultiAZ", False):
                    findings.append(Finding(
                        skill=self.name,
                        title=f"Single-AZ RDS: {db['DBInstanceIdentifier']}",
                        severity=Severity.HIGH, region=region,
                        resource_id=db["DBInstanceIdentifier"],
                        description=f"{db['DBInstanceClass']} | {db['Engine']} | No Multi-AZ failover",
                        recommended_action="Enable Multi-AZ for production databases",
                        metadata={"wafr_pillar": "reliability", "engine": db["Engine"]},
                    ))
        except Exception:
            pass
        return findings

    def _check_single_az_elb(self, region, profile):
        findings = []
        try:
            elb = get_client("elbv2", region, profile)
            for lb in elb.describe_load_balancers().get("LoadBalancers", []):
                azs = lb.get("AvailabilityZones", [])
                if len(azs) < 2:
                    findings.append(Finding(
                        skill=self.name,
                        title=f"Single-AZ ALB/NLB: {lb['LoadBalancerName']}",
                        severity=Severity.HIGH, region=region,
                        resource_id=lb["LoadBalancerArn"],
                        description=f"Only {len(azs)} AZ(s) — no cross-AZ redundancy",
                        recommended_action="Add subnets in at least 2 AZs",
                        metadata={"wafr_pillar": "reliability"},
                    ))
        except Exception:
            pass
        return findings

    def _check_no_backups(self, region, profile):
        findings = []
        try:
            rds = get_client("rds", region, profile)
            for db in rds.describe_db_instances().get("DBInstances", []):
                if db.get("BackupRetentionPeriod", 0) == 0:
                    findings.append(Finding(
                        skill=self.name,
                        title=f"No backups: RDS {db['DBInstanceIdentifier']}",
                        severity=Severity.CRITICAL, region=region,
                        resource_id=db["DBInstanceIdentifier"],
                        description=f"Backup retention is 0 days — no automated backups",
                        recommended_action="Enable automated backups with at least 7-day retention",
                        metadata={"wafr_pillar": "reliability"},
                    ))
        except Exception:
            pass
        return findings

    def _check_no_autoscaling(self, region, profile):
        findings = []
        try:
            asg = get_client("autoscaling", region, profile)
            for group in asg.describe_auto_scaling_groups().get("AutoScalingGroups", []):
                if group["MinSize"] == group["MaxSize"]:
                    findings.append(Finding(
                        skill=self.name,
                        title=f"No auto-scaling: ASG {group['AutoScalingGroupName']}",
                        severity=Severity.MEDIUM, region=region,
                        resource_id=group["AutoScalingGroupName"],
                        description=f"Min={group['MinSize']} Max={group['MaxSize']} — cannot scale",
                        recommended_action="Set MaxSize > MinSize to enable scaling",
                        metadata={"wafr_pillar": "reliability"},
                    ))
        except Exception:
            pass
        return findings

    # === SECURITY PILLAR ===

    def _check_unencrypted_ebs(self, region, profile):
        findings = []
        try:
            ec2 = get_client("ec2", region, profile)
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for vol in page["Volumes"]:
                    if not vol.get("Encrypted", False) and vol["State"] == "in-use":
                        findings.append(Finding(
                            skill=self.name,
                            title=f"Unencrypted EBS: {vol['VolumeId']}",
                            severity=Severity.MEDIUM, region=region,
                            resource_id=vol["VolumeId"],
                            description=f"{vol['VolumeType']} | {vol['Size']}GB | attached, not encrypted",
                            recommended_action="Create encrypted snapshot and replace volume",
                            metadata={"wafr_pillar": "security"},
                        ))
        except Exception:
            pass
        return findings

    def _check_unencrypted_rds(self, region, profile):
        findings = []
        try:
            rds = get_client("rds", region, profile)
            for db in rds.describe_db_instances().get("DBInstances", []):
                if not db.get("StorageEncrypted", False):
                    findings.append(Finding(
                        skill=self.name,
                        title=f"Unencrypted RDS: {db['DBInstanceIdentifier']}",
                        severity=Severity.HIGH, region=region,
                        resource_id=db["DBInstanceIdentifier"],
                        description=f"{db['Engine']} — storage not encrypted at rest",
                        recommended_action="Create encrypted snapshot, restore to new encrypted instance",
                        metadata={"wafr_pillar": "security"},
                    ))
        except Exception:
            pass
        return findings

    def _check_no_vpc_flow_logs(self, region, profile):
        findings = []
        try:
            ec2 = get_client("ec2", region, profile)
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
            flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
            logged_vpcs = {fl["ResourceId"] for fl in flow_logs if fl["ResourceType"] == "VPC"}
            for vpc in vpcs:
                if vpc["VpcId"] not in logged_vpcs:
                    findings.append(Finding(
                        skill=self.name,
                        title=f"No VPC Flow Logs: {vpc['VpcId']}",
                        severity=Severity.MEDIUM, region=region,
                        resource_id=vpc["VpcId"],
                        description="VPC has no flow logs enabled — no network visibility",
                        recommended_action="Enable VPC Flow Logs to CloudWatch or S3",
                        metadata={"wafr_pillar": "security"},
                    ))
        except Exception:
            pass
        return findings

    # === PERFORMANCE PILLAR ===

    def _check_old_gen_instances(self, region, profile):
        OLD_GENS = {"m4", "m3", "c4", "c3", "r4", "r3", "t2", "i2", "d2"}
        findings = []
        try:
            ec2 = get_client("ec2", region, profile)
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
                for res in page["Reservations"]:
                    for inst in res["Instances"]:
                        family = inst["InstanceType"].split(".")[0]
                        if family in OLD_GENS:
                            name = ""
                            for t in inst.get("Tags", []):
                                if t["Key"] == "Name":
                                    name = t["Value"]
                            findings.append(Finding(
                                skill=self.name,
                                title=f"Old-gen instance: {inst['InstanceId']}",
                                severity=Severity.LOW, region=region,
                                resource_id=inst["InstanceId"],
                                description=f"{inst['InstanceType']} | {name} — consider upgrading to current gen",
                                recommended_action=f"Migrate from {family} to latest gen (Graviton for best price-perf)",
                                metadata={"wafr_pillar": "performance", "instance_type": inst["InstanceType"]},
                            ))
        except Exception:
            pass
        return findings

    # === OPERATIONAL EXCELLENCE ===

    def _check_missing_alarms(self, region, profile):
        findings = []
        try:
            ec2 = get_client("ec2", region, profile)
            cw = get_client("cloudwatch", region, profile)
            # Get running instances
            instances = []
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
                for res in page["Reservations"]:
                    for inst in res["Instances"]:
                        instances.append(inst["InstanceId"])
            # Get alarms
            alarmed = set()
            paginator = cw.get_paginator("describe_alarms")
            for page in paginator.paginate(StateValue="OK"):
                for alarm in page.get("MetricAlarms", []):
                    for dim in alarm.get("Dimensions", []):
                        if dim["Name"] == "InstanceId":
                            alarmed.add(dim["Value"])
            # Also check ALARM state
            for page in paginator.paginate(StateValue="ALARM"):
                for alarm in page.get("MetricAlarms", []):
                    for dim in alarm.get("Dimensions", []):
                        if dim["Name"] == "InstanceId":
                            alarmed.add(dim["Value"])

            unmonitored = [i for i in instances if i not in alarmed]
            if len(unmonitored) > 0 and len(instances) > 0:
                pct = len(unmonitored) / len(instances) * 100
                if pct > 50:
                    findings.append(Finding(
                        skill=self.name,
                        title=f"{len(unmonitored)}/{len(instances)} EC2 instances have no CloudWatch alarms",
                        severity=Severity.MEDIUM, region=region,
                        description=f"{pct:.0f}% of running instances have no alarms configured",
                        recommended_action="Add CPU/StatusCheck alarms for all production instances",
                        metadata={"wafr_pillar": "ops", "unmonitored": len(unmonitored), "total": len(instances)},
                    ))
        except Exception:
            pass
        return findings

    def _check_no_tags(self, region, profile):
        findings = []
        try:
            ec2 = get_client("ec2", region, profile)
            untagged = 0
            total = 0
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
                for res in page["Reservations"]:
                    for inst in res["Instances"]:
                        total += 1
                        tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                        if "Environment" not in tags and "env" not in tags and "Team" not in tags and "Owner" not in tags:
                            untagged += 1
            if untagged > 0 and total > 0:
                pct = untagged / total * 100
                if pct > 30:
                    findings.append(Finding(
                        skill=self.name,
                        title=f"{untagged}/{total} instances missing standard tags",
                        severity=Severity.LOW, region=region,
                        description=f"{pct:.0f}% missing Environment/Team/Owner tags",
                        recommended_action="Implement tagging strategy for cost allocation and ownership",
                        metadata={"wafr_pillar": "ops", "untagged": untagged, "total": total},
                    ))
        except Exception:
            pass
        return findings

    # === SUSTAINABILITY PILLAR ===

    def _check_graviton_eligible(self, region, profile):
        """Flag x86 instances where a Graviton equivalent exists for better energy efficiency."""
        GRAVITON_MAP = {
            "m5": "m7g", "m6i": "m7g", "c5": "c7g", "c6i": "c7g",
            "r5": "r7g", "r6i": "r7g", "t3": "t4g", "t3a": "t4g",
            "m5a": "m7g", "c5a": "c7g", "r5a": "r7g",
            "t2": "t4g", "m4": "m7g", "m3": "m7g",
            "c4": "c7g", "c3": "c7g", "r4": "r7g", "r3": "r7g",
        }
        findings = []
        try:
            ec2 = get_client("ec2", region, profile)
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
                for res in page["Reservations"]:
                    for inst in res["Instances"]:
                        itype = inst["InstanceType"]
                        family = itype.split(".")[0]
                        if family in GRAVITON_MAP:
                            size = itype.split(".")[1]
                            graviton_type = f"{GRAVITON_MAP[family]}.{size}"
                            name = ""
                            for t in inst.get("Tags", []):
                                if t["Key"] == "Name":
                                    name = t["Value"]
                            findings.append(Finding(
                                skill=self.name,
                                title=f"Graviton eligible: {inst['InstanceId']}",
                                severity=Severity.LOW, region=region,
                                resource_id=inst["InstanceId"],
                                description=f"{itype} | {name} — migrate to {graviton_type} for ~20% cost savings and better energy efficiency",
                                recommended_action=f"Migrate to {graviton_type} (Graviton, ARM64)",
                                metadata={"wafr_pillar": "sustainability", "current_type": itype, "suggested_type": graviton_type},
                            ))
        except Exception:
            pass
        return findings

    def _check_oversized_instances(self, region, profile):
        """Flag instances with consistently low CPU that could be downsized."""
        from datetime import datetime, timedelta, timezone
        findings = []
        try:
            ec2 = get_client("ec2", region, profile)
            cw = get_client("cloudwatch", region, profile)
            end = datetime.now(timezone.utc)
            start = end - timedelta(days=14)
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
                for res in page["Reservations"]:
                    for inst in res["Instances"]:
                        itype = inst["InstanceType"]
                        iid = inst["InstanceId"]
                        size = itype.split(".")[-1]
                        if size in ("nano", "micro", "small", "medium"):
                            continue
                        try:
                            resp = cw.get_metric_statistics(
                                Namespace="AWS/EC2", MetricName="CPUUtilization",
                                Dimensions=[{"Name": "InstanceId", "Value": iid}],
                                StartTime=start, EndTime=end, Period=86400, Statistics=["Average"],
                            )
                            pts = resp.get("Datapoints", [])
                            if not pts:
                                continue
                            avg = sum(p["Average"] for p in pts) / len(pts)
                            if avg < 10:
                                name = ""
                                for t in inst.get("Tags", []):
                                    if t["Key"] == "Name":
                                        name = t["Value"]
                                findings.append(Finding(
                                    skill=self.name,
                                    title=f"Oversized instance: {iid}",
                                    severity=Severity.LOW, region=region,
                                    resource_id=iid,
                                    description=f"{itype} | {name} | Avg CPU: {avg:.1f}% over 14 days — consider downsizing",
                                    recommended_action="Right-size to a smaller instance type to reduce cost and energy footprint",
                                    metadata={"wafr_pillar": "sustainability", "instance_type": itype, "avg_cpu": round(avg, 1)},
                                ))
                        except Exception:
                            pass
        except Exception:
            pass
        return findings


SkillRegistry.register(ResiliencyGapsSkill())
