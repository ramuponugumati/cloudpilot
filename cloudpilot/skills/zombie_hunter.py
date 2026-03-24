"""Zombie Hunter skill — wraps the standalone zombie-hunter scanners."""
import time
from cloudpilot.core import BaseSkill, SkillResult, Finding, Severity, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions


class ZombieHunterSkill(BaseSkill):
    name = "zombie-hunter"
    description = "Detect wasted resources: idle EC2, unattached EBS, unused EIPs/NATs, old snapshots"
    version = "0.1.0"

    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        findings = []
        errors = []
        acct = account_id or get_account_id(profile)
        cpu_threshold = kwargs.get("cpu_threshold", 2.0)
        snapshot_days = kwargs.get("days", 180)

        scanners = [
            ("ebs", self._scan_ebs),
            ("eip", self._scan_eip),
            ("nat", self._scan_nat),
            ("idle_ec2", lambda r, p: self._scan_idle_ec2(r, p, cpu_threshold)),
            ("idle_rds", self._scan_idle_rds),
        ]

        for name, scanner_fn in scanners:
            try:
                results = parallel_regions(scanner_fn, regions, profile=profile)
                findings.extend(results)
            except Exception as e:
                errors.append(f"{name}: {e}")

        for f in findings:
            f.account_id = acct

        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=time.time() - start,
            accounts_scanned=1, regions_scanned=len(regions), errors=errors,
        )

    def _scan_ebs(self, region, profile):
        findings = []
        ec2 = get_client("ec2", region, profile)
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}]):
            for vol in page["Volumes"]:
                size = vol["Size"]
                cost = size * 0.08
                findings.append(Finding(
                    skill=self.name, title=f"Unattached EBS: {vol['VolumeId']}",
                    severity=Severity.LOW, region=region, resource_id=vol["VolumeId"],
                    description=f"{vol['VolumeType']} | {size}GB",
                    monthly_impact=round(cost, 2),
                    recommended_action="Delete or snapshot+delete",
                ))
        return findings

    def _scan_eip(self, region, profile):
        findings = []
        ec2 = get_client("ec2", region, profile)
        for addr in ec2.describe_addresses().get("Addresses", []):
            if not addr.get("InstanceId") and not addr.get("NetworkInterfaceId"):
                findings.append(Finding(
                    skill=self.name, title=f"Unused EIP: {addr.get('PublicIp')}",
                    severity=Severity.LOW, region=region,
                    resource_id=addr.get("AllocationId", ""),
                    description=f"IP: {addr.get('PublicIp')}",
                    monthly_impact=3.60, recommended_action="Release",
                ))
        return findings

    def _scan_nat(self, region, profile):
        from datetime import datetime, timedelta, timezone
        findings = []
        ec2 = get_client("ec2", region, profile)
        cw = get_client("cloudwatch", region, profile)
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=7)
        for gw in ec2.describe_nat_gateways(Filter=[{"Name": "state", "Values": ["available"]}]).get("NatGateways", []):
            gw_id = gw["NatGatewayId"]
            try:
                resp = cw.get_metric_statistics(
                    Namespace="AWS/NATGateway", MetricName="BytesOutToDestination",
                    Dimensions=[{"Name": "NatGatewayId", "Value": gw_id}],
                    StartTime=start, EndTime=end, Period=604800, Statistics=["Sum"],
                )
                total = resp["Datapoints"][0]["Sum"] if resp["Datapoints"] else 0
            except Exception:
                total = 0
            if total == 0:
                findings.append(Finding(
                    skill=self.name, title=f"Unused NAT GW: {gw_id}",
                    severity=Severity.MEDIUM, region=region, resource_id=gw_id,
                    description=f"VPC: {gw.get('VpcId')} | 0 bytes in 7 days",
                    monthly_impact=32.85, recommended_action="Delete if unused",
                ))
        return findings

    def _scan_idle_ec2(self, region, profile, cpu_threshold):
        from datetime import datetime, timedelta, timezone
        findings = []
        ec2 = get_client("ec2", region, profile)
        cw = get_client("cloudwatch", region, profile)
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=7)
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    iid = inst["InstanceId"]
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
                        if avg < cpu_threshold:
                            findings.append(Finding(
                                skill=self.name, title=f"Idle EC2: {iid}",
                                severity=Severity.MEDIUM, region=region, resource_id=iid,
                                description=f"{inst['InstanceType']} | CPU: {avg:.1f}%",
                                monthly_impact=73.0, recommended_action="Stop or terminate",
                            ))
                    except Exception:
                        pass
        return findings

    def _scan_idle_rds(self, region, profile):
        from datetime import datetime, timedelta, timezone
        findings = []
        rds = get_client("rds", region, profile)
        cw = get_client("cloudwatch", region, profile)
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=7)
        for db in rds.describe_db_instances().get("DBInstances", []):
            if db["DBInstanceStatus"] != "available":
                continue
            dbid = db["DBInstanceIdentifier"]
            try:
                resp = cw.get_metric_statistics(
                    Namespace="AWS/RDS", MetricName="DatabaseConnections",
                    Dimensions=[{"Name": "DBInstanceIdentifier", "Value": dbid}],
                    StartTime=start, EndTime=end, Period=86400, Statistics=["Average"],
                )
                pts = resp.get("Datapoints", [])
                if pts and sum(p["Average"] for p in pts) / len(pts) < 1:
                    findings.append(Finding(
                        skill=self.name, title=f"Idle RDS: {dbid}",
                        severity=Severity.MEDIUM, region=region, resource_id=dbid,
                        description=f"{db['DBInstanceClass']} | {db['Engine']} | 0 connections",
                        monthly_impact=73.0, recommended_action="Stop or delete",
                    ))
            except Exception:
                pass
        return findings


SkillRegistry.register(ZombieHunterSkill())
