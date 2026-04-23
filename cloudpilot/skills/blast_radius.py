"""Incident & Blast Radius — dependency mapping, SPOF analysis,
blast radius calculation for infrastructure failures."""
import logging
import time
from collections import defaultdict

from cloudpilot.core import BaseSkill, Finding, Severity, SkillResult, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions

logger = logging.getLogger(__name__)


class BlastRadiusSkill(BaseSkill):
    name = "blast-radius"
    description = "Dependency mapping, SPOF analysis, blast radius calculation"
    version = "0.1.0"

    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        acct = account_id or get_account_id(profile)
        region_results = parallel_regions(
            lambda r, p: self._collect(r, p), regions, profile=profile)
        data = self._merge(region_results)
        findings = self._run_checks(data)
        for f in findings:
            f.account_id = acct
        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=time.time() - start,
            accounts_scanned=1, regions_scanned=len(regions),
            errors=data.get("errors", []))

    def _collect(self, region, profile=None):
        data = {"elbs": [], "target_groups": [], "asgs": [], "rds": [],
                "single_az_resources": [], "errors": [], "region": region}
        # ELBs + target groups
        try:
            elbv2 = get_client("elbv2", region, profile)
            lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
            for lb in lbs:
                arn = lb.get("LoadBalancerArn", "")
                azs = [az.get("ZoneName", "") for az in lb.get("AvailabilityZones", [])]
                data["elbs"].append({
                    "name": lb.get("LoadBalancerName", ""), "arn": arn,
                    "type": lb.get("Type", ""), "scheme": lb.get("Scheme", ""),
                    "az_count": len(azs), "azs": azs, "region": region,
                })
                # Target groups
                try:
                    tgs = elbv2.describe_target_groups(LoadBalancerArn=arn).get("TargetGroups", [])
                    for tg in tgs:
                        tg_arn = tg.get("TargetGroupArn", "")
                        try:
                            health = elbv2.describe_target_health(TargetGroupArn=tg_arn)
                            targets = health.get("TargetHealthDescriptions", [])
                            healthy = sum(1 for t in targets if t.get("TargetHealth", {}).get("State") == "healthy")
                            data["target_groups"].append({
                                "name": tg.get("TargetGroupName", ""), "arn": tg_arn,
                                "lb_name": lb.get("LoadBalancerName", ""),
                                "total_targets": len(targets), "healthy_targets": healthy,
                                "region": region,
                            })
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception as e:
            logger.warning("ELBv2 in %s: %s", region, e)
            data["errors"].append(f"elbv2 in {region}: {e}")
        # ASGs
        try:
            asg = get_client("autoscaling", region, profile)
            groups = asg.describe_auto_scaling_groups().get("AutoScalingGroups", [])
            for g in groups:
                azs = g.get("AvailabilityZones", [])
                data["asgs"].append({
                    "name": g.get("AutoScalingGroupName", ""),
                    "min": g.get("MinSize", 0), "max": g.get("MaxSize", 0),
                    "desired": g.get("DesiredCapacity", 0),
                    "az_count": len(azs), "azs": azs,
                    "instances": len(g.get("Instances", [])),
                    "region": region,
                })
        except Exception as e:
            logger.warning("ASG in %s: %s", region, e)
            data["errors"].append(f"autoscaling in {region}: {e}")
        # RDS single-AZ
        try:
            rds = get_client("rds", region, profile)
            for page in rds.get_paginator("describe_db_instances").paginate():
                for db in page.get("DBInstances", []):
                    if not db.get("MultiAZ", False):
                        data["single_az_resources"].append({
                            "type": "rds", "id": db["DBInstanceIdentifier"],
                            "engine": db.get("Engine", ""), "region": region,
                        })
        except Exception as e:
            logger.warning("RDS in %s: %s", region, e)
            data["errors"].append(f"rds in {region}: {e}")
        return data

    def _merge(self, results):
        merged = {"elbs": [], "target_groups": [], "asgs": [],
                  "rds": [], "single_az_resources": [], "errors": []}
        for rd in (results if isinstance(results, list) else []):
            if isinstance(rd, dict):
                for k in merged:
                    merged[k].extend(rd.get(k, []))
        return merged

    def _run_checks(self, data):
        findings = []
        for checker in [self._check_single_az_elb, self._check_single_target,
                        self._check_single_az_asg, self._check_single_az_db,
                        self._check_no_autoscaling]:
            try:
                findings.extend(checker(data))
            except Exception as e:
                logger.warning("Checker failed: %s", e)
        return findings

    def _check_single_az_elb(self, data):
        """ELBs in only one AZ = single point of failure."""
        findings = []
        for elb in data.get("elbs", []):
            if elb.get("az_count", 0) <= 1:
                findings.append(Finding(
                    skill=self.name, title=f"Single-AZ load balancer: {elb['name']}",
                    severity=Severity.HIGH, resource_id=elb["name"], region=elb["region"],
                    description=f"ELB {elb['name']} is in only {elb['az_count']} AZ — AZ failure takes it down",
                    recommended_action="Add subnets in additional AZs",
                    metadata={"elb_name": elb["name"], "azs": elb.get("azs", []),
                              "blast_radius": "all traffic behind this LB"}))
        return findings

    def _check_single_target(self, data):
        """Target groups with only 1 healthy target = SPOF."""
        findings = []
        for tg in data.get("target_groups", []):
            if tg.get("healthy_targets", 0) <= 1 and tg.get("total_targets", 0) >= 1:
                findings.append(Finding(
                    skill=self.name, title=f"Single healthy target: {tg['name']}",
                    severity=Severity.HIGH, resource_id=tg["name"], region=tg["region"],
                    description=f"Target group {tg['name']} (LB: {tg['lb_name']}) has only {tg['healthy_targets']} healthy target(s)",
                    recommended_action="Add more targets or enable auto-scaling",
                    metadata={"target_group": tg["name"], "lb_name": tg["lb_name"],
                              "healthy": tg["healthy_targets"], "total": tg["total_targets"],
                              "blast_radius": f"all traffic from {tg['lb_name']}"}))
        return findings

    def _check_single_az_asg(self, data):
        """ASGs in only one AZ."""
        findings = []
        for asg in data.get("asgs", []):
            if asg.get("az_count", 0) <= 1:
                findings.append(Finding(
                    skill=self.name, title=f"Single-AZ ASG: {asg['name']}",
                    severity=Severity.MEDIUM, resource_id=asg["name"], region=asg["region"],
                    description=f"ASG {asg['name']} spans only {asg['az_count']} AZ with {asg['instances']} instances",
                    recommended_action="Add additional AZs to the ASG for resilience",
                    metadata={"asg_name": asg["name"], "azs": asg.get("azs", []),
                              "instances": asg["instances"],
                              "blast_radius": f"{asg['instances']} instances"}))
        return findings

    def _check_single_az_db(self, data):
        """Single-AZ RDS instances."""
        findings = []
        for res in data.get("single_az_resources", []):
            if res["type"] == "rds":
                findings.append(Finding(
                    skill=self.name, title=f"Single-AZ database: {res['id']}",
                    severity=Severity.HIGH, resource_id=res["id"], region=res["region"],
                    description=f"RDS {res['id']} ({res['engine']}) is single-AZ — AZ failure causes downtime",
                    recommended_action="Enable Multi-AZ for production databases",
                    metadata={"instance": res["id"], "engine": res["engine"],
                              "blast_radius": "database unavailable during AZ failure"}))
        return findings

    def _check_no_autoscaling(self, data):
        """ASGs with min == max == desired (no scaling)."""
        findings = []
        for asg in data.get("asgs", []):
            if asg["min"] == asg["max"] == asg["desired"] and asg["desired"] > 0:
                findings.append(Finding(
                    skill=self.name, title=f"No autoscaling: {asg['name']}",
                    severity=Severity.MEDIUM, resource_id=asg["name"], region=asg["region"],
                    description=f"ASG {asg['name']} has min=max=desired={asg['desired']} — cannot scale on demand",
                    recommended_action="Configure min < max to allow auto-scaling",
                    metadata={"asg_name": asg["name"], "min": asg["min"],
                              "max": asg["max"], "desired": asg["desired"]}))
        return findings


SkillRegistry.register(BlastRadiusSkill())
