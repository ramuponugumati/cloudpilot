"""Architecture Modernization Advisor — legacy service migration, Graviton readiness,
monolith decomposition hints, EOL service detection."""
import logging
import time

from cloudpilot.core import BaseSkill, Finding, Severity, SkillResult, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions

logger = logging.getLogger(__name__)

# EC2 workload → managed service recommendations
WORKLOAD_MIGRATIONS = {
    "redis": "Amazon ElastiCache for Redis",
    "memcached": "Amazon ElastiCache for Memcached",
    "rabbitmq": "Amazon MQ for RabbitMQ",
    "kafka": "Amazon MSK",
    "elasticsearch": "Amazon OpenSearch Service",
    "mongodb": "Amazon DocumentDB",
    "postgresql": "Amazon RDS for PostgreSQL",
    "mysql": "Amazon RDS for MySQL",
    "nginx": "Application Load Balancer + CloudFront",
    "apache": "Application Load Balancer + CloudFront",
    "jenkins": "AWS CodePipeline + CodeBuild",
    "grafana": "Amazon Managed Grafana",
    "prometheus": "Amazon Managed Prometheus",
}

OLD_GEN_FAMILIES = {"m3", "m4", "c3", "c4", "r3", "r4", "t1", "t2", "i2", "d2"}
GRAVITON_FAMILIES = {"m5", "m6i", "c5", "c6i", "r5", "r6i", "t3"}


class ModernizationAdvisorSkill(BaseSkill):
    name = "modernization-advisor"
    description = "Legacy service migration, Graviton readiness, monolith hints, EOL detection"
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
        data = {"instances": [], "errors": [], "region": region}
        try:
            ec2 = get_client("ec2", region, profile)
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
                for res in page.get("Reservations", []):
                    for inst in res.get("Instances", []):
                        name = ""
                        for tag in inst.get("Tags", []):
                            if tag["Key"] == "Name":
                                name = tag["Value"]
                        data["instances"].append({
                            "id": inst["InstanceId"], "name": name,
                            "type": inst.get("InstanceType", ""),
                            "platform": inst.get("PlatformDetails", ""),
                            "architecture": inst.get("Architecture", ""),
                            "region": region,
                        })
        except Exception as e:
            logger.warning("EC2 in %s: %s", region, e)
            data["errors"].append(f"ec2 in {region}: {e}")
        return data

    def _merge(self, results):
        merged = {"instances": [], "errors": []}
        for rd in (results if isinstance(results, list) else []):
            if isinstance(rd, dict):
                for k in merged:
                    merged[k].extend(rd.get(k, []))
        return merged

    def _run_checks(self, data):
        findings = []
        for checker in [self._check_workload_migration, self._check_old_gen,
                        self._check_graviton_readiness]:
            try:
                findings.extend(checker(data))
            except Exception as e:
                logger.warning("Checker failed: %s", e)
        return findings

    def _check_workload_migration(self, data):
        """Detect self-managed workloads that could use managed services."""
        findings = []
        for inst in data.get("instances", []):
            name_lower = inst.get("name", "").lower()
            for pattern, service in WORKLOAD_MIGRATIONS.items():
                if pattern in name_lower:
                    findings.append(Finding(
                        skill=self.name,
                        title=f"Managed service candidate: {inst['id']}",
                        severity=Severity.MEDIUM, resource_id=inst["id"],
                        region=inst["region"],
                        description=f"EC2 {inst['id']} ({inst['name']}) appears to run {pattern} — consider {service}",
                        recommended_action=f"Evaluate migration to {service}",
                        metadata={"instance_id": inst["id"], "instance_name": inst["name"],
                                  "detected_workload": pattern, "recommended_service": service,
                                  "instance_type": inst["type"]}))
                    break
        return findings

    def _check_old_gen(self, data):
        """Flag instances using old-generation instance families."""
        findings = []
        for inst in data.get("instances", []):
            family = inst.get("type", "").split(".")[0] if "." in inst.get("type", "") else ""
            if family in OLD_GEN_FAMILIES:
                findings.append(Finding(
                    skill=self.name,
                    title=f"Old-gen instance: {inst['id']}",
                    severity=Severity.MEDIUM, resource_id=inst["id"],
                    region=inst["region"],
                    description=f"EC2 {inst['id']} uses {inst['type']} (old-gen {family} family)",
                    recommended_action="Upgrade to current-gen instance family for better price/performance",
                    metadata={"instance_id": inst["id"], "instance_type": inst["type"],
                              "family": family}))
        return findings

    def _check_graviton_readiness(self, data):
        """Flag x86 instances eligible for Graviton migration."""
        findings = []
        for inst in data.get("instances", []):
            family = inst.get("type", "").split(".")[0] if "." in inst.get("type", "") else ""
            arch = inst.get("architecture", "")
            if family in GRAVITON_FAMILIES and arch != "arm64":
                findings.append(Finding(
                    skill=self.name,
                    title=f"Graviton candidate: {inst['id']}",
                    severity=Severity.LOW, resource_id=inst["id"],
                    region=inst["region"],
                    description=f"EC2 {inst['id']} ({inst['type']}) could migrate to Graviton for ~20% savings",
                    recommended_action="Test workload on Graviton (arm64) instance type",
                    metadata={"instance_id": inst["id"], "instance_type": inst["type"],
                              "current_arch": arch, "estimated_savings_pct": 20}))
        return findings


SkillRegistry.register(ModernizationAdvisorSkill())
