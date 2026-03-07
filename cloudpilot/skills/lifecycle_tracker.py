"""Service Lifecycle Tracker — flag deprecated runtimes, EOL engines, and outdated platforms."""
import time
from cloudpilot.core import BaseSkill, SkillResult, Finding, Severity, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions

# Deprecated/EOL Lambda runtimes as of 2025
DEPRECATED_RUNTIMES = {
    "python3.7": {"eol": "2023-12-04", "severity": "critical", "upgrade": "python3.12"},
    "python3.8": {"eol": "2024-10-14", "severity": "high", "upgrade": "python3.12"},
    "python3.9": {"eol": "2025-10-01", "severity": "medium", "upgrade": "python3.12"},
    "nodejs14.x": {"eol": "2024-01-09", "severity": "critical", "upgrade": "nodejs20.x"},
    "nodejs16.x": {"eol": "2024-06-12", "severity": "critical", "upgrade": "nodejs20.x"},
    "nodejs18.x": {"eol": "2025-07-31", "severity": "medium", "upgrade": "nodejs22.x"},
    "dotnet6": {"eol": "2024-12-20", "severity": "high", "upgrade": "dotnet8"},
    "ruby3.2": {"eol": "2025-06-30", "severity": "medium", "upgrade": "ruby3.3"},
    "java8.al2": {"eol": "2025-02-01", "severity": "high", "upgrade": "java21"},
    "java11": {"eol": "2025-08-01", "severity": "medium", "upgrade": "java21"},
    "go1.x": {"eol": "2024-01-08", "severity": "critical", "upgrade": "provided.al2023"},
}

# EOL RDS engine versions
EOL_RDS_ENGINES = {
    "mysql": {"eol_versions": ["5.7"], "upgrade": "8.0", "severity": "critical"},
    "postgres": {"eol_versions": ["11", "12", "13"], "upgrade": "16", "severity": "high"},
    "mariadb": {"eol_versions": ["10.3", "10.4"], "upgrade": "10.11", "severity": "high"},
    "aurora-mysql": {"eol_versions": ["5.7"], "upgrade": "8.0", "severity": "critical"},
    "aurora-postgresql": {"eol_versions": ["11", "12", "13"], "upgrade": "16", "severity": "high"},
}


class LifecycleTrackerSkill(BaseSkill):
    name = "lifecycle-tracker"
    description = "Flag deprecated Lambda runtimes, EOL RDS engines, and outdated ECS platforms"
    version = "0.1.0"

    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        findings = []
        errors = []
        acct = account_id or get_account_id(profile)

        # Lambda runtimes (per region)
        try:
            results = parallel_regions(lambda r: self._check_lambda_runtimes(r, profile), regions)
            findings.extend(results)
        except Exception as e:
            errors.append(f"lambda: {e}")

        # RDS engine versions (per region)
        try:
            results = parallel_regions(lambda r: self._check_rds_engines(r, profile), regions)
            findings.extend(results)
        except Exception as e:
            errors.append(f"rds: {e}")

        # ECS Fargate platform versions (per region)
        try:
            results = parallel_regions(lambda r: self._check_ecs_platforms(r, profile), regions)
            findings.extend(results)
        except Exception as e:
            errors.append(f"ecs: {e}")

        for f in findings:
            f.account_id = acct

        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=time.time() - start,
            accounts_scanned=1, regions_scanned=len(regions), errors=errors,
        )

    def _check_lambda_runtimes(self, region, profile):
        findings = []
        try:
            lam = get_client("lambda", region, profile)
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page["Functions"]:
                    runtime = fn.get("Runtime", "")
                    if runtime in DEPRECATED_RUNTIMES:
                        info = DEPRECATED_RUNTIMES[runtime]
                        sev = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM}.get(info["severity"], Severity.LOW)
                        findings.append(Finding(
                            skill=self.name,
                            title=f"Deprecated runtime: {fn['FunctionName']}",
                            severity=sev, region=region,
                            resource_id=fn["FunctionName"],
                            description=f"{runtime} (EOL: {info['eol']}) — upgrade to {info['upgrade']}",
                            recommended_action=f"Update runtime to {info['upgrade']}",
                            metadata={"resource_type": "lambda", "runtime": runtime, "eol": info["eol"], "upgrade_to": info["upgrade"], "arn": fn["FunctionArn"]},
                        ))
        except Exception:
            pass
        return findings

    def _check_rds_engines(self, region, profile):
        findings = []
        try:
            rds = get_client("rds", region, profile)
            for db in rds.describe_db_instances().get("DBInstances", []):
                engine = db["Engine"]
                version = db["EngineVersion"]
                major = version.split(".")[0] if "." in version else version
                major_minor = ".".join(version.split(".")[:2]) if "." in version else version

                engine_info = EOL_RDS_ENGINES.get(engine)
                if not engine_info:
                    continue
                eol_versions = engine_info["eol_versions"]
                if major in eol_versions or major_minor in eol_versions:
                    sev = {"critical": Severity.CRITICAL, "high": Severity.HIGH}.get(engine_info["severity"], Severity.MEDIUM)
                    findings.append(Finding(
                        skill=self.name,
                        title=f"EOL RDS engine: {db['DBInstanceIdentifier']}",
                        severity=sev, region=region,
                        resource_id=db["DBInstanceIdentifier"],
                        description=f"{engine} {version} — upgrade to {engine_info['upgrade']}",
                        recommended_action=f"Upgrade to {engine} {engine_info['upgrade']}",
                        metadata={"resource_type": "rds", "engine": engine, "version": version, "upgrade_to": engine_info["upgrade"]},
                    ))
        except Exception:
            pass
        return findings

    def _check_ecs_platforms(self, region, profile):
        findings = []
        try:
            ecs = get_client("ecs", region, profile)
            clusters = ecs.list_clusters().get("clusterArns", [])
            for cluster_arn in clusters:
                services = ecs.list_services(cluster=cluster_arn).get("serviceArns", [])
                if not services:
                    continue
                details = ecs.describe_services(cluster=cluster_arn, services=services[:10]).get("services", [])
                for svc in details:
                    if svc.get("launchType") != "FARGATE":
                        continue
                    pv = svc.get("platformVersion", "LATEST")
                    if pv not in ("LATEST", "1.4.0"):
                        findings.append(Finding(
                            skill=self.name,
                            title=f"Old Fargate platform: {svc['serviceName']}",
                            severity=Severity.LOW, region=region,
                            resource_id=svc["serviceName"],
                            description=f"Platform version {pv} — upgrade to 1.4.0 or LATEST",
                            recommended_action="Update service to use platform version LATEST",
                            metadata={"resource_type": "ecs", "platform_version": pv, "cluster": cluster_arn},
                        ))
        except Exception:
            pass
        return findings


SkillRegistry.register(LifecycleTrackerSkill())
