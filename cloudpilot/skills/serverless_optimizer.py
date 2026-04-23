"""Serverless Optimization — Lambda memory/timeout tuning, cold start analysis,
Step Functions cost, API Gateway configuration."""
import logging
import time

from cloudpilot.core import BaseSkill, Finding, Severity, SkillResult, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions

logger = logging.getLogger(__name__)

MEMORY_OVERSIZED_THRESHOLD = 512  # MB — flag if memory > this and invocations low
TIMEOUT_MAX_RECOMMENDED = 300  # seconds
COLD_START_RUNTIMES = {"java11", "java17", "java21", "dotnet6", "dotnet8"}


class ServerlessOptimizerSkill(BaseSkill):
    name = "serverless-optimizer"
    description = "Lambda memory/timeout tuning, cold start analysis, Step Functions cost optimization"
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
        data = {"functions": [], "step_functions": [], "errors": [], "region": region}
        # Lambda functions
        try:
            lam = get_client("lambda", region, profile)
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []):
                    data["functions"].append({
                        "name": fn["FunctionName"], "runtime": fn.get("Runtime", ""),
                        "memory": fn.get("MemorySize", 128), "timeout": fn.get("Timeout", 3),
                        "code_size": fn.get("CodeSize", 0), "handler": fn.get("Handler", ""),
                        "layers": len(fn.get("Layers", [])),
                        "architectures": fn.get("Architectures", ["x86_64"]),
                        "arn": fn.get("FunctionArn", ""), "region": region,
                    })
        except Exception as e:
            logger.warning("Lambda in %s: %s", region, e)
            data["errors"].append(f"lambda in {region}: {e}")
        # Step Functions
        try:
            sfn = get_client("stepfunctions", region, profile)
            machines = sfn.list_state_machines().get("stateMachines", [])
            for sm in machines:
                data["step_functions"].append({
                    "name": sm.get("name", ""), "arn": sm.get("stateMachineArn", ""),
                    "type": sm.get("type", "STANDARD"), "region": region,
                })
        except Exception as e:
            logger.warning("StepFunctions in %s: %s", region, e)
            data["errors"].append(f"stepfunctions in {region}: {e}")
        return data

    def _merge(self, results):
        merged = {"functions": [], "step_functions": [], "errors": []}
        for rd in (results if isinstance(results, list) else []):
            if isinstance(rd, dict):
                for k in merged:
                    merged[k].extend(rd.get(k, []))
        return merged

    def _run_checks(self, data):
        findings = []
        for fn in data.get("functions", []):
            findings.extend(self._check_lambda(fn))
        for sm in data.get("step_functions", []):
            findings.extend(self._check_step_function(sm))
        return findings

    def _check_lambda(self, fn):
        findings = []
        name, region = fn["name"], fn["region"]
        runtime = fn.get("runtime", "")
        memory = fn.get("memory", 128)
        timeout = fn.get("timeout", 3)
        code_size = fn.get("code_size", 0)
        archs = fn.get("architectures", ["x86_64"])

        # Memory optimization
        if memory > MEMORY_OVERSIZED_THRESHOLD:
            findings.append(Finding(
                skill=self.name, title=f"Lambda high memory: {name}",
                severity=Severity.MEDIUM, resource_id=name, region=region,
                description=f"Lambda {name} has {memory}MB memory — consider right-sizing with Lambda Power Tuning",
                recommended_action="Run AWS Lambda Power Tuning to find optimal memory",
                metadata={"function": name, "memory_mb": memory, "runtime": runtime}))

        # Timeout
        if timeout >= TIMEOUT_MAX_RECOMMENDED:
            findings.append(Finding(
                skill=self.name, title=f"Lambda max timeout: {name}",
                severity=Severity.MEDIUM, resource_id=name, region=region,
                description=f"Lambda {name} has {timeout}s timeout (max recommended: {TIMEOUT_MAX_RECOMMENDED}s)",
                recommended_action="Review if function needs such a long timeout or refactor to async",
                metadata={"function": name, "timeout_seconds": timeout}))

        # Cold start risk
        if runtime in COLD_START_RUNTIMES:
            findings.append(Finding(
                skill=self.name, title=f"Cold start risk: {name}",
                severity=Severity.LOW, resource_id=name, region=region,
                description=f"Lambda {name} uses {runtime} which has higher cold start times",
                recommended_action="Consider provisioned concurrency or SnapStart (Java)",
                metadata={"function": name, "runtime": runtime}))

        # Large code size
        if code_size > 50_000_000:  # 50MB
            findings.append(Finding(
                skill=self.name, title=f"Lambda large package: {name}",
                severity=Severity.LOW, resource_id=name, region=region,
                description=f"Lambda {name} has {code_size // 1_000_000}MB deployment package",
                recommended_action="Reduce package size with layers or tree-shaking",
                metadata={"function": name, "code_size_mb": code_size // 1_000_000}))

        # Graviton (ARM) eligibility
        if "x86_64" in archs and "arm64" not in archs:
            findings.append(Finding(
                skill=self.name, title=f"Lambda Graviton eligible: {name}",
                severity=Severity.LOW, resource_id=name, region=region,
                description=f"Lambda {name} runs on x86_64 — Graviton (arm64) offers ~20% cost savings",
                recommended_action="Test with arm64 architecture for cost savings",
                metadata={"function": name, "current_arch": "x86_64"}))

        return findings

    def _check_step_function(self, sm):
        findings = []
        name, region = sm["name"], sm["region"]
        sf_type = sm.get("type", "STANDARD")
        if sf_type == "STANDARD":
            findings.append(Finding(
                skill=self.name, title=f"Step Function STANDARD type: {name}",
                severity=Severity.LOW, resource_id=name, region=region,
                description=f"State machine {name} uses STANDARD type — consider EXPRESS for high-volume short workflows",
                recommended_action="Evaluate if EXPRESS type is suitable for cost savings",
                metadata={"state_machine": name, "type": sf_type}))
        return findings


SkillRegistry.register(ServerlessOptimizerSkill())
