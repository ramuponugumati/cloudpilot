"""Secrets & DevOps Hygiene — secrets rotation, hardcoded secret detection,
Secrets Manager sprawl, Parameter Store sensitive values."""
import logging
import time
from datetime import datetime, timezone

from cloudpilot.core import BaseSkill, Finding, Severity, SkillResult, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions

logger = logging.getLogger(__name__)

ROTATION_MAX_DAYS = 90
UNUSED_SECRET_DAYS = 90


class SecretsHygieneSkill(BaseSkill):
    name = "secrets-hygiene"
    description = "Secrets rotation enforcement, Secrets Manager sprawl, Parameter Store sensitive values"
    version = "0.1.0"

    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        acct = account_id or get_account_id(profile)
        region_results = parallel_regions(
            lambda r, p: self._collect_region_data(r, p), regions, profile=profile)
        data = self._merge(region_results)
        findings = self._run_checks(data)
        for f in findings:
            f.account_id = acct
        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=time.time() - start,
            accounts_scanned=1, regions_scanned=len(regions),
            errors=data.get("errors", []))

    def _collect_region_data(self, region, profile=None):
        data = {"secrets": [], "parameters": [], "errors": [], "region": region}
        # Secrets Manager
        try:
            sm = get_client("secretsmanager", region, profile)
            paginator = sm.get_paginator("list_secrets")
            for page in paginator.paginate():
                for s in page.get("SecretList", []):
                    data["secrets"].append({
                        "name": s.get("Name", ""), "arn": s.get("ARN", ""),
                        "rotation_enabled": s.get("RotationEnabled", False),
                        "last_rotated": s.get("LastRotatedDate", "").isoformat() if hasattr(s.get("LastRotatedDate", ""), "isoformat") else str(s.get("LastRotatedDate", "")),
                        "last_accessed": s.get("LastAccessedDate", "").isoformat() if hasattr(s.get("LastAccessedDate", ""), "isoformat") else str(s.get("LastAccessedDate", "")),
                        "created": s.get("CreatedDate", "").isoformat() if hasattr(s.get("CreatedDate", ""), "isoformat") else "",
                        "tags": s.get("Tags", []),
                        "region": region,
                    })
        except Exception as e:
            logger.warning("SecretsManager in %s: %s", region, e)
            data["errors"].append(f"secretsmanager in {region}: {e}")
        # SSM Parameter Store — SecureString params
        try:
            ssm = get_client("ssm", region, profile)
            paginator = ssm.get_paginator("describe_parameters")
            for page in paginator.paginate(
                ParameterFilters=[{"Key": "Type", "Values": ["SecureString"]}]
            ):
                for p in page.get("Parameters", []):
                    data["parameters"].append({
                        "name": p.get("Name", ""), "type": p.get("Type", ""),
                        "last_modified": p.get("LastModifiedDate", "").isoformat() if hasattr(p.get("LastModifiedDate", ""), "isoformat") else "",
                        "version": p.get("Version", 1),
                        "region": region,
                    })
        except Exception as e:
            logger.warning("SSM params in %s: %s", region, e)
            data["errors"].append(f"ssm in {region}: {e}")
        return data

    def _merge(self, region_results):
        merged = {"secrets": [], "parameters": [], "errors": []}
        for rd in (region_results if isinstance(region_results, list) else []):
            if isinstance(rd, dict):
                for k in merged:
                    merged[k].extend(rd.get(k, []))
        return merged

    def _run_checks(self, data):
        findings = []
        for checker in [self._check_rotation, self._check_unused_secrets,
                        self._check_no_rotation_config, self._check_ssm_sensitive]:
            try:
                findings.extend(checker(data))
            except Exception as e:
                logger.warning("Checker failed: %s", e)
        return findings

    def _check_rotation(self, data):
        """Flag secrets with rotation enabled but not rotated recently."""
        findings = []
        now = datetime.now(timezone.utc)
        for s in data.get("secrets", []):
            if not s.get("rotation_enabled"):
                continue
            last_rot = s.get("last_rotated", "")
            if not last_rot:
                continue
            try:
                rot_date = datetime.fromisoformat(last_rot)
                if rot_date.tzinfo is None:
                    rot_date = rot_date.replace(tzinfo=timezone.utc)
                age = (now - rot_date).days
                if age > ROTATION_MAX_DAYS:
                    findings.append(Finding(
                        skill=self.name, title=f"Secret rotation overdue: {s['name']}",
                        severity=Severity.HIGH, resource_id=s["name"], region=s.get("region", ""),
                        description=f"Secret {s['name']} was last rotated {age} days ago (max {ROTATION_MAX_DAYS}d)",
                        recommended_action="Trigger rotation or review rotation schedule",
                        metadata={"secret_name": s["name"], "last_rotated_days": age, "rotation_enabled": True}))
            except (ValueError, TypeError):
                pass
        return findings

    def _check_unused_secrets(self, data):
        """Flag secrets not accessed recently."""
        findings = []
        now = datetime.now(timezone.utc)
        for s in data.get("secrets", []):
            last_acc = s.get("last_accessed", "")
            if not last_acc:
                findings.append(Finding(
                    skill=self.name, title=f"Secret never accessed: {s['name']}",
                    severity=Severity.MEDIUM, resource_id=s["name"], region=s.get("region", ""),
                    description=f"Secret {s['name']} has never been accessed",
                    recommended_action="Review if this secret is still needed",
                    metadata={"secret_name": s["name"], "last_accessed": "never"}))
                continue
            try:
                acc_date = datetime.fromisoformat(last_acc)
                if acc_date.tzinfo is None:
                    acc_date = acc_date.replace(tzinfo=timezone.utc)
                age = (now - acc_date).days
                if age > UNUSED_SECRET_DAYS:
                    findings.append(Finding(
                        skill=self.name, title=f"Unused secret: {s['name']}",
                        severity=Severity.LOW, resource_id=s["name"], region=s.get("region", ""),
                        description=f"Secret {s['name']} last accessed {age} days ago",
                        recommended_action="Delete if no longer needed",
                        metadata={"secret_name": s["name"], "last_accessed_days": age}))
            except (ValueError, TypeError):
                pass
        return findings

    def _check_no_rotation_config(self, data):
        """Flag secrets without rotation enabled."""
        findings = []
        for s in data.get("secrets", []):
            if not s.get("rotation_enabled"):
                findings.append(Finding(
                    skill=self.name, title=f"No rotation configured: {s['name']}",
                    severity=Severity.HIGH, resource_id=s["name"], region=s.get("region", ""),
                    description=f"Secret {s['name']} does not have automatic rotation enabled",
                    recommended_action="Configure automatic rotation with a Lambda function",
                    metadata={"secret_name": s["name"], "rotation_enabled": False}))
        return findings

    def _check_ssm_sensitive(self, data):
        """Flag SSM SecureString parameters that haven't been updated recently."""
        findings = []
        now = datetime.now(timezone.utc)
        for p in data.get("parameters", []):
            last_mod = p.get("last_modified", "")
            if not last_mod:
                continue
            try:
                mod_date = datetime.fromisoformat(last_mod)
                if mod_date.tzinfo is None:
                    mod_date = mod_date.replace(tzinfo=timezone.utc)
                age = (now - mod_date).days
                if age > ROTATION_MAX_DAYS:
                    findings.append(Finding(
                        skill=self.name, title=f"Stale SSM SecureString: {p['name']}",
                        severity=Severity.MEDIUM, resource_id=p["name"], region=p.get("region", ""),
                        description=f"SSM parameter {p['name']} last modified {age} days ago",
                        recommended_action="Review and rotate the parameter value",
                        metadata={"parameter_name": p["name"], "last_modified_days": age, "version": p.get("version", 1)}))
            except (ValueError, TypeError):
                pass
        return findings


SkillRegistry.register(SecretsHygieneSkill())
