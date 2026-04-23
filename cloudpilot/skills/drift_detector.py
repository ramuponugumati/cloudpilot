"""Drift Detector — detects infrastructure drift across CloudFormation,
Terraform, configuration baselines, and compliance policies.

Compares live AWS resource state against IaC definitions, stored baselines,
and policy rules. All API calls are read-only."""

import json
import logging
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from cloudpilot.core import BaseSkill, Finding, Severity, SkillResult, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, get_regions

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CloudFormation Drift Scanner
# ---------------------------------------------------------------------------


class CloudFormationDriftScanner:
    """Detects drift between CloudFormation stacks and live AWS state."""

    def scan_region(self, region, profile=None, stack_names=None):
        """Scan all (or specified) stacks in a region for drift.

        Returns list[Finding].
        """
        findings = []
        try:
            cfn = get_client("cloudformation", region=region, profile=profile)
            stacks = self._list_stacks(cfn, stack_names)
        except Exception as exc:
            logger.warning("Failed to list CloudFormation stacks in %s: %s", region, exc)
            return findings

        for stack in stacks:
            stack_name = stack["StackName"]
            stack_status = stack.get("StackStatus", "")

            # Skip stacks that are being deleted
            if stack_status == "DELETE_IN_PROGRESS":
                continue

            try:
                detection_id = self._start_drift_detection(cfn, stack_name)
                status = self._poll_drift_detection(cfn, stack_name, detection_id, timeout=30.0)

                if status != "DETECTION_COMPLETE":
                    findings.append(Finding(
                        skill="drift-detector",
                        title=f"Drift detection incomplete for stack {stack_name}",
                        severity=Severity.INFO,
                        description=f"Drift detection ended with status: {status}",
                        region=region,
                        metadata={"stack_name": stack_name, "drift_type": "iac_cfn"},
                    ))
                    continue

                drifts = self._get_resource_drifts(cfn, stack_name)
                for drift in drifts:
                    if drift.get("StackResourceDriftStatus") == "IN_SYNC":
                        continue
                    findings.append(self._resource_drift_to_finding(drift, stack_name, region))

            except Exception as exc:
                logger.warning("Drift detection failed for stack %s in %s: %s", stack_name, region, exc)

        return findings

    # -- helpers --

    def _list_stacks(self, cfn_client, stack_names=None):
        """List stacks, optionally filtering by name."""
        paginator = cfn_client.get_paginator("describe_stacks")
        stacks = []
        for page in paginator.paginate():
            stacks.extend(page.get("Stacks", []))

        if stack_names:
            name_set = set(stack_names)
            stacks = [s for s in stacks if s["StackName"] in name_set]

        return stacks

    def _start_drift_detection(self, cfn_client, stack_name):
        resp = cfn_client.detect_stack_drift(StackName=stack_name)
        return resp["StackDriftDetectionId"]

    def _poll_drift_detection(self, cfn_client, stack_name, detection_id, timeout=30.0):
        """Poll describe_stack_drift_detection_status until complete.

        Uses exponential backoff: 1s, 2s, 4s, …
        Returns detection status string.
        """
        delay = 1.0
        elapsed = 0.0
        while elapsed < timeout:
            resp = cfn_client.describe_stack_drift_detection_status(
                StackDriftDetectionId=detection_id,
            )
            status = resp.get("DetectionStatus", "")
            if status in ("DETECTION_COMPLETE", "DETECTION_FAILED"):
                return status
            time.sleep(delay)
            elapsed += delay
            delay = min(delay * 2, timeout - elapsed) if elapsed < timeout else delay
        return "DETECTION_TIMED_OUT"

    def _get_resource_drifts(self, cfn_client, stack_name):
        """Retrieve per-resource drift results for a stack."""
        try:
            resp = cfn_client.describe_stack_resource_drifts(
                StackName=stack_name,
                StackResourceDriftStatusFilters=["MODIFIED", "DELETED", "NOT_CHECKED"],
            )
            return resp.get("StackResourceDrifts", [])
        except Exception as exc:
            logger.warning("Failed to get resource drifts for stack %s: %s", stack_name, exc)
            return []

    def _resource_drift_to_finding(self, drift, stack_name, region):
        """Convert a single resource drift result to a Finding.

        MODIFIED → HIGH, DELETED → CRITICAL, NOT_CHECKED → INFO.
        """
        status = drift.get("StackResourceDriftStatus", "NOT_CHECKED")
        severity_map = {
            "MODIFIED": Severity.HIGH,
            "DELETED": Severity.CRITICAL,
            "NOT_CHECKED": Severity.INFO,
        }
        severity = severity_map.get(status, Severity.INFO)

        resource_type = drift.get("ResourceType", "Unknown")
        logical_id = drift.get("LogicalResourceId", "")
        physical_id = drift.get("PhysicalResourceId", "")

        metadata = {
            "stack_name": stack_name,
            "resource_type": resource_type,
            "logical_resource_id": logical_id,
            "physical_resource_id": physical_id,
            "drift_type": "iac_cfn",
        }

        if status == "MODIFIED":
            property_diffs = drift.get("PropertyDifferences", [])
            metadata["property_differences"] = property_diffs

        title_map = {
            "MODIFIED": f"CloudFormation drift: {resource_type} {logical_id} modified",
            "DELETED": f"CloudFormation drift: {resource_type} {logical_id} deleted",
            "NOT_CHECKED": f"CloudFormation drift: {resource_type} {logical_id} not checked",
        }

        return Finding(
            skill="drift-detector",
            title=title_map.get(status, f"CloudFormation drift: {logical_id}"),
            severity=severity,
            description=f"Resource {logical_id} ({physical_id}) in stack {stack_name} has drift status {status}",
            resource_id=physical_id or logical_id,
            region=region,
            recommended_action="Review and update CloudFormation template or re-import the resource",
            metadata=metadata,
        )


# ---------------------------------------------------------------------------
# Terraform Drift Scanner
# ---------------------------------------------------------------------------

TERRAFORM_RESOURCE_MAP = {
    "aws_instance": ("ec2", "describe_instances", "InstanceIds", "id"),
    "aws_s3_bucket": ("s3", "head_bucket", "Bucket", "bucket"),
    "aws_db_instance": ("rds", "describe_db_instances", "DBInstanceIdentifier", "identifier"),
    "aws_lambda_function": ("lambda", "get_function", "FunctionName", "function_name"),
    "aws_dynamodb_table": ("dynamodb", "describe_table", "TableName", "name"),
    "aws_sqs_queue": ("sqs", "get_queue_url", "QueueName", "name"),
    "aws_sns_topic": ("sns", "get_topic_attributes", "TopicArn", "arn"),
}


class TerraformDriftScanner:
    """Detects drift between Terraform state and live AWS resources."""

    def scan(self, terraform_state_path, profile=None):
        """Parse state file, compare each resource against live AWS state.

        Returns list[Finding].
        """
        # Read and parse the state file
        try:
            with open(terraform_state_path, "r") as f:
                state_json = json.load(f)
        except FileNotFoundError:
            return [Finding(
                skill="drift-detector",
                title=f"Terraform state file not found: {terraform_state_path}",
                severity=Severity.MEDIUM,
                description=f"The Terraform state file at '{terraform_state_path}' does not exist.",
                recommended_action="Verify the terraform_state_path parameter points to a valid .tfstate file",
                metadata={"drift_type": "iac_terraform"},
            )]
        except json.JSONDecodeError as exc:
            return [Finding(
                skill="drift-detector",
                title=f"Terraform state file is malformed JSON",
                severity=Severity.MEDIUM,
                description=f"Failed to parse '{terraform_state_path}' as JSON: {exc}",
                recommended_action="Ensure the state file is valid JSON (terraform.tfstate)",
                metadata={"drift_type": "iac_terraform"},
            )]

        # Check state version
        version = state_json.get("version")
        if version != 4:
            return [Finding(
                skill="drift-detector",
                title=f"Unsupported Terraform state version: {version}",
                severity=Severity.MEDIUM,
                description=f"Expected Terraform state version 4, got {version}. Only v4 (Terraform 0.12+) is supported.",
                recommended_action="Upgrade Terraform state to version 4 format",
                metadata={"drift_type": "iac_terraform"},
            )]

        # Parse resources and compare each against live state
        resources = self.parse_state(state_json)
        findings = []
        for resource_record in resources:
            finding = self._compare_resource(resource_record, profile)
            if finding is not None:
                findings.append(finding)
        return findings

    def parse_state(self, state_json):
        """Extract resource records from Terraform state v4 JSON.

        Returns list of dicts with: provider, resource_type, resource_name,
        resource_id, attributes.
        Only includes resources whose provider contains 'hashicorp/aws'.
        """
        records = []
        for resource in state_json.get("resources", []):
            provider = resource.get("provider", "")
            if "hashicorp/aws" not in provider:
                continue

            resource_type = resource.get("type", "")
            resource_name = resource.get("name", "")

            for instance in resource.get("instances", []):
                attributes = instance.get("attributes", {})
                resource_id = attributes.get("id") or attributes.get("arn", "")
                records.append({
                    "provider": provider,
                    "resource_type": resource_type,
                    "resource_name": resource_name,
                    "resource_id": resource_id,
                    "attributes": attributes,
                })
        return records

    def _compare_resource(self, resource_record, profile=None):
        """Compare a single Terraform resource against live AWS state.

        Returns Finding if drifted or missing, None if in sync.
        """
        resource_type = resource_record["resource_type"]
        mapping = TERRAFORM_RESOURCE_MAP.get(resource_type)
        if mapping is None:
            logger.debug("Skipping unsupported Terraform resource type: %s", resource_type)
            return None

        service_name, api_method, id_param_name, id_attr = mapping
        attributes = resource_record["attributes"]
        resource_name = resource_record["resource_name"]
        resource_id = resource_record["resource_id"]

        # Resolve the identifier value from attributes
        id_value = attributes.get(id_attr) or resource_id
        if not id_value:
            logger.debug("No ID found for %s.%s, skipping", resource_type, resource_name)
            return None

        try:
            client = get_client(service_name, profile=profile)
            method = getattr(client, api_method)

            # Build the API call kwargs based on the id_param_name
            if id_param_name == "InstanceIds":
                kwargs = {id_param_name: [id_value]}
            else:
                kwargs = {id_param_name: id_value}

            response = method(**kwargs)

            # Basic property comparison for supported types
            diffs = self._check_property_diffs(resource_type, attributes, response)
            if diffs:
                return Finding(
                    skill="drift-detector",
                    title=f"Terraform drift: {resource_type}.{resource_name} properties differ",
                    severity=Severity.HIGH,
                    description=f"Resource {resource_type}.{resource_name} ({id_value}) exists but has differing properties: {', '.join(diffs)}",
                    resource_id=id_value,
                    recommended_action="Run 'terraform plan' to review changes and 'terraform apply' to reconcile",
                    metadata={
                        "drift_type": "iac_terraform",
                        "resource_type": resource_type,
                        "resource_name": resource_name,
                        "differing_properties": diffs,
                    },
                )

            # Resource exists and is in sync
            return None

        except client.exceptions.ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            # Resource not found patterns
            not_found_codes = [
                "NotFound", "NotFoundException", "NoSuchBucket",
                "ResourceNotFoundException", "DBInstanceNotFound",
                "InvalidInstanceID.NotFound", "404",
                "AWS.SimpleQueueService.NonExistentQueue",
            ]
            if error_code in not_found_codes or "NotFound" in error_code or "NoSuch" in error_code:
                return Finding(
                    skill="drift-detector",
                    title=f"Terraform drift: {resource_type}.{resource_name} missing from AWS",
                    severity=Severity.CRITICAL,
                    description=f"Resource {resource_type}.{resource_name} ({id_value}) is declared in Terraform state but does not exist in AWS.",
                    resource_id=id_value,
                    recommended_action="Run 'terraform plan' to review and 'terraform apply' or remove from state with 'terraform state rm'",
                    metadata={
                        "drift_type": "iac_terraform",
                        "resource_type": resource_type,
                        "resource_name": resource_name,
                    },
                )
            # Other client errors — log and skip
            logger.warning("Error checking %s.%s: %s", resource_type, resource_name, exc)
            return None
        except Exception as exc:
            logger.warning("Error checking %s.%s: %s", resource_type, resource_name, exc)
            return None

    def _check_property_diffs(self, resource_type, tf_attributes, api_response):
        """Basic property comparison between Terraform state and live API response.

        Returns list of property names that differ, or empty list if in sync.
        """
        diffs = []
        try:
            if resource_type == "aws_instance":
                reservations = api_response.get("Reservations", [])
                if reservations:
                    instance = reservations[0].get("Instances", [{}])[0]
                    if tf_attributes.get("instance_type") and instance.get("InstanceType"):
                        if tf_attributes["instance_type"] != instance["InstanceType"]:
                            diffs.append("instance_type")
            elif resource_type == "aws_lambda_function":
                config = api_response.get("Configuration", {})
                if tf_attributes.get("runtime") and config.get("Runtime"):
                    if tf_attributes["runtime"] != config["Runtime"]:
                        diffs.append("runtime")
                if tf_attributes.get("memory_size") and config.get("MemorySize"):
                    if int(tf_attributes["memory_size"]) != config["MemorySize"]:
                        diffs.append("memory_size")
            elif resource_type == "aws_dynamodb_table":
                table = api_response.get("Table", {})
                if tf_attributes.get("billing_mode") and table.get("BillingModeSummary", {}).get("BillingMode"):
                    if tf_attributes["billing_mode"] != table["BillingModeSummary"]["BillingMode"]:
                        diffs.append("billing_mode")
        except Exception as exc:
            logger.debug("Property comparison failed for %s: %s", resource_type, exc)
        return diffs


# ---------------------------------------------------------------------------
# Configuration Drift Scanner
# ---------------------------------------------------------------------------

# Fields to ignore when comparing resource properties (volatile/transient)
_VOLATILE_FIELDS = {"timestamp", "last_modified", "last_updated", "created_at", "updated_at"}


class ConfigurationDriftScanner:
    """Compares current live resource state against a stored baseline snapshot."""

    def scan(self, baseline, regions, profile=None):
        """Discover current resources via ArchMapper, diff against baseline.

        Returns list[Finding].
        """
        if not baseline:
            return []

        from cloudpilot.skills.arch_mapper import ArchMapper

        try:
            mapper = ArchMapper()
            result = mapper.discover(regions, profile)
            current_resources = result.get("resources", [])
        except Exception as exc:
            logger.warning("ArchMapper discovery failed during configuration drift scan: %s", exc)
            return []

        baseline_resources = baseline.get("resources", [])

        # Build dicts keyed by resource ID
        baseline_by_id = {r.get("id", ""): r for r in baseline_resources if r.get("id")}
        current_by_id = {r.get("id", ""): r for r in current_resources if r.get("id")}

        return self._diff_resources(baseline_by_id, current_by_id)

    def _diff_resources(self, baseline_resources, current_resources):
        """Compare two resource dicts (keyed by ID) and produce drift findings.

        Args:
            baseline_resources: dict mapping resource_id → resource dict
            current_resources: dict mapping resource_id → resource dict

        Returns list[Finding].
        """
        findings = []

        # Resources in baseline but not in current → deleted (HIGH)
        for rid, b_res in baseline_resources.items():
            if rid not in current_resources:
                findings.append(Finding(
                    skill="drift-detector",
                    title=f"Configuration drift: resource {rid} deleted",
                    severity=Severity.HIGH,
                    description=f"Resource {rid} ({b_res.get('service', 'unknown')}) was present in the baseline but no longer exists.",
                    resource_id=rid,
                    region=b_res.get("region", ""),
                    recommended_action="Investigate why the resource was removed or update the baseline",
                    metadata={
                        "drift_type": "configuration",
                        "resource_type": b_res.get("service", ""),
                        "change_type": "deleted",
                    },
                ))

        # Resources in current but not in baseline → new/untracked (LOW)
        for rid, c_res in current_resources.items():
            if rid not in baseline_resources:
                findings.append(Finding(
                    skill="drift-detector",
                    title=f"Configuration drift: new resource {rid} detected",
                    severity=Severity.LOW,
                    description=f"Resource {rid} ({c_res.get('service', 'unknown')}) exists but is not in the baseline.",
                    resource_id=rid,
                    region=c_res.get("region", ""),
                    recommended_action="Add the resource to the baseline or investigate its origin",
                    metadata={
                        "drift_type": "configuration",
                        "resource_type": c_res.get("service", ""),
                        "change_type": "new",
                    },
                ))

        # Resources in both → compare properties
        for rid in baseline_resources:
            if rid in current_resources:
                prop_findings = self._diff_properties(
                    baseline_resources[rid],
                    current_resources[rid],
                    rid,
                    current_resources[rid].get("region", ""),
                )
                findings.extend(prop_findings)

        return findings

    def _diff_properties(self, baseline_res, current_res, resource_id, region):
        """Compare individual resource properties, return findings for differences.

        Compares the metadata dicts of both resources, skipping volatile fields.
        """
        findings = []
        b_meta = baseline_res.get("metadata", {})
        c_meta = current_res.get("metadata", {})

        all_keys = set(b_meta.keys()) | set(c_meta.keys())

        for key in sorted(all_keys):
            if key in _VOLATILE_FIELDS:
                continue

            b_val = b_meta.get(key)
            c_val = c_meta.get(key)

            if b_val != c_val:
                findings.append(Finding(
                    skill="drift-detector",
                    title=f"Configuration drift: {resource_id} property '{key}' changed",
                    severity=Severity.MEDIUM,
                    description=f"Property '{key}' of resource {resource_id} changed from {b_val!r} to {c_val!r}.",
                    resource_id=resource_id,
                    region=region,
                    recommended_action="Review the property change and update the baseline if intentional",
                    metadata={
                        "drift_type": "configuration",
                        "resource_type": baseline_res.get("service", ""),
                        "change_type": "modified",
                        "property_name": key,
                        "baseline_value": b_val,
                        "current_value": c_val,
                    },
                ))

        return findings


# ---------------------------------------------------------------------------
# Compliance Drift Scanner
# ---------------------------------------------------------------------------

DEFAULT_COMPLIANCE_POLICIES = [
    {"name": "s3-encryption-enabled", "resource_type": "s3", "property_path": "metadata.encryption",
     "operator": "exists", "expected_value": True, "severity": "high"},
    {"name": "s3-public-access-blocked", "resource_type": "s3", "property_path": "metadata.public_access_block",
     "operator": "exists", "expected_value": True, "severity": "high"},
    {"name": "rds-encryption-enabled", "resource_type": "rds", "property_path": "metadata.storage_encrypted",
     "operator": "equals", "expected_value": True, "severity": "high"},
    {"name": "rds-multi-az-enabled", "resource_type": "rds", "property_path": "metadata.multi_az",
     "operator": "equals", "expected_value": True, "severity": "medium"},
    {"name": "ebs-encryption-enabled", "resource_type": "ec2", "property_path": "metadata.ebs_encrypted",
     "operator": "equals", "expected_value": True, "severity": "medium"},
    {"name": "ec2-imdsv2-enforced", "resource_type": "ec2", "property_path": "metadata.imdsv2",
     "operator": "equals", "expected_value": "required", "severity": "medium"},
]


class ComplianceDriftScanner:
    """Evaluates live resources against compliance policy rules."""

    def scan(self, policies, regions, profile=None):
        """Discover current resources via ArchMapper, evaluate each policy.

        Uses built-in defaults if policies is empty/None.
        Returns list[Finding].
        """
        if not policies:
            policies = DEFAULT_COMPLIANCE_POLICIES

        from cloudpilot.skills.arch_mapper import ArchMapper

        try:
            mapper = ArchMapper()
            result = mapper.discover(regions, profile)
            current_resources = result.get("resources", [])
        except Exception as exc:
            logger.warning("ArchMapper discovery failed during compliance drift scan: %s", exc)
            return []

        findings = []
        for policy in policies:
            resource_type = policy.get("resource_type", "")
            matching = [r for r in current_resources if r.get("service") == resource_type]
            for resource in matching:
                finding = self.evaluate_policy(policy, resource)
                if finding is not None:
                    findings.append(finding)

        return findings

    def evaluate_policy(self, policy, resource):
        """Evaluate a single policy rule against a single resource.

        Returns Finding if violated, None if compliant.
        """
        property_path = policy.get("property_path", "")
        operator = policy.get("operator", "")
        expected_value = policy.get("expected_value")
        severity_str = policy.get("severity", "medium")
        policy_name = policy.get("name", "unknown-policy")

        actual_value = self._resolve_property(resource, property_path)
        compliant = self._evaluate_operator(actual_value, operator, expected_value)

        if not compliant:
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }
            severity = severity_map.get(severity_str, Severity.MEDIUM)

            return Finding(
                skill="drift-detector",
                title=f"Compliance violation: {policy_name} on {resource.get('id', 'unknown')}",
                severity=severity,
                resource_id=resource.get("id", ""),
                region=resource.get("region", ""),
                description=(
                    f"Resource {resource.get('id', 'unknown')} violates policy '{policy_name}': "
                    f"expected {property_path} {operator} {expected_value!r}, got {actual_value!r}"
                ),
                recommended_action=f"Remediate the resource to comply with policy '{policy_name}'",
                metadata={
                    "drift_type": "compliance",
                    "policy_name": policy_name,
                    "expected_value": expected_value,
                    "actual_value": actual_value,
                },
            )

        return None

    def _resolve_property(self, resource, property_path):
        """Resolve a dot-separated property path against a resource dict.

        e.g., 'metadata.multi_az' → resource['metadata']['multi_az']
        Returns None if any key not found.
        """
        parts = property_path.split(".")
        current = resource
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current

    def _evaluate_operator(self, actual_value, operator, expected_value):
        """Evaluate a comparison operator. Returns True if compliant."""
        try:
            if operator == "equals":
                return actual_value == expected_value
            elif operator == "not_equals":
                return actual_value != expected_value
            elif operator == "exists":
                return actual_value is not None
            elif operator == "not_exists":
                return actual_value is None
            elif operator == "contains":
                return expected_value in actual_value
            elif operator == "greater_than":
                return actual_value > expected_value
            elif operator == "less_than":
                return actual_value < expected_value
            else:
                logger.warning("Unknown compliance operator: %s", operator)
                return True
        except (TypeError, AttributeError):
            return False


# ---------------------------------------------------------------------------
# DriftDetector Skill
# ---------------------------------------------------------------------------

ALL_DRIFT_TYPES = ["iac_cfn", "iac_terraform", "configuration", "compliance"]


class DriftDetector(BaseSkill):
    """Detect infrastructure drift across CloudFormation, Terraform,
    configuration baselines, and compliance policies."""

    name = "drift-detector"
    description = (
        "Detect infrastructure drift across CloudFormation, Terraform, "
        "configuration baselines, and compliance policies"
    )
    version = "0.1.0"

    def __init__(self):
        self._cfn_scanner = CloudFormationDriftScanner()
        self._tf_scanner = TerraformDriftScanner()
        self._cfg_scanner = ConfigurationDriftScanner()
        self._cmp_scanner = ComplianceDriftScanner()

    def scan(self, regions, profile=None, account_id=None, **kwargs):
        """Run drift detection across specified drift types.

        Keyword args:
            drift_types: list[str] — subset of ALL_DRIFT_TYPES
            stack_names: list[str] — limit CFN scanning to these stacks
            terraform_state_path: str — path to terraform.tfstate file
            baseline: dict — Baseline_Snapshot for configuration drift
            policies: list[dict] — Compliance_Policy dicts
        """
        start = time.time()
        drift_types = kwargs.get("drift_types") or list(ALL_DRIFT_TYPES)
        stack_names = kwargs.get("stack_names")
        terraform_state_path = kwargs.get("terraform_state_path")
        baseline = kwargs.get("baseline")
        policies = kwargs.get("policies")

        all_findings = []
        errors = []

        # --- CloudFormation drift ---
        if "iac_cfn" in drift_types:
            cfn_findings = self._scan_cfn(regions, profile, stack_names, errors)
            all_findings.extend(cfn_findings)

        # --- Terraform drift (stub) ---
        if "iac_terraform" in drift_types:
            tf_findings = self._scan_terraform(terraform_state_path, profile, errors)
            all_findings.extend(tf_findings)

        # --- Configuration drift (stub) ---
        if "configuration" in drift_types:
            cfg_findings = self._scan_configuration(baseline, regions, profile, errors)
            all_findings.extend(cfg_findings)

        # --- Compliance drift (stub) ---
        if "compliance" in drift_types:
            cmp_findings = self._scan_compliance(policies, regions, profile, errors)
            all_findings.extend(cmp_findings)

        # If no drift found, return a single INFO finding
        if not all_findings:
            all_findings.append(Finding(
                skill=self.name,
                title="No drift detected",
                severity=Severity.INFO,
                description="No infrastructure drift was detected across the scanned regions and drift types.",
                recommended_action="No action required",
                metadata={"drift_type": "none"},
            ))

        duration = time.time() - start
        summary = self._build_summary(all_findings)

        return SkillResult(
            skill_name=self.name,
            findings=all_findings,
            duration_seconds=duration,
            regions_scanned=len(regions),
            errors=errors,
            metadata={
                "drift_summary": summary,
                "scan_duration_seconds": round(duration, 1),
                "regions_scanned": list(regions),
            },
        )

    def create_baseline(self, regions, profile=None):
        """Capture current resource state as a Baseline_Snapshot."""
        from cloudpilot.skills.arch_mapper import ArchMapper

        mapper = ArchMapper()
        result = mapper.discover(regions, profile)
        resources = result.get("resources", [])

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "account_id": get_account_id(profile),
            "regions": list(regions),
            "resources": resources,
        }

    # -- scanner dispatch helpers --

    def _scan_cfn(self, regions, profile, stack_names, errors):
        """Run CloudFormation drift scanning across regions in parallel."""
        findings = []
        with ThreadPoolExecutor(max_workers=min(len(regions), 10)) as pool:
            futures = {
                pool.submit(
                    self._cfn_scanner.scan_region, region, profile, stack_names
                ): region
                for region in regions
            }
            for future in as_completed(futures):
                region = futures[future]
                try:
                    region_findings = future.result()
                    findings.extend(region_findings)
                except Exception as exc:
                    msg = f"CloudFormation scan failed for {region}: {exc}"
                    logger.warning(msg)
                    errors.append(msg)
        return findings

    def _scan_terraform(self, terraform_state_path, profile, errors):
        """Run Terraform drift scanning against state file."""
        if not terraform_state_path:
            return []
        try:
            return self._tf_scanner.scan(terraform_state_path, profile)
        except Exception as exc:
            errors.append(f"Terraform scan failed: {exc}")
            return []

    def _scan_configuration(self, baseline, regions, profile, errors):
        """Run configuration drift scanning against baseline."""
        if not baseline:
            return []
        try:
            return self._cfg_scanner.scan(baseline, regions, profile)
        except Exception as exc:
            errors.append(f"Configuration scan failed: {exc}")
            return []

    def _scan_compliance(self, policies, regions, profile, errors):
        """Run compliance drift scanning against policies."""
        try:
            return self._cmp_scanner.scan(policies, regions, profile)
        except Exception as exc:
            errors.append(f"Compliance scan failed: {exc}")
            return []

    # -- summary builder --

    def _build_summary(self, findings):
        """Build summary metadata from a list of findings."""
        by_drift_type = {}
        by_severity = {}
        affected_resource_ids = set()
        affected_services = set()

        for f in findings:
            # Count by drift type
            dt = f.metadata.get("drift_type", "unknown")
            by_drift_type[dt] = by_drift_type.get(dt, 0) + 1

            # Count by severity
            sev = f.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1

            # Collect affected resources
            if f.resource_id:
                affected_resource_ids.add(f.resource_id)

            # Collect affected services from metadata or resource_id patterns
            resource_type = f.metadata.get("resource_type", "")
            if resource_type:
                svc = resource_type.split("::")[1] if "::" in resource_type else resource_type
                affected_services.add(svc)

        return {
            "total_drift_count": len(findings),
            "by_drift_type": by_drift_type,
            "by_severity": by_severity,
            "affected_resource_ids": sorted(affected_resource_ids),
            "affected_services": sorted(affected_services),
        }


# ---------------------------------------------------------------------------
# Register the skill
# ---------------------------------------------------------------------------

SkillRegistry.register(DriftDetector())
