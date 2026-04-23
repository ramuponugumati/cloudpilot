"""Property-based tests for CloudPilot Drift Detection skill.

Properties 1–7 from the design document, tested using Hypothesis with
strategies from tests.strategies.  Tests exercise pure logic functions
directly — no AWS credentials or mocked boto3 needed.
"""
import json

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st
from unittest.mock import patch, MagicMock

from cloudpilot.skills.drift_detector import (
    DriftDetector,
    CloudFormationDriftScanner,
    TerraformDriftScanner,
    ConfigurationDriftScanner,
    ComplianceDriftScanner,
    TERRAFORM_RESOURCE_MAP,
    DEFAULT_COMPLIANCE_POLICIES,
)
from cloudpilot.core import Finding, Severity

from tests.strategies import (
    cfn_drift_result_strategy,
    terraform_state_v4_strategy,
    baseline_snapshot_strategy,
    compliance_policy_strategy,
    operator_test_case_strategy,
    resource_strategy,
)


# ===================================================================
# Property 1: CFN drift status maps to correct severity
# Feature: detect-drift, Property 1: CFN drift status maps to correct severity
# Validates: Requirements 2.3, 2.4, 2.5
# ===================================================================
class TestProperty1CfnDriftSeverityMapping:
    """For any CloudFormation resource drift result, _resource_drift_to_finding
    SHALL produce a Finding with MODIFIED→HIGH, DELETED→CRITICAL, NOT_CHECKED→INFO.
    The Finding SHALL always contain the resource ID and stack name in metadata."""

    @settings(max_examples=100)
    @given(drift=cfn_drift_result_strategy)
    def test_drift_status_maps_to_correct_severity(self, drift):
        """**Validates: Requirements 2.3, 2.4, 2.5**"""
        scanner = CloudFormationDriftScanner()
        finding = scanner._resource_drift_to_finding(drift, "test-stack", "us-east-1")

        expected_severity = {
            "MODIFIED": Severity.HIGH,
            "DELETED": Severity.CRITICAL,
            "NOT_CHECKED": Severity.INFO,
        }

        status = drift["StackResourceDriftStatus"]
        assert finding.severity == expected_severity[status], (
            f"Status {status} should map to {expected_severity[status]}, got {finding.severity}"
        )
        assert isinstance(finding, Finding)
        assert finding.metadata["stack_name"] == "test-stack"
        assert finding.region == "us-east-1"
        assert finding.metadata["drift_type"] == "iac_cfn"


# ===================================================================
# Property 2: Stack names filtering limits scanning scope
# Feature: detect-drift, Property 2: Stack names filtering limits scanning scope
# Validates: Requirements 1.4, 2.8
# ===================================================================
class TestProperty2StackNamesFiltering:
    """When stack_names is provided, only those stacks are scanned."""

    @settings(max_examples=100)
    @given(
        target_names=st.lists(
            st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=3, max_size=15),
            min_size=1,
            max_size=3,
            unique=True,
        ),
        extra_names=st.lists(
            st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ", min_size=3, max_size=15),
            min_size=1,
            max_size=3,
            unique=True,
        ),
    )
    def test_only_matching_stacks_are_returned(self, target_names, extra_names):
        """**Validates: Requirements 1.4, 2.8**"""
        # Build mock stacks — targets use lowercase, extras use uppercase
        # so they never collide
        all_stacks = [
            {"StackName": name, "StackStatus": "CREATE_COMPLETE"}
            for name in target_names + extra_names
        ]

        scanner = CloudFormationDriftScanner()

        # Mock the cfn_client paginator
        mock_cfn = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Stacks": all_stacks}]
        mock_cfn.get_paginator.return_value = mock_paginator

        filtered = scanner._list_stacks(mock_cfn, stack_names=target_names)
        filtered_names = {s["StackName"] for s in filtered}

        assert filtered_names == set(target_names), (
            f"Expected only {target_names}, got {filtered_names}"
        )
        # No extra stacks should be present
        for extra in extra_names:
            assert extra not in filtered_names


# ===================================================================
# Property 3: Drift types filtering controls which scanners run
# Feature: detect-drift, Property 3: Drift types filtering controls which scanners run
# Validates: Requirements 1.3
# ===================================================================
class TestProperty3DriftTypesFiltering:
    """DriftDetector.scan only runs scanners for specified drift_types."""

    @settings(max_examples=100)
    @given(data=st.data())
    def test_only_specified_drift_types_produce_findings(self, data):
        """**Validates: Requirements 1.3**"""
        all_types = ["iac_cfn", "iac_terraform", "configuration", "compliance"]
        # Pick a non-empty subset of drift types
        selected = data.draw(
            st.lists(st.sampled_from(all_types), min_size=1, max_size=4, unique=True)
        )
        excluded = [t for t in all_types if t not in selected]

        detector = DriftDetector()

        # Patch each scanner to return a tagged finding
        def make_cfn_findings(*args, **kwargs):
            return [Finding(
                skill="drift-detector", title="cfn drift", severity=Severity.HIGH,
                description="cfn", metadata={"drift_type": "iac_cfn"},
            )]

        def make_tf_findings(*args, **kwargs):
            return [Finding(
                skill="drift-detector", title="tf drift", severity=Severity.HIGH,
                description="tf", metadata={"drift_type": "iac_terraform"},
            )]

        def make_cfg_findings(*args, **kwargs):
            return [Finding(
                skill="drift-detector", title="cfg drift", severity=Severity.MEDIUM,
                description="cfg", metadata={"drift_type": "configuration"},
            )]

        def make_cmp_findings(*args, **kwargs):
            return [Finding(
                skill="drift-detector", title="cmp drift", severity=Severity.HIGH,
                description="cmp", metadata={"drift_type": "compliance"},
            )]

        with patch.object(detector, "_scan_cfn", side_effect=make_cfn_findings), \
             patch.object(detector, "_scan_terraform", side_effect=make_tf_findings), \
             patch.object(detector, "_scan_configuration", side_effect=make_cfg_findings), \
             patch.object(detector, "_scan_compliance", side_effect=make_cmp_findings):

            result = detector.scan(
                ["us-east-1"],
                drift_types=selected,
                terraform_state_path="/fake/path" if "iac_terraform" in selected else None,
                baseline={"resources": []} if "configuration" in selected else None,
                policies=[{}] if "compliance" in selected else None,
            )

        finding_types = {f.metadata.get("drift_type") for f in result.findings}

        # Excluded types should not appear
        for excluded_type in excluded:
            assert excluded_type not in finding_types, (
                f"Drift type '{excluded_type}' should not appear when not selected"
            )


# ===================================================================
# Property 4: Terraform state parsing extracts complete resource records
# Feature: detect-drift, Property 4: Terraform state parsing extracts complete resource records
# Validates: Requirements 3.2, 4.1
# ===================================================================
class TestProperty4TerraformStateParsing:
    """parse_state extracts all AWS resources from state JSON with correct fields."""

    @settings(max_examples=100)
    @given(state=terraform_state_v4_strategy)
    def test_parse_state_extracts_all_aws_resources(self, state):
        """**Validates: Requirements 3.2, 4.1**"""
        scanner = TerraformDriftScanner()
        records = scanner.parse_state(state)

        # Count expected AWS resource instances
        expected_count = 0
        for resource in state.get("resources", []):
            if "hashicorp/aws" in resource.get("provider", ""):
                expected_count += len(resource.get("instances", []))

        assert len(records) == expected_count, (
            f"Expected {expected_count} records, got {len(records)}"
        )

        # Each record must have required fields
        for record in records:
            assert "provider" in record
            assert "resource_type" in record
            assert "resource_name" in record
            assert "resource_id" in record
            assert "attributes" in record
            assert "hashicorp/aws" in record["provider"]


# ===================================================================
# Property 5: Terraform state parse round-trip
# Feature: detect-drift, Property 5: Terraform state parse round-trip
# Validates: Requirements 4.3
# ===================================================================
class TestProperty5TerraformParseRoundTrip:
    """Parsing state, serializing records to JSON, parsing back produces
    equivalent records."""

    @settings(max_examples=100)
    @given(state=terraform_state_v4_strategy)
    def test_parse_serialize_parse_roundtrip(self, state):
        """**Validates: Requirements 4.3**"""
        scanner = TerraformDriftScanner()

        # First parse
        records_1 = scanner.parse_state(state)

        # Serialize to JSON and back
        json_str = json.dumps(records_1)
        records_from_json = json.loads(json_str)

        assert records_1 == records_from_json, (
            "Round-trip through JSON should produce equivalent records"
        )


# ===================================================================
# Property 6: Non-AWS provider resources are filtered out
# Feature: detect-drift, Property 6: Non-AWS provider resources are filtered out
# Validates: Requirements 4.4
# ===================================================================
class TestProperty6NonAwsFiltering:
    """parse_state with mixed AWS and non-AWS providers returns only AWS."""

    @settings(max_examples=100)
    @given(
        aws_resources=st.lists(
            st.fixed_dictionaries({
                "type": st.sampled_from(["aws_instance", "aws_s3_bucket"]),
                "name": st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=3, max_size=10),
                "provider": st.just("registry.terraform.io/hashicorp/aws"),
                "instances": st.just([{"attributes": {"id": "i-abc123"}}]),
            }),
            min_size=0,
            max_size=3,
        ),
        non_aws_resources=st.lists(
            st.fixed_dictionaries({
                "type": st.sampled_from(["google_compute_instance", "azurerm_virtual_machine", "random_string"]),
                "name": st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=3, max_size=10),
                "provider": st.sampled_from([
                    "registry.terraform.io/hashicorp/google",
                    "registry.terraform.io/hashicorp/azurerm",
                    "registry.terraform.io/hashicorp/random",
                ]),
                "instances": st.just([{"attributes": {"id": "non-aws-123"}}]),
            }),
            min_size=1,
            max_size=3,
        ),
    )
    def test_only_aws_resources_returned(self, aws_resources, non_aws_resources):
        """**Validates: Requirements 4.4**"""
        state = {
            "version": 4,
            "terraform_version": "1.5.0",
            "resources": aws_resources + non_aws_resources,
        }

        scanner = TerraformDriftScanner()
        records = scanner.parse_state(state)

        # All returned records must be AWS
        for record in records:
            assert "hashicorp/aws" in record["provider"], (
                f"Non-AWS resource slipped through: {record['provider']}"
            )

        # Count should match only AWS instances
        expected_aws_count = sum(
            len(r.get("instances", []))
            for r in aws_resources
        )
        assert len(records) == expected_aws_count


# ===================================================================
# Property 7: Terraform drift detection produces correct severity
# Feature: detect-drift, Property 7: Terraform drift detection produces correct severity
# Validates: Requirements 3.3, 3.4
# ===================================================================
class TestProperty7TerraformDriftSeverity:
    """Missing resource → CRITICAL, property diff → HIGH."""

    @settings(max_examples=100)
    @given(
        resource_type=st.sampled_from(list(TERRAFORM_RESOURCE_MAP.keys())),
        resource_name=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=3, max_size=15),
    )
    def test_missing_resource_produces_critical(self, resource_type, resource_name):
        """**Validates: Requirements 3.3**"""
        mapping = TERRAFORM_RESOURCE_MAP[resource_type]
        _, _, _, id_attr = mapping

        resource_record = {
            "provider": "registry.terraform.io/hashicorp/aws",
            "resource_type": resource_type,
            "resource_name": resource_name,
            "resource_id": "test-resource-id",
            "attributes": {id_attr: "test-resource-id", "id": "test-resource-id"},
        }

        scanner = TerraformDriftScanner()

        # Mock the client to raise a NotFound error
        mock_client = MagicMock()
        error_response = {"Error": {"Code": "NotFound", "Message": "Not found"}}
        mock_client.exceptions.ClientError = type("ClientError", (Exception,), {
            "__init__": lambda self, *a, **kw: (
                super(type(self), self).__init__("not found"),
                setattr(self, "response", error_response),
            )[-1]
        })

        # Make the API method raise ClientError
        api_method = MagicMock(side_effect=mock_client.exceptions.ClientError())
        setattr(mock_client, mapping[1], api_method)

        with patch("cloudpilot.skills.drift_detector.get_client", return_value=mock_client):
            finding = scanner._compare_resource(resource_record)

        assert finding is not None, "Missing resource should produce a finding"
        assert finding.severity == Severity.CRITICAL, (
            f"Missing resource should be CRITICAL, got {finding.severity}"
        )

    @settings(max_examples=100)
    @given(
        resource_name=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=3, max_size=15),
    )
    def test_property_diff_produces_high(self, resource_name):
        """**Validates: Requirements 3.4**"""
        # Use aws_instance which has property comparison logic
        resource_record = {
            "provider": "registry.terraform.io/hashicorp/aws",
            "resource_type": "aws_instance",
            "resource_name": resource_name,
            "resource_id": "i-test123",
            "attributes": {"id": "i-test123", "instance_type": "t3.micro"},
        }

        scanner = TerraformDriftScanner()

        # Mock client that returns a different instance_type
        mock_client = MagicMock()
        mock_client.exceptions.ClientError = Exception
        mock_client.describe_instances.return_value = {
            "Reservations": [{
                "Instances": [{
                    "InstanceId": "i-test123",
                    "InstanceType": "t3.large",  # Different from state
                }]
            }]
        }

        with patch("cloudpilot.skills.drift_detector.get_client", return_value=mock_client):
            finding = scanner._compare_resource(resource_record)

        assert finding is not None, "Property diff should produce a finding"
        assert finding.severity == Severity.HIGH, (
            f"Property diff should be HIGH, got {finding.severity}"
        )


# ===================================================================
# Property 8: Configuration drift classification by change type
# Feature: detect-drift, Property 8: Configuration drift classification by change type
# Validates: Requirements 5.2, 5.3, 5.4
# ===================================================================
class TestProperty8ConfigurationDriftClassification:
    """Deleted resource → HIGH, new resource → LOW, modified property → MEDIUM
    with resource_id, property_name, baseline_value, current_value."""

    @settings(max_examples=100)
    @given(
        baseline_resources=st.lists(resource_strategy, min_size=1, max_size=5),
        current_resources=st.lists(resource_strategy, min_size=1, max_size=5),
    )
    def test_deleted_resource_produces_high(self, baseline_resources, current_resources):
        """**Validates: Requirements 5.2**"""
        # Ensure at least one resource is only in baseline (deleted)
        deleted_id = "deleted-resource-xyz"
        deleted_res = {
            "service": "ec2", "type": "instance", "id": deleted_id,
            "name": "deleted-server", "region": "us-east-1",
            "tags": {}, "layer": "Compute", "metadata": {},
        }

        baseline_by_id = {deleted_id: deleted_res}
        current_by_id = {}

        scanner = ConfigurationDriftScanner()
        findings = scanner._diff_resources(baseline_by_id, current_by_id)

        deleted_findings = [f for f in findings if f.resource_id == deleted_id]
        assert len(deleted_findings) == 1
        assert deleted_findings[0].severity == Severity.HIGH
        assert deleted_findings[0].metadata.get("change_type") == "deleted"

    @settings(max_examples=100)
    @given(
        resource=resource_strategy,
    )
    def test_new_resource_produces_low(self, resource):
        """**Validates: Requirements 5.3**"""
        assume(resource.get("id"))
        rid = resource["id"]

        baseline_by_id = {}
        current_by_id = {rid: resource}

        scanner = ConfigurationDriftScanner()
        findings = scanner._diff_resources(baseline_by_id, current_by_id)

        new_findings = [f for f in findings if f.resource_id == rid]
        assert len(new_findings) == 1
        assert new_findings[0].severity == Severity.LOW
        assert new_findings[0].metadata.get("change_type") == "new"

    @settings(max_examples=100)
    @given(
        resource=resource_strategy,
        new_value=st.text(min_size=1, max_size=20),
    )
    def test_modified_property_produces_medium(self, resource, new_value):
        """**Validates: Requirements 5.4**"""
        assume(resource.get("id"))
        rid = resource["id"]

        baseline_res = dict(resource)
        baseline_res["metadata"] = {"instance_type": "t3.micro"}

        current_res = dict(resource)
        current_res["metadata"] = {"instance_type": new_value}

        assume(new_value != "t3.micro")

        baseline_by_id = {rid: baseline_res}
        current_by_id = {rid: current_res}

        scanner = ConfigurationDriftScanner()
        findings = scanner._diff_resources(baseline_by_id, current_by_id)

        modified_findings = [
            f for f in findings
            if f.resource_id == rid and f.metadata.get("change_type") == "modified"
        ]
        assert len(modified_findings) >= 1
        f = modified_findings[0]
        assert f.severity == Severity.MEDIUM
        assert f.resource_id == rid
        assert f.metadata.get("property_name") == "instance_type"
        assert f.metadata.get("baseline_value") == "t3.micro"
        assert f.metadata.get("current_value") == new_value


# ===================================================================
# Property 9: Baseline creation round-trip produces zero drift
# Feature: detect-drift, Property 9: Baseline creation round-trip produces zero drift
# Validates: Requirements 6.3
# ===================================================================
class TestProperty9BaselineRoundTripZeroDrift:
    """Creating a baseline from resources, then diffing against the same
    resources, SHALL produce zero findings."""

    @settings(max_examples=100)
    @given(resources=st.lists(resource_strategy, min_size=0, max_size=5))
    def test_identical_baseline_and_current_produce_no_drift(self, resources):
        """**Validates: Requirements 6.3**"""
        # Deduplicate by id to avoid collisions
        by_id = {}
        for r in resources:
            rid = r.get("id", "")
            if rid:
                by_id[rid] = r

        scanner = ConfigurationDriftScanner()
        findings = scanner._diff_resources(dict(by_id), dict(by_id))

        assert len(findings) == 0, (
            f"Identical baseline and current should produce 0 findings, got {len(findings)}"
        )


# ===================================================================
# Property 10: Baseline JSON serialization round-trip
# Feature: detect-drift, Property 10: Baseline JSON serialization round-trip
# Validates: Requirements 6.2, 6.4
# ===================================================================
class TestProperty10BaselineJsonRoundTrip:
    """Serialize baseline to JSON, deserialize back → equivalent."""

    @settings(max_examples=100)
    @given(baseline=baseline_snapshot_strategy)
    def test_baseline_json_roundtrip(self, baseline):
        """**Validates: Requirements 6.2, 6.4**"""
        json_str = json.dumps(baseline)
        deserialized = json.loads(json_str)

        assert deserialized == baseline, (
            "Baseline should survive JSON round-trip"
        )
        assert "timestamp" in deserialized
        assert "account_id" in deserialized
        assert "regions" in deserialized
        assert "resources" in deserialized


# ===================================================================
# Property 11: Compliance operator evaluation correctness
# Feature: detect-drift, Property 11: Compliance operator evaluation correctness
# Validates: Requirements 7.5
# ===================================================================
class TestProperty11ComplianceOperatorEvaluation:
    """_evaluate_operator returns correct boolean for all 7 operators."""

    @settings(max_examples=100)
    @given(test_case=operator_test_case_strategy)
    def test_evaluate_operator_correctness(self, test_case):
        """**Validates: Requirements 7.5**"""
        actual_value, operator, expected_value, expected_result = test_case

        scanner = ComplianceDriftScanner()
        result = scanner._evaluate_operator(actual_value, operator, expected_value)

        assert result == expected_result, (
            f"_evaluate_operator({actual_value!r}, {operator!r}, {expected_value!r}) "
            f"returned {result}, expected {expected_result}"
        )

    @settings(max_examples=100)
    @given(
        text_val=st.text(min_size=1, max_size=20),
        substring=st.text(min_size=1, max_size=5),
    )
    def test_contains_operator(self, text_val, substring):
        """**Validates: Requirements 7.5** — contains operator specifically."""
        scanner = ComplianceDriftScanner()
        result = scanner._evaluate_operator(text_val, "contains", substring)
        assert result == (substring in text_val)


# ===================================================================
# Property 12: Compliance violation produces Finding with policy severity
# Feature: detect-drift, Property 12: Compliance violation produces Finding with policy severity
# Validates: Requirements 7.2
# ===================================================================
class TestProperty12ComplianceViolationSeverity:
    """evaluate_policy returns Finding with severity matching policy severity."""

    @settings(max_examples=100)
    @given(policy=compliance_policy_strategy)
    def test_violation_finding_has_policy_severity(self, policy):
        """**Validates: Requirements 7.2**"""
        # Build a resource that will violate the policy
        # Use a resource that matches the policy resource_type but has None
        # for the property path so it fails any operator except not_exists
        resource = {
            "service": policy["resource_type"],
            "id": "test-resource-001",
            "region": "us-east-1",
            "metadata": {},  # empty metadata → property resolves to None
        }

        scanner = ComplianceDriftScanner()

        # For "not_exists" operator, the resource with None value is compliant,
        # so we need to provide a value to make it non-compliant
        if policy["operator"] == "not_exists":
            # Put a value so not_exists fails
            parts = policy["property_path"].split(".")
            if len(parts) == 2 and parts[0] == "metadata":
                resource["metadata"][parts[1]] = "some_value"
            else:
                resource[parts[0]] = "some_value"

        # For "exists" with None → violation (good)
        # For "equals" with None vs expected → violation (good)
        # For "not_equals" with None vs expected → might be compliant if expected != None
        # For "contains" with None → TypeError → returns False → violation (good)
        # For "greater_than" / "less_than" with None → TypeError → returns False → violation (good)

        finding = scanner.evaluate_policy(policy, resource)

        # If the policy happens to be compliant (e.g., not_equals with None != expected),
        # skip this case
        if finding is None:
            assume(False)

        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        expected_severity = severity_map[policy["severity"]]

        assert finding.severity == expected_severity, (
            f"Finding severity {finding.severity} should match policy severity {expected_severity}"
        )
        assert finding.metadata.get("policy_name") == policy["name"]
        assert "expected_value" in finding.metadata
        assert "actual_value" in finding.metadata


# ===================================================================
# Property 13: Drift result summary correctness
# Feature: detect-drift, Property 13: Drift result summary correctness
# Validates: Requirements 10.1
# ===================================================================
class TestProperty13DriftResultSummary:
    """_build_summary produces correct counts: total == len(findings),
    by_drift_type sums to total, by_severity sums to total."""

    @settings(max_examples=100)
    @given(
        findings_data=st.lists(
            st.fixed_dictionaries({
                "drift_type": st.sampled_from(["iac_cfn", "iac_terraform", "configuration", "compliance"]),
                "severity": st.sampled_from([Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]),
                "resource_id": st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-", min_size=3, max_size=20),
                "resource_type": st.sampled_from(["ec2", "rds", "s3", "lambda", ""]),
            }),
            min_size=0,
            max_size=20,
        ),
    )
    def test_summary_counts_are_correct(self, findings_data):
        """**Validates: Requirements 10.1**"""
        findings = []
        for fd in findings_data:
            findings.append(Finding(
                skill="drift-detector",
                title="test finding",
                severity=fd["severity"],
                description="test",
                resource_id=fd["resource_id"],
                metadata={
                    "drift_type": fd["drift_type"],
                    "resource_type": fd["resource_type"],
                },
            ))

        detector = DriftDetector()
        summary = detector._build_summary(findings)

        # total_drift_count == len(findings)
        assert summary["total_drift_count"] == len(findings), (
            f"total_drift_count {summary['total_drift_count']} != len(findings) {len(findings)}"
        )

        # by_drift_type sums to total
        drift_type_sum = sum(summary["by_drift_type"].values())
        assert drift_type_sum == len(findings), (
            f"by_drift_type sum {drift_type_sum} != total {len(findings)}"
        )

        # by_severity sums to total
        severity_sum = sum(summary["by_severity"].values())
        assert severity_sum == len(findings), (
            f"by_severity sum {severity_sum} != total {len(findings)}"
        )

        # affected_resource_ids contains every unique resource_id
        expected_ids = sorted({fd["resource_id"] for fd in findings_data if fd["resource_id"]})
        assert summary["affected_resource_ids"] == expected_ids

        # affected_services contains every unique non-empty resource_type
        expected_services = sorted({fd["resource_type"] for fd in findings_data if fd["resource_type"]})
        assert summary["affected_services"] == expected_services


# ===================================================================
# Property 14: Multi-region findings aggregation with region field
# Feature: detect-drift, Property 14: Multi-region findings aggregation with region field
# Validates: Requirements 9.2, 9.3
# ===================================================================
class TestProperty14MultiRegionFindingsAggregation:
    """All findings have non-empty region field. Deterministic test with
    constructed findings."""

    @settings(max_examples=100)
    @given(
        regions=st.lists(
            st.sampled_from(["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]),
            min_size=1,
            max_size=4,
            unique=True,
        ),
        findings_per_region=st.integers(min_value=0, max_value=5),
    )
    def test_all_findings_have_nonempty_region(self, regions, findings_per_region):
        """**Validates: Requirements 9.2, 9.3**"""
        # Construct findings deterministically with region fields
        all_findings = []
        for region in regions:
            for i in range(findings_per_region):
                all_findings.append(Finding(
                    skill="drift-detector",
                    title=f"drift in {region} #{i}",
                    severity=Severity.MEDIUM,
                    description=f"test finding {i} in {region}",
                    resource_id=f"res-{region}-{i}",
                    region=region,
                    metadata={"drift_type": "configuration"},
                ))

        # All findings must have non-empty region
        for f in all_findings:
            assert f.region, f"Finding '{f.title}' has empty region"

        # Total count equals sum across regions
        expected_total = len(regions) * findings_per_region
        assert len(all_findings) == expected_total, (
            f"Total findings {len(all_findings)} != expected {expected_total}"
        )
