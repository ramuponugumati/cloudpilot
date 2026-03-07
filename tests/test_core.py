"""Tests for core data models — Finding, SkillResult, Resource, and related dataclasses."""
from cloudpilot.core import (
    Finding,
    Severity,
    ActionStatus,
    SkillResult,
    Resource,
    AntiPattern,
    ServiceRecommendation,
    ResourceConnection,
    DiagramResult,
    IaCResult,
    GuardrailResult,
    RemediationResult,
    StubToolResponse,
)


class TestFinding:
    """Unit tests for Finding dataclass."""

    def test_finding_to_dict(self, sample_finding):
        d = sample_finding.to_dict()
        assert d["severity"] == "high"
        assert d["action_status"] == "pending_approval"
        assert d["skill"] == "test-skill"
        assert d["resource_id"] == "i-1234567890abcdef0"

    def test_finding_defaults(self):
        f = Finding(
            skill="test", title="t", severity=Severity.LOW, description="d"
        )
        assert f.resource_id == ""
        assert f.monthly_impact == 0.0
        assert f.action_status == ActionStatus.PENDING
        assert f.auto_remediate is False
        assert isinstance(f.metadata, dict)
        assert f.timestamp  # auto-generated


class TestSkillResult:
    """Unit tests for SkillResult dataclass."""

    def test_total_impact(self, sample_skill_result):
        assert sample_skill_result.total_impact == 100.0

    def test_critical_count_zero(self, sample_skill_result):
        # sample_finding is HIGH, not CRITICAL
        assert sample_skill_result.critical_count == 0

    def test_critical_count_nonzero(self):
        sr = SkillResult(
            skill_name="test",
            findings=[
                Finding(skill="x", title="t", severity=Severity.CRITICAL, description="d"),
                Finding(skill="x", title="t2", severity=Severity.HIGH, description="d2"),
            ],
        )
        assert sr.critical_count == 1


class TestResource:
    """Unit tests for Resource dataclass."""

    def test_resource_to_dict(self, sample_resource):
        d = sample_resource.to_dict()
        assert d["service"] == "ec2"
        assert d["layer"] == "Compute"
        assert d["id"] == "i-1234567890abcdef0"
        assert isinstance(d["tags"], dict)
        assert isinstance(d["metadata"], dict)

    def test_resource_defaults(self):
        r = Resource(service="s3", type="bucket", id="my-bucket", name="my-bucket", region="us-east-1")
        assert r.arn == ""
        assert r.tags == {}
        assert r.layer == ""
        assert r.metadata == {}
        assert r.account_id == ""


class TestAntiPattern:
    """Unit tests for AntiPattern dataclass."""

    def test_anti_pattern_to_dict(self, sample_anti_pattern):
        d = sample_anti_pattern.to_dict()
        assert d["severity"] == "high"
        assert d["pattern_type"] == "single-az-rds"
        assert d["well_architected_pillar"] == "reliability"


class TestServiceRecommendation:
    """Unit tests for ServiceRecommendation dataclass."""

    def test_service_recommendation_to_dict(self, sample_service_recommendation):
        d = sample_service_recommendation.to_dict()
        assert d["detected_workload"] == "Redis"
        assert d["recommended_service"] == "Amazon ElastiCache"
        assert d["detection_method"] == "name_tag"


class TestResourceConnection:
    """Unit tests for ResourceConnection dataclass."""

    def test_connection_to_dict(self, sample_connection):
        d = sample_connection.to_dict()
        assert d["connection_type"] == "vpc_member"
        assert d["source_id"] == "i-1234567890abcdef0"
        assert d["target_id"] == "mydb"


class TestDiagramResult:
    """Unit tests for DiagramResult dataclass."""

    def test_diagram_result_to_dict(self):
        dr = DiagramResult(mermaid_code="graph TB\n  A-->B", view_type="default", resource_count=2)
        d = dr.to_dict()
        assert d["mermaid_code"].startswith("graph TB")
        assert d["view_type"] == "default"
        assert d["resource_count"] == 2
        assert d["collapsed_groups"] == 0


class TestIaCResult:
    """Unit tests for IaCResult dataclass."""

    def test_iac_result_to_dict(self):
        ir = IaCResult(format="cloudformation", scope="all", resource_count=3, code="AWSTemplateFormatVersion: '2010-09-09'")
        d = ir.to_dict()
        assert d["format"] == "cloudformation"
        assert d["resource_count"] == 3
        assert d["warnings"] == []


class TestGuardrailResult:
    """Unit tests for GuardrailResult dataclass."""

    def test_guardrail_allowed(self):
        gr = GuardrailResult(allowed=True)
        assert gr.to_dict() == {"allowed": True, "reason": "", "filtered_message": ""}

    def test_guardrail_blocked(self):
        gr = GuardrailResult(allowed=False, reason="injection", filtered_message="Request blocked.")
        d = gr.to_dict()
        assert d["allowed"] is False
        assert d["reason"] == "injection"


class TestRemediationResult:
    """Unit tests for RemediationResult dataclass."""

    def test_remediation_result_to_dict(self):
        rr = RemediationResult(success=True, finding_id="f-001", action="delete_ebs_volume", message="Deleted vol-abc")
        d = rr.to_dict()
        assert d["success"] is True
        assert d["action"] == "delete_ebs_volume"
        assert d["timestamp"]  # auto-generated


class TestStubToolResponse:
    """Unit tests for StubToolResponse dataclass."""

    def test_stub_defaults(self):
        s = StubToolResponse()
        assert s.status == "coming_soon"
        assert s.planned_phase == "Phase 2"
        assert s.planned_capabilities == []

    def test_stub_to_dict(self):
        s = StubToolResponse(
            tool_name="detect_drift",
            description="Detect IaC drift",
            planned_capabilities=["IaC drift", "config drift"],
        )
        d = s.to_dict()
        assert d["status"] == "coming_soon"
        assert d["tool_name"] == "detect_drift"
        assert len(d["planned_capabilities"]) == 2
