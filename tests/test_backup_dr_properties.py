"""Property-based tests for CloudPilot Backup & DR Posture skill.

Tests exercise pure logic functions directly — no AWS credentials needed.
"""
import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from cloudpilot.core import Finding, Severity
from cloudpilot.skills.backup_dr_posture import (
    BackupDRPostureSkill,
    DR_SCORE_WEIGHTS,
    MIN_RETENTION_DAYS,
    STALE_SNAPSHOT_DAYS,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------
_rds_instance = st.fixed_dictionaries({
    "id": st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-", min_size=3, max_size=15),
    "arn": st.builds(lambda n: f"arn:aws:rds:us-east-1:123456789012:db:{n}",
                     st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=3, max_size=10)),
    "region": st.sampled_from(["us-east-1", "us-west-2", "eu-west-1"]),
    "backup_retention_period": st.integers(min_value=0, max_value=35),
})

_ddb_table = st.fixed_dictionaries({
    "name": st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-", min_size=3, max_size=15),
    "arn": st.builds(lambda n: f"arn:aws:dynamodb:us-east-1:123456789012:table/{n}",
                     st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=3, max_size=10)),
    "region": st.sampled_from(["us-east-1", "us-west-2"]),
    "pitr_enabled": st.booleans(),
})

_ebs_volume = st.fixed_dictionaries({
    "volume_id": st.builds(lambda s: f"vol-{s}",
                           st.text(alphabet="abcdef0123456789", min_size=8, max_size=12)),
    "state": st.sampled_from(["in-use", "available"]),
    "region": st.sampled_from(["us-east-1", "us-west-2"]),
})


# ===================================================================
# Property 1: Unprotected resources produce HIGH findings
# ===================================================================
class TestBackupCoverageFindings:

    @settings(max_examples=50)
    @given(rds=st.lists(_rds_instance, min_size=1, max_size=5))
    def test_unprotected_rds_produces_high(self, rds):
        """Every unprotected RDS instance → HIGH finding."""
        skill = BackupDRPostureSkill()
        data = {"rds_instances": rds, "protected_resource_arns": set(),
                "dynamodb_tables": [], "ebs_volumes": [], "efs_file_systems": [], "s3_buckets": []}
        findings = skill._check_backup_coverage(data)
        rds_findings = [f for f in findings if f.metadata.get("resource_type") == "rds"]
        assert len(rds_findings) == len(rds)
        for f in rds_findings:
            assert f.severity == Severity.HIGH

    @settings(max_examples=50)
    @given(rds=st.lists(_rds_instance, min_size=1, max_size=5))
    def test_protected_rds_produces_no_findings(self, rds):
        """Fully protected RDS instances → zero findings."""
        skill = BackupDRPostureSkill()
        protected = {inst["arn"] for inst in rds}
        data = {"rds_instances": rds, "protected_resource_arns": protected,
                "dynamodb_tables": [], "ebs_volumes": [], "efs_file_systems": [], "s3_buckets": []}
        findings = skill._check_backup_coverage(data)
        rds_findings = [f for f in findings if f.metadata.get("resource_type") == "rds"]
        assert len(rds_findings) == 0

    @settings(max_examples=50)
    @given(tables=st.lists(_ddb_table, min_size=1, max_size=5))
    def test_unprotected_ddb_produces_high(self, tables):
        """Every unprotected DynamoDB table → HIGH finding."""
        skill = BackupDRPostureSkill()
        data = {"dynamodb_tables": tables, "protected_resource_arns": set(),
                "rds_instances": [], "ebs_volumes": [], "efs_file_systems": [], "s3_buckets": []}
        findings = skill._check_backup_coverage(data)
        ddb_findings = [f for f in findings if f.metadata.get("resource_type") == "dynamodb"]
        assert len(ddb_findings) == len(tables)
        for f in ddb_findings:
            assert f.severity == Severity.HIGH


# ===================================================================
# Property 2: DR score is bounded [0, 100] and weights sum to 1.0
# ===================================================================
class TestDRScoreBounds:

    def test_weights_sum_to_one(self):
        """DR_SCORE_WEIGHTS must sum to 1.0."""
        assert abs(sum(DR_SCORE_WEIGHTS.values()) - 1.0) < 1e-9

    @settings(max_examples=50)
    @given(
        rds=st.lists(_rds_instance, max_size=3),
        tables=st.lists(_ddb_table, max_size=3),
    )
    def test_score_between_0_and_100(self, rds, tables):
        """Composite DR score is always in [0, 100]."""
        skill = BackupDRPostureSkill()
        data = {
            "rds_instances": rds, "dynamodb_tables": tables,
            "ebs_volumes": [], "efs_file_systems": [], "s3_buckets": [],
            "protected_resource_arns": set(), "backup_plans": [],
        }
        score_finding, meta = skill._compute_dr_score(data, [])
        score = meta["dr_readiness_score"]
        assert 0 <= score <= 100, f"DR score {score} out of bounds"

    @settings(max_examples=50)
    @given(
        rds=st.lists(_rds_instance, min_size=1, max_size=3),
        tables=st.lists(_ddb_table, min_size=1, max_size=3),
    )
    def test_no_backup_plans_score_low(self, rds, tables):
        """With resources but zero backup plans, frequency/retention/cross-region = 0."""
        skill = BackupDRPostureSkill()
        data = {
            "rds_instances": rds, "dynamodb_tables": tables,
            "ebs_volumes": [], "efs_file_systems": [], "s3_buckets": [],
            "protected_resource_arns": set(), "backup_plans": [],
        }
        _, meta = skill._compute_dr_score(data, [])
        assert meta["sub_scores"]["frequency"]["score"] == 0
        assert meta["sub_scores"]["retention"]["score"] == 0
        assert meta["sub_scores"]["cross_region"]["score"] == 0


# ===================================================================
# Property 3: DR score severity mapping
# ===================================================================
class TestDRScoreSeverityMapping:

    @settings(max_examples=50)
    @given(st.just(None))
    def test_zero_resources_gives_high_score(self, _):
        """No resources at all → coverage=100, pitr=100 → score ≥ 45."""
        skill = BackupDRPostureSkill()
        data = {
            "rds_instances": [], "dynamodb_tables": [],
            "ebs_volumes": [], "efs_file_systems": [], "s3_buckets": [],
            "protected_resource_arns": set(), "backup_plans": [],
        }
        score_finding, meta = skill._compute_dr_score(data, [])
        # coverage=100 (0.30) + pitr=100 (0.15) = 45 minimum
        assert meta["dr_readiness_score"] >= 45

    @settings(max_examples=50)
    @given(st.just(None))
    def test_score_below_40_is_critical(self, _):
        """Score < 40 → CRITICAL severity."""
        skill = BackupDRPostureSkill()
        # Force low score: resources but no protection, no plans
        data = {
            "rds_instances": [{"id": "db-1", "arn": "arn:aws:rds:us-east-1:123:db:db-1",
                               "region": "us-east-1", "backup_retention_period": 0}],
            "dynamodb_tables": [{"name": "t1", "arn": "arn:aws:dynamodb:us-east-1:123:table/t1",
                                 "region": "us-east-1", "pitr_enabled": False}],
            "ebs_volumes": [{"volume_id": "vol-abc", "state": "in-use", "region": "us-east-1"}],
            "efs_file_systems": [{"file_system_id": "fs-abc", "region": "us-east-1"}],
            "s3_buckets": [{"name": "my-bucket"}],
            "protected_resource_arns": set(), "backup_plans": [],
        }
        score_finding, meta = skill._compute_dr_score(data, [])
        # coverage=0, freq=0, ret=0, xr=0, pitr=0 → score=0
        assert score_finding.severity == Severity.CRITICAL


# ===================================================================
# Property 4: Finding metadata completeness
# ===================================================================
class TestBackupFindingMetadata:

    @settings(max_examples=50)
    @given(rds=st.lists(_rds_instance, min_size=1, max_size=3))
    def test_coverage_findings_have_required_metadata(self, rds):
        """Coverage findings must have resource_id, resource_type, region."""
        skill = BackupDRPostureSkill()
        data = {"rds_instances": rds, "protected_resource_arns": set(),
                "dynamodb_tables": [], "ebs_volumes": [], "efs_file_systems": [], "s3_buckets": []}
        findings = skill._check_backup_coverage(data)
        for f in findings:
            assert "resource_id" in f.metadata
            assert "resource_type" in f.metadata
            assert "region" in f.metadata
