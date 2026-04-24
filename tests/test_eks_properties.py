"""Property-based tests for CloudPilot EKS Optimizer skill.

Tests exercise pure logic functions directly — no AWS credentials needed.
"""
import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from cloudpilot.core import Finding, Severity
from cloudpilot.skills.eks_optimizer import (
    EKSOptimizerSkill,
    LATEST_EKS_VERSION,
    ALL_LOG_TYPES,
    GRAVITON_MAP,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_latest_minor = int(LATEST_EKS_VERSION.split(".")[1])


def _cluster(version="1.31", name="test-cluster", region="us-east-1",
             logging_types=None, encryption=True, public_access=True,
             private_access=False, public_cidrs=None):
    enc_config = [{"resources": ["secrets"]}] if encryption else []
    return {
        "name": name, "region": region, "version": version,
        "logging": {"types": logging_types if logging_types is not None else list(ALL_LOG_TYPES)},
        "encryption_config": enc_config,
        "endpoint": {
            "public": public_access,
            "private": private_access,
            "public_cidrs": public_cidrs or (["0.0.0.0/0"] if public_access else []),
        },
        "node_groups": [], "tags": {},
    }


def _ecr_repo(name="my-repo", region="us-east-1", scan_on_push=True,
              latest_scan=None, image_count=5, total_size=1024*1024*100):
    return {
        "name": name, "region": region, "scan_on_push": scan_on_push,
        "latest_scan": latest_scan, "image_count": image_count,
        "total_size_bytes": total_size,
    }


# ===================================================================
# Property 1: Version gap → correct severity
# ===================================================================
class TestEKSVersionGap:

    @settings(max_examples=50)
    @given(gap=st.integers(min_value=2, max_value=10))
    def test_version_gap_gte_2_produces_high(self, gap):
        """Cluster ≥2 versions behind → HIGH."""
        skill = EKSOptimizerSkill()
        minor = max(_latest_minor - gap, 20)
        cluster = _cluster(version=f"1.{minor}")
        findings = skill._check_cluster_version(cluster)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    @settings(max_examples=50)
    @given(st.just(None))
    def test_version_gap_1_produces_medium(self, _):
        """Cluster 1 version behind → MEDIUM."""
        skill = EKSOptimizerSkill()
        cluster = _cluster(version=f"1.{_latest_minor - 1}")
        findings = skill._check_cluster_version(cluster)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    @settings(max_examples=50)
    @given(st.just(None))
    def test_current_version_produces_info(self, _):
        """Cluster on latest version → INFO."""
        skill = EKSOptimizerSkill()
        cluster = _cluster(version=LATEST_EKS_VERSION)
        findings = skill._check_cluster_version(cluster)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    @settings(max_examples=50)
    @given(bad_version=st.sampled_from(["", "invalid", "abc", "1", "1."]))
    def test_invalid_version_returns_zero_gap(self, bad_version):
        """Invalid version string → gap=0 → INFO."""
        skill = EKSOptimizerSkill()
        gap = skill._get_version_gap(bad_version)
        assert gap == 0


# ===================================================================
# Property 2: ECR scan-on-push disabled → HIGH
# ===================================================================
class TestECRScanOnPush:

    @settings(max_examples=50)
    @given(name=st.text(alphabet="abcdefghijklmnopqrstuvwxyz-/", min_size=3, max_size=20))
    def test_scan_disabled_produces_high(self, name):
        """ECR repo without scan-on-push → HIGH."""
        skill = EKSOptimizerSkill()
        repo = _ecr_repo(name=name, scan_on_push=False)
        findings = skill._check_ecr_security(repo)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    @settings(max_examples=50)
    @given(st.just(None))
    def test_scan_enabled_no_results_produces_medium(self, _):
        """ECR repo with scan-on-push but no scan results → MEDIUM."""
        skill = EKSOptimizerSkill()
        repo = _ecr_repo(scan_on_push=True, latest_scan=None)
        findings = skill._check_ecr_security(repo)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM


# ===================================================================
# Property 3: ECR vulnerability severity mapping
# ===================================================================
class TestECRVulnerabilities:

    @settings(max_examples=50)
    @given(crit=st.integers(min_value=1, max_value=100))
    def test_critical_vulns_produce_critical(self, crit):
        """ECR image with critical vulns → CRITICAL finding."""
        skill = EKSOptimizerSkill()
        repo = _ecr_repo(latest_scan={"critical_count": crit, "high_count": 0, "image_tag": "latest"})
        findings = skill._check_ecr_security(repo)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    @settings(max_examples=50)
    @given(high=st.integers(min_value=1, max_value=100))
    def test_high_vulns_produce_high(self, high):
        """ECR image with high vulns (no critical) → HIGH finding."""
        skill = EKSOptimizerSkill()
        repo = _ecr_repo(latest_scan={"critical_count": 0, "high_count": high, "image_tag": "latest"})
        findings = skill._check_ecr_security(repo)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    @settings(max_examples=50)
    @given(st.just(None))
    def test_clean_scan_produces_no_finding(self, _):
        """ECR image with zero vulns → no finding from _check_ecr_security."""
        skill = EKSOptimizerSkill()
        repo = _ecr_repo(latest_scan={"critical_count": 0, "high_count": 0, "image_tag": "latest"})
        findings = skill._check_ecr_security(repo)
        assert len(findings) == 0


# ===================================================================
# Property 4: Cluster logging completeness
# ===================================================================
class TestClusterLogging:

    @settings(max_examples=50)
    @given(st.just(None))
    def test_all_log_types_enabled_produces_info(self, _):
        """All 5 log types enabled → INFO."""
        skill = EKSOptimizerSkill()
        cluster = _cluster(logging_types=list(ALL_LOG_TYPES))
        findings = skill._check_cluster_logging(cluster)
        info_findings = [f for f in findings if f.severity == Severity.INFO]
        assert len(info_findings) >= 1

    @settings(max_examples=50)
    @given(
        enabled=st.lists(
            st.sampled_from(list(ALL_LOG_TYPES)),
            min_size=1, max_size=4, unique=True,
        )
    )
    def test_missing_log_types_produces_medium(self, enabled):
        """Missing log types (but at least 1 enabled) → MEDIUM finding."""
        assume(set(enabled) != ALL_LOG_TYPES)
        skill = EKSOptimizerSkill()
        cluster = _cluster(logging_types=enabled)
        findings = skill._check_cluster_logging(cluster)
        medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(medium_findings) >= 1

    @settings(max_examples=50)
    @given(st.just(None))
    def test_no_logging_produces_high(self, _):
        """Zero log types enabled → HIGH finding."""
        skill = EKSOptimizerSkill()
        cluster = _cluster(logging_types=[])
        findings = skill._check_cluster_logging(cluster)
        high_findings = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high_findings) >= 1


# ===================================================================
# Property 5: Graviton mapping correctness
# ===================================================================
class TestGravitonMapping:

    @settings(max_examples=50)
    @given(family=st.sampled_from(list(GRAVITON_MAP.keys())))
    def test_graviton_equivalent_exists(self, family):
        """Every mapped family has a Graviton equivalent."""
        skill = EKSOptimizerSkill()
        instance_type = f"{family}.xlarge"
        result = skill._get_graviton_equivalent(instance_type)
        assert result is not None
        assert result != instance_type

    @settings(max_examples=50)
    @given(family=st.sampled_from(["m7g", "c7g", "r7g", "t4g", "p4d", "inf2"]))
    def test_already_graviton_returns_none(self, family):
        """Already-Graviton or non-mapped family → None."""
        skill = EKSOptimizerSkill()
        result = skill._get_graviton_equivalent(f"{family}.xlarge")
        assert result is None


# ===================================================================
# Property 6: Encryption/endpoint checks
# ===================================================================
class TestClusterEncryptionEndpoint:

    @settings(max_examples=50)
    @given(st.just(None))
    def test_no_encryption_produces_high(self, _):
        """Cluster without secrets encryption → HIGH."""
        skill = EKSOptimizerSkill()
        cluster = _cluster(encryption=False)
        findings = skill._check_cluster_encryption_endpoint(cluster)
        enc_findings = [f for f in findings if "encrypt" in f.title.lower() or "secrets" in f.title.lower()]
        assert len(enc_findings) >= 1
        assert enc_findings[0].severity == Severity.HIGH

    @settings(max_examples=50)
    @given(st.just(None))
    def test_public_only_endpoint_produces_critical_or_high(self, _):
        """Cluster with public endpoint open to 0.0.0.0/0 → CRITICAL."""
        skill = EKSOptimizerSkill()
        cluster = _cluster(public_access=True, private_access=False, public_cidrs=["0.0.0.0/0"])
        findings = skill._check_cluster_encryption_endpoint(cluster)
        endpoint_findings = [f for f in findings if "public" in f.title.lower() or "api" in f.title.lower()]
        assert len(endpoint_findings) >= 1
        assert endpoint_findings[0].severity == Severity.CRITICAL
