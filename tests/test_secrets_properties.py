"""Property-based tests for CloudPilot Secrets Hygiene skill.

Tests exercise pure logic functions directly — no AWS credentials needed.
"""
import pytest
from datetime import datetime, timezone, timedelta
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from cloudpilot.core import Finding, Severity
from cloudpilot.skills.secrets_hygiene import (
    SecretsHygieneSkill,
    ROTATION_MAX_DAYS,
    UNUSED_SECRET_DAYS,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------
def _iso_date(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


_secret_with_rotation = st.builds(
    lambda name, age: {
        "name": name, "arn": f"arn:aws:secretsmanager:us-east-1:123:secret:{name}",
        "rotation_enabled": True,
        "last_rotated": _iso_date(age),
        "last_accessed": _iso_date(1),
        "region": "us-east-1",
    },
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz-", min_size=3, max_size=15),
    st.integers(min_value=1, max_value=365),
)

_secret_no_rotation = st.builds(
    lambda name: {
        "name": name, "arn": f"arn:aws:secretsmanager:us-east-1:123:secret:{name}",
        "rotation_enabled": False,
        "last_rotated": "",
        "last_accessed": _iso_date(1),
        "region": "us-east-1",
    },
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz-", min_size=3, max_size=15),
)


# ===================================================================
# Property 1: Overdue rotation → HIGH finding
# ===================================================================
class TestRotationOverdue:

    @settings(max_examples=50)
    @given(age=st.integers(min_value=ROTATION_MAX_DAYS + 1, max_value=365))
    def test_overdue_rotation_produces_high(self, age):
        """Secret with rotation enabled but last rotated > 90 days → HIGH."""
        skill = SecretsHygieneSkill()
        secret = {
            "name": "my-secret", "rotation_enabled": True,
            "last_rotated": _iso_date(age), "last_accessed": _iso_date(1),
            "region": "us-east-1",
        }
        data = {"secrets": [secret], "parameters": []}
        findings = skill._check_rotation(data)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].metadata["last_rotated_days"] >= ROTATION_MAX_DAYS

    @settings(max_examples=50)
    @given(age=st.integers(min_value=1, max_value=ROTATION_MAX_DAYS))
    def test_recent_rotation_produces_no_finding(self, age):
        """Secret rotated within 90 days → no finding."""
        skill = SecretsHygieneSkill()
        secret = {
            "name": "my-secret", "rotation_enabled": True,
            "last_rotated": _iso_date(age), "last_accessed": _iso_date(1),
            "region": "us-east-1",
        }
        data = {"secrets": [secret], "parameters": []}
        findings = skill._check_rotation(data)
        assert len(findings) == 0


# ===================================================================
# Property 2: No rotation config → HIGH finding
# ===================================================================
class TestNoRotationConfig:

    @settings(max_examples=50)
    @given(name=st.text(alphabet="abcdefghijklmnopqrstuvwxyz-", min_size=3, max_size=15))
    def test_no_rotation_config_produces_high(self, name):
        """Secret without rotation enabled → HIGH."""
        skill = SecretsHygieneSkill()
        secret = {"name": name, "rotation_enabled": False, "region": "us-east-1"}
        data = {"secrets": [secret], "parameters": []}
        findings = skill._check_no_rotation_config(data)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].metadata["rotation_enabled"] is False

    @settings(max_examples=50)
    @given(name=st.text(alphabet="abcdefghijklmnopqrstuvwxyz-", min_size=3, max_size=15))
    def test_rotation_enabled_produces_no_finding(self, name):
        """Secret with rotation enabled → no finding from this checker."""
        skill = SecretsHygieneSkill()
        secret = {"name": name, "rotation_enabled": True, "region": "us-east-1"}
        data = {"secrets": [secret], "parameters": []}
        findings = skill._check_no_rotation_config(data)
        assert len(findings) == 0


# ===================================================================
# Property 3: Unused secrets → LOW or MEDIUM finding
# ===================================================================
class TestUnusedSecrets:

    @settings(max_examples=50)
    @given(age=st.integers(min_value=UNUSED_SECRET_DAYS + 1, max_value=365))
    def test_old_access_produces_low(self, age):
        """Secret last accessed > 90 days ago → LOW."""
        skill = SecretsHygieneSkill()
        secret = {
            "name": "old-secret", "last_accessed": _iso_date(age),
            "rotation_enabled": False, "region": "us-east-1",
        }
        data = {"secrets": [secret], "parameters": []}
        findings = skill._check_unused_secrets(data)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    @settings(max_examples=50)
    @given(st.just(None))
    def test_never_accessed_produces_medium(self, _):
        """Secret never accessed → MEDIUM."""
        skill = SecretsHygieneSkill()
        secret = {
            "name": "never-used", "last_accessed": "",
            "rotation_enabled": False, "region": "us-east-1",
        }
        data = {"secrets": [secret], "parameters": []}
        findings = skill._check_unused_secrets(data)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    @settings(max_examples=50)
    @given(age=st.integers(min_value=1, max_value=UNUSED_SECRET_DAYS))
    def test_recently_accessed_produces_no_finding(self, age):
        """Secret accessed within 90 days → no finding."""
        skill = SecretsHygieneSkill()
        secret = {
            "name": "active-secret", "last_accessed": _iso_date(age),
            "rotation_enabled": False, "region": "us-east-1",
        }
        data = {"secrets": [secret], "parameters": []}
        findings = skill._check_unused_secrets(data)
        assert len(findings) == 0


# ===================================================================
# Property 4: Stale SSM SecureString → MEDIUM finding
# ===================================================================
class TestSSMSensitive:

    @settings(max_examples=50)
    @given(age=st.integers(min_value=ROTATION_MAX_DAYS + 1, max_value=365))
    def test_stale_ssm_param_produces_medium(self, age):
        """SSM SecureString not modified in > 90 days → MEDIUM."""
        skill = SecretsHygieneSkill()
        param = {
            "name": "/app/db-password", "type": "SecureString",
            "last_modified": _iso_date(age), "version": 1, "region": "us-east-1",
        }
        data = {"secrets": [], "parameters": [param]}
        findings = skill._check_ssm_sensitive(data)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    @settings(max_examples=50)
    @given(age=st.integers(min_value=1, max_value=ROTATION_MAX_DAYS))
    def test_recent_ssm_param_produces_no_finding(self, age):
        """SSM SecureString modified within 90 days → no finding."""
        skill = SecretsHygieneSkill()
        param = {
            "name": "/app/db-password", "type": "SecureString",
            "last_modified": _iso_date(age), "version": 2, "region": "us-east-1",
        }
        data = {"secrets": [], "parameters": [param]}
        findings = skill._check_ssm_sensitive(data)
        assert len(findings) == 0


# ===================================================================
# Property 5: Merge preserves all data
# ===================================================================
class TestMerge:

    @settings(max_examples=50)
    @given(
        n_regions=st.integers(min_value=1, max_value=4),
        secrets_per=st.integers(min_value=0, max_value=3),
        params_per=st.integers(min_value=0, max_value=3),
    )
    def test_merge_preserves_counts(self, n_regions, secrets_per, params_per):
        """Merging N region results preserves total secret + param counts."""
        skill = SecretsHygieneSkill()
        region_results = []
        for i in range(n_regions):
            region_results.append({
                "secrets": [{"name": f"s-{i}-{j}"} for j in range(secrets_per)],
                "parameters": [{"name": f"p-{i}-{j}"} for j in range(params_per)],
                "errors": [],
            })
        merged = skill._merge(region_results)
        assert len(merged["secrets"]) == n_regions * secrets_per
        assert len(merged["parameters"]) == n_regions * params_per
