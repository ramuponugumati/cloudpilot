"""Tests for tool_executor dispatch logic — verifies tool routing, error handling,
and result structure without hitting AWS."""
import pytest
from unittest.mock import patch, MagicMock
from cloudpilot.agent.tool_executor import execute_tool
from cloudpilot.core import SkillResult, Finding, Severity, SkillRegistry


class TestListSkills:

    def test_list_skills_returns_all_registered(self):
        """list_skills returns every registered skill."""
        result = execute_tool("list_skills", {})
        assert "skills" in result
        names = {s["name"] for s in result["skills"]}
        assert "cost-radar" in names
        assert "zombie-hunter" in names
        assert "security-posture" in names
        assert len(names) == 28

    def test_list_skills_has_required_fields(self):
        """Each skill entry has name, description, version."""
        result = execute_tool("list_skills", {})
        for s in result["skills"]:
            assert "name" in s
            assert "description" in s
            assert "version" in s


class TestRunSkill:

    def test_unknown_skill_returns_error(self):
        """Unknown skill name → error message."""
        result = execute_tool("run_skill", {"skill_name": "nonexistent-skill"})
        assert "error" in result
        assert "nonexistent-skill" in result["error"]

    @patch("cloudpilot.agent.tool_executor.get_regions", return_value=["us-east-1"])
    def test_run_skill_returns_findings_structure(self, mock_regions):
        """run_skill returns expected keys in result."""
        # Mock the skill's scan method
        skill = SkillRegistry.get("cost-radar")
        original_scan = skill.scan
        skill.scan = MagicMock(return_value=SkillResult(
            skill_name="cost-radar",
            findings=[Finding(skill="cost-radar", title="test", severity=Severity.LOW, description="d")],
        ))
        try:
            result = execute_tool("run_skill", {"skill_name": "cost-radar"}, profile="test")
            assert result["skill"] == "cost-radar"
            assert "findings_count" in result
            assert "findings" in result
            assert "duration_seconds" in result
            assert "total_impact" in result
            assert "critical_count" in result
        finally:
            skill.scan = original_scan


class TestRunSuite:

    @patch("cloudpilot.agent.tool_executor.get_regions", return_value=["us-east-1"])
    def test_run_suite_unknown_skill_reports_error(self, mock_regions):
        """Suite with unknown skill name → error in summary."""
        result = execute_tool("run_suite", {"skill_names": ["nonexistent"]}, profile="test")
        assert result["suite_skills"] == ["nonexistent"]
        assert any("error" in s for s in result["skills_summary"])

    @patch("cloudpilot.agent.tool_executor.get_regions", return_value=["us-east-1"])
    def test_run_suite_populates_findings_store(self, mock_regions):
        """Suite results are appended to findings_store."""
        findings_store = []
        skills_run = []
        skill = SkillRegistry.get("zombie-hunter")
        original_scan = skill.scan
        skill.scan = MagicMock(return_value=SkillResult(
            skill_name="zombie-hunter",
            findings=[Finding(skill="zombie-hunter", title="z", severity=Severity.LOW, description="d")],
        ))
        try:
            execute_tool("run_suite", {"skill_names": ["zombie-hunter"]},
                         profile="test", findings_store=findings_store, skills_run=skills_run)
            assert len(findings_store) == 1
            assert "zombie-hunter" in skills_run
        finally:
            skill.scan = original_scan


class TestGetFindingsSummary:

    def test_empty_store_returns_message(self):
        """No findings → helpful message."""
        result = execute_tool("get_findings_summary", {}, findings_store=[])
        assert result["findings_count"] == 0

    def test_summary_counts_by_severity(self):
        """Summary correctly counts by severity."""
        store = [
            {"severity": "high", "skill": "security-posture", "monthly_impact": 0},
            {"severity": "high", "skill": "security-posture", "monthly_impact": 0},
            {"severity": "low", "skill": "zombie-hunter", "monthly_impact": 50},
        ]
        result = execute_tool("get_findings_summary", {}, findings_store=store)
        assert result["total_findings"] == 3
        assert result["by_severity"]["high"] == 2
        assert result["by_severity"]["low"] == 1
        assert result["total_monthly_impact"] == 50


class TestUnknownTool:

    def test_unknown_tool_returns_error(self):
        """Unknown tool name → error."""
        result = execute_tool("totally_fake_tool", {})
        assert "error" in result
        assert "totally_fake_tool" in result["error"]
