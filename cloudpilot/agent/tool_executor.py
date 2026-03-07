"""Tool executor — dispatches agent tool calls to actual skill/capability implementations."""
import logging
import time
from typing import Optional

from cloudpilot.core import SkillRegistry
from cloudpilot.aws_client import get_regions

logger = logging.getLogger(__name__)


def execute_tool(
    tool_name: str,
    tool_input: dict,
    profile: Optional[str] = None,
    findings_store: Optional[list] = None,
    resources_store: Optional[list] = None,
    skills_run: Optional[list] = None,
) -> dict:
    """Execute a tool and return the result dict."""

    if tool_name == "list_skills":
        skills = SkillRegistry.all()
        return {
            "skills": [
                {"name": s.name, "description": s.description, "version": s.version}
                for s in skills.values()
            ]
        }

    elif tool_name == "run_skill":
        skill_name = tool_input["skill_name"]
        skill = SkillRegistry.get(skill_name)
        if not skill:
            return {"error": f"Unknown skill: {skill_name}. Available: {SkillRegistry.names()}"}
        regions = tool_input.get("regions") or get_regions(profile=profile)
        start = time.time()
        result = skill.scan(regions, profile)
        duration = time.time() - start
        findings = [f.to_dict() for f in result.findings]
        if findings_store is not None:
            findings_store.extend(findings)
        if skills_run is not None and skill_name not in skills_run:
            skills_run.append(skill_name)
        return {
            "skill": skill_name,
            "findings_count": len(findings),
            "findings": findings[:20],  # Cap at 20 for context window
            "duration_seconds": round(duration, 1),
            "total_impact": round(result.total_impact, 2),
            "critical_count": result.critical_count,
        }

    elif tool_name == "run_all_skills":
        regions = tool_input.get("regions") or get_regions(profile=profile)
        all_findings = []
        summaries = []
        for skill in SkillRegistry.all().values():
            try:
                start = time.time()
                result = skill.scan(regions, profile)
                duration = time.time() - start
                findings = [f.to_dict() for f in result.findings]
                all_findings.extend(findings)
                if skills_run is not None and skill.name not in skills_run:
                    skills_run.append(skill.name)
                summaries.append({
                    "skill": skill.name,
                    "findings": len(findings),
                    "impact": round(result.total_impact, 2),
                    "critical": result.critical_count,
                    "duration": round(duration, 1),
                })
            except Exception as e:
                summaries.append({"skill": skill.name, "error": str(e)})
        if findings_store is not None:
            findings_store.extend(all_findings)
        return {
            "total_findings": len(all_findings),
            "skills_summary": summaries,
            "top_findings": sorted(all_findings, key=lambda f: f.get("monthly_impact", 0), reverse=True)[:10],
        }

    elif tool_name == "remediate_finding":
        finding = tool_input.get("finding", {})
        from cloudpilot.dashboard.remediation import has_remediation, execute_remediation
        if not has_remediation(finding):
            return {"error": "No remediation available for this finding type"}
        success, message = execute_remediation(finding, profile)
        return {"success": success, "message": message}

    elif tool_name == "discover_architecture":
        regions = tool_input.get("regions") or get_regions(profile=profile)
        from cloudpilot.skills.arch_mapper import ArchMapper
        mapper = ArchMapper()
        result = mapper.discover(regions, profile)
        if resources_store is not None:
            resources_store.clear()
            resources_store.extend(result.get("resources", []))
        return result

    elif tool_name == "generate_iac":
        fmt = tool_input["format"]
        resources = tool_input.get("resources") or resources_store or []
        if not resources:
            # Auto-discover first
            from cloudpilot.skills.arch_mapper import ArchMapper
            mapper = ArchMapper()
            regions = get_regions(profile=profile)
            disc = mapper.discover(regions, profile)
            resources = disc.get("resources", [])
            if resources_store is not None:
                resources_store.clear()
                resources_store.extend(resources)
        scope = tool_input.get("scope", "all")
        from cloudpilot.skills.iac_generator import IaCGenerator
        gen = IaCGenerator()
        return gen.generate(resources, fmt, scope)

    elif tool_name == "get_findings_summary":
        if not findings_store:
            return {"message": "No findings yet. Run a scan first.", "findings_count": 0}
        by_severity = {}
        by_skill = {}
        total_impact = 0
        for f in findings_store:
            sev = f.get("severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            sk = f.get("skill", "unknown")
            by_skill[sk] = by_skill.get(sk, 0) + 1
            total_impact += f.get("monthly_impact", 0)
        return {
            "total_findings": len(findings_store),
            "by_severity": by_severity,
            "by_skill": by_skill,
            "total_monthly_impact": round(total_impact, 2),
            "skills_run": skills_run or [],
            "top_findings": sorted(findings_store, key=lambda f: f.get("monthly_impact", 0), reverse=True)[:5],
        }

    else:
        return {"error": f"Unknown tool: {tool_name}"}
