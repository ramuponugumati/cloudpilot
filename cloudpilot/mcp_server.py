"""CloudPilot MCP Server — exposes capabilities as MCP tools for Kiro/Claude Desktop."""
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def create_mcp_server(profile: Optional[str] = None):
    """Create FastMCP server with CloudPilot tools registered."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("cloudpilot", instructions="CloudPilot — AWS Infrastructure Intelligence Platform")

    # Lazy agent
    _agent = {}

    def _get_agent():
        if "agent" not in _agent:
            from cloudpilot.agent.loop import CloudPilotAgent
            _agent["agent"] = CloudPilotAgent(profile=profile)
        return _agent["agent"]

    @mcp.tool()
    def chat(message: str) -> str:
        """Chat with CloudPilot agent about your AWS infrastructure."""
        agent = _get_agent()
        return agent.chat(message)

    @mcp.tool()
    def list_skills() -> str:
        """List all available CloudPilot scanning skills."""
        from cloudpilot.core import SkillRegistry
        import cloudpilot.skills  # noqa: ensure registered
        skills = [{"name": s.name, "description": s.description, "version": s.version}
                  for s in SkillRegistry.all().values()]
        return json.dumps(skills, indent=2)

    @mcp.tool()
    def run_skill(skill_name: str, regions: Optional[list[str]] = None) -> str:
        """Run a specific CloudPilot scanning skill."""
        from cloudpilot.core import SkillRegistry
        from cloudpilot.aws_client import get_regions
        import cloudpilot.skills  # noqa
        skill = SkillRegistry.get(skill_name)
        if not skill:
            return json.dumps({"error": f"Unknown skill: {skill_name}. Available: {SkillRegistry.names()}"})
        scan_regions = regions or get_regions(profile=profile)
        result = skill.scan(scan_regions, profile)
        return json.dumps({
            "skill": skill_name,
            "findings_count": len(result.findings),
            "findings": [f.to_dict() for f in result.findings][:20],
            "total_impact": round(result.total_impact, 2),
        }, default=str)

    @mcp.tool()
    def discover_architecture(regions: Optional[list[str]] = None) -> str:
        """Discover all AWS resources and generate architecture map."""
        from cloudpilot.skills.arch_mapper import ArchMapper
        from cloudpilot.aws_client import get_regions
        mapper = ArchMapper()
        scan_regions = regions or get_regions(profile=profile)
        result = mapper.discover(scan_regions, profile)
        agent = _get_agent()
        agent.resources_store.clear()
        agent.resources_store.extend(result.get("resources", []))
        return json.dumps({
            "summary": result.get("summary"),
            "diagram": result.get("diagram"),
            "anti_patterns_count": len(result.get("anti_patterns", [])),
            "recommendations_count": len(result.get("service_recommendations", [])),
        }, default=str)

    @mcp.tool()
    def generate_iac(format: str, scope: str = "all") -> str:
        """Generate IaC (cdk-python, cloudformation, terraform) from discovered resources."""
        agent = _get_agent()
        if not agent.resources_store:
            return json.dumps({"error": "No resources discovered. Run discover_architecture first."})
        from cloudpilot.skills.iac_generator import IaCGenerator
        gen = IaCGenerator()
        result = gen.generate(agent.resources_store, format, scope)
        return json.dumps(result, default=str)

    @mcp.tool()
    def get_findings_summary() -> str:
        """Get summary of current scan findings."""
        agent = _get_agent()
        if not agent.findings_store:
            return json.dumps({"message": "No findings yet. Run a scan first."})
        by_sev = {}
        for f in agent.findings_store:
            sev = f.get("severity", "info")
            by_sev[sev] = by_sev.get(sev, 0) + 1
        return json.dumps({
            "total": len(agent.findings_store),
            "by_severity": by_sev,
            "total_impact": sum(f.get("monthly_impact", 0) for f in agent.findings_store),
        })

    @mcp.tool()
    def run_all_skills(regions: Optional[list[str]] = None) -> str:
        """Run all CloudPilot scanning skills in parallel."""
        from cloudpilot.core import SkillRegistry
        from cloudpilot.aws_client import get_regions
        import cloudpilot.skills  # noqa
        import concurrent.futures
        scan_regions = regions or get_regions(profile=profile)
        skills = list(SkillRegistry.all().values())
        all_findings = []
        summaries = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(skills)) as pool:
            futures = {pool.submit(s.scan, scan_regions, profile): s for s in skills}
            for future in concurrent.futures.as_completed(futures):
                skill = futures[future]
                try:
                    result = future.result()
                    findings = [f.to_dict() for f in result.findings]
                    all_findings.extend(findings)
                    summaries.append({"skill": skill.name, "findings": len(findings), "impact": round(result.total_impact, 2)})
                except Exception as e:
                    summaries.append({"skill": skill.name, "error": str(e)})
        agent = _get_agent()
        agent.findings_store.extend(all_findings)
        return json.dumps({"total_findings": len(all_findings), "skills_summary": summaries}, default=str)

    @mcp.tool()
    def generate_diagram(view_type: str = "default") -> str:
        """Generate Mermaid architecture diagram. Views: default, security, cost, multi-region, traffic-flow."""
        agent = _get_agent()
        if not agent.resources_store:
            return json.dumps({"error": "No resources discovered. Run discover_architecture first."})
        from cloudpilot.skills.arch_mapper import generate_diagram as gen_diag
        mermaid = gen_diag(agent.resources_store, [], view_type)
        return json.dumps({"diagram": mermaid, "view_type": view_type, "resource_count": len(agent.resources_store)})

    @mcp.tool()
    def aws_docs_search(query: str, max_results: int = 5) -> str:
        """Search official AWS documentation for authoritative technical details."""
        from cloudpilot.agent.web_search import search_aws_docs
        return json.dumps(search_aws_docs(query, max_results), default=str)

    @mcp.tool()
    def aws_blog_search(query: str, max_results: int = 5) -> str:
        """Search AWS What's New and blog posts for latest launches and features."""
        from cloudpilot.agent.web_search import search_aws_blog
        return json.dumps(search_aws_blog(query, max_results), default=str)

    @mcp.tool()
    def remediate_finding(finding: dict) -> str:
        """Execute a one-click remediation for a finding. Requires user confirmation."""
        from cloudpilot.dashboard.remediation import has_remediation, execute_remediation
        if not has_remediation(finding):
            return json.dumps({"error": "No remediation available for this finding type"})
        result = execute_remediation(finding, profile)
        return json.dumps({"success": result.success, "action": result.action, "message": result.message}, default=str)

    return mcp


def run_mcp_server(profile: Optional[str] = None, transport: str = "stdio"):
    """Start MCP server. Transport: 'stdio' (local) or 'sse' (HTTP)."""
    mcp = create_mcp_server(profile=profile)
    if transport == "sse":
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")
