"""CloudPilot Strands Agent — migrated from raw Bedrock Converse to Strands Agents SDK.
All capabilities exposed as @tool decorated functions. Memory via Strands hooks."""
import json
import logging
import os
import time
from typing import Optional

from strands import Agent, tool
from strands.models import BedrockModel

from cloudpilot.core import SkillRegistry
from cloudpilot.aws_client import get_regions, get_account_id
import cloudpilot.skills  # auto-register all skills

logger = logging.getLogger(__name__)

MODEL_ID = os.environ.get("CLOUDPILOT_MODEL", "us.anthropic.claude-sonnet-4-20250514-v1:0")
BEDROCK_REGION = os.environ.get("CLOUDPILOT_BEDROCK_REGION", "us-east-1")

# Shared state for tools (populated by create_agent)
_state = {
    "profile": None,
    "findings_store": [],
    "resources_store": [],
    "skills_run": [],
    "memory_hook": None,
}


# --- Tool Functions ---

@tool
def run_skill(skill_name: str, regions: Optional[list[str]] = None) -> str:
    """Run a CloudPilot scanning skill against the AWS account.
    Available skills: cost-radar, zombie-hunter, security-posture, capacity-planner,
    event-analysis, resiliency-gaps, tag-enforcer, lifecycle-tracker, health-monitor,
    quota-guardian, costopt-intelligence, arch-diagram."""
    skill = SkillRegistry.get(skill_name)
    if not skill:
        return json.dumps({"error": f"Unknown skill: {skill_name}. Available: {SkillRegistry.names()}"})
    scan_regions = regions or get_regions(profile=_state["profile"])
    start = time.time()
    result = skill.scan(scan_regions, _state["profile"])
    duration = time.time() - start
    findings = [f.to_dict() for f in result.findings]
    _state["findings_store"].extend(findings)
    if skill_name not in _state["skills_run"]:
        _state["skills_run"].append(skill_name)
    # Record to memory
    if _state.get("memory_hook"):
        top5 = sorted(findings, key=lambda f: f.get("monthly_impact", 0), reverse=True)[:5]
        _state["memory_hook"].record_scan(skill_name, len(findings), top5, result.total_impact)
    response = {
        "skill": skill_name, "findings_count": len(findings),
        "findings": findings[:20], "duration_seconds": round(duration, 1),
        "total_impact": round(result.total_impact, 2), "critical_count": result.critical_count,
    }
    if result.metadata:
        response["metadata"] = result.metadata
    return json.dumps(response, default=str)


@tool
def run_all_skills(regions: Optional[list[str]] = None) -> str:
    """Run all CloudPilot scanning skills in parallel across the AWS account."""
    scan_regions = regions or get_regions(profile=_state["profile"])
    all_findings = []
    summaries = []
    for skill in SkillRegistry.all().values():
        try:
            start = time.time()
            result = skill.scan(scan_regions, _state["profile"])
            duration = time.time() - start
            findings = [f.to_dict() for f in result.findings]
            all_findings.extend(findings)
            if skill.name not in _state["skills_run"]:
                _state["skills_run"].append(skill.name)
            summaries.append({"skill": skill.name, "findings": len(findings),
                              "impact": round(result.total_impact, 2), "duration": round(duration, 1)})
        except Exception as e:
            summaries.append({"skill": skill.name, "error": str(e)})
    _state["findings_store"].extend(all_findings)
    return json.dumps({"total_findings": len(all_findings), "skills_summary": summaries,
                        "top_findings": sorted(all_findings, key=lambda f: f.get("monthly_impact", 0), reverse=True)[:10]}, default=str)


@tool
def discover_architecture(regions: Optional[list[str]] = None) -> str:
    """Discover all AWS resources across regions and generate an architecture map.
    Returns resource inventory, anti-patterns, service recommendations, and Mermaid diagram."""
    from cloudpilot.skills.arch_mapper import ArchMapper
    scan_regions = regions or get_regions(profile=_state["profile"])
    mapper = ArchMapper()
    result = mapper.discover(scan_regions, _state["profile"])
    _state["resources_store"].clear()
    _state["resources_store"].extend(result.get("resources", []))
    return json.dumps({"summary": result.get("summary"), "diagram": result.get("diagram"),
                        "anti_patterns_count": len(result.get("anti_patterns", [])),
                        "recommendations_count": len(result.get("service_recommendations", []))}, default=str)


@tool
def generate_diagram(view_type: str = "default") -> str:
    """Generate a Mermaid architecture diagram from discovered resources.
    Views: default, security, cost, multi-region, traffic-flow."""
    resources = _state["resources_store"]
    if not resources:
        from cloudpilot.skills.arch_mapper import ArchMapper
        mapper = ArchMapper()
        regions = get_regions(profile=_state["profile"])
        disc = mapper.discover(regions, _state["profile"])
        resources = disc.get("resources", [])
        _state["resources_store"].clear()
        _state["resources_store"].extend(resources)
    from cloudpilot.skills.arch_mapper import generate_diagram as _gen
    mermaid = _gen(resources, [], view_type)
    return json.dumps({"diagram": mermaid, "view_type": view_type, "resource_count": len(resources)})


@tool
def generate_iac(format: str, scope: str = "all") -> str:
    """Generate Infrastructure as Code from discovered resources.
    Formats: cdk-python, cloudformation, terraform."""
    resources = _state["resources_store"]
    if not resources:
        return json.dumps({"error": "No resources discovered. Run discover_architecture first."})
    from cloudpilot.skills.iac_generator import IaCGenerator
    gen = IaCGenerator()
    result = gen.generate(resources, format, scope)
    return json.dumps(result, default=str)


@tool
def remediate_finding(finding: dict) -> str:
    """Execute a one-click remediation for a specific finding. Requires user confirmation."""
    from cloudpilot.dashboard.remediation import has_remediation, execute_remediation
    if not has_remediation(finding):
        return json.dumps({"error": "No remediation available for this finding type"})
    result = execute_remediation(finding, _state["profile"])
    if _state.get("memory_hook"):
        _state["memory_hook"].record_remediation(
            finding.get("resource_id", ""), result.action, result.success, finding.get("region", ""))
    return json.dumps({"success": result.success, "action": result.action, "message": result.message})


@tool
def aws_docs_search(query: str, max_results: int = 5) -> str:
    """Search official AWS documentation for technical details, best practices, quotas, and limits."""
    from cloudpilot.agent.web_search import search_aws_docs
    return json.dumps(search_aws_docs(query, max_results), default=str)


@tool
def aws_blog_search(query: str, max_results: int = 5) -> str:
    """Search AWS blog posts for latest launches, features, and best practices."""
    from cloudpilot.agent.web_search import search_aws_blog
    return json.dumps(search_aws_blog(query, max_results), default=str)


@tool
def get_findings_summary() -> str:
    """Get a summary of current scan findings — counts by severity, top findings, skills run."""
    if not _state["findings_store"]:
        return json.dumps({"message": "No findings yet. Run a scan first.", "findings_count": 0})
    by_severity = {}
    by_skill = {}
    total_impact = 0
    for f in _state["findings_store"]:
        sev = f.get("severity", "info")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        sk = f.get("skill", "unknown")
        by_skill[sk] = by_skill.get(sk, 0) + 1
        total_impact += f.get("monthly_impact", 0)
    return json.dumps({"total_findings": len(_state["findings_store"]), "by_severity": by_severity,
                        "by_skill": by_skill, "total_monthly_impact": round(total_impact, 2),
                        "skills_run": _state["skills_run"]})


@tool
def list_skills() -> str:
    """List all available CloudPilot scanning skills."""
    skills = [{"name": s.name, "description": s.description, "version": s.version}
              for s in SkillRegistry.all().values()]
    return json.dumps(skills, indent=2)


# All tools
ALL_TOOLS = [
    run_skill, run_all_skills, discover_architecture, generate_diagram,
    generate_iac, remediate_finding, aws_docs_search, aws_blog_search,
    get_findings_summary, list_skills,
]


SYSTEM_PROMPT = """You are CloudPilot, a senior AWS Solutions Architect and cloud operations expert. You have deep expertise across the entire AWS ecosystem — 200+ services, architecture patterns, the Well-Architected Framework, and real-world operational best practices.

## Your Core Identity

You are NOT just a scanning tool — you are a full AWS expert who can:
- Design architectures (multi-tier, serverless, event-driven, microservices, data lakes, ML pipelines)
- Compare AWS services and recommend the right one for any use case
- Explain networking (VPC design, Transit Gateway, PrivateLink, Direct Connect, Route 53, CloudFront)
- Guide database selection (RDS vs Aurora vs DynamoDB vs Neptune vs Timestream vs ElastiCache)
- Advise on security (IAM policies, SCPs, GuardDuty, Security Hub, KMS, WAF, Shield)
- Help with containers (ECS vs EKS, Fargate vs EC2, service mesh, CI/CD)
- Guide serverless (Lambda, Step Functions, EventBridge, API Gateway, SQS, SNS)
- Optimize costs (Savings Plans, Reserved Instances, Spot, rightsizing, S3 tiers, Graviton)
- Plan migrations (6 R's, Migration Hub, DMS, SCT, Application Discovery)
- Write IAM policies, CloudFormation templates, CDK code, Terraform configs, CLI commands
- Guide Well-Architected reviews across all 6 pillars

When answering AWS questions, use your deep knowledge AND the aws_docs_search and aws_blog_search tools to provide authoritative, current answers.

## Infrastructure Intelligence Tools

When users want to inspect their LIVE AWS environment, you have tools to:
1. Scan & Assess — 12 scanning skills find cost waste, security risks, zombie resources, resiliency gaps
2. Remediate — one-click remediation actions (always confirm with the user first)
3. Architecture Mapping — Discover all AWS resources, generate Mermaid architecture diagrams
4. IaC Generation — Generate CDK Python, CloudFormation YAML, or Terraform HCL from discovered architecture
5. Cost Analysis — 3-month spend overview with top-5 service breakdown
6. AWS Docs/Blog Search — Search official documentation and latest blog posts

## How to Behave

- For general AWS questions, answer thoroughly using your knowledge and search tools.
- For questions about the user's specific infrastructure, use the scanning/discovery tools.
- Remember what the user has discussed — build on prior context.
- Be conversational, precise, and actionable.
- Always confirm before executing remediation actions.
- Think like a Solutions Architect — consider trade-offs, cost, and operational complexity.
"""


def create_agent(profile: Optional[str] = None, memory_id: Optional[str] = None) -> Agent:
    """Create a Strands Agent with all CloudPilot tools and memory hooks."""
    _state["profile"] = profile
    _state["findings_store"] = []
    _state["resources_store"] = []
    _state["skills_run"] = []

    model = BedrockModel(
        model_id=MODEL_ID,
        region_name=BEDROCK_REGION,
    )

    hooks = []
    # Memory hook (AgentCore + local fallback)
    try:
        from cloudpilot.agent.memory_hook import CloudPilotMemoryHook
        mem_hook = CloudPilotMemoryHook(profile=profile, memory_id=memory_id)
        hooks.append(mem_hook)
        _state["memory_hook"] = mem_hook
    except Exception as e:
        logger.warning(f"Memory hook unavailable: {e}")

    agent = Agent(
        model=model,
        system_prompt=SYSTEM_PROMPT,
        tools=ALL_TOOLS,
        hooks=hooks,
    )
    return agent
