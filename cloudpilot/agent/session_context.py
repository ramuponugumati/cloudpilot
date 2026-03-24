"""Session context — in-memory tracking of current session activity.
Injected into the LLM system prompt each turn so the agent knows what happened."""
from dataclasses import dataclass, field


@dataclass
class SessionContext:
    skills_run: list = field(default_factory=list)
    findings_by_skill: dict = field(default_factory=dict)
    total_findings: int = 0
    total_impact: float = 0.0
    remediations_applied: list = field(default_factory=list)
    discovered_resources_count: int = 0

    def record_skill_run(self, skill_name: str, finding_count: int, impact: float):
        if skill_name not in self.skills_run:
            self.skills_run.append(skill_name)
        self.findings_by_skill[skill_name] = finding_count
        self.total_findings += finding_count
        self.total_impact += impact

    def record_remediation(self, resource_id: str, action: str, success: bool):
        self.remediations_applied.append({
            "resource_id": resource_id, "action": action, "success": success,
        })

    def to_prompt(self) -> str:
        if not self.skills_run:
            return ""
        lines = [
            f"Skills run this session: {', '.join(self.skills_run)}",
            f"Total findings: {self.total_findings} (${self.total_impact:.2f}/mo impact)",
        ]
        for skill, count in self.findings_by_skill.items():
            lines.append(f"  {skill}: {count} findings")
        if self.remediations_applied:
            lines.append(f"Remediations applied: {len(self.remediations_applied)}")
            for r in self.remediations_applied[-5:]:
                status = "✅" if r["success"] else "❌"
                lines.append(f"  {status} {r['action']} on {r['resource_id']}")
        if self.discovered_resources_count:
            lines.append(f"Resources discovered: {self.discovered_resources_count}")
        return "\n".join(lines)
