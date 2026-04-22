"""Security Group Chain Analyzer — scan SGs for overly permissive rules
and trace SG-to-SG reference chains.

Scans all security groups across regions in parallel, classifies each rule
by severity, and follows SG-to-SG references transitively.

All API calls are read-only (describe/list/get).
"""
import time
import logging

from cloudpilot.core import (
    BaseSkill, Finding, Severity, SkillResult, SkillRegistry,
)
from cloudpilot.aws_client import get_account_id, get_regions, parallel_regions
from cloudpilot.skills.network_helpers import discover_security_groups

logger = logging.getLogger(__name__)


class SGChainAnalyzer(BaseSkill):
    name = "sg-chain-analyzer"
    description = "Analyze security group rules for overly permissive configurations and trace SG chains"
    version = "0.1.0"

    def scan(self, regions=None, profile=None, account_id=None, **kwargs) -> SkillResult:
        """Scan all SGs across regions, produce findings for risky rules."""
        start = time.time()
        findings: list[Finding] = []
        errors: list[str] = []
        acct = account_id or ""

        try:
            acct = acct or get_account_id(profile)
        except Exception:
            pass

        # Resolve regions
        scan_regions = regions or get_regions(profile=profile)

        # Discover SGs across all regions in parallel
        try:
            all_sgs = parallel_regions(discover_security_groups, scan_regions, profile=profile)
        except Exception as e:
            errors.append(f"parallel_regions discover_security_groups: {e}")
            all_sgs = []

        # Build lookup map: group_id -> sg dict
        sg_map: dict[str, dict] = {}
        for sg in all_sgs:
            sg_map[sg["group_id"]] = sg

        # Analyze each SG
        for sg in all_sgs:
            try:
                sg_findings = self._analyze_sg(sg, sg_map, acct)
                findings.extend(sg_findings)
            except Exception as e:
                errors.append(f"_analyze_sg {sg.get('group_id', '?')}: {e}")

        duration = time.time() - start
        return SkillResult(
            skill_name=self.name,
            findings=findings,
            duration_seconds=duration,
            accounts_scanned=1,
            regions_scanned=len(scan_regions),
            errors=errors,
        )

    def _analyze_sg(self, sg: dict, all_sgs: dict[str, dict], account_id: str = "") -> list[Finding]:
        """Analyze a single SG and return findings for risky rules."""
        findings: list[Finding] = []
        group_id = sg.get("group_id", "")
        vpc_id = sg.get("vpc_id", "")
        associated = sg.get("associated_resources", [])
        inbound_rules = sg.get("inbound_rules", [])
        outbound_rules = sg.get("outbound_rules", [])

        # Check for no inbound rules → INFO
        if not inbound_rules:
            findings.append(Finding(
                skill=self.name,
                title=f"No inbound rules: {group_id}",
                severity=Severity.INFO,
                description=f"Security group {group_id} has no inbound rules — no inbound traffic is allowed.",
                resource_id=group_id,
                account_id=account_id,
                region=sg.get("region", ""),
                recommended_action="Verify this is intentional. Add inbound rules if traffic is expected.",
                metadata={
                    "security_group_id": group_id,
                    "vpc_id": vpc_id,
                    "associated_resources": associated,
                    "triggering_rule": "none — no inbound rules",
                },
            ))

        # Evaluate inbound rules
        for rule in inbound_rules:
            severity, description = self._classify_rule_severity(rule, direction="inbound")
            if severity is not None:
                findings.append(Finding(
                    skill=self.name,
                    title=f"{severity.value.upper()} SG rule: {group_id}",
                    severity=severity,
                    description=description,
                    resource_id=group_id,
                    account_id=account_id,
                    region=sg.get("region", ""),
                    recommended_action=self._recommend_action(severity, rule, "inbound"),
                    metadata={
                        "security_group_id": group_id,
                        "vpc_id": vpc_id,
                        "associated_resources": associated,
                        "triggering_rule": rule,
                    },
                ))

        # Evaluate outbound rules
        for rule in outbound_rules:
            severity, description = self._classify_rule_severity(rule, direction="outbound")
            if severity is not None:
                findings.append(Finding(
                    skill=self.name,
                    title=f"{severity.value.upper()} SG rule: {group_id}",
                    severity=severity,
                    description=description,
                    resource_id=group_id,
                    account_id=account_id,
                    region=sg.get("region", ""),
                    recommended_action=self._recommend_action(severity, rule, "outbound"),
                    metadata={
                        "security_group_id": group_id,
                        "vpc_id": vpc_id,
                        "associated_resources": associated,
                        "triggering_rule": rule,
                    },
                ))

        # Trace SG-to-SG chains for inbound rules referencing other SGs
        chain = self._trace_sg_chain(group_id, all_sgs)
        if chain:
            for entry in chain:
                ref_sg_id = entry.get("sg_id", "")
                findings.append(Finding(
                    skill=self.name,
                    title=f"SG chain reference: {group_id} → {ref_sg_id}",
                    severity=Severity.INFO,
                    description=(
                        f"Security group {group_id} references {ref_sg_id} as a source. "
                        f"Chain depth: {len(chain)} group(s)."
                    ),
                    resource_id=group_id,
                    account_id=account_id,
                    region=sg.get("region", ""),
                    recommended_action="Review referenced security group rules for combined access.",
                    metadata={
                        "security_group_id": group_id,
                        "vpc_id": vpc_id,
                        "associated_resources": associated,
                        "triggering_rule": f"SG reference to {ref_sg_id}",
                        "sg_chain": chain,
                    },
                ))

        return findings

    def _classify_rule_severity(self, rule: dict, direction: str = "inbound") -> tuple[Severity | None, str]:
        """Classify a single inbound/outbound rule.

        Returns (severity, description) or (None, "") if the rule is benign.

        Classification logic:
        - CRITICAL: all-traffic (protocol -1) from any source (inbound)
        - CRITICAL: 0.0.0.0/0 on port 22 or 3389 (inbound)
        - HIGH: 0.0.0.0/0 on any port other than 80/443 (inbound)
        - LOW: all outbound to 0.0.0.0/0 with protocol -1
        """
        protocol = str(rule.get("protocol", ""))
        from_port = rule.get("from_port", 0)
        to_port = rule.get("to_port", 0)
        source = rule.get("source", "")
        source_type = rule.get("source_type", "")

        is_open_cidr = source in ("0.0.0.0/0", "::/0")

        if direction == "inbound":
            # CRITICAL: all-traffic (protocol -1) from any source
            if protocol == "-1" and is_open_cidr:
                return (
                    Severity.CRITICAL,
                    f"Security group allows ALL traffic (protocol -1) from {source}. "
                    "This grants unrestricted inbound access.",
                )

            # CRITICAL: SSH (22) or RDP (3389) open to the world
            if is_open_cidr and self._port_in_range(22, from_port, to_port):
                return (
                    Severity.CRITICAL,
                    f"Security group allows SSH (port 22) from {source}. "
                    "Administrative port exposed to the internet.",
                )
            if is_open_cidr and self._port_in_range(3389, from_port, to_port):
                return (
                    Severity.CRITICAL,
                    f"Security group allows RDP (port 3389) from {source}. "
                    "Administrative port exposed to the internet.",
                )

            # HIGH: 0.0.0.0/0 on any port other than 80/443
            if is_open_cidr and protocol != "-1":
                # Check if the rule is ONLY for 80 or 443
                if self._is_only_web_port(from_port, to_port):
                    return (None, "")
                return (
                    Severity.HIGH,
                    f"Security group allows inbound from {source} on ports {from_port}-{to_port} "
                    f"(protocol {protocol}). Non-web port exposed to the internet.",
                )

        if direction == "outbound":
            # LOW: all outbound to 0.0.0.0/0 with protocol -1
            if protocol == "-1" and is_open_cidr:
                return (
                    Severity.LOW,
                    f"Security group allows ALL outbound traffic to {source} (protocol -1). "
                    "Unrestricted egress.",
                )

        return (None, "")

    def _port_in_range(self, port: int, from_port: int, to_port: int) -> bool:
        """Check if a specific port falls within a from_port-to_port range."""
        try:
            return int(from_port) <= port <= int(to_port)
        except (ValueError, TypeError):
            return False

    def _is_only_web_port(self, from_port: int, to_port: int) -> bool:
        """Return True if the port range covers ONLY port 80 or ONLY port 443."""
        try:
            fp = int(from_port)
            tp = int(to_port)
        except (ValueError, TypeError):
            return False
        return (fp == 80 and tp == 80) or (fp == 443 and tp == 443)

    def _trace_sg_chain(self, sg_id: str, all_sgs: dict[str, dict],
                        visited: set | None = None) -> list[dict]:
        """Follow SG-to-SG references transitively.

        Returns a list of dicts: [{sg_id, rules}] for each referenced SG.
        """
        if visited is None:
            visited = set()

        if sg_id in visited:
            return []
        visited.add(sg_id)

        sg = all_sgs.get(sg_id)
        if not sg:
            return []

        chain: list[dict] = []
        inbound_rules = sg.get("inbound_rules", [])

        for rule in inbound_rules:
            if rule.get("source_type") == "security_group":
                ref_sg_id = rule.get("source", "")
                if ref_sg_id and ref_sg_id not in visited:
                    ref_sg = all_sgs.get(ref_sg_id)
                    if ref_sg:
                        chain.append({
                            "sg_id": ref_sg_id,
                            "rules": ref_sg.get("inbound_rules", []) + ref_sg.get("outbound_rules", []),
                        })
                        # Recurse into the referenced SG
                        chain.extend(self._trace_sg_chain(ref_sg_id, all_sgs, visited))

        return chain

    def _recommend_action(self, severity: Severity, rule: dict, direction: str) -> str:
        """Generate a recommended action based on severity and rule."""
        source = rule.get("source", "")
        from_port = rule.get("from_port", 0)
        to_port = rule.get("to_port", 0)

        if severity == Severity.CRITICAL:
            return (
                f"Restrict {direction} access. Replace {source} with specific "
                "IP ranges or security group references."
            )
        if severity == Severity.HIGH:
            return (
                f"Restrict {direction} ports {from_port}-{to_port} to specific "
                f"IP ranges instead of {source}."
            )
        if severity == Severity.LOW:
            return (
                "Consider restricting outbound traffic to only required "
                "destinations and protocols."
            )
        return "Review security group configuration."


# ---------------------------------------------------------------------------
# Auto-register
# ---------------------------------------------------------------------------
SkillRegistry.register(SGChainAnalyzer())
