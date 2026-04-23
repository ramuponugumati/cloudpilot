"""Multi-Account Governance — Organization inventory, SCP analysis,
Control Tower drift, cross-account visibility."""
import logging
import time

from cloudpilot.core import BaseSkill, Finding, Severity, SkillResult, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id

logger = logging.getLogger(__name__)


class MultiAccountGovernanceSkill(BaseSkill):
    name = "multi-account-governance"
    description = "Organization inventory, SCP analysis, Control Tower drift, cross-account visibility"
    version = "0.1.0"

    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        acct = account_id or get_account_id(profile)
        findings, errors = [], []
        data = self._collect(profile, errors)
        for checker in [self._check_org_structure, self._check_scps,
                        self._check_control_tower, self._check_account_tags]:
            try:
                findings.extend(checker(data))
            except Exception as e:
                logger.warning("Checker failed: %s", e)
                errors.append(str(e))
        for f in findings:
            f.account_id = acct
        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=time.time() - start,
            accounts_scanned=1, regions_scanned=len(regions), errors=errors)

    def _collect(self, profile, errors):
        data = {"accounts": [], "scps": [], "roots": [], "ous": [],
                "ct_landing_zone": None, "errors": errors}
        # Organizations
        try:
            org = get_client("organizations", "us-east-1", profile)
            paginator = org.get_paginator("list_accounts")
            for page in paginator.paginate():
                for a in page.get("Accounts", []):
                    data["accounts"].append({
                        "id": a.get("Id", ""), "name": a.get("Name", ""),
                        "email": a.get("Email", ""), "status": a.get("Status", ""),
                        "joined": a.get("JoinedTimestamp", "").isoformat() if hasattr(a.get("JoinedTimestamp", ""), "isoformat") else "",
                    })
            # Roots
            data["roots"] = org.list_roots().get("Roots", [])
            # SCPs
            for root in data["roots"]:
                try:
                    policies = org.list_policies_for_target(
                        TargetId=root["Id"], Filter="SERVICE_CONTROL_POLICY"
                    ).get("Policies", [])
                    data["scps"].extend(policies)
                except Exception as e:
                    errors.append(f"list_policies: {e}")
            # OUs
            for root in data["roots"]:
                try:
                    ous = org.list_organizational_units_for_parent(
                        ParentId=root["Id"]).get("OrganizationalUnits", [])
                    data["ous"].extend(ous)
                except Exception as e:
                    errors.append(f"list_ous: {e}")
        except Exception as e:
            logger.warning("Organizations: %s", e)
            errors.append(f"organizations: {e}")
        # Control Tower
        try:
            ct = get_client("controltower", "us-east-1", profile)
            lz = ct.list_landing_zones().get("landingZones", [])
            if lz:
                data["ct_landing_zone"] = lz[0]
        except Exception as e:
            logger.warning("Control Tower: %s", e)
            errors.append(f"controltower: {e}")
        return data

    def _check_org_structure(self, data):
        findings = []
        accounts = data.get("accounts", [])
        if not accounts:
            findings.append(Finding(
                skill=self.name, title="No AWS Organization detected",
                severity=Severity.HIGH,
                description="Could not enumerate organization accounts — may not be the management account",
                recommended_action="Run from the management account or delegate admin"))
            return findings
        suspended = [a for a in accounts if a.get("status") == "SUSPENDED"]
        if suspended:
            findings.append(Finding(
                skill=self.name, title=f"{len(suspended)} suspended account(s)",
                severity=Severity.LOW,
                description=f"Found {len(suspended)} suspended accounts in the organization",
                recommended_action="Review and close suspended accounts",
                metadata={"suspended_accounts": [a["id"] for a in suspended]}))
        findings.append(Finding(
            skill=self.name, title=f"Organization: {len(accounts)} accounts",
            severity=Severity.INFO,
            description=f"Organization has {len(accounts)} accounts across {len(data.get('ous', []))} OUs",
            metadata={"account_count": len(accounts), "ou_count": len(data.get("ous", []))}))
        return findings

    def _check_scps(self, data):
        findings = []
        scps = data.get("scps", [])
        if not scps:
            findings.append(Finding(
                skill=self.name, title="No SCPs attached to root",
                severity=Severity.HIGH,
                description="No Service Control Policies found on the organization root",
                recommended_action="Attach SCPs to enforce guardrails across accounts"))
        else:
            # Check for FullAWSAccess only (no restrictions)
            names = [s.get("Name", "") for s in scps]
            if names == ["FullAWSAccess"]:
                findings.append(Finding(
                    skill=self.name, title="Only FullAWSAccess SCP — no guardrails",
                    severity=Severity.MEDIUM,
                    description="The only SCP is FullAWSAccess — no restrictions are enforced",
                    recommended_action="Add restrictive SCPs to enforce security guardrails",
                    metadata={"scp_names": names}))
            else:
                findings.append(Finding(
                    skill=self.name, title=f"{len(scps)} SCP(s) attached",
                    severity=Severity.INFO,
                    description=f"Found {len(scps)} SCPs on the organization root",
                    metadata={"scp_names": names}))
        return findings

    def _check_control_tower(self, data):
        findings = []
        lz = data.get("ct_landing_zone")
        if lz is None:
            findings.append(Finding(
                skill=self.name, title="Control Tower not detected",
                severity=Severity.MEDIUM,
                description="AWS Control Tower landing zone was not found",
                recommended_action="Consider enabling Control Tower for automated governance"))
        else:
            status = lz.get("status", "")
            if status != "ACTIVE":
                findings.append(Finding(
                    skill=self.name, title=f"Control Tower status: {status}",
                    severity=Severity.HIGH,
                    description=f"Control Tower landing zone is in {status} state",
                    recommended_action="Investigate and resolve Control Tower issues",
                    metadata={"status": status}))
            else:
                findings.append(Finding(
                    skill=self.name, title="Control Tower active",
                    severity=Severity.INFO,
                    description="Control Tower landing zone is active",
                    metadata={"status": status}))
        return findings

    def _check_account_tags(self, data):
        """Check if accounts have proper tags via Organizations tagging."""
        findings = []
        # Organizations API doesn't directly expose account tags in list_accounts
        # This is a placeholder — in practice you'd use list_tags_for_resource
        accounts = data.get("accounts", [])
        if len(accounts) > 50:
            findings.append(Finding(
                skill=self.name, title=f"Large organization: {len(accounts)} accounts",
                severity=Severity.MEDIUM,
                description=f"Organization has {len(accounts)} accounts — ensure proper OU structure and tagging",
                recommended_action="Review OU hierarchy and implement account tagging strategy",
                metadata={"account_count": len(accounts)}))
        return findings


SkillRegistry.register(MultiAccountGovernanceSkill())
