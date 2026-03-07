"""Core framework — skill registry, finding models, base skill class.
Carried forward from aws-ops-agent with CloudPilot branding."""
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ActionStatus(Enum):
    PENDING = "pending_approval"
    APPROVED = "approved"
    EXECUTED = "executed"
    SKIPPED = "skipped"


@dataclass
class Finding:
    skill: str
    title: str
    severity: Severity
    description: str
    resource_id: str = ""
    account_id: str = ""
    region: str = ""
    monthly_impact: float = 0.0
    recommended_action: str = ""
    action_status: ActionStatus = ActionStatus.PENDING
    auto_remediate: bool = False
    metadata: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        d["action_status"] = self.action_status.value
        return d


@dataclass
class SkillResult:
    skill_name: str
    findings: list[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0
    accounts_scanned: int = 0
    regions_scanned: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def total_impact(self):
        return sum(f.monthly_impact for f in self.findings)

    @property
    def critical_count(self):
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)


class BaseSkill:
    """Base class for all CloudPilot skills."""
    name: str = "base"
    description: str = ""
    version: str = "0.1.0"

    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        raise NotImplementedError

    def remediate(self, finding: Finding, profile=None) -> bool:
        return False


class SkillRegistry:
    """Registry of all available skills."""
    _skills: dict[str, BaseSkill] = {}

    @classmethod
    def register(cls, skill: BaseSkill):
        cls._skills[skill.name] = skill

    @classmethod
    def get(cls, name: str) -> Optional[BaseSkill]:
        return cls._skills.get(name)

    @classmethod
    def all(cls) -> dict[str, BaseSkill]:
        return cls._skills

    @classmethod
    def names(cls) -> list[str]:
        return list(cls._skills.keys())


@dataclass
class Resource:
    """A discovered AWS resource."""
    service: str          # e.g., "ec2", "rds", "lambda", "s3"
    type: str             # e.g., "instance", "cluster", "function", "bucket"
    id: str               # AWS resource ID
    name: str             # Name tag or identifier
    region: str           # AWS region (or "global" for S3, CloudFront)
    arn: str = ""         # Full ARN
    tags: dict = field(default_factory=dict)
    layer: str = ""       # Classified layer: Edge|Compute|Data|Storage|Networking|Security|Messaging|Load_Balancing
    metadata: dict = field(default_factory=dict)  # Service-specific fields
    account_id: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class AntiPattern:
    """A detected infrastructure anti-pattern."""
    pattern_type: str       # e.g., "single-az-rds", "public-database", "missing-backup"
    severity: Severity
    resource_id: str
    region: str
    description: str
    recommendation: str
    well_architected_pillar: str = ""  # reliability | security | cost | performance | operational

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ServiceRecommendation:
    """Recommendation to replace self-managed EC2 workload with managed service."""
    ec2_instance_id: str
    ec2_instance_name: str
    detected_workload: str       # e.g., "PostgreSQL", "Redis", "RabbitMQ"
    detection_method: str        # "name_tag" | "user_data" | "port_pattern"
    recommended_service: str     # e.g., "Amazon RDS for PostgreSQL", "Amazon ElastiCache"
    migration_rationale: str
    region: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class ResourceConnection:
    """A relationship between two AWS resources."""
    source_id: str
    target_id: str
    connection_type: str    # "vpc_member" | "security_group_ref" | "subnet_placement" | "elb_target" | "route_table" | "nat_gateway"
    metadata: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


@dataclass
class DiagramResult:
    """Result of diagram generation."""
    mermaid_code: str
    view_type: str
    resource_count: int
    collapsed_groups: int = 0
    resources: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


@dataclass
class IaCResult:
    """Result of IaC generation."""
    format: str             # "cdk-python" | "cloudformation" | "terraform"
    scope: str
    resource_count: int
    code: str
    warnings: list[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


@dataclass
class GuardrailResult:
    """Result of guardrail check."""
    allowed: bool
    reason: str = ""
    filtered_message: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class RemediationResult:
    """Result of a remediation action."""
    success: bool
    finding_id: str
    action: str
    message: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self):
        return asdict(self)


@dataclass
class StubToolResponse:
    """Response from Phase 2 stub tools."""
    status: str = "coming_soon"
    tool_name: str = ""
    planned_phase: str = "Phase 2"
    description: str = ""
    planned_capabilities: list[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)

