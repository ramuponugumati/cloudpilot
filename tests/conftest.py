"""Shared fixtures for all CloudPilot tests."""
import pytest
from unittest.mock import MagicMock, patch
from cloudpilot.core import (
    Finding,
    Severity,
    ActionStatus,
    SkillResult,
    SkillRegistry,
    BaseSkill,
    Resource,
    AntiPattern,
    ServiceRecommendation,
    ResourceConnection,
    DiagramResult,
    IaCResult,
    GuardrailResult,
    RemediationResult,
    StubToolResponse,
)


@pytest.fixture
def mock_profile():
    return "test-profile"


@pytest.fixture
def mock_regions():
    return ["us-east-1", "us-west-2"]


@pytest.fixture
def mock_account_id():
    return "123456789012"


@pytest.fixture(autouse=True)
def patch_get_account_id(mock_account_id):
    """Patch get_account_id globally so no test hits real STS."""
    with patch("cloudpilot.aws_client.get_client") as mock_gc:
        sts_mock = MagicMock()
        sts_mock.get_caller_identity.return_value = {"Account": mock_account_id}
        mock_gc.return_value = sts_mock
        yield mock_gc


@pytest.fixture
def sample_finding():
    return Finding(
        skill="test-skill",
        title="Test finding",
        severity=Severity.HIGH,
        description="A test finding",
        resource_id="i-1234567890abcdef0",
        account_id="123456789012",
        region="us-east-1",
        monthly_impact=100.0,
        recommended_action="Fix it",
        metadata={"key": "value"},
    )


@pytest.fixture
def sample_skill_result(sample_finding):
    return SkillResult(
        skill_name="test-skill",
        findings=[sample_finding],
        duration_seconds=1.5,
        accounts_scanned=1,
        regions_scanned=2,
    )


@pytest.fixture
def sample_resource():
    return Resource(
        service="ec2",
        type="instance",
        id="i-1234567890abcdef0",
        name="web-server-1",
        region="us-east-1",
        arn="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
        tags={"Name": "web-server-1", "Environment": "production"},
        layer="Compute",
        metadata={
            "instance_type": "t3.large",
            "state": "running",
            "vpc_id": "vpc-abc123",
            "subnet_id": "subnet-abc123",
            "security_groups": ["sg-abc123"],
            "public_ip": "1.2.3.4",
            "imdsv2": "required",
        },
        account_id="123456789012",
    )


@pytest.fixture
def sample_rds_resource():
    return Resource(
        service="rds",
        type="instance",
        id="mydb",
        name="mydb",
        region="us-east-1",
        arn="arn:aws:rds:us-east-1:123456789012:db:mydb",
        tags={"Name": "mydb"},
        layer="Data",
        metadata={
            "engine": "mysql",
            "instance_class": "db.t3.medium",
            "multi_az": False,
            "backup_retention": 0,
            "publicly_accessible": False,
            "az": "us-east-1a",
        },
    )


@pytest.fixture
def sample_resources(sample_resource, sample_rds_resource):
    """A list of sample resources for testing discovery-related features."""
    return [sample_resource, sample_rds_resource]


@pytest.fixture
def sample_anti_pattern():
    return AntiPattern(
        pattern_type="single-az-rds",
        severity=Severity.HIGH,
        resource_id="mydb",
        region="us-east-1",
        description="RDS instance 'mydb' is deployed in a single AZ",
        recommendation="Enable Multi-AZ for production databases",
        well_architected_pillar="reliability",
    )


@pytest.fixture
def sample_service_recommendation():
    return ServiceRecommendation(
        ec2_instance_id="i-redis001",
        ec2_instance_name="redis-cache-prod",
        detected_workload="Redis",
        detection_method="name_tag",
        recommended_service="Amazon ElastiCache",
        migration_rationale="Managed Redis with automatic failover and patching",
        region="us-east-1",
    )


@pytest.fixture
def sample_connection():
    return ResourceConnection(
        source_id="i-1234567890abcdef0",
        target_id="mydb",
        connection_type="vpc_member",
        metadata={"vpc_id": "vpc-abc123"},
    )


@pytest.fixture
def sample_findings_list():
    """A realistic set of findings across skills for chat/dashboard tests."""
    return [
        Finding(
            skill="zombie-hunter",
            title="Unattached EBS: vol-abc123",
            severity=Severity.LOW,
            description="gp2 | 100GB",
            resource_id="vol-abc123",
            region="us-east-1",
            monthly_impact=8.0,
            recommended_action="Delete or snapshot+delete",
        ).to_dict(),
        Finding(
            skill="security-posture",
            title="Open port 22 to 0.0.0.0/0: sg-xyz789",
            severity=Severity.HIGH,
            description="SG 'default' allows inbound on port 22",
            resource_id="sg-xyz789",
            region="us-east-1",
            monthly_impact=0,
            recommended_action="Restrict source IP range",
        ).to_dict(),
        Finding(
            skill="zombie-hunter",
            title="Idle EC2: i-idle001",
            severity=Severity.MEDIUM,
            description="t3.large | CPU: 0.5%",
            resource_id="i-idle001",
            region="us-west-2",
            monthly_impact=73.0,
            recommended_action="Stop or terminate",
        ).to_dict(),
    ]


@pytest.fixture
def mock_bedrock_client():
    """Mock Bedrock Runtime client for agent loop tests."""
    client = MagicMock()
    client.converse.return_value = {
        "output": {
            "message": {
                "role": "assistant",
                "content": [{"text": "Hello! I'm CloudPilot."}],
            }
        },
        "stopReason": "end_turn",
    }
    return client


@pytest.fixture
def mock_memory():
    """Mock AgentMemory for agent loop tests."""
    memory = MagicMock()
    memory.retrieve_context.return_value = ""
    memory.retrieve_cross_session.return_value = ""
    memory.store_conversation.return_value = None
    return memory
