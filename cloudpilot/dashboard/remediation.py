"""Remediation engine — maps findings to corrective AWS API actions."""
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from cloudpilot.aws_client import get_client

logger = logging.getLogger(__name__)

# Pattern: (skill, title_regex) -> (action_name, handler_function_name)
REMEDIATION_PATTERNS = [
    # zombie-hunter
    ("zombie-hunter", r"^Unattached EBS:", "delete_ebs_volume"),
    ("zombie-hunter", r"^Unused EIP:", "release_eip"),
    ("zombie-hunter", r"^Unused NAT GW:", "delete_nat_gateway"),
    ("zombie-hunter", r"^Idle EC2:", "stop_ec2_instance"),
    ("zombie-hunter", r"^Idle RDS:", "stop_rds_instance"),
    # security-posture
    ("security-posture", r"^Open port .+ to 0\.0\.0\.0/0:", "restrict_security_group"),
    ("security-posture", r"^Public S3 bucket:", "block_s3_public_access"),
    ("security-posture", r"^Old access key:", "deactivate_access_key"),
    # resiliency-gaps — Reliability pillar
    ("resiliency-gaps", r"^Single-AZ RDS:", "enable_rds_multi_az"),
    ("resiliency-gaps", r"^No backups: RDS", "enable_rds_backups"),
    # resiliency-gaps — Security pillar
    ("resiliency-gaps", r"^No VPC Flow Logs:", "enable_vpc_flow_logs"),
    # capacity-planner
    ("capacity-planner", r"^Underutilized ODCR:", "cancel_capacity_reservation"),
    # tag-enforcer
    ("tag-enforcer", r"^Untagged EC2:", "apply_tags_ec2"),
    ("tag-enforcer", r"^Untagged RDS:", "apply_tags_rds"),
    ("tag-enforcer", r"^Untagged S3:", "apply_tags_s3"),
    ("tag-enforcer", r"^Untagged Lambda:", "apply_tags_lambda"),
    # lifecycle-tracker
    ("lifecycle-tracker", r"^Deprecated runtime:", "upgrade_lambda_runtime"),
    ("lifecycle-tracker", r"^EOL RDS engine:", "upgrade_rds_engine"),
]


@dataclass
class RemediationResult:
    success: bool
    finding_id: str
    action: str
    message: str
    timestamp: str


def has_remediation(finding: dict) -> bool:
    """Check if a finding has a known remediation action."""
    skill = finding.get("skill", "")
    title = finding.get("title", "")
    return any(
        s == skill and re.search(pattern, title)
        for s, pattern, _ in REMEDIATION_PATTERNS
    )


def _get_handler(finding: dict):
    """Return (action_name, handler_fn) for a finding, or None."""
    skill = finding.get("skill", "")
    title = finding.get("title", "")
    for s, pattern, action in REMEDIATION_PATTERNS:
        if s == skill and re.search(pattern, title):
            return action, _HANDLERS[action]
    return None, None


def execute_remediation(finding: dict, profile: Optional[str] = None) -> RemediationResult:
    """Look up and execute the remediation action for a finding."""
    ts = datetime.now(timezone.utc).isoformat()
    resource_id = finding.get("resource_id", "")
    action_name, handler = _get_handler(finding)

    if not handler:
        result = RemediationResult(
            success=False, finding_id=resource_id, action="none",
            message=f"No remediation available for this finding type", timestamp=ts,
        )
        logger.info("Remediation attempt: %s | action=%s | outcome=no_handler", resource_id, "none")
        return result

    region = finding.get("region", "us-east-1")
    try:
        msg = handler(resource_id, region, profile, finding)
        result = RemediationResult(
            success=True, finding_id=resource_id, action=action_name,
            message=msg, timestamp=ts,
        )
        logger.info("Remediation attempt: %s | action=%s | outcome=success", resource_id, action_name)
    except Exception as e:
        result = RemediationResult(
            success=False, finding_id=resource_id, action=action_name,
            message=str(e), timestamp=ts,
        )
        logger.error("Remediation attempt: %s | action=%s | outcome=failure | error=%s", resource_id, action_name, e)

    return result


# --- Remediation handlers ---

def _delete_ebs_volume(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    ec2 = get_client("ec2", region, profile)
    ec2.delete_volume(VolumeId=resource_id)
    return f"Deleted EBS volume {resource_id}"


def _release_eip(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    ec2 = get_client("ec2", region, profile)
    ec2.release_address(AllocationId=resource_id)
    return f"Released Elastic IP {resource_id}"


def _delete_nat_gateway(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    ec2 = get_client("ec2", region, profile)
    ec2.delete_nat_gateway(NatGatewayId=resource_id)
    return f"Deleted NAT Gateway {resource_id}"


def _stop_ec2_instance(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    ec2 = get_client("ec2", region, profile)
    ec2.stop_instances(InstanceIds=[resource_id])
    return f"Stopped EC2 instance {resource_id}"


def _restrict_security_group(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    ec2 = get_client("ec2", region, profile)
    # Extract port from title like "Open port 22 to 0.0.0.0/0: sg-xxx"
    title = finding.get("title", "")
    port_match = re.search(r"Open port (\d+)", title)
    port = int(port_match.group(1)) if port_match else 0
    if not port:
        raise ValueError(f"Could not extract port from finding title: {title}")

    ec2.revoke_security_group_ingress(
        GroupId=resource_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": port,
            "ToPort": port,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )
    return f"Revoked 0.0.0.0/0 ingress on port {port} for {resource_id}"


def _block_s3_public_access(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    s3 = get_client("s3", "us-east-1", profile)
    s3.put_public_access_block(
        Bucket=resource_id,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    return f"Enabled Block Public Access on S3 bucket {resource_id}"


def _deactivate_access_key(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    iam = get_client("iam", "us-east-1", profile)
    username = finding.get("metadata", {}).get("user", "")
    if not username:
        # Extract from title: "Old access key: username (N days)"
        title = finding.get("title", "")
        match = re.search(r"Old access key: (.+?) \(", title)
        username = match.group(1) if match else ""
    if not username:
        raise ValueError("Could not determine IAM username from finding")
    iam.update_access_key(UserName=username, AccessKeyId=resource_id, Status="Inactive")
    return f"Deactivated access key {resource_id} for user {username}"


def _stop_rds_instance(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    rds = get_client("rds", region, profile)
    rds.stop_db_instance(DBInstanceIdentifier=resource_id)
    return f"Stopped RDS instance {resource_id}"


def _enable_rds_multi_az(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    rds = get_client("rds", region, profile)
    rds.modify_db_instance(
        DBInstanceIdentifier=resource_id,
        MultiAZ=True,
        ApplyImmediately=False,
    )
    return f"Enabled Multi-AZ for RDS instance {resource_id} (applies during next maintenance window)"


def _enable_rds_backups(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    rds = get_client("rds", region, profile)
    rds.modify_db_instance(
        DBInstanceIdentifier=resource_id,
        BackupRetentionPeriod=7,
        ApplyImmediately=True,
    )
    return f"Enabled automated backups (7-day retention) for RDS instance {resource_id}"


def _enable_vpc_flow_logs(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    ec2 = get_client("ec2", region, profile)
    ec2.create_flow_logs(
        ResourceIds=[resource_id],
        ResourceType="VPC",
        TrafficType="ALL",
        LogDestinationType="cloud-watch-logs",
        LogGroupName=f"/aws/vpc/flowlogs/{resource_id}",
    )
    return f"Enabled VPC Flow Logs for {resource_id} (to CloudWatch Logs)"


def _cancel_capacity_reservation(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    ec2 = get_client("ec2", region, profile)
    ec2.cancel_capacity_reservation(CapacityReservationId=resource_id)
    return f"Cancelled capacity reservation {resource_id}"


# --- Tag application handlers ---

DEFAULT_TAGS = {"Environment": "untagged", "Team": "unassigned", "Owner": "unassigned"}


def _apply_tags_ec2(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    missing = finding.get("metadata", {}).get("missing_tags", list(DEFAULT_TAGS.keys()))
    tags = [{"Key": k, "Value": DEFAULT_TAGS.get(k, "unassigned")} for k in missing]
    ec2 = get_client("ec2", region, profile)
    ec2.create_tags(Resources=[resource_id], Tags=tags)
    return f"Applied {len(tags)} tags to EC2 {resource_id}: {', '.join(missing)}"


def _apply_tags_rds(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    missing = finding.get("metadata", {}).get("missing_tags", list(DEFAULT_TAGS.keys()))
    arn = finding.get("metadata", {}).get("arn", "")
    if not arn:
        rds = get_client("rds", region, profile)
        db = rds.describe_db_instances(DBInstanceIdentifier=resource_id)["DBInstances"][0]
        arn = db["DBInstanceArn"]
    tags = [{"Key": k, "Value": DEFAULT_TAGS.get(k, "unassigned")} for k in missing]
    rds = get_client("rds", region, profile)
    rds.add_tags_to_resource(ResourceName=arn, Tags=tags)
    return f"Applied {len(tags)} tags to RDS {resource_id}: {', '.join(missing)}"


def _apply_tags_s3(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    missing = finding.get("metadata", {}).get("missing_tags", list(DEFAULT_TAGS.keys()))
    s3 = get_client("s3", "us-east-1", profile)
    # Get existing tags and merge
    try:
        existing = s3.get_bucket_tagging(Bucket=resource_id).get("TagSet", [])
    except Exception:
        existing = []
    existing_keys = {t["Key"] for t in existing}
    new_tags = existing + [{"Key": k, "Value": DEFAULT_TAGS.get(k, "unassigned")} for k in missing if k not in existing_keys]
    s3.put_bucket_tagging(Bucket=resource_id, Tagging={"TagSet": new_tags})
    return f"Applied {len(missing)} tags to S3 {resource_id}: {', '.join(missing)}"


def _apply_tags_lambda(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    missing = finding.get("metadata", {}).get("missing_tags", list(DEFAULT_TAGS.keys()))
    arn = finding.get("metadata", {}).get("arn", "")
    if not arn:
        lam = get_client("lambda", region, profile)
        fn = lam.get_function(FunctionName=resource_id)
        arn = fn["Configuration"]["FunctionArn"]
    tags = {k: DEFAULT_TAGS.get(k, "unassigned") for k in missing}
    lam = get_client("lambda", region, profile)
    lam.tag_resource(Resource=arn, Tags=tags)
    return f"Applied {len(tags)} tags to Lambda {resource_id}: {', '.join(missing)}"


def _upgrade_lambda_runtime(resource_id: Optional[str], region: Optional[str], profile: Optional[str], finding: dict) -> str:
    upgrade_to = finding.get("metadata", {}).get("upgrade_to", "python3.12")
    arn = finding.get("metadata", {}).get("arn", "")
    lam = get_client("lambda", region or "us-east-1", profile)
    lam.update_function_configuration(FunctionName=arn or resource_id, Runtime=upgrade_to)
    return f"Updated Lambda {resource_id} runtime to {upgrade_to}"


def _upgrade_rds_engine(resource_id: Optional[str], region: Optional[str], profile: Optional[str], finding: dict) -> str:
    upgrade_to = finding.get("metadata", {}).get("upgrade_to", "")
    engine = finding.get("metadata", {}).get("engine", "")
    if not upgrade_to:
        raise ValueError("No upgrade version specified in finding metadata")
    rds = get_client("rds", region or "us-east-1", profile)
    rds.modify_db_instance(
        DBInstanceIdentifier=resource_id,
        EngineVersion=upgrade_to,
        AllowMajorVersionUpgrade=True,
        ApplyImmediately=False,
    )
    return f"Scheduled {resource_id} upgrade to {engine} {upgrade_to} (applies during next maintenance window)"


# Handler dispatch table
_HANDLERS = {
    "delete_ebs_volume": _delete_ebs_volume,
    "release_eip": _release_eip,
    "delete_nat_gateway": _delete_nat_gateway,
    "stop_ec2_instance": _stop_ec2_instance,
    "restrict_security_group": _restrict_security_group,
    "block_s3_public_access": _block_s3_public_access,
    "deactivate_access_key": _deactivate_access_key,
    "stop_rds_instance": _stop_rds_instance,
    "enable_rds_multi_az": _enable_rds_multi_az,
    "enable_rds_backups": _enable_rds_backups,
    "enable_vpc_flow_logs": _enable_vpc_flow_logs,
    "cancel_capacity_reservation": _cancel_capacity_reservation,
    "apply_tags_ec2": _apply_tags_ec2,
    "apply_tags_rds": _apply_tags_rds,
    "apply_tags_s3": _apply_tags_s3,
    "apply_tags_lambda": _apply_tags_lambda,
    "upgrade_lambda_runtime": _upgrade_lambda_runtime,
    "upgrade_rds_engine": _upgrade_rds_engine,
}
