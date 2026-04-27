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
    ("security-posture", r"^IMDSv1 enabled:", "enforce_imdsv2"),
    ("security-posture", r"^GuardDuty not enabled:", "enable_guardduty"),
    ("security-posture", r"^CloudTrail logging stopped:", "enable_cloudtrail"),
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
    # data-security
    ("data-security", r"^S3 bucket not encrypted:", "enable_s3_encryption"),
    ("data-security", r"^S3 versioning disabled:", "enable_s3_versioning"),
    ("data-security", r"^S3 access logging disabled:", "enable_s3_access_logging"),
    ("data-security", r"^RDS not encrypted:", "enable_rds_encryption_flag"),
    # secrets-hygiene
    ("secrets-hygiene", r"^No rotation configured:", "enable_secrets_rotation"),
    ("secrets-hygiene", r"^Secret never accessed:", "delete_unused_secret"),
    # eks-optimizer
    ("eks-optimizer", r"^ECR scan disabled:", "enable_ecr_scan"),
    ("eks-optimizer", r"^No EKS logging:", "enable_eks_logging"),
    ("eks-optimizer", r"^Partial EKS logging:", "enable_eks_logging"),
    ("eks-optimizer", r"^EKS secrets not encrypted:", "enable_eks_encryption"),
    # backup-dr-posture
    ("backup-dr-posture", r"^DynamoDB PITR disabled:", "enable_dynamodb_pitr"),
    ("backup-dr-posture", r"^RDS backup retention.+below:", "increase_rds_backup_retention"),
    ("backup-dr-posture", r"^Very stale snapshot:", "delete_stale_snapshot"),
    # sg-chain-analyzer
    ("sg-chain-analyzer", r"^Unused security group:", "delete_unused_sg"),
    ("sg-chain-analyzer", r"^All traffic inbound:", "restrict_security_group"),
    # network-topology
    ("network-topology", r"^VPC DNS hostnames disabled:", "enable_vpc_dns_hostnames"),
    # costopt-intelligence
    ("costopt-intelligence", r"^Stopped EC2 .+ days:", "terminate_long_stopped_ec2"),
    # zombie-hunter (additional)
    ("zombie-hunter", r"^Unused VPC endpoint:", "delete_vpc_endpoint"),
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


# --- Security handlers ---

def _enforce_imdsv2(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    ec2 = get_client("ec2", region, profile)
    ec2.modify_instance_metadata_options(
        InstanceId=resource_id,
        HttpTokens="required",
        HttpEndpoint="enabled",
    )
    return f"Enforced IMDSv2 (HttpTokens=required) on {resource_id}"


def _enable_guardduty(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    gd = get_client("guardduty", region, profile)
    resp = gd.create_detector(Enable=True, FindingPublishingFrequency="FIFTEEN_MINUTES")
    detector_id = resp.get("DetectorId", "unknown")
    return f"Enabled GuardDuty in {region} (detector: {detector_id})"


def _enable_cloudtrail(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    ct = get_client("cloudtrail", region, profile)
    trail_name = resource_id or finding.get("metadata", {}).get("trail_name", "")
    if not trail_name:
        raise ValueError("No trail name found in finding")
    ct.start_logging(Name=trail_name)
    return f"Re-enabled CloudTrail logging for trail {trail_name}"


# --- Data protection handlers ---

def _enable_s3_encryption(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    s3 = get_client("s3", "us-east-1", profile)
    s3.put_bucket_encryption(
        Bucket=resource_id,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    return f"Enabled SSE-S3 default encryption on bucket {resource_id}"


def _enable_s3_versioning(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    s3 = get_client("s3", "us-east-1", profile)
    s3.put_bucket_versioning(Bucket=resource_id, VersioningConfiguration={"Status": "Enabled"})
    return f"Enabled versioning on S3 bucket {resource_id}"


def _enable_s3_access_logging(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    s3 = get_client("s3", "us-east-1", profile)
    log_bucket = finding.get("metadata", {}).get("log_bucket", f"{resource_id}-access-logs")
    s3.put_bucket_logging(
        Bucket=resource_id,
        BucketLoggingStatus={
            "LoggingEnabled": {"TargetBucket": log_bucket, "TargetPrefix": f"logs/{resource_id}/"}
        },
    )
    return f"Enabled access logging on {resource_id} → {log_bucket}"


def _enable_rds_encryption_flag(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    # RDS encryption can't be enabled in-place — inform user of the snapshot approach
    return (f"RDS instance {resource_id} is not encrypted. To encrypt: "
            f"1) Create encrypted snapshot, 2) Restore from encrypted snapshot, "
            f"3) Update DNS/connection strings, 4) Delete old instance. "
            f"This requires downtime and cannot be done with a single API call.")


# --- Secrets handlers ---

def _enable_secrets_rotation(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    # Can't auto-configure rotation without a Lambda ARN — provide guidance
    return (f"Secret {resource_id} needs rotation configured. "
            f"Use: aws secretsmanager rotate-secret --secret-id {resource_id} "
            f"--rotation-lambda-arn <your-rotation-lambda> --rotation-rules AutomaticallyAfterDays=90")


def _delete_unused_secret(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    sm = get_client("secretsmanager", region, profile)
    sm.delete_secret(SecretId=resource_id, RecoveryWindowInDays=30)
    return f"Scheduled deletion of unused secret {resource_id} (30-day recovery window)"


# --- EKS/Container handlers ---

def _enable_ecr_scan(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    ecr = get_client("ecr", region, profile)
    ecr.put_image_scanning_configuration(
        repositoryName=resource_id,
        imageScanningConfiguration={"scanOnPush": True},
    )
    return f"Enabled scan-on-push for ECR repository {resource_id}"


def _enable_eks_logging(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    eks = get_client("eks", region, profile)
    all_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
    eks.update_cluster_config(
        name=resource_id,
        logging={"clusterLogging": [{"types": all_types, "enabled": True}]},
    )
    return f"Enabled all 5 EKS control plane log types for cluster {resource_id}"


def _enable_eks_encryption(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    eks = get_client("eks", region, profile)
    kms_key = finding.get("metadata", {}).get("kms_key_arn", "")
    if not kms_key:
        return (f"EKS cluster {resource_id} needs secrets encryption. "
                f"Provide a KMS key ARN: aws eks associate-encryption-config "
                f"--cluster-name {resource_id} --encryption-config type=secrets,provider.keyArn=<KMS_KEY_ARN>")
    eks.associate_encryption_config(
        clusterName=resource_id,
        encryptionConfig=[{"resources": ["secrets"], "provider": {"keyArn": kms_key}}],
    )
    return f"Associated KMS encryption for secrets on EKS cluster {resource_id}"


# --- Backup/DR handlers ---

def _enable_dynamodb_pitr(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    ddb = get_client("dynamodb", region, profile)
    ddb.update_continuous_backups(
        TableName=resource_id,
        PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
    )
    return f"Enabled Point-in-Time Recovery for DynamoDB table {resource_id}"


def _increase_rds_backup_retention(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    rds = get_client("rds", region, profile)
    rds.modify_db_instance(
        DBInstanceIdentifier=resource_id,
        BackupRetentionPeriod=7,
        ApplyImmediately=True,
    )
    return f"Increased backup retention to 7 days for RDS instance {resource_id}"


def _delete_stale_snapshot(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    snap_type = finding.get("metadata", {}).get("snapshot_type", "ebs")
    if snap_type == "rds":
        rds = get_client("rds", region, profile)
        rds.delete_db_snapshot(DBSnapshotIdentifier=resource_id)
        return f"Deleted stale RDS snapshot {resource_id}"
    else:
        ec2 = get_client("ec2", region, profile)
        ec2.delete_snapshot(SnapshotId=resource_id)
        return f"Deleted stale EBS snapshot {resource_id}"


# --- Networking handlers ---

def _delete_unused_sg(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    ec2 = get_client("ec2", region, profile)
    ec2.delete_security_group(GroupId=resource_id)
    return f"Deleted unused security group {resource_id}"


def _enable_vpc_dns_hostnames(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    ec2 = get_client("ec2", region, profile)
    ec2.modify_vpc_attribute(VpcId=resource_id, EnableDnsHostnames={"Value": True})
    return f"Enabled DNS hostnames on VPC {resource_id}"


def _delete_vpc_endpoint(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    ec2 = get_client("ec2", region, profile)
    ec2.delete_vpc_endpoints(VpcEndpointIds=[resource_id])
    return f"Deleted unused VPC endpoint {resource_id}"


# --- Cost handlers ---

def _terminate_long_stopped_ec2(resource_id: str, region: str, profile: Optional[str], finding: dict) -> str:
    ec2 = get_client("ec2", region, profile)
    ec2.terminate_instances(InstanceIds=[resource_id])
    return f"Terminated long-stopped EC2 instance {resource_id} (was incurring EBS costs)"


# Handler dispatch table
_HANDLERS = {
    # Zombie / Cost
    "delete_ebs_volume": _delete_ebs_volume,
    "release_eip": _release_eip,
    "delete_nat_gateway": _delete_nat_gateway,
    "stop_ec2_instance": _stop_ec2_instance,
    "stop_rds_instance": _stop_rds_instance,
    "terminate_long_stopped_ec2": _terminate_long_stopped_ec2,
    "cancel_capacity_reservation": _cancel_capacity_reservation,
    # Security
    "restrict_security_group": _restrict_security_group,
    "block_s3_public_access": _block_s3_public_access,
    "deactivate_access_key": _deactivate_access_key,
    "enforce_imdsv2": _enforce_imdsv2,
    "enable_guardduty": _enable_guardduty,
    "enable_cloudtrail": _enable_cloudtrail,
    # Resilience
    "enable_rds_multi_az": _enable_rds_multi_az,
    "enable_rds_backups": _enable_rds_backups,
    "enable_vpc_flow_logs": _enable_vpc_flow_logs,
    # Tags
    "apply_tags_ec2": _apply_tags_ec2,
    "apply_tags_rds": _apply_tags_rds,
    "apply_tags_s3": _apply_tags_s3,
    "apply_tags_lambda": _apply_tags_lambda,
    # Lifecycle
    "upgrade_lambda_runtime": _upgrade_lambda_runtime,
    "upgrade_rds_engine": _upgrade_rds_engine,
    # Data protection
    "enable_s3_encryption": _enable_s3_encryption,
    "enable_s3_versioning": _enable_s3_versioning,
    "enable_s3_access_logging": _enable_s3_access_logging,
    "enable_rds_encryption_flag": _enable_rds_encryption_flag,
    # Secrets
    "enable_secrets_rotation": _enable_secrets_rotation,
    "delete_unused_secret": _delete_unused_secret,
    # EKS / Containers
    "enable_ecr_scan": _enable_ecr_scan,
    "enable_eks_logging": _enable_eks_logging,
    "enable_eks_encryption": _enable_eks_encryption,
    # Backup / DR
    "enable_dynamodb_pitr": _enable_dynamodb_pitr,
    "increase_rds_backup_retention": _increase_rds_backup_retention,
    "delete_stale_snapshot": _delete_stale_snapshot,
    # Networking
    "delete_unused_sg": _delete_unused_sg,
    "enable_vpc_dns_hostnames": _enable_vpc_dns_hostnames,
    "delete_vpc_endpoint": _delete_vpc_endpoint,
}
