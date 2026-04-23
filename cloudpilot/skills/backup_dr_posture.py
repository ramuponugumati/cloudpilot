"""Backup & DR Posture — comprehensive backup coverage, DR readiness scoring,
PITR, cross-region replication, snapshot lifecycle analysis."""
import logging
import time
from datetime import datetime, timezone

from cloudpilot.core import BaseSkill, Finding, Severity, SkillResult, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configurable thresholds
# ---------------------------------------------------------------------------
STALE_SNAPSHOT_DAYS = 90
VERY_STALE_SNAPSHOT_DAYS = 180
RECENT_SNAPSHOT_DAYS = 7
MIN_RETENTION_DAYS = 7
STANDARD_RETENTION_DAYS = 30
MAX_BACKUP_FREQUENCY_HOURS = 24
DR_SCORE_WEIGHTS = {
    "coverage": 0.30,
    "frequency": 0.15,
    "retention": 0.15,
    "cross_region": 0.25,
    "pitr": 0.15,
}


class BackupDRPostureSkill(BaseSkill):
    name = "backup-dr-posture"
    description = (
        "Backup coverage, DR readiness scoring, PITR, cross-region "
        "replication, snapshot lifecycle analysis"
    )
    version = "0.1.0"

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        acct = account_id or get_account_id(profile)

        region_results = parallel_regions(
            lambda r, p: self._collect_region_data(r, p), regions, profile=profile,
        )

        data = self._merge_region_data(region_results)
        findings = self._run_checks(data, acct)

        # Attach account_id to every finding
        for f in findings:
            f.account_id = acct

        # Collect errors from region data
        errors = list(data.get("errors", []))

        # Compute DR score and add to metadata
        dr_score_finding, dr_meta = self._compute_dr_score(data, findings)
        findings.append(dr_score_finding)

        return SkillResult(
            skill_name=self.name,
            findings=findings,
            duration_seconds=time.time() - start,
            accounts_scanned=1,
            regions_scanned=len(regions),
            errors=errors,
            metadata={"dr_readiness_score": dr_meta},
        )

    # ------------------------------------------------------------------
    # Data collection (Pass 1)
    # ------------------------------------------------------------------
    def _collect_region_data(self, region: str, profile=None) -> dict:
        """Collect all AWS data needed for checks from a single region."""
        data = {
            "backup_plans": [],
            "protected_resource_arns": [],
            "rds_instances": [],
            "dynamodb_tables": [],
            "ebs_volumes": [],
            "efs_file_systems": [],
            "s3_buckets": [],
            "ebs_snapshots": [],
            "rds_snapshots": [],
            "dlm_policies": [],
            "errors": [],
        }

        # --- AWS Backup: plans, selections, protected resources ---
        try:
            backup = get_client("backup", region, profile)
            plan_ids = []
            paginator = backup.get_paginator("list_backup_plans")
            for page in paginator.paginate():
                for p in page.get("BackupPlansList", []):
                    plan_ids.append(p["BackupPlanId"])

            for pid in plan_ids:
                try:
                    plan_resp = backup.get_backup_plan(BackupPlanId=pid)
                    plan_obj = plan_resp.get("BackupPlan", {})
                    rules = []
                    for rule in plan_obj.get("Rules", []):
                        copy_actions = []
                        for ca in rule.get("CopyActions", []):
                            copy_actions.append({
                                "destination_vault_arn": ca.get("DestinationBackupVaultArn", ""),
                            })
                        lifecycle = rule.get("Lifecycle", {})
                        rules.append({
                            "rule_name": rule.get("RuleName", ""),
                            "schedule": rule.get("ScheduleExpression", ""),
                            "lifecycle": {
                                "DeleteAfterDays": lifecycle.get("DeleteAfterDays", 0),
                            },
                            "copy_actions": copy_actions,
                        })

                    # Gather selections for this plan
                    selections = []
                    try:
                        sel_paginator = backup.get_paginator("list_backup_selections")
                        for sel_page in sel_paginator.paginate(BackupPlanId=pid):
                            for sel in sel_page.get("BackupSelectionsList", []):
                                try:
                                    sel_detail = backup.get_backup_selection(
                                        BackupPlanId=pid,
                                        SelectionId=sel["SelectionId"],
                                    )
                                    sel_obj = sel_detail.get("BackupSelection", {})
                                    for res in sel_obj.get("Resources", []):
                                        selections.append(res)
                                except Exception as e:
                                    logger.warning("Failed to get backup selection %s: %s", sel.get("SelectionId"), e)
                    except Exception as e:
                        logger.warning("Failed to list backup selections for plan %s: %s", pid, e)

                    data["backup_plans"].append({
                        "plan_id": pid,
                        "plan_name": plan_obj.get("BackupPlanName", ""),
                        "rules": rules,
                        "selections": selections,
                    })
                except Exception as e:
                    logger.warning("Failed to get backup plan %s: %s", pid, e)
                    data["errors"].append(f"backup plan {pid} in {region}: {e}")
        except Exception as e:
            logger.warning("Failed to list backup plans in %s: %s", region, e)
            data["errors"].append(f"list_backup_plans in {region}: {e}")

        # --- Protected resources ---
        try:
            backup = get_client("backup", region, profile)
            paginator = backup.get_paginator("list_protected_resources")
            for page in paginator.paginate():
                for res in page.get("Results", []):
                    data["protected_resource_arns"].append(res.get("ResourceArn", ""))
        except Exception as e:
            logger.warning("Failed to list protected resources in %s: %s", region, e)
            data["errors"].append(f"list_protected_resources in {region}: {e}")

        # --- RDS instances ---
        try:
            rds = get_client("rds", region, profile)
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page.get("DBInstances", []):
                    data["rds_instances"].append({
                        "id": db["DBInstanceIdentifier"],
                        "engine": db.get("Engine", ""),
                        "instance_class": db.get("DBInstanceClass", ""),
                        "backup_retention_period": db.get("BackupRetentionPeriod", 0),
                        "multi_az": db.get("MultiAZ", False),
                        "latest_restorable_time": (
                            db["LatestRestorableTime"].isoformat()
                            if db.get("LatestRestorableTime") else None
                        ),
                        "preferred_backup_window": db.get("PreferredBackupWindow", ""),
                        "arn": db.get("DBInstanceArn", ""),
                        "region": region,
                    })
        except Exception as e:
            logger.warning("Failed to describe RDS instances in %s: %s", region, e)
            data["errors"].append(f"describe_db_instances in {region}: {e}")

        # --- DynamoDB tables + PITR status ---
        try:
            ddb = get_client("dynamodb", region, profile)
            table_names = []
            paginator = ddb.get_paginator("list_tables")
            for page in paginator.paginate():
                table_names.extend(page.get("TableNames", []))

            for tname in table_names:
                try:
                    desc = ddb.describe_table(TableName=tname)["Table"]
                    table_arn = desc.get("TableArn", "")
                    pitr_enabled = False
                    earliest = None
                    latest = None
                    try:
                        cb = ddb.describe_continuous_backups(TableName=tname)
                        pitr_desc = cb.get("ContinuousBackupsDescription", {}).get(
                            "PointInTimeRecoveryDescription", {}
                        )
                        pitr_enabled = pitr_desc.get("PointInTimeRecoveryStatus") == "ENABLED"
                        if pitr_enabled:
                            earliest = (
                                pitr_desc["EarliestRestorableDateTime"].isoformat()
                                if pitr_desc.get("EarliestRestorableDateTime") else None
                            )
                            latest = (
                                pitr_desc["LatestRestorableDateTime"].isoformat()
                                if pitr_desc.get("LatestRestorableDateTime") else None
                            )
                    except Exception as e:
                        logger.warning("Failed to describe continuous backups for %s: %s", tname, e)

                    data["dynamodb_tables"].append({
                        "name": tname,
                        "pitr_enabled": pitr_enabled,
                        "earliest_restorable": earliest,
                        "latest_restorable": latest,
                        "arn": table_arn,
                        "region": region,
                    })
                except Exception as e:
                    logger.warning("Failed to describe DynamoDB table %s: %s", tname, e)
        except Exception as e:
            logger.warning("Failed to list DynamoDB tables in %s: %s", region, e)
            data["errors"].append(f"list_tables in {region}: {e}")

        # --- EBS volumes (in-use only) ---
        try:
            ec2 = get_client("ec2", region, profile)
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate(
                Filters=[{"Name": "status", "Values": ["in-use"]}]
            ):
                for vol in page.get("Volumes", []):
                    data["ebs_volumes"].append({
                        "volume_id": vol["VolumeId"],
                        "state": vol.get("State", "in-use"),
                        "size_gb": vol.get("Size", 0),
                        "region": region,
                    })
        except Exception as e:
            logger.warning("Failed to describe EBS volumes in %s: %s", region, e)
            data["errors"].append(f"describe_volumes in {region}: {e}")

        # --- EFS file systems ---
        try:
            efs = get_client("efs", region, profile)
            paginator = efs.get_paginator("describe_file_systems")
            for page in paginator.paginate():
                for fs in page.get("FileSystems", []):
                    data["efs_file_systems"].append({
                        "file_system_id": fs["FileSystemId"],
                        "region": region,
                    })
        except Exception as e:
            logger.warning("Failed to describe EFS file systems in %s: %s", region, e)
            data["errors"].append(f"describe_file_systems in {region}: {e}")

        # --- S3 buckets (global, only from us-east-1) ---
        if region == "us-east-1":
            try:
                s3 = get_client("s3", region, profile)
                resp = s3.list_buckets()
                for b in resp.get("Buckets", []):
                    data["s3_buckets"].append({"name": b["Name"]})
            except Exception as e:
                logger.warning("Failed to list S3 buckets: %s", e)
                data["errors"].append(f"list_buckets: {e}")

        # --- EBS snapshots ---
        try:
            ec2 = get_client("ec2", region, profile)
            paginator = ec2.get_paginator("describe_snapshots")
            for page in paginator.paginate(OwnerIds=["self"]):
                for snap in page.get("Snapshots", []):
                    data["ebs_snapshots"].append({
                        "snapshot_id": snap["SnapshotId"],
                        "volume_id": snap.get("VolumeId", ""),
                        "start_time": (
                            snap["StartTime"].isoformat()
                            if snap.get("StartTime") else ""
                        ),
                        "region": region,
                    })
        except Exception as e:
            logger.warning("Failed to describe EBS snapshots in %s: %s", region, e)
            data["errors"].append(f"describe_snapshots in {region}: {e}")

        # --- RDS snapshots ---
        try:
            rds = get_client("rds", region, profile)
            paginator = rds.get_paginator("describe_db_snapshots")
            for page in paginator.paginate(SnapshotType="manual"):
                for snap in page.get("DBSnapshots", []):
                    data["rds_snapshots"].append({
                        "snapshot_id": snap.get("DBSnapshotIdentifier", ""),
                        "db_instance_id": snap.get("DBInstanceIdentifier", ""),
                        "snapshot_create_time": (
                            snap["SnapshotCreateTime"].isoformat()
                            if snap.get("SnapshotCreateTime") else ""
                        ),
                        "region": region,
                    })
            # Also include automated snapshots
            for page in paginator.paginate(SnapshotType="automated"):
                for snap in page.get("DBSnapshots", []):
                    data["rds_snapshots"].append({
                        "snapshot_id": snap.get("DBSnapshotIdentifier", ""),
                        "db_instance_id": snap.get("DBInstanceIdentifier", ""),
                        "snapshot_create_time": (
                            snap["SnapshotCreateTime"].isoformat()
                            if snap.get("SnapshotCreateTime") else ""
                        ),
                        "region": region,
                    })
        except Exception as e:
            logger.warning("Failed to describe RDS snapshots in %s: %s", region, e)
            data["errors"].append(f"describe_db_snapshots in {region}: {e}")

        # --- DLM policies ---
        try:
            dlm = get_client("dlm", region, profile)
            policies_resp = dlm.get_lifecycle_policies()
            for pol_summary in policies_resp.get("Policies", []):
                pol_id = pol_summary.get("PolicyId", "")
                try:
                    pol_detail = dlm.get_lifecycle_policy(PolicyId=pol_id)
                    policy = pol_detail.get("Policy", {})
                    policy_details = policy.get("PolicyDetails", {})

                    schedules = []
                    for sched in policy_details.get("Schedules", []):
                        schedules.append({
                            "Name": sched.get("Name", ""),
                            "CreateRule": sched.get("CreateRule", {}),
                            "RetainRule": sched.get("RetainRule", {}),
                        })

                    # Extract target volume IDs from target tags
                    target_volume_ids = []
                    target_tags = policy_details.get("TargetTags", [])

                    data["dlm_policies"].append({
                        "policy_id": pol_id,
                        "state": policy.get("State", ""),
                        "description": policy.get("Description", ""),
                        "schedules": schedules,
                        "target_tags": target_tags,
                        "target_volume_ids": target_volume_ids,
                        "region": region,
                    })
                except Exception as e:
                    logger.warning("Failed to get DLM policy %s: %s", pol_id, e)
                    data["errors"].append(f"get_lifecycle_policy {pol_id} in {region}: {e}")
        except Exception as e:
            logger.warning("Failed to get DLM policies in %s: %s", region, e)
            data["errors"].append(f"get_lifecycle_policies in {region}: {e}")

        return data

    # ------------------------------------------------------------------
    # Data merging (between Pass 1 and Pass 2)
    # ------------------------------------------------------------------
    def _merge_region_data(self, region_results: list) -> dict:
        """Merge per-region data dicts into a single aggregated dict."""
        merged = {
            "backup_plans": [],
            "protected_resource_arns": [],
            "rds_instances": [],
            "dynamodb_tables": [],
            "ebs_volumes": [],
            "efs_file_systems": [],
            "s3_buckets": [],
            "ebs_snapshots": [],
            "rds_snapshots": [],
            "dlm_policies": [],
            "errors": [],
        }
        if not isinstance(region_results, list):
            region_results = [region_results] if region_results else []

        for rd in region_results:
            if not isinstance(rd, dict):
                continue
            for key in merged:
                merged[key].extend(rd.get(key, []))
        return merged

    # ------------------------------------------------------------------
    # Run all checkers (Pass 2)
    # ------------------------------------------------------------------
    def _run_checks(self, data: dict, account_id: str) -> list:
        """Run all checker methods against aggregated data."""
        findings = []
        checkers = [
            self._check_backup_coverage,
            self._check_backup_frequency_retention,
            self._check_cross_region_replication,
            self._check_pitr,
            self._check_snapshot_age,
            self._check_rds_backup_retention,
            self._check_dlm_policies,
        ]
        for checker in checkers:
            try:
                results = checker(data)
                findings.extend(results)
            except Exception as e:
                logger.warning("Checker %s failed: %s", checker.__name__, e)
        return findings

    # ------------------------------------------------------------------
    # Checker: Backup Coverage (Requirement 1)
    # ------------------------------------------------------------------
    def _check_backup_coverage(self, data: dict) -> list:
        """Identify unprotected resources across all 5 resource types."""
        findings = []
        protected_arns = set(data.get("protected_resource_arns", []))

        # --- RDS instances ---
        rds_protected = 0
        rds_total = len(data.get("rds_instances", []))
        for inst in data.get("rds_instances", []):
            arn = inst.get("arn", "")
            if arn in protected_arns:
                rds_protected += 1
            else:
                findings.append(Finding(
                    skill=self.name,
                    title=f"Unprotected RDS instance: {inst['id']}",
                    severity=Severity.HIGH,
                    description=f"RDS instance {inst['id']} is not covered by any AWS Backup plan",
                    resource_id=inst["id"],
                    region=inst.get("region", ""),
                    recommended_action="Add this RDS instance to an AWS Backup plan",
                    metadata={
                        "resource_id": inst["id"],
                        "resource_type": "rds",
                        "region": inst.get("region", ""),
                        "protected_count": rds_protected,
                        "unprotected_count": rds_total - rds_protected,
                    },
                ))

        # --- DynamoDB tables ---
        ddb_protected = 0
        ddb_total = len(data.get("dynamodb_tables", []))
        for tbl in data.get("dynamodb_tables", []):
            arn = tbl.get("arn", "")
            if arn in protected_arns:
                ddb_protected += 1
            else:
                findings.append(Finding(
                    skill=self.name,
                    title=f"Unprotected DynamoDB table: {tbl['name']}",
                    severity=Severity.HIGH,
                    description=f"DynamoDB table {tbl['name']} is not covered by any AWS Backup plan",
                    resource_id=tbl["name"],
                    region=tbl.get("region", ""),
                    recommended_action="Add this DynamoDB table to an AWS Backup plan",
                    metadata={
                        "resource_id": tbl["name"],
                        "resource_type": "dynamodb",
                        "region": tbl.get("region", ""),
                        "protected_count": ddb_protected,
                        "unprotected_count": ddb_total - ddb_protected,
                    },
                ))

        # --- EBS volumes (in-use) ---
        ebs_protected = 0
        ebs_total = len(data.get("ebs_volumes", []))
        for vol in data.get("ebs_volumes", []):
            if vol.get("state") != "in-use":
                continue
            # Check if volume ARN is in protected set
            # ARN pattern: arn:aws:ec2:<region>:<account>:volume/<vol-id>
            vol_id = vol["volume_id"]
            vol_region = vol.get("region", "")
            matched = any(
                vol_id in arn for arn in protected_arns
            )
            if matched:
                ebs_protected += 1
            else:
                findings.append(Finding(
                    skill=self.name,
                    title=f"Unprotected EBS volume: {vol_id}",
                    severity=Severity.HIGH,
                    description=f"In-use EBS volume {vol_id} is not covered by any AWS Backup plan",
                    resource_id=vol_id,
                    region=vol_region,
                    recommended_action="Add this EBS volume to an AWS Backup plan or DLM policy",
                    metadata={
                        "resource_id": vol_id,
                        "resource_type": "ebs",
                        "region": vol_region,
                        "protected_count": ebs_protected,
                        "unprotected_count": ebs_total - ebs_protected,
                    },
                ))

        # --- EFS file systems ---
        efs_protected = 0
        efs_total = len(data.get("efs_file_systems", []))
        for fs in data.get("efs_file_systems", []):
            fs_id = fs["file_system_id"]
            fs_region = fs.get("region", "")
            matched = any(fs_id in arn for arn in protected_arns)
            if matched:
                efs_protected += 1
            else:
                findings.append(Finding(
                    skill=self.name,
                    title=f"Unprotected EFS file system: {fs_id}",
                    severity=Severity.MEDIUM,
                    description=f"EFS file system {fs_id} is not covered by any AWS Backup plan",
                    resource_id=fs_id,
                    region=fs_region,
                    recommended_action="Add this EFS file system to an AWS Backup plan",
                    metadata={
                        "resource_id": fs_id,
                        "resource_type": "efs",
                        "region": fs_region,
                        "protected_count": efs_protected,
                        "unprotected_count": efs_total - efs_protected,
                    },
                ))

        # --- S3 buckets ---
        s3_protected = 0
        s3_total = len(data.get("s3_buckets", []))
        for bucket in data.get("s3_buckets", []):
            bname = bucket["name"]
            matched = any(bname in arn for arn in protected_arns)
            if matched:
                s3_protected += 1
            else:
                findings.append(Finding(
                    skill=self.name,
                    title=f"Unprotected S3 bucket: {bname}",
                    severity=Severity.MEDIUM,
                    description=f"S3 bucket {bname} is not covered by any AWS Backup plan",
                    resource_id=bname,
                    recommended_action="Add this S3 bucket to an AWS Backup plan",
                    metadata={
                        "resource_id": bname,
                        "resource_type": "s3",
                        "region": "global",
                        "protected_count": s3_protected,
                        "unprotected_count": s3_total - s3_protected,
                    },
                ))

        return findings

    # ------------------------------------------------------------------
    # Stub checkers (to be implemented in later tasks)
    # ------------------------------------------------------------------
    def _check_backup_frequency_retention(self, data: dict) -> list:
        """Req 2: Analyze backup plan frequency and retention periods."""
        findings = []
        for plan in data.get("backup_plans", []):
            plan_name = plan.get("plan_name", plan.get("plan_id", "unknown"))
            covered_resources = plan.get("selections", [])

            for rule in plan.get("rules", []):
                schedule = rule.get("schedule", "")
                # Heuristic: determine if frequency is daily or better
                is_daily_or_better = False
                if schedule:
                    lower_sched = schedule.lower()
                    if "rate(1 day)" in lower_sched or "rate(12 hour" in lower_sched or "rate(1 hour" in lower_sched:
                        is_daily_or_better = True
                    elif lower_sched.startswith("cron("):
                        # cron(Minutes Hours DayOfMonth Month DayOfWeek Year)
                        # A daily cron runs every day — check DayOfMonth and DayOfWeek
                        # If DayOfMonth is * or ? and DayOfWeek is * or ?, it's daily or more frequent
                        parts = lower_sched.replace("cron(", "").rstrip(")").split()
                        if len(parts) >= 5:
                            dom = parts[2]  # day of month
                            dow = parts[4]  # day of week
                            if dom in ("*", "?") and dow in ("*", "?"):
                                is_daily_or_better = True

                frequency_label = "daily_or_better" if is_daily_or_better else "greater_than_24h"

                if not is_daily_or_better:
                    findings.append(Finding(
                        skill=self.name,
                        title=f"Backup frequency > 24h: {plan_name}",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Backup plan '{plan_name}' rule '{rule.get('rule_name', '')}' "
                            f"has a schedule that may not meet a 24-hour RPO target"
                        ),
                        resource_id=plan_name,
                        recommended_action="Increase backup frequency to at least once every 24 hours",
                        metadata={
                            "plan_name": plan_name,
                            "frequency": frequency_label,
                            "schedule": schedule,
                            "retention_days": rule.get("lifecycle", {}).get("DeleteAfterDays", 0),
                            "covered_resource_ids": covered_resources,
                        },
                    ))

                retention_days = rule.get("lifecycle", {}).get("DeleteAfterDays", 0)
                if retention_days > 0 and retention_days < MIN_RETENTION_DAYS:
                    findings.append(Finding(
                        skill=self.name,
                        title=f"Backup retention < {MIN_RETENTION_DAYS} days: {plan_name}",
                        severity=Severity.HIGH,
                        description=(
                            f"Backup plan '{plan_name}' rule '{rule.get('rule_name', '')}' "
                            f"has retention of {retention_days} days, below the recommended "
                            f"minimum of {MIN_RETENTION_DAYS} days"
                        ),
                        resource_id=plan_name,
                        recommended_action=f"Increase retention to at least {MIN_RETENTION_DAYS} days",
                        metadata={
                            "plan_name": plan_name,
                            "frequency": frequency_label,
                            "retention_days": retention_days,
                            "covered_resource_ids": covered_resources,
                        },
                    ))
                elif MIN_RETENTION_DAYS <= retention_days < STANDARD_RETENTION_DAYS:
                    findings.append(Finding(
                        skill=self.name,
                        title=f"Backup retention < {STANDARD_RETENTION_DAYS} days: {plan_name}",
                        severity=Severity.LOW,
                        description=(
                            f"Backup plan '{plan_name}' rule '{rule.get('rule_name', '')}' "
                            f"has retention of {retention_days} days, below the recommended "
                            f"standard of {STANDARD_RETENTION_DAYS} days"
                        ),
                        resource_id=plan_name,
                        recommended_action=f"Consider increasing retention to {STANDARD_RETENTION_DAYS} days",
                        metadata={
                            "plan_name": plan_name,
                            "frequency": frequency_label,
                            "retention_days": retention_days,
                            "covered_resource_ids": covered_resources,
                        },
                    ))
        return findings

    def _check_cross_region_replication(self, data: dict) -> list:
        """Req 3: Check backup plans for cross-region copy rules."""
        findings = []
        for plan in data.get("backup_plans", []):
            plan_name = plan.get("plan_name", plan.get("plan_id", "unknown"))
            has_cross_region = False
            dest_regions = []
            dest_vault_arns = []

            for rule in plan.get("rules", []):
                for ca in rule.get("copy_actions", []):
                    vault_arn = ca.get("destination_vault_arn", "")
                    if vault_arn:
                        # Parse region from ARN: arn:aws:backup:REGION:ACCOUNT:...
                        arn_parts = vault_arn.split(":")
                        if len(arn_parts) >= 4:
                            dest_region = arn_parts[3]
                            dest_regions.append(dest_region)
                            dest_vault_arns.append(vault_arn)
                            has_cross_region = True

            if not has_cross_region:
                findings.append(Finding(
                    skill=self.name,
                    title=f"No cross-region backup replication: {plan_name}",
                    severity=Severity.HIGH,
                    description=(
                        f"Backup plan '{plan_name}' does not replicate backups to another "
                        f"region. A regional outage could destroy both primary data and backups."
                    ),
                    resource_id=plan_name,
                    recommended_action="Add a cross-region copy rule to replicate backups to a secondary region",
                    metadata={
                        "plan_name": plan_name,
                        "has_cross_region_copy": False,
                    },
                ))
            else:
                findings.append(Finding(
                    skill=self.name,
                    title=f"Cross-region replication configured: {plan_name}",
                    severity=Severity.INFO,
                    description=(
                        f"Backup plan '{plan_name}' replicates to region(s): {', '.join(dest_regions)}"
                    ),
                    resource_id=plan_name,
                    metadata={
                        "plan_name": plan_name,
                        "has_cross_region_copy": True,
                        "source_region": "",  # source region not tracked per-plan in aggregated data
                        "destination_regions": dest_regions,
                        "destination_vault_arns": dest_vault_arns,
                    },
                ))
        return findings

    def _check_pitr(self, data: dict) -> list:
        """Req 4: Verify PITR on RDS instances and DynamoDB tables."""
        findings = []

        # RDS instances
        for inst in data.get("rds_instances", []):
            inst_id = inst.get("id", "")
            retention = inst.get("backup_retention_period", 0)
            if retention == 0:
                findings.append(Finding(
                    skill=self.name,
                    title=f"PITR unavailable — no automated backups: {inst_id}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"RDS instance {inst_id} has BackupRetentionPeriod=0, meaning "
                        f"automated backups and PITR are disabled"
                    ),
                    resource_id=inst_id,
                    region=inst.get("region", ""),
                    recommended_action="Enable automated backups with a retention period of at least 7 days",
                    metadata={
                        "resource_type": "rds",
                        "id": inst_id,
                        "backup_retention_period": retention,
                    },
                ))
            else:
                findings.append(Finding(
                    skill=self.name,
                    title=f"PITR available: {inst_id}",
                    severity=Severity.INFO,
                    description=(
                        f"RDS instance {inst_id} has automated backups enabled "
                        f"(retention={retention} days). PITR is available."
                    ),
                    resource_id=inst_id,
                    region=inst.get("region", ""),
                    metadata={
                        "resource_type": "rds",
                        "id": inst_id,
                        "backup_retention_period": retention,
                        "latest_restorable_time": inst.get("latest_restorable_time"),
                    },
                ))

        # DynamoDB tables
        for tbl in data.get("dynamodb_tables", []):
            tbl_name = tbl.get("name", "")
            pitr_enabled = tbl.get("pitr_enabled", False)
            if not pitr_enabled:
                findings.append(Finding(
                    skill=self.name,
                    title=f"PITR disabled on DynamoDB table: {tbl_name}",
                    severity=Severity.HIGH,
                    description=(
                        f"DynamoDB table {tbl_name} does not have Point-in-Time Recovery enabled"
                    ),
                    resource_id=tbl_name,
                    region=tbl.get("region", ""),
                    recommended_action="Enable Point-in-Time Recovery on this DynamoDB table",
                    metadata={
                        "resource_type": "dynamodb",
                        "name": tbl_name,
                        "pitr_enabled": False,
                    },
                ))
            else:
                findings.append(Finding(
                    skill=self.name,
                    title=f"PITR enabled on DynamoDB table: {tbl_name}",
                    severity=Severity.INFO,
                    description=(
                        f"DynamoDB table {tbl_name} has Point-in-Time Recovery enabled"
                    ),
                    resource_id=tbl_name,
                    region=tbl.get("region", ""),
                    metadata={
                        "resource_type": "dynamodb",
                        "name": tbl_name,
                        "pitr_enabled": True,
                        "earliest_restorable": tbl.get("earliest_restorable"),
                        "latest_restorable": tbl.get("latest_restorable"),
                    },
                ))
        return findings

    def _check_snapshot_age(self, data: dict) -> list:
        """Req 5: Analyze EBS and RDS snapshot ages."""
        findings = []
        now = datetime.now(timezone.utc)

        # Collect all snapshots with unified fields
        all_snapshots = []
        for snap in data.get("ebs_snapshots", []):
            ts = snap.get("start_time", "")
            if ts:
                all_snapshots.append({
                    "snapshot_id": snap["snapshot_id"],
                    "resource_id": snap.get("volume_id", ""),
                    "creation_timestamp": ts,
                    "type": "ebs",
                })
        for snap in data.get("rds_snapshots", []):
            ts = snap.get("snapshot_create_time", "")
            if ts:
                all_snapshots.append({
                    "snapshot_id": snap["snapshot_id"],
                    "resource_id": snap.get("db_instance_id", ""),
                    "creation_timestamp": ts,
                    "type": "rds",
                })

        # Group snapshots by resource_id and track newest per resource
        newest_by_resource: dict[str, float] = {}  # resource_id -> min age in days

        for snap in all_snapshots:
            try:
                create_time = datetime.fromisoformat(snap["creation_timestamp"])
                if create_time.tzinfo is None:
                    create_time = create_time.replace(tzinfo=timezone.utc)
                age_days = (now - create_time).days
            except (ValueError, TypeError):
                continue

            snap_id = snap["snapshot_id"]
            resource_id = snap["resource_id"]

            # Track newest snapshot per resource
            if resource_id:
                if resource_id not in newest_by_resource or age_days < newest_by_resource[resource_id]:
                    newest_by_resource[resource_id] = age_days

            # Individual snapshot age findings
            if age_days > VERY_STALE_SNAPSHOT_DAYS:
                findings.append(Finding(
                    skill=self.name,
                    title=f"Very stale snapshot ({age_days}d): {snap_id}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Snapshot {snap_id} is {age_days} days old (>{VERY_STALE_SNAPSHOT_DAYS}d). "
                        f"It is likely stale and should be reviewed."
                    ),
                    resource_id=snap_id,
                    recommended_action="Review and delete if no longer needed for recovery",
                    metadata={
                        "snapshot_id": snap_id,
                        "resource_id": resource_id,
                        "age_days": age_days,
                        "creation_timestamp": snap["creation_timestamp"],
                        "snapshot_type": snap["type"],
                    },
                ))
            elif age_days > STALE_SNAPSHOT_DAYS:
                findings.append(Finding(
                    skill=self.name,
                    title=f"Stale snapshot ({age_days}d): {snap_id}",
                    severity=Severity.LOW,
                    description=(
                        f"Snapshot {snap_id} is {age_days} days old (>{STALE_SNAPSHOT_DAYS}d). "
                        f"It may be stale."
                    ),
                    resource_id=snap_id,
                    recommended_action="Review snapshot retention policy",
                    metadata={
                        "snapshot_id": snap_id,
                        "resource_id": resource_id,
                        "age_days": age_days,
                        "creation_timestamp": snap["creation_timestamp"],
                        "snapshot_type": snap["type"],
                    },
                ))

        # Check for resources with no recent snapshot
        for resource_id, newest_age in newest_by_resource.items():
            if newest_age > RECENT_SNAPSHOT_DAYS:
                findings.append(Finding(
                    skill=self.name,
                    title=f"No recent snapshot for resource: {resource_id}",
                    severity=Severity.HIGH,
                    description=(
                        f"Resource {resource_id} has no snapshot newer than "
                        f"{RECENT_SNAPSHOT_DAYS} days (newest is {newest_age}d old)"
                    ),
                    resource_id=resource_id,
                    recommended_action="Create a fresh snapshot or verify backup automation",
                    metadata={
                        "resource_id": resource_id,
                        "newest_snapshot_age_days": newest_age,
                    },
                ))

        return findings

    def _compute_dr_score(self, data: dict, findings: list) -> tuple:
        """Req 6: Compute weighted DR readiness score (0-100)."""
        # --- Coverage sub-score ---
        protected_arns = set(data.get("protected_resource_arns", []))
        total_resources = (
            len(data.get("rds_instances", []))
            + len(data.get("dynamodb_tables", []))
            + len(data.get("ebs_volumes", []))
            + len(data.get("efs_file_systems", []))
            + len(data.get("s3_buckets", []))
        )
        if total_resources == 0:
            coverage_score = 100.0
            protected_count = 0
        else:
            protected_count = 0
            for inst in data.get("rds_instances", []):
                if inst.get("arn", "") in protected_arns:
                    protected_count += 1
            for tbl in data.get("dynamodb_tables", []):
                if tbl.get("arn", "") in protected_arns:
                    protected_count += 1
            for vol in data.get("ebs_volumes", []):
                if any(vol["volume_id"] in arn for arn in protected_arns):
                    protected_count += 1
            for fs in data.get("efs_file_systems", []):
                if any(fs["file_system_id"] in arn for arn in protected_arns):
                    protected_count += 1
            for bucket in data.get("s3_buckets", []):
                if any(bucket["name"] in arn for arn in protected_arns):
                    protected_count += 1
            coverage_score = (protected_count / total_resources) * 100.0

        # --- Frequency sub-score ---
        plans = data.get("backup_plans", [])
        total_plans = len(plans)
        if total_plans == 0:
            frequency_score = 0.0
            adequate_freq = 0
        else:
            adequate_freq = 0
            for plan in plans:
                plan_is_daily = False
                for rule in plan.get("rules", []):
                    schedule = rule.get("schedule", "")
                    if schedule:
                        lower_sched = schedule.lower()
                        if "rate(1 day)" in lower_sched or "rate(12 hour" in lower_sched or "rate(1 hour" in lower_sched:
                            plan_is_daily = True
                            break
                        elif lower_sched.startswith("cron("):
                            parts = lower_sched.replace("cron(", "").rstrip(")").split()
                            if len(parts) >= 5:
                                dom = parts[2]
                                dow = parts[4]
                                if dom in ("*", "?") and dow in ("*", "?"):
                                    plan_is_daily = True
                                    break
                if plan_is_daily:
                    adequate_freq += 1
            frequency_score = (adequate_freq / total_plans) * 100.0

        # --- Retention sub-score ---
        if total_plans == 0:
            retention_score = 0.0
            adequate_ret = 0
        else:
            adequate_ret = 0
            for plan in plans:
                plan_adequate = False
                for rule in plan.get("rules", []):
                    ret_days = rule.get("lifecycle", {}).get("DeleteAfterDays", 0)
                    if ret_days >= MIN_RETENTION_DAYS:
                        plan_adequate = True
                        break
                if plan_adequate:
                    adequate_ret += 1
            retention_score = (adequate_ret / total_plans) * 100.0

        # --- Cross-region sub-score ---
        if total_plans == 0:
            cross_region_score = 0.0
            replicated_plans = 0
        else:
            replicated_plans = 0
            for plan in plans:
                has_xr = False
                for rule in plan.get("rules", []):
                    for ca in rule.get("copy_actions", []):
                        if ca.get("destination_vault_arn", ""):
                            has_xr = True
                            break
                    if has_xr:
                        break
                if has_xr:
                    replicated_plans += 1
            cross_region_score = (replicated_plans / total_plans) * 100.0

        # --- PITR sub-score ---
        rds_instances = data.get("rds_instances", [])
        ddb_tables = data.get("dynamodb_tables", [])
        total_pitr = len(rds_instances) + len(ddb_tables)
        if total_pitr == 0:
            pitr_score = 100.0
            pitr_enabled_count = 0
        else:
            pitr_enabled_count = 0
            for inst in rds_instances:
                if inst.get("backup_retention_period", 0) > 0:
                    pitr_enabled_count += 1
            for tbl in ddb_tables:
                if tbl.get("pitr_enabled", False):
                    pitr_enabled_count += 1
            pitr_score = (pitr_enabled_count / total_pitr) * 100.0

        # --- Composite score ---
        sub_scores = {
            "coverage": coverage_score,
            "frequency": frequency_score,
            "retention": retention_score,
            "cross_region": cross_region_score,
            "pitr": pitr_score,
        }
        composite = sum(DR_SCORE_WEIGHTS[dim] * sub_scores[dim] for dim in DR_SCORE_WEIGHTS)
        composite = round(composite, 2)

        # Severity mapping
        if composite < 40:
            severity = Severity.CRITICAL
        elif composite <= 69:
            severity = Severity.HIGH
        elif composite <= 89:
            severity = Severity.MEDIUM
        else:
            severity = Severity.INFO

        # Weakest dimensions (sorted ascending by score)
        sorted_dims = sorted(sub_scores.items(), key=lambda x: x[1])
        weakest = [d[0] for d in sorted_dims if d[1] < 90]

        score_meta = {
            "dr_readiness_score": composite,
            "sub_scores": {
                "coverage": {"score": round(coverage_score, 2), "weight": DR_SCORE_WEIGHTS["coverage"], "protected": protected_count, "total": total_resources},
                "frequency": {"score": round(frequency_score, 2), "weight": DR_SCORE_WEIGHTS["frequency"], "adequate_plans": adequate_freq, "total_plans": total_plans},
                "retention": {"score": round(retention_score, 2), "weight": DR_SCORE_WEIGHTS["retention"], "adequate_plans": adequate_ret, "total_plans": total_plans},
                "cross_region": {"score": round(cross_region_score, 2), "weight": DR_SCORE_WEIGHTS["cross_region"], "replicated_plans": replicated_plans, "total_plans": total_plans},
                "pitr": {"score": round(pitr_score, 2), "weight": DR_SCORE_WEIGHTS["pitr"], "enabled": pitr_enabled_count, "total": total_pitr},
            },
            "weakest_dimensions": weakest,
            "weights": dict(DR_SCORE_WEIGHTS),
        }

        score_finding = Finding(
            skill=self.name,
            title=f"DR Readiness Score: {composite}",
            severity=severity,
            description=(
                f"Overall DR readiness score is {composite}/100. "
                f"Weakest dimensions: {', '.join(weakest) if weakest else 'none'}"
            ),
            metadata=score_meta,
        )
        return (score_finding, score_meta)

    def _check_rds_backup_retention(self, data: dict) -> list:
        """Req 7: Check RDS automated backup retention periods."""
        findings = []
        for inst in data.get("rds_instances", []):
            inst_id = inst.get("id", "")
            retention = inst.get("backup_retention_period", 0)
            engine = inst.get("engine", "")
            instance_class = inst.get("instance_class", "")
            backup_window = inst.get("preferred_backup_window", "")
            meta = {
                "id": inst_id,
                "engine": engine,
                "instance_class": instance_class,
                "backup_retention_period": retention,
                "preferred_backup_window": backup_window,
            }

            if retention == 0:
                findings.append(Finding(
                    skill=self.name,
                    title=f"RDS automated backups disabled: {inst_id}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"RDS instance {inst_id} ({engine}) has automated backups disabled "
                        f"(BackupRetentionPeriod=0)"
                    ),
                    resource_id=inst_id,
                    region=inst.get("region", ""),
                    recommended_action="Enable automated backups with a retention period of at least 7 days",
                    metadata=meta,
                ))
            elif retention < MIN_RETENTION_DAYS:
                findings.append(Finding(
                    skill=self.name,
                    title=f"RDS backup retention below minimum: {inst_id}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"RDS instance {inst_id} ({engine}) has backup retention of "
                        f"{retention} days, below the recommended {MIN_RETENTION_DAYS}-day minimum"
                    ),
                    resource_id=inst_id,
                    region=inst.get("region", ""),
                    recommended_action=f"Increase backup retention to at least {MIN_RETENTION_DAYS} days",
                    metadata=meta,
                ))
            else:
                findings.append(Finding(
                    skill=self.name,
                    title=f"RDS backup retention adequate: {inst_id}",
                    severity=Severity.INFO,
                    description=(
                        f"RDS instance {inst_id} ({engine}) has backup retention of "
                        f"{retention} days"
                    ),
                    resource_id=inst_id,
                    region=inst.get("region", ""),
                    metadata=meta,
                ))
        return findings

    def _check_dlm_policies(self, data: dict) -> list:
        """Req 8: Check EBS volumes for DLM lifecycle policies."""
        findings = []

        # Build set of volume IDs covered by DLM policies
        dlm_covered_volumes = set()
        for policy in data.get("dlm_policies", []):
            for vid in policy.get("target_volume_ids", []):
                dlm_covered_volumes.add(vid)

        # Build set of volume IDs covered by AWS Backup
        backup_covered_volumes = set()
        for arn in data.get("protected_resource_arns", []):
            # ARN pattern: arn:aws:ec2:<region>:<account>:volume/<vol-id>
            if ":volume/" in arn:
                vol_id = arn.split(":volume/")[-1]
                backup_covered_volumes.add(vol_id)
            # Also match if the volume ID appears anywhere in the ARN
            for vol in data.get("ebs_volumes", []):
                if vol["volume_id"] in arn:
                    backup_covered_volumes.add(vol["volume_id"])

        # Check each in-use EBS volume
        for vol in data.get("ebs_volumes", []):
            if vol.get("state") != "in-use":
                continue
            vol_id = vol["volume_id"]
            if vol_id not in dlm_covered_volumes and vol_id not in backup_covered_volumes:
                findings.append(Finding(
                    skill=self.name,
                    title=f"No automated snapshot lifecycle: {vol_id}",
                    severity=Severity.HIGH,
                    description=(
                        f"In-use EBS volume {vol_id} is not targeted by any DLM policy "
                        f"and is not covered by an AWS Backup plan"
                    ),
                    resource_id=vol_id,
                    region=vol.get("region", ""),
                    recommended_action="Add a DLM lifecycle policy or AWS Backup plan for this volume",
                    metadata={
                        "volume_id": vol_id,
                        "region": vol.get("region", ""),
                    },
                ))

        # Check for disabled DLM policies
        for policy in data.get("dlm_policies", []):
            if policy.get("state", "") != "ENABLED":
                findings.append(Finding(
                    skill=self.name,
                    title=f"DLM policy disabled: {policy['policy_id']}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"DLM policy {policy['policy_id']} is in state "
                        f"'{policy.get('state', 'unknown')}' and is not actively managing snapshots"
                    ),
                    resource_id=policy["policy_id"],
                    region=policy.get("region", ""),
                    recommended_action="Enable the DLM policy or remove it if no longer needed",
                    metadata={
                        "policy_id": policy["policy_id"],
                        "state": policy.get("state", ""),
                        "schedules": policy.get("schedules", []),
                        "target_volume_ids": policy.get("target_volume_ids", []),
                    },
                ))

        return findings


# ---------------------------------------------------------------------------
# Auto-register on import
# ---------------------------------------------------------------------------
SkillRegistry.register(BackupDRPostureSkill())
