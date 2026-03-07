"""Tag Enforcer — find untagged resources and apply mandatory tags across the org."""
import time
from cloudpilot.core import BaseSkill, SkillResult, Finding, Severity, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions

MANDATORY_TAGS = {"Environment", "Team", "Owner"}


class TagEnforcerSkill(BaseSkill):
    name = "tag-enforcer"
    description = "Find untagged EC2, RDS, S3, and Lambda resources missing mandatory tags"
    version = "0.1.0"

    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        findings = []
        errors = []
        acct = account_id or get_account_id(profile)

        scanners = [
            ("ec2", self._scan_ec2_tags),
            ("rds", self._scan_rds_tags),
            ("lambda", self._scan_lambda_tags),
        ]
        for name, fn in scanners:
            try:
                results = parallel_regions(lambda r: fn(r, profile), regions)
                findings.extend(results)
            except Exception as e:
                errors.append(f"{name}: {e}")

        # S3 is global
        try:
            findings.extend(self._scan_s3_tags(profile))
        except Exception as e:
            errors.append(f"s3: {e}")

        for f in findings:
            f.account_id = acct

        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=time.time() - start,
            accounts_scanned=1, regions_scanned=len(regions), errors=errors,
        )

    def _scan_ec2_tags(self, region, profile):
        findings = []
        try:
            ec2 = get_client("ec2", region, profile)
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
                for res in page["Reservations"]:
                    for inst in res["Instances"]:
                        tags = {t["Key"] for t in inst.get("Tags", [])}
                        missing = MANDATORY_TAGS - tags
                        if missing:
                            name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), "")
                            findings.append(Finding(
                                skill=self.name,
                                title=f"Untagged EC2: {inst['InstanceId']}",
                                severity=Severity.LOW, region=region,
                                resource_id=inst["InstanceId"],
                                description=f"{inst['InstanceType']} | {name} | Missing: {', '.join(sorted(missing))}",
                                recommended_action="Add mandatory tags: " + ", ".join(sorted(missing)),
                                metadata={"resource_type": "ec2", "missing_tags": sorted(missing)},
                            ))
        except Exception:
            pass
        return findings

    def _scan_rds_tags(self, region, profile):
        findings = []
        try:
            rds = get_client("rds", region, profile)
            for db in rds.describe_db_instances().get("DBInstances", []):
                arn = db["DBInstanceArn"]
                tag_resp = rds.list_tags_for_resource(ResourceName=arn)
                tags = {t["Key"] for t in tag_resp.get("TagList", [])}
                missing = MANDATORY_TAGS - tags
                if missing:
                    findings.append(Finding(
                        skill=self.name,
                        title=f"Untagged RDS: {db['DBInstanceIdentifier']}",
                        severity=Severity.LOW, region=region,
                        resource_id=db["DBInstanceIdentifier"],
                        description=f"{db['DBInstanceClass']} | {db['Engine']} | Missing: {', '.join(sorted(missing))}",
                        recommended_action="Add mandatory tags: " + ", ".join(sorted(missing)),
                        metadata={"resource_type": "rds", "missing_tags": sorted(missing), "arn": arn},
                    ))
        except Exception:
            pass
        return findings

    def _scan_lambda_tags(self, region, profile):
        findings = []
        try:
            lam = get_client("lambda", region, profile)
            for fn in lam.list_functions().get("Functions", []):
                tag_resp = lam.list_tags(Resource=fn["FunctionArn"])
                tags = set(tag_resp.get("Tags", {}).keys())
                missing = MANDATORY_TAGS - tags
                if missing:
                    findings.append(Finding(
                        skill=self.name,
                        title=f"Untagged Lambda: {fn['FunctionName']}",
                        severity=Severity.LOW, region=region,
                        resource_id=fn["FunctionName"],
                        description=f"Runtime: {fn.get('Runtime', 'N/A')} | Missing: {', '.join(sorted(missing))}",
                        recommended_action="Add mandatory tags: " + ", ".join(sorted(missing)),
                        metadata={"resource_type": "lambda", "missing_tags": sorted(missing), "arn": fn["FunctionArn"]},
                    ))
        except Exception:
            pass
        return findings

    def _scan_s3_tags(self, profile):
        findings = []
        try:
            s3 = get_client("s3", "us-east-1", profile)
            for bucket in s3.list_buckets().get("Buckets", []):
                name = bucket["Name"]
                try:
                    tag_resp = s3.get_bucket_tagging(Bucket=name)
                    tags = {t["Key"] for t in tag_resp.get("TagSet", [])}
                except s3.exceptions.ClientError:
                    tags = set()  # No tags at all
                missing = MANDATORY_TAGS - tags
                if missing:
                    findings.append(Finding(
                        skill=self.name,
                        title=f"Untagged S3: {name}",
                        severity=Severity.LOW, region="global",
                        resource_id=name,
                        description=f"Missing: {', '.join(sorted(missing))}",
                        recommended_action="Add mandatory tags: " + ", ".join(sorted(missing)),
                        metadata={"resource_type": "s3", "missing_tags": sorted(missing)},
                    ))
        except Exception:
            pass
        return findings


SkillRegistry.register(TagEnforcerSkill())
