"""Data Security & Classification — sensitive data discovery, audit evidence
collection, data sovereignty auditing."""
import json
import logging
import re
import time
from datetime import datetime, timezone

from cloudpilot.core import BaseSkill, Finding, Severity, SkillResult, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions

logger = logging.getLogger(__name__)

SENSITIVE_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\bpii\b", r"\bhipaa\b", r"\bpatient\b", r"\bmedical\b",
        r"\bfinancial\b", r"\bssn\b", r"\bcredit[_\s]?card\b",
        r"\bdate[_\s]?of[_\s]?birth\b", r"\bdob\b", r"\bsocial[_\s]?security\b",
        r"\bbank[_\s]?account\b", r"\bphi\b", r"\bhealthcare\b",
        r"\bcardholder\b", r"\bcvv\b", r"\bpassport\b",
    ]
]

DEFAULT_ALLOWED_REGIONS = ["us-east-1", "us-west-2"]

_PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


class DataSecuritySkill(BaseSkill):
    name = "data-security"
    description = "Sensitive data discovery, audit evidence collection, data sovereignty auditing"
    version = "0.1.0"

    # --- Public entry point ---
    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        acct = account_id or get_account_id(profile)
        region_results = parallel_regions(
            lambda r, p: self._collect_region_data(r, p), regions, profile=profile,
        )
        data = self._merge_region_data(region_results)
        findings = self._run_checks(data, acct, kwargs)
        sensitivity_map = self._build_sensitivity_map(data, findings)
        findings = self._elevate_severity(findings, sensitivity_map)
        for f in findings:
            f.account_id = acct
        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=time.time() - start,
            accounts_scanned=1, regions_scanned=len(regions),
            errors=list(data.get("errors", [])),
        )

    # --- Pass 1: Data collection ---
    def _collect_region_data(self, region: str, profile=None) -> dict:
        data = {"macie_enabled": False, "macie_findings": [], "s3_buckets": [],
                "rds_instances": [], "errors": [], "region": region,
                "cloudtrail_trails": [], "guardduty_enabled": False,
                "config_recording": False, "iam_summary": {},
                "iam_password_policy": {}, "ebs_encryption_default": False,
                "vpc_flow_logs": [], "security_groups": [],
                "dynamodb_tables": [], "efs_file_systems": [],
                "redshift_clusters": [], "waf_web_acls": [], "elb_load_balancers": []}
        self._collect_macie(data, region, profile)
        if region == "us-east-1":
            self._collect_s3(data, region, profile)
        self._collect_rds(data, region, profile)
        self._collect_compliance_data(data, region, profile)
        self._collect_sovereignty_resources(data, region, profile)
        return data

    def _collect_compliance_data(self, data, region, profile):
        # CloudTrail
        try:
            ct = get_client("cloudtrail", region, profile)
            trails = ct.describe_trails().get("trailList", [])
            for t in trails:
                status = {}
                try:
                    status = ct.get_trail_status(Name=t.get("TrailARN", t.get("Name", "")))
                except Exception:
                    pass
                data["cloudtrail_trails"].append({**t, "status": status})
        except Exception as e:
            logger.warning("CloudTrail in %s: %s", region, e)
            data["errors"].append(f"cloudtrail in {region}: {e}")
        # GuardDuty
        try:
            gd = get_client("guardduty", region, profile)
            detectors = gd.list_detectors().get("DetectorIds", [])
            data["guardduty_enabled"] = len(detectors) > 0
        except Exception as e:
            logger.warning("GuardDuty in %s: %s", region, e)
            data["errors"].append(f"guardduty in {region}: {e}")
        # Config
        try:
            cfg = get_client("config", region, profile)
            recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
            data["config_recording"] = len(recorders) > 0
        except Exception as e:
            logger.warning("Config in %s: %s", region, e)
            data["errors"].append(f"config in {region}: {e}")
        # IAM (global — only from us-east-1)
        if region == "us-east-1":
            try:
                iam = get_client("iam", region, profile)
                data["iam_summary"] = iam.get_account_summary().get("SummaryMap", {})
            except Exception as e:
                logger.warning("IAM summary: %s", e)
                data["errors"].append(f"iam summary: {e}")
            try:
                iam = get_client("iam", region, profile)
                data["iam_password_policy"] = iam.get_account_password_policy().get("PasswordPolicy", {})
            except Exception as e:
                logger.warning("IAM password policy: %s", e)
                data["errors"].append(f"iam password_policy: {e}")
        # EBS encryption default
        try:
            ec2 = get_client("ec2", region, profile)
            data["ebs_encryption_default"] = ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault", False)
        except Exception as e:
            logger.warning("EBS encryption in %s: %s", region, e)
            data["errors"].append(f"ebs encryption in {region}: {e}")
        # VPC flow logs
        try:
            ec2 = get_client("ec2", region, profile)
            data["vpc_flow_logs"] = ec2.describe_flow_logs().get("FlowLogs", [])
        except Exception as e:
            logger.warning("VPC flow logs in %s: %s", region, e)
            data["errors"].append(f"vpc flow_logs in {region}: {e}")
        # Security groups
        try:
            ec2 = get_client("ec2", region, profile)
            data["security_groups"] = ec2.describe_security_groups().get("SecurityGroups", [])
        except Exception as e:
            logger.warning("Security groups in %s: %s", region, e)
            data["errors"].append(f"security_groups in {region}: {e}")
        # WAF web ACLs
        try:
            waf = get_client("wafv2", region, profile)
            data["waf_web_acls"] = waf.list_web_acls(Scope="REGIONAL").get("WebACLs", [])
        except Exception as e:
            logger.warning("WAF in %s: %s", region, e)
            data["errors"].append(f"waf in {region}: {e}")
        # ELB load balancers
        try:
            elbv2 = get_client("elbv2", region, profile)
            data["elb_load_balancers"] = elbv2.describe_load_balancers().get("LoadBalancers", [])
        except Exception as e:
            logger.warning("ELBv2 in %s: %s", region, e)
            data["errors"].append(f"elbv2 in {region}: {e}")

    def _collect_sovereignty_resources(self, data, region, profile):
        # DynamoDB tables
        try:
            ddb = get_client("dynamodb", region, profile)
            data["dynamodb_tables"] = [
                {"name": t, "region": region}
                for t in ddb.list_tables().get("TableNames", [])
            ]
        except Exception as e:
            logger.warning("DynamoDB in %s: %s", region, e)
            data["errors"].append(f"dynamodb in {region}: {e}")
        # EFS file systems
        try:
            efs = get_client("efs", region, profile)
            data["efs_file_systems"] = [
                {"id": fs.get("FileSystemId", ""), "name": fs.get("Name", ""), "region": region}
                for fs in efs.describe_file_systems().get("FileSystems", [])
            ]
        except Exception as e:
            logger.warning("EFS in %s: %s", region, e)
            data["errors"].append(f"efs in {region}: {e}")
        # Redshift clusters
        try:
            rs = get_client("redshift", region, profile)
            data["redshift_clusters"] = [
                {"id": c.get("ClusterIdentifier", ""), "region": region}
                for c in rs.describe_clusters().get("Clusters", [])
            ]
        except Exception as e:
            logger.warning("Redshift in %s: %s", region, e)
            data["errors"].append(f"redshift in {region}: {e}")

    def _collect_macie(self, data, region, profile):
        try:
            macie = get_client("macie2", region, profile)
            if macie.get_macie_session().get("status") == "ENABLED":
                data["macie_enabled"] = True
                try:
                    ids = macie.list_findings(
                        findingCriteria={"criterion": {"severity.description": {"neq": ["Low"]}}},
                        maxResults=50,
                    ).get("findingIds", [])
                    if ids:
                        data["macie_findings"].extend(macie.get_findings(findingIds=ids).get("findings", []))
                except Exception as e:
                    logger.warning("Macie findings in %s: %s", region, e)
                    data["errors"].append(f"macie2 findings in {region}: {e}")
        except Exception as e:
            logger.warning("Macie unavailable in %s: %s", region, e)
            data["errors"].append(f"macie2 session in {region}: {e}")

    def _collect_s3(self, data, region, profile):
        try:
            s3 = get_client("s3", region, profile)
            for b in s3.list_buckets().get("Buckets", []):
                name = b["Name"]
                cd = b.get("CreationDate", "")
                info = {"name": name, "creation_date": cd.isoformat() if hasattr(cd, "isoformat") else str(cd),
                        "public_access_block": None, "policy": None, "encryption": None,
                        "location": None, "versioning": None}
                for key, call, extract in [
                    ("public_access_block", lambda: s3.get_public_access_block(Bucket=name),
                     lambda r: r.get("PublicAccessBlockConfiguration", {})),
                    ("policy", lambda: s3.get_bucket_policy(Bucket=name), lambda r: r.get("Policy")),
                    ("encryption", lambda: s3.get_bucket_encryption(Bucket=name),
                     lambda r: r.get("ServerSideEncryptionConfiguration", {})),
                    ("location", lambda: s3.get_bucket_location(Bucket=name),
                     lambda r: r.get("LocationConstraint") or "us-east-1"),
                    ("versioning", lambda: s3.get_bucket_versioning(Bucket=name),
                     lambda r: r.get("Status", "Disabled")),
                ]:
                    try:
                        info[key] = extract(call())
                    except Exception:
                        pass
                data["s3_buckets"].append(info)
        except Exception as e:
            logger.warning("S3 list_buckets: %s", e)
            data["errors"].append(f"s3 list_buckets: {e}")

    def _collect_rds(self, data, region, profile):
        try:
            rds = get_client("rds", region, profile)
            for page in rds.get_paginator("describe_db_instances").paginate():
                for db in page.get("DBInstances", []):
                    arn = db.get("DBInstanceArn", "")
                    tags = []
                    try:
                        tags = rds.list_tags_for_resource(ResourceName=arn).get("TagList", [])
                    except Exception as e:
                        logger.warning("RDS tags for %s: %s", arn, e)
                    data["rds_instances"].append({
                        "id": db["DBInstanceIdentifier"], "engine": db.get("Engine", ""),
                        "instance_class": db.get("DBInstanceClass", ""),
                        "tags": tags, "storage_encrypted": db.get("StorageEncrypted", False),
                        "publicly_accessible": db.get("PubliclyAccessible", False),
                        "arn": arn, "region": region,
                    })
        except Exception as e:
            logger.warning("RDS in %s: %s", region, e)
            data["errors"].append(f"rds in {region}: {e}")

    def _merge_region_data(self, region_results: list) -> dict:
        merged = {"macie_enabled_regions": [], "macie_disabled_regions": [],
                  "macie_findings": [], "s3_buckets": [], "rds_instances": [], "errors": [],
                  "cloudtrail_trails": [], "guardduty_enabled": False,
                  "config_recording": False, "iam_summary": {}, "iam_password_policy": {},
                  "ebs_encryption_default": False, "vpc_flow_logs": [],
                  "security_groups": [], "dynamodb_tables": [], "efs_file_systems": [],
                  "redshift_clusters": [], "waf_web_acls": [], "elb_load_balancers": []}
        for rd in (region_results if isinstance(region_results, list) else []):
            if not isinstance(rd, dict):
                continue
            rgn = rd.get("region", "unknown")
            (merged["macie_enabled_regions"] if rd.get("macie_enabled") else merged["macie_disabled_regions"]).append(rgn)
            for k in ("macie_findings", "s3_buckets", "rds_instances", "errors",
                       "cloudtrail_trails", "vpc_flow_logs", "security_groups",
                       "dynamodb_tables", "efs_file_systems", "redshift_clusters",
                       "waf_web_acls", "elb_load_balancers"):
                merged[k].extend(rd.get(k, []))
            if rd.get("guardduty_enabled"):
                merged["guardduty_enabled"] = True
            if rd.get("config_recording"):
                merged["config_recording"] = True
            if rd.get("ebs_encryption_default"):
                merged["ebs_encryption_default"] = True
            if rd.get("iam_summary"):
                merged["iam_summary"] = rd["iam_summary"]
            if rd.get("iam_password_policy"):
                merged["iam_password_policy"] = rd["iam_password_policy"]
        return merged

    # --- Pass 2: Run all checkers ---
    def _run_checks(self, data, account_id, kwargs):
        findings = []
        allowed = kwargs.get("allowed_regions", DEFAULT_ALLOWED_REGIONS)
        for checker in [
            lambda d: self._check_macie_findings(d),
            lambda d: self._check_s3_access(d),
            lambda d: self._check_rds_metadata(d),
            lambda d: self._collect_soc2_evidence(d),
            lambda d: self._collect_hipaa_evidence(d),
            lambda d: self._collect_pci_evidence(d),
            lambda d: self._check_sovereignty(d, allowed),
        ]:
            try:
                r = checker(data)
                findings.extend(r if isinstance(r, list) else ([r] if r else []))
            except Exception as e:
                logger.warning("Checker failed: %s", e)
        return findings

    # --- Checker: Macie findings (Req 1) ---
    def _check_macie_findings(self, data: dict) -> list:
        findings = []
        for rgn in data.get("macie_disabled_regions", []):
            findings.append(Finding(
                skill=self.name, title=f"Macie not enabled in {rgn}",
                severity=Severity.HIGH, region=rgn,
                description=f"Amazon Macie is not enabled in {rgn}. Sensitive data discovery unavailable.",
                recommended_action="Enable Amazon Macie for sensitive data discovery",
                metadata={"region": rgn, "macie_enabled": False},
            ))
        for mf in data.get("macie_findings", []):
            sev_info = mf.get("severity", {})
            macie_sev = sev_info.get("description", "Low") if isinstance(sev_info, dict) else str(sev_info)
            if macie_sev.upper() == "LOW":
                continue
            cat = self._classify_macie_category(mf)
            bucket = mf.get("resourcesAffected", {}).get("s3Bucket", {}).get("name", "unknown")
            sev = Severity.CRITICAL if cat in ("PII", "PHI") else (Severity.HIGH if cat == "FINANCIAL" else Severity.MEDIUM)
            findings.append(Finding(
                skill=self.name, title=f"Sensitive data ({cat}) in bucket {bucket}",
                severity=sev, resource_id=bucket,
                description=f"Macie found {cat} data in S3 bucket {bucket}",
                recommended_action="Review and remediate sensitive data exposure",
                metadata={"bucket_name": bucket, "category": cat, "finding_count": 1, "macie_severity": macie_sev},
            ))
        return findings

    @staticmethod
    def _classify_macie_category(finding: dict) -> str:
        for sd in finding.get("classificationDetails", {}).get("result", {}).get("sensitiveData", []):
            cat = sd.get("category", "").upper()
            if "PERSONAL" in cat or "PII" in cat:
                return "PII"
            if "PHI" in cat or "HEALTH" in cat or "PROTECTED_HEALTH" in cat:
                return "PHI"
            if "FINANCIAL" in cat:
                return "FINANCIAL"
        ftype = finding.get("type", "").upper()
        if "PERSONAL" in ftype or "PII" in ftype:
            return "PII"
        if "PHI" in ftype or "HEALTH" in ftype:
            return "PHI"
        if "FINANCIAL" in ftype:
            return "FINANCIAL"
        return "OTHER"

    # --- Checker: S3 bucket access (Req 2) ---
    def _check_s3_access(self, data: dict) -> list:
        findings = []
        for bucket in data.get("s3_buckets", []):
            bname, region = bucket.get("name", "unknown"), bucket.get("location", "unknown")
            cdate, pab, enc = bucket.get("creation_date", ""), bucket.get("public_access_block"), bucket.get("encryption")
            policy_str = bucket.get("policy")

            pub_issue = pab is None or any(not pab.get(k, False) for k in _PAB_KEYS)
            enc_issue = enc is None
            ext_accts, actions = self._parse_cross_account(policy_str)
            cross_acct = bool(ext_accts)

            profile = {
                "bucket_name": bname, "region": region, "creation_date": cdate,
                "public_access_block": pab or {}, "has_cross_account_access": cross_acct,
                "external_account_ids": ext_accts, "granted_actions": actions,
                "encryption_enabled": not enc_issue,
                "encryption_algorithm": self._enc_algo(enc),
            }
            meta = {"bucket_name": bname, "region": region, "creation_date": cdate, "Bucket_Access_Profile": profile}

            if pub_issue:
                findings.append(Finding(
                    skill=self.name, title=f"S3 public access not fully blocked: {bname}",
                    severity=Severity.CRITICAL, resource_id=bname, region=region,
                    description=f"Bucket {bname} does not have all Block Public Access settings enabled",
                    recommended_action="Enable all Block Public Access settings",
                    metadata={**meta, "public_access_block": pab or {}},
                ))
            if cross_acct:
                findings.append(Finding(
                    skill=self.name, title=f"S3 cross-account access: {bname}",
                    severity=Severity.HIGH, resource_id=bname, region=region,
                    description=f"Bucket {bname} grants access to external accounts",
                    recommended_action="Review and restrict cross-account access",
                    metadata={**meta, "external_account_ids": ext_accts, "granted_actions": actions},
                ))
            if enc_issue:
                findings.append(Finding(
                    skill=self.name, title=f"S3 missing encryption: {bname}",
                    severity=Severity.HIGH, resource_id=bname, region=region,
                    description=f"Bucket {bname} lacks default server-side encryption",
                    recommended_action="Enable default server-side encryption",
                    metadata=meta,
                ))
            if not pub_issue and not cross_acct and not enc_issue:
                findings.append(Finding(
                    skill=self.name, title=f"S3 bucket secure: {bname}",
                    severity=Severity.INFO, resource_id=bname, region=region,
                    description=f"Bucket {bname} has a secure access profile", metadata=meta,
                ))
        return findings

    @staticmethod
    def _parse_cross_account(policy_str) -> tuple:
        if not policy_str:
            return [], []
        try:
            policy = json.loads(policy_str) if isinstance(policy_str, str) else policy_str
        except (json.JSONDecodeError, TypeError):
            return [], []
        ext, acts = set(), set()
        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            princ = stmt.get("Principal", {})
            if princ == "*":
                ext.add("*")
            elif isinstance(princ, str):
                princ = {"AWS": [princ]}
            elif isinstance(princ, dict):
                aws_p = princ.get("AWS", [])
                princ = {"AWS": [aws_p] if isinstance(aws_p, str) else aws_p}
            else:
                continue
            for p in princ.get("AWS", []):
                aid = _extract_acct(p)
                if aid:
                    ext.add(aid)
            if ext & set(p for p in ext):
                a = stmt.get("Action", [])
                acts.update(a if isinstance(a, list) else [a])
        return list(ext), list(acts)

    @staticmethod
    def _enc_algo(enc):
        if not enc:
            return None
        rules = enc.get("Rules", [])
        return rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") if rules else None

    # --- Checker: RDS metadata (Req 3) ---
    def _check_rds_metadata(self, data):
        findings = []
        for inst in data.get("rds_instances", []):
            text_parts = [inst.get("id", "")]
            for tag in inst.get("tags", []):
                text_parts.append(tag.get("Key", ""))
                text_parts.append(tag.get("Value", ""))
            combined = " ".join(text_parts)
            matched = [p.pattern for p in SENSITIVE_PATTERNS if p.search(combined)]
            if not matched:
                continue
            encrypted = inst.get("storage_encrypted", False)
            public = inst.get("publicly_accessible", False)
            meta = {"id": inst.get("id", ""), "engine": inst.get("engine", ""),
                    "instance_class": inst.get("instance_class", ""),
                    "matched_patterns": matched, "encryption_status": encrypted,
                    "public_accessibility": public}
            if not encrypted or public:
                findings.append(Finding(
                    skill=self.name,
                    title=f"RDS sensitive instance unprotected: {inst.get('id', '')}",
                    severity=Severity.CRITICAL, resource_id=inst.get("id", ""),
                    region=inst.get("region", ""),
                    description=f"RDS instance {inst.get('id', '')} matches sensitive patterns and "
                                f"{'lacks encryption' if not encrypted else 'is publicly accessible'}",
                    recommended_action="Enable encryption and disable public access for sensitive databases",
                    metadata=meta,
                ))
            else:
                findings.append(Finding(
                    skill=self.name,
                    title=f"RDS sensitive instance detected: {inst.get('id', '')}",
                    severity=Severity.HIGH, resource_id=inst.get("id", ""),
                    region=inst.get("region", ""),
                    description=f"RDS instance {inst.get('id', '')} matches sensitive data patterns",
                    recommended_action="Review data classification and access controls",
                    metadata=meta,
                ))
        return findings

    # --- SOC2 base evidence controls ---
    def _soc2_base_items(self, data):
        items = []
        # CloudTrail logging
        trails = data.get("cloudtrail_trails", [])
        multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]
        logging_on = any(t.get("status", {}).get("IsLogging") for t in multi_region)
        items.append(self._make_evidence_item(
            "SOC2-CT-001", "CloudTrail Multi-Region Logging",
            "pass" if logging_on else "fail",
            {"multi_region_trails": len(multi_region), "logging": logging_on}))
        # GuardDuty
        gd_enabled = data.get("guardduty_enabled", False)
        items.append(self._make_evidence_item(
            "SOC2-GD-001", "GuardDuty Enabled",
            "pass" if gd_enabled else "fail",
            {"enabled": gd_enabled}))
        # Config recording
        cfg = data.get("config_recording", False)
        items.append(self._make_evidence_item(
            "SOC2-CFG-001", "AWS Config Recording",
            "pass" if cfg else "fail",
            {"recording": cfg}))
        # IAM MFA
        summary = data.get("iam_summary", {})
        mfa_devices = summary.get("MFADevicesInUse", 0)
        users = summary.get("Users", 0)
        mfa_ok = users == 0 or mfa_devices > 0
        items.append(self._make_evidence_item(
            "SOC2-IAM-001", "IAM MFA Enforcement",
            "pass" if mfa_ok else "fail",
            {"mfa_devices": mfa_devices, "users": users}))
        # IAM password policy
        pp = data.get("iam_password_policy", {})
        pp_ok = pp.get("RequireUppercaseCharacters", False) and pp.get("MinimumPasswordLength", 0) >= 8
        items.append(self._make_evidence_item(
            "SOC2-IAM-002", "IAM Password Policy",
            "pass" if pp_ok else ("fail" if pp else "not_applicable"),
            {"password_policy": pp}))
        # IAM key age — not_applicable if no summary
        items.append(self._make_evidence_item(
            "SOC2-IAM-003", "IAM Access Key Age",
            "pass" if summary else "not_applicable",
            {"account_summary_available": bool(summary)}))
        # S3 encryption
        buckets = data.get("s3_buckets", [])
        enc_count = sum(1 for b in buckets if b.get("encryption"))
        s3_ok = len(buckets) == 0 or enc_count == len(buckets)
        items.append(self._make_evidence_item(
            "SOC2-ENC-001", "S3 Default Encryption",
            "pass" if s3_ok else "fail",
            {"total_buckets": len(buckets), "encrypted_buckets": enc_count}))
        # RDS encryption
        rds_list = data.get("rds_instances", [])
        rds_enc = sum(1 for r in rds_list if r.get("storage_encrypted"))
        rds_ok = len(rds_list) == 0 or rds_enc == len(rds_list)
        items.append(self._make_evidence_item(
            "SOC2-ENC-002", "RDS Storage Encryption",
            "pass" if rds_ok else "fail",
            {"total_instances": len(rds_list), "encrypted_instances": rds_enc}))
        # EBS encryption
        ebs_enc = data.get("ebs_encryption_default", False)
        items.append(self._make_evidence_item(
            "SOC2-ENC-003", "EBS Default Encryption",
            "pass" if ebs_enc else "fail",
            {"ebs_encryption_default": ebs_enc}))
        return items

    def _collect_soc2_evidence(self, data):
        items = self._soc2_base_items(data)
        sev = self._evidence_severity(items)
        applicable = [i for i in items if i.get("status") != "not_applicable"]
        passing = sum(1 for i in applicable if i.get("status") == "pass")
        total = len(applicable)
        return Finding(
            skill=self.name, title="SOC2 Compliance Evidence Report",
            severity=sev, description="Automated SOC2 compliance evidence collection",
            recommended_action="Review failing controls and remediate",
            metadata={"check_type": "compliance_evidence", "framework": "SOC2",
                      "evidence_items": items, "total_controls": total,
                      "passing_controls": passing, "failing_controls": total - passing,
                      "pass_ratio": passing / total if total else 0.0})

    def _collect_hipaa_evidence(self, data):
        items = self._soc2_base_items(data)
        # HIPAA-specific: CloudTrail log validation
        trails = data.get("cloudtrail_trails", [])
        log_val = any(t.get("LogFileValidationEnabled") for t in trails)
        items.append(self._make_evidence_item(
            "HIPAA-CT-001", "CloudTrail Log File Validation",
            "pass" if log_val else "fail",
            {"log_file_validation": log_val}))
        # S3 versioning
        buckets = data.get("s3_buckets", [])
        ver_count = sum(1 for b in buckets if b.get("versioning") == "Enabled")
        ver_ok = len(buckets) == 0 or ver_count == len(buckets)
        items.append(self._make_evidence_item(
            "HIPAA-S3-001", "S3 Versioning Enabled",
            "pass" if ver_ok else "fail",
            {"total_buckets": len(buckets), "versioned_buckets": ver_count}))
        # RDS backup retention ≥7d
        rds_list = data.get("rds_instances", [])
        bk_ok_count = sum(1 for r in rds_list if r.get("backup_retention", 0) >= 7)
        bk_ok = len(rds_list) == 0 or bk_ok_count == len(rds_list)
        items.append(self._make_evidence_item(
            "HIPAA-BK-001", "RDS Backup Retention >= 7 Days",
            "pass" if bk_ok else "fail",
            {"total_instances": len(rds_list), "compliant_instances": bk_ok_count}))
        sev = self._evidence_severity(items)
        applicable = [i for i in items if i.get("status") != "not_applicable"]
        passing = sum(1 for i in applicable if i.get("status") == "pass")
        total = len(applicable)
        return Finding(
            skill=self.name, title="HIPAA Compliance Evidence Report",
            severity=sev, description="Automated HIPAA compliance evidence collection",
            recommended_action="Review failing controls and remediate",
            metadata={"check_type": "compliance_evidence", "framework": "HIPAA",
                      "evidence_items": items, "total_controls": total,
                      "passing_controls": passing, "failing_controls": total - passing,
                      "pass_ratio": passing / total if total else 0.0})

    def _collect_pci_evidence(self, data):
        items = self._soc2_base_items(data)
        # PCI-specific: VPC flow logs
        flow_logs = data.get("vpc_flow_logs", [])
        fl_ok = len(flow_logs) > 0
        items.append(self._make_evidence_item(
            "PCI-FL-001", "VPC Flow Logs Enabled",
            "pass" if fl_ok else "fail",
            {"flow_log_count": len(flow_logs)}))
        # SG no open DB ports
        db_ports = {3306, 5432, 1433, 1521, 27017}
        open_sgs = []
        for sg in data.get("security_groups", []):
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 0)
                open_cidrs = [r.get("CidrIp", "") for r in rule.get("IpRanges", [])]
                open_v6 = [r.get("CidrIpv6", "") for r in rule.get("Ipv6Ranges", [])]
                unrestricted = "0.0.0.0/0" in open_cidrs or "::/0" in open_v6
                if unrestricted and any(from_port <= p <= to_port for p in db_ports):
                    open_sgs.append(sg.get("GroupId", ""))
                    break
        items.append(self._make_evidence_item(
            "PCI-SG-001", "Security Groups No Open DB Ports",
            "pass" if not open_sgs else "fail",
            {"open_db_port_security_groups": open_sgs}))
        # WAF on internet-facing ELBs
        elbs = data.get("elb_load_balancers", [])
        internet_facing = [e for e in elbs if e.get("Scheme") == "internet-facing"]
        waf_acls = data.get("waf_web_acls", [])
        waf_ok = len(internet_facing) == 0 or len(waf_acls) > 0
        items.append(self._make_evidence_item(
            "PCI-WAF-001", "WAF on Internet-Facing ELBs",
            "pass" if waf_ok else "fail",
            {"internet_facing_elbs": len(internet_facing), "waf_acl_count": len(waf_acls)}))
        sev = self._evidence_severity(items)
        applicable = [i for i in items if i.get("status") != "not_applicable"]
        passing = sum(1 for i in applicable if i.get("status") == "pass")
        total = len(applicable)
        return Finding(
            skill=self.name, title="PCI Compliance Evidence Report",
            severity=sev, description="Automated PCI DSS compliance evidence collection",
            recommended_action="Review failing controls and remediate",
            metadata={"check_type": "compliance_evidence", "framework": "PCI",
                      "evidence_items": items, "total_controls": total,
                      "passing_controls": passing, "failing_controls": total - passing,
                      "pass_ratio": passing / total if total else 0.0})

    # --- Checker: Sovereignty (Req 7) ---
    def _check_sovereignty(self, data, allowed_regions):
        findings = []
        violations = []
        # S3 buckets by location
        for b in data.get("s3_buckets", []):
            loc = b.get("location") or "us-east-1"
            if loc not in allowed_regions:
                violations.append(("s3_bucket", b.get("name", ""), loc))
        # RDS instances
        for r in data.get("rds_instances", []):
            if r.get("region", "") not in allowed_regions:
                violations.append(("rds_instance", r.get("id", ""), r.get("region", "")))
        # DynamoDB tables
        for t in data.get("dynamodb_tables", []):
            if t.get("region", "") not in allowed_regions:
                violations.append(("dynamodb_table", t.get("name", ""), t.get("region", "")))
        # EFS file systems
        for fs in data.get("efs_file_systems", []):
            if fs.get("region", "") not in allowed_regions:
                violations.append(("efs_filesystem", fs.get("id", ""), fs.get("region", "")))
        # Redshift clusters
        for c in data.get("redshift_clusters", []):
            if c.get("region", "") not in allowed_regions:
                violations.append(("redshift_cluster", c.get("id", ""), c.get("region", "")))
        for rtype, rid, actual in violations:
            findings.append(Finding(
                skill=self.name,
                title=f"Data sovereignty violation: {rid}",
                severity=Severity.HIGH, resource_id=rid, region=actual,
                description=f"{rtype} {rid} in {actual} is outside allowed regions",
                recommended_action="Migrate resource to an allowed region or update allowed regions policy",
                metadata={"resource_id": rid, "resource_type": rtype,
                          "actual_region": actual, "allowed_regions": allowed_regions},
            ))
        if violations:
            count = len(violations)
            sev = Severity.CRITICAL if count >= 10 else (Severity.HIGH if count >= 5 else Severity.MEDIUM)
            findings.append(Finding(
                skill=self.name,
                title=f"Data sovereignty summary: {count} violation(s)",
                severity=sev,
                description=f"{count} data resource(s) found outside allowed regions {allowed_regions}",
                recommended_action="Review and remediate data sovereignty violations",
                metadata={"violation_count": count, "allowed_regions": allowed_regions},
            ))
        return findings

    # --- Sensitivity map and severity elevation (Req 8) ---
    def _build_sensitivity_map(self, data, findings):
        smap = {}
        # From Macie findings
        for mf in data.get("macie_findings", []):
            bucket = mf.get("resourcesAffected", {}).get("s3Bucket", {}).get("name", "")
            if not bucket:
                continue
            cat = self._classify_macie_category(mf)
            if cat in ("PII", "PHI"):
                smap[bucket] = "confirmed_pii_phi"
            elif cat == "FINANCIAL" and smap.get(bucket) != "confirmed_pii_phi":
                smap[bucket] = "confirmed_financial"
        # From RDS pattern matches
        for f in findings:
            if f.skill == self.name and f.metadata.get("matched_patterns"):
                smap.setdefault(f.resource_id, "suspected_sensitive")
        return smap

    def _elevate_severity(self, findings, sensitivity_map):
        sev_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        for f in findings:
            level = sensitivity_map.get(f.resource_id, "unknown")
            f.metadata["data_sensitivity_level"] = level
            if level == "confirmed_pii_phi":
                idx = sev_order.index(f.severity)
                f.severity = sev_order[min(idx + 1, len(sev_order) - 1)]
            elif level == "confirmed_financial":
                if sev_order.index(f.severity) < sev_order.index(Severity.HIGH):
                    f.severity = Severity.HIGH
        return findings

    def _make_evidence_item(self, control_id, control_name, status, evidence_data):
        return {"control_id": control_id, "control_name": control_name, "status": status,
                "evidence_data": evidence_data, "timestamp": datetime.now(timezone.utc).isoformat()}

    def _evidence_severity(self, items):
        applicable = [i for i in items if i.get("status") != "not_applicable"]
        if not applicable:
            return Severity.INFO
        ratio = sum(1 for i in applicable if i.get("status") == "pass") / len(applicable)
        if ratio >= 1.0: return Severity.INFO
        if ratio > 0.8: return Severity.LOW
        if ratio > 0.6: return Severity.MEDIUM
        if ratio > 0.4: return Severity.HIGH
        return Severity.CRITICAL


def _extract_acct(principal: str) -> str:
    if principal == "*":
        return "*"
    if principal.startswith("arn:aws"):
        parts = principal.split(":")
        return parts[4] if len(parts) >= 5 else ""
    return principal if principal.isdigit() and len(principal) == 12 else ""


SkillRegistry.register(DataSecuritySkill())
