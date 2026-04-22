"""CSPM Engine — 25 security checks across 8 categories.

Enhances the original 5-check SecurityPostureSkill into a comprehensive
Cloud Security Posture Management engine with:
  - Check Registry pattern for modular check management
  - Risk scoring (1-10) per finding
  - Compliance tagging (CIS AWS Foundations v1.5 + FSBP)
  - Posture Summary aggregation
  - Parallel scanning via ThreadPoolExecutor / parallel_regions

All API calls are read-only (describe/list/get/head).
"""
import json
import time
import logging
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from cloudpilot.core import (
    BaseSkill, Finding, Severity, SkillResult, SkillRegistry,
)
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------
SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
    "INFORMATIONAL": Severity.INFO,
}

CONTROL_REMEDIATION = {
    "IAM.1": "Remove overly permissive IAM policies",
    "IAM.3": "Rotate IAM access keys older than 90 days",
    "IAM.5": "Enable MFA for IAM users with console access",
    "IAM.6": "Enable MFA on the root account",
    "S3.1": "Remove public bucket policies",
    "S3.2": "Remove public ACL grants from S3 buckets",
    "S3.4": "Enable default encryption on S3 buckets",
    "EC2.2": "Avoid using default VPCs for production workloads",
    "EC2.3": "Enable encryption on EBS volumes",
    "EC2.9": "Remove public IP from EC2 instances or restrict security groups",
    "EC2.19": "Restrict security group rules to specific IPs",
    "RDS.2": "Disable public accessibility on RDS instances",
    "RDS.3": "Enable encryption on RDS instances",
    "CloudTrail.1": "Enable multi-region CloudTrail logging",
    "GuardDuty.1": "Enable GuardDuty in all regions",
    "ELB.6": "Associate WAF WebACL with internet-facing load balancers",
    "APIGateway.1": "Add authorization to API Gateway methods",
    "Redshift.1": "Disable public accessibility on Redshift clusters",
    "ES.2": "Deploy OpenSearch domains within a VPC",
    "ECR.1": "Enable image scanning on ECR repositories",
    "EC2.1": "Remove public launch permissions from AMIs",
}


# ---------------------------------------------------------------------------
# Check Registry
# ---------------------------------------------------------------------------
@dataclass
class CheckDefinition:
    """Metadata for a single CSPM check."""
    name: str
    fn_name: str
    category: str
    compliance_tags: list
    default_risk_score: int
    is_regional: bool


CHECK_REGISTRY: list[CheckDefinition] = [
    # --- Public Exposure (1-10) ---
    CheckDefinition("s3_public_acl", "_check_s3_public_acl", "Public_Exposure",
                     ["CIS 2.1.1", "FSBP S3.2"], 9, False),
    CheckDefinition("s3_public_policy", "_check_s3_public_policy", "Public_Exposure",
                     ["CIS 2.1.2", "FSBP S3.1"], 9, False),
    CheckDefinition("ec2_public_instance", "_check_ec2_public_instance", "Public_Exposure",
                     ["FSBP EC2.9"], 7, True),
    CheckDefinition("rds_public_access", "_check_rds_public_access", "Public_Exposure",
                     ["CIS 2.3.1", "FSBP RDS.2"], 9, True),
    CheckDefinition("redshift_public_access", "_check_redshift_public_access", "Public_Exposure",
                     ["FSBP Redshift.1"], 9, True),
    CheckDefinition("opensearch_public_endpoint", "_check_opensearch_public_endpoint", "Public_Exposure",
                     ["FSBP ES.2"], 7, True),
    CheckDefinition("ec2_public_ami", "_check_ec2_public_ami", "Public_Exposure",
                     ["FSBP EC2.1"], 7, True),
    CheckDefinition("elb_no_waf", "_check_elb_no_waf", "Public_Exposure",
                     ["FSBP ELB.6"], 5, True),
    CheckDefinition("apigw_no_auth", "_check_apigw_no_auth", "Public_Exposure",
                     ["FSBP APIGateway.1"], 7, True),
    CheckDefinition("lambda_public_url", "_check_lambda_public_url", "Public_Exposure",
                     [], 7, True),
    # --- Network Configuration (11, 24) ---
    CheckDefinition("sg_open_non_web", "_check_sg_open_non_web", "Network_Configuration",
                     ["CIS 5.2", "FSBP EC2.19"], 7, True),
    CheckDefinition("default_vpc_in_use", "_check_default_vpc_in_use", "Network_Configuration",
                     ["CIS 5.4", "FSBP EC2.2"], 5, True),
    # --- Encryption (12-14) ---
    CheckDefinition("ebs_unencrypted", "_check_ebs_unencrypted", "Encryption",
                     ["CIS 2.2.1", "FSBP EC2.3"], 5, True),
    CheckDefinition("s3_no_encryption", "_check_s3_no_encryption", "Encryption",
                     ["CIS 2.1.1", "FSBP S3.4"], 5, False),
    CheckDefinition("rds_unencrypted", "_check_rds_unencrypted", "Encryption",
                     ["CIS 2.3.1", "FSBP RDS.3"], 6, True),
    # --- IAM Hygiene (15-19) ---
    CheckDefinition("iam_user_no_mfa", "_check_iam_user_no_mfa", "IAM_Hygiene",
                     ["CIS 1.10", "FSBP IAM.5"], 7, False),
    CheckDefinition("iam_root_no_mfa", "_check_iam_root_no_mfa", "IAM_Hygiene",
                     ["CIS 1.5", "FSBP IAM.6"], 10, False),
    CheckDefinition("iam_old_access_keys", "_check_iam_old_access_keys", "IAM_Hygiene",
                     ["CIS 1.12", "FSBP IAM.3"], 5, False),
    CheckDefinition("iam_overly_permissive", "_check_iam_overly_permissive", "IAM_Hygiene",
                     ["CIS 1.16", "FSBP IAM.1"], 8, False),
    CheckDefinition("iam_weak_password_policy", "_check_iam_weak_password_policy", "IAM_Hygiene",
                     ["CIS 1.8", "CIS 1.9"], 5, False),
    # --- Logging & Monitoring (20-23) ---
    CheckDefinition("cloudtrail_disabled", "_check_cloudtrail_disabled", "Logging_Monitoring",
                     ["CIS 3.1", "FSBP CloudTrail.1"], 8, True),
    CheckDefinition("guardduty_findings", "_check_guardduty_findings", "Logging_Monitoring",
                     [], 7, True),
    CheckDefinition("guardduty_disabled", "_check_guardduty_disabled", "Logging_Monitoring",
                     ["FSBP GuardDuty.1"], 7, True),
    CheckDefinition("securityhub_findings", "_check_securityhub_findings", "Logging_Monitoring",
                     [], 6, True),
    # --- Container Security (25) ---
    CheckDefinition("ecr_image_vulns", "_check_ecr_image_vulns", "Container_Security",
                     ["FSBP ECR.1"], 7, True),
]


# ---------------------------------------------------------------------------
# CSPM Engine
# ---------------------------------------------------------------------------
class SecurityPostureSkill(BaseSkill):
    name = "security-posture"
    description = "CSPM engine — 25 checks: public exposure, encryption, IAM, logging, network, containers"
    version = "1.0.0"

    # ── Orchestrator ──────────────────────────────────────────────────────

    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        findings: list[Finding] = []
        errors: list[str] = []
        acct = account_id or get_account_id(profile)

        checks_filter = kwargs.get("checks")
        categories_filter = kwargs.get("categories")
        selected = self._select_checks(checks_filter, categories_filter)

        regional = [c for c in selected if c.is_regional]
        global_checks = [c for c in selected if not c.is_regional]

        # Pre-cache S3 bucket list so all S3 checks share one API call
        self._s3_bucket_cache = None
        s3_check_names = {"s3_public_acl", "s3_public_policy", "s3_no_encryption", "cross_account_s3_policy"}
        if any(c.name in s3_check_names for c in global_checks):
            try:
                s3 = get_client("s3", "us-east-1", profile)
                self._s3_bucket_cache = s3.list_buckets().get("Buckets", [])[:100]
            except Exception as e:
                errors.append(f"s3_list_buckets: {e}")
                self._s3_bucket_cache = []

        # Execute global checks in PARALLEL (ThreadPoolExecutor)
        def _run_global(cdef):
            fn = getattr(self, cdef.fn_name)
            return cdef, fn(profile=profile, account_id=acct)

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {pool.submit(_run_global, c): c for c in global_checks}
            for fut in as_completed(futures):
                cdef = futures[fut]
                try:
                    _, results = fut.result()
                    for f in results:
                        findings.append(self._enrich_finding(f, cdef))
                except Exception as e:
                    errors.append(f"{cdef.name}: {e}")

        # Execute ALL regional checks per region in a single parallel pass
        def _run_region(region):
            region_findings = []
            for cdef in regional:
                try:
                    fn = getattr(self, cdef.fn_name)
                    results = fn(region=region, profile=profile)
                    for f in results:
                        region_findings.append(self._enrich_finding(f, cdef))
                except Exception as e:
                    errors.append(f"{cdef.name}@{region}: {e}")
            return region_findings

        region_results = parallel_regions(_run_region, regions)
        findings.extend(region_results)

        # Clean up cache
        self._s3_bucket_cache = None

        for f in findings:
            f.account_id = acct

        duration = time.time() - start
        checks_run = [c.name for c in selected]
        summary = self._build_posture_summary(findings, checks_run, duration)

        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=duration,
            accounts_scanned=1, regions_scanned=len(regions), errors=errors,
            metadata={
                "posture_summary": summary,
                "posture_score": summary["posture_score"],
                "checks_run": checks_run,
            },
        )

    # ── Helpers ───────────────────────────────────────────────────────────

    def _select_checks(self, checks_filter=None, categories_filter=None):
        if checks_filter:
            return [c for c in CHECK_REGISTRY if c.name in checks_filter]
        if categories_filter:
            return [c for c in CHECK_REGISTRY if c.category in categories_filter]
        return list(CHECK_REGISTRY)

    def _enrich_finding(self, finding: Finding, cdef: CheckDefinition) -> Finding:
        finding.metadata["risk_score"] = self._compute_risk_score(finding, cdef)
        finding.metadata["compliance_tags"] = cdef.compliance_tags
        finding.metadata.setdefault("internet_exposed", False)
        finding.metadata["category"] = cdef.category
        finding.metadata["_check_name"] = cdef.name
        finding.skill = "security-posture"
        return finding

    def _compute_risk_score(self, finding: Finding, cdef: CheckDefinition) -> int:
        score = cdef.default_risk_score
        if finding.metadata.get("internet_exposed"):
            score = max(score, 7)
        if finding.metadata.get("has_data"):
            score = min(score + 1, 10)
        if finding.severity == Severity.CRITICAL:
            score = max(score, 8)
        elif finding.severity == Severity.HIGH:
            score = max(score, 6)
        return min(max(score, 1), 10)

    def _build_posture_summary(self, findings, checks_run, duration):
        sev_counts = Counter(f.severity.value for f in findings)
        cat_counts = Counter(f.metadata.get("category", "Unknown") for f in findings)
        total = len(checks_run)

        # Score = % of checks that produced zero findings
        checks_with_findings = set(f.metadata.get("_check_name", "") for f in findings) & set(checks_run)
        passed = total - len(checks_with_findings)
        score = round((passed / max(total, 1)) * 100, 1)

        top5 = sorted(findings, key=lambda f: f.metadata.get("risk_score", 0), reverse=True)[:5]
        return {
            "total_checks_run": total,
            "total_findings": len(findings),
            "by_severity": dict(sev_counts),
            "by_category": dict(cat_counts),
            "posture_score": score,
            "top_5_risks": [{"title": f.title, "risk_score": f.metadata.get("risk_score", 0),
                             "severity": f.severity.value, "resource_id": f.resource_id} for f in top5],
            "duration_seconds": round(duration, 2),
            "errors_count": 0,
        }

    # ══════════════════════════════════════════════════════════════════════
    # PUBLIC EXPOSURE CHECKS (1-10)
    # ══════════════════════════════════════════════════════════════════════

    def _get_s3_buckets(self, profile):
        """Return cached bucket list or fetch fresh."""
        if self._s3_bucket_cache is not None:
            return self._s3_bucket_cache
        try:
            s3 = get_client("s3", "us-east-1", profile)
            return s3.list_buckets().get("Buckets", [])[:100]
        except Exception:
            return []

    # 1. S3 Public ACL ─────────────────────────────────────────────────────
    def _check_s3_public_acl(self, profile=None, **kw):
        findings = []
        try:
            s3 = get_client("s3", "us-east-1", profile)
            buckets = self._get_s3_buckets(profile)
            for bucket in buckets:
                name = bucket["Name"]
                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    for grant in acl.get("Grants", []):
                        uri = grant.get("Grantee", {}).get("URI", "")
                        if uri.endswith("AllUsers") or uri.endswith("AuthenticatedUsers"):
                            has_data = self._s3_has_data(s3, name)
                            findings.append(Finding(
                                skill=self.name,
                                title=f"Public S3 bucket (ACL): {name}",
                                severity=Severity.CRITICAL,
                                resource_id=name,
                                description=f"Bucket has public ACL grant to {uri.split('/')[-1]}: {grant.get('Permission')}",
                                recommended_action="Remove public ACL grants and enable S3 Block Public Access",
                                metadata={"internet_exposed": True, "has_data": has_data},
                            ))
                            break
                except Exception as e:
                    logger.debug(f"S3 ACL check skipped for {name}: {e}")
        except Exception as e:
            logger.warning(f"S3 public ACL check failed: {e}")
        return findings

    # 2. S3 Public Policy ──────────────────────────────────────────────────
    def _check_s3_public_policy(self, profile=None, **kw):
        findings = []
        try:
            s3 = get_client("s3", "us-east-1", profile)
            buckets = self._get_s3_buckets(profile)
            for bucket in buckets:
                name = bucket["Name"]
                try:
                    policy_str = s3.get_bucket_policy(Bucket=name)["Policy"]
                    policy = json.loads(policy_str)
                    for stmt in policy.get("Statement", []):
                        if stmt.get("Effect") != "Allow":
                            continue
                        principal = stmt.get("Principal", {})
                        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                            has_data = self._s3_has_data(s3, name)
                            findings.append(Finding(
                                skill=self.name,
                                title=f"Public S3 bucket (policy): {name}",
                                severity=Severity.CRITICAL,
                                resource_id=name,
                                description="Bucket policy allows access from any principal (*)",
                                recommended_action="Restrict bucket policy Principal to specific accounts or remove public access",
                                metadata={"internet_exposed": True, "has_data": has_data},
                            ))
                            break
                except s3.exceptions.from_code("NoSuchBucketPolicy") if hasattr(s3, 'exceptions') else Exception:
                    pass
                except Exception as e:
                    if "NoSuchBucketPolicy" in str(e):
                        continue
                    logger.debug(f"S3 policy check skipped for {name}: {e}")
        except Exception as e:
            logger.warning(f"S3 public policy check failed: {e}")
        return findings

    def _s3_has_data(self, s3_client, bucket_name):
        """Check if bucket contains objects (for content risk scoring)."""
        try:
            resp = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
            return resp.get("KeyCount", 0) > 0
        except Exception:
            return False

    # 3. EC2 Public Instance ───────────────────────────────────────────────
    def _check_ec2_public_instance(self, region=None, profile=None, **kw):
        findings = []
        try:
            ec2 = get_client("ec2", region, profile)
            reservations = ec2.describe_instances(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
            ).get("Reservations", [])
            # Pre-fetch SGs with open ingress
            open_sgs = set()
            try:
                sgs = ec2.describe_security_groups().get("SecurityGroups", [])
                for sg in sgs:
                    for perm in sg.get("IpPermissions", []):
                        for ip_range in perm.get("IpRanges", []):
                            if ip_range.get("CidrIp") in ("0.0.0.0/0",):
                                open_sgs.add(sg["GroupId"])
                        for ip6 in perm.get("Ipv6Ranges", []):
                            if ip6.get("CidrIpv6") == "::/0":
                                open_sgs.add(sg["GroupId"])
            except Exception:
                pass
            for res in reservations:
                for inst in res.get("Instances", []):
                    pub_ip = inst.get("PublicIpAddress")
                    if not pub_ip:
                        continue
                    inst_sgs = {sg["GroupId"] for sg in inst.get("SecurityGroups", [])}
                    if inst_sgs & open_sgs:
                        name = ""
                        for tag in inst.get("Tags", []):
                            if tag["Key"] == "Name":
                                name = tag["Value"]
                        findings.append(Finding(
                            skill=self.name,
                            title=f"Public EC2 instance: {inst['InstanceId']}",
                            severity=Severity.HIGH, region=region,
                            resource_id=inst["InstanceId"],
                            description=f"Instance {name or inst['InstanceId']} has public IP {pub_ip} with open security group",
                            recommended_action="Remove public IP or restrict security group ingress rules",
                            metadata={"internet_exposed": True, "public_ip": pub_ip},
                        ))
        except Exception as e:
            logger.debug(f"EC2 public instance check failed in {region}: {e}")
        return findings

    # 4. RDS Public Access ─────────────────────────────────────────────────
    def _check_rds_public_access(self, region=None, profile=None, **kw):
        findings = []
        try:
            rds = get_client("rds", region, profile)
            instances = rds.describe_db_instances().get("DBInstances", [])
            for db in instances:
                if db.get("PubliclyAccessible"):
                    findings.append(Finding(
                        skill=self.name,
                        title=f"Public RDS instance: {db['DBInstanceIdentifier']}",
                        severity=Severity.CRITICAL, region=region,
                        resource_id=db["DBInstanceIdentifier"],
                        description=f"RDS instance {db['DBInstanceIdentifier']} ({db.get('Engine','')}) is publicly accessible",
                        recommended_action="Set PubliclyAccessible to false and use private subnets",
                        metadata={"internet_exposed": True, "engine": db.get("Engine", "")},
                    ))
        except Exception as e:
            logger.debug(f"RDS public check failed in {region}: {e}")
        return findings

    # 5. Redshift Public Access ────────────────────────────────────────────
    def _check_redshift_public_access(self, region=None, profile=None, **kw):
        findings = []
        try:
            rs = get_client("redshift", region, profile)
            clusters = rs.describe_clusters().get("Clusters", [])
            for cl in clusters:
                if cl.get("PubliclyAccessible"):
                    findings.append(Finding(
                        skill=self.name,
                        title=f"Public Redshift cluster: {cl['ClusterIdentifier']}",
                        severity=Severity.CRITICAL, region=region,
                        resource_id=cl["ClusterIdentifier"],
                        description=f"Redshift cluster {cl['ClusterIdentifier']} is publicly accessible",
                        recommended_action="Disable public accessibility and move to private subnets",
                        metadata={"internet_exposed": True},
                    ))
        except Exception as e:
            logger.debug(f"Redshift public check failed in {region}: {e}")
        return findings

    # 6. OpenSearch Public Endpoint ────────────────────────────────────────
    def _check_opensearch_public_endpoint(self, region=None, profile=None, **kw):
        findings = []
        try:
            os_client = get_client("opensearch", region, profile)
            domains = os_client.list_domain_names().get("DomainNames", [])
            if not domains:
                return findings
            names = [d["DomainName"] for d in domains]
            details = os_client.describe_domains(DomainNames=names).get("DomainStatusList", [])
            for dom in details:
                vpc = dom.get("VPCOptions", {})
                if not vpc.get("VPCId"):
                    findings.append(Finding(
                        skill=self.name,
                        title=f"Public OpenSearch domain: {dom['DomainName']}",
                        severity=Severity.HIGH, region=region,
                        resource_id=dom["DomainName"],
                        description=f"OpenSearch domain {dom['DomainName']} has a public endpoint (no VPC)",
                        recommended_action="Deploy OpenSearch domain within a VPC",
                        metadata={"internet_exposed": True},
                    ))
        except Exception as e:
            logger.debug(f"OpenSearch public check failed in {region}: {e}")
        return findings

    # 7. EC2 Public AMI ────────────────────────────────────────────────────
    def _check_ec2_public_ami(self, region=None, profile=None, **kw):
        findings = []
        try:
            ec2 = get_client("ec2", region, profile)
            images = ec2.describe_images(Owners=["self"]).get("Images", [])
            for img in images:
                if img.get("Public", False):
                    findings.append(Finding(
                        skill=self.name,
                        title=f"Public AMI: {img['ImageId']}",
                        severity=Severity.HIGH, region=region,
                        resource_id=img["ImageId"],
                        description=f"AMI {img.get('Name', img['ImageId'])} has public launch permissions",
                        recommended_action="Remove public launch permissions from the AMI",
                        metadata={"internet_exposed": False},
                    ))
        except Exception as e:
            logger.debug(f"EC2 public AMI check failed in {region}: {e}")
        return findings

    # 8. ELB No WAF ────────────────────────────────────────────────────────
    def _check_elb_no_waf(self, region=None, profile=None, **kw):
        findings = []
        try:
            elbv2 = get_client("elbv2", region, profile)
            lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
            for lb in lbs:
                if lb.get("Scheme") != "internet-facing":
                    continue
                arn = lb["LoadBalancerArn"]
                try:
                    waf = get_client("wafv2", region, profile)
                    waf.get_web_acl_for_resource(ResourceArn=arn)
                except Exception as e:
                    if "WAFNonexistentItemException" in str(e) or "not associated" in str(e).lower():
                        findings.append(Finding(
                            skill=self.name,
                            title=f"Internet-facing LB without WAF: {lb['LoadBalancerName']}",
                            severity=Severity.MEDIUM, region=region,
                            resource_id=lb["LoadBalancerName"],
                            description=f"Load balancer {lb['LoadBalancerName']} is internet-facing without WAF protection",
                            recommended_action="Associate an AWS WAF WebACL with this load balancer",
                            metadata={"internet_exposed": True, "lb_type": lb.get("Type", "")},
                        ))
        except Exception as e:
            logger.debug(f"ELB WAF check failed in {region}: {e}")
        return findings

    # 9. API Gateway No Auth ───────────────────────────────────────────────
    def _check_apigw_no_auth(self, region=None, profile=None, **kw):
        findings = []
        try:
            apigw = get_client("apigateway", region, profile)
            apis = apigw.get_rest_apis().get("items", [])
            for api in apis:
                api_id = api["id"]
                api_name = api.get("name", api_id)
                try:
                    resources = apigw.get_resources(restApiId=api_id).get("items", [])
                    for res in resources:
                        for method in res.get("resourceMethods", {}).keys():
                            try:
                                m = apigw.get_method(restApiId=api_id, resourceId=res["id"], httpMethod=method)
                                if m.get("authorizationType") == "NONE":
                                    findings.append(Finding(
                                        skill=self.name,
                                        title=f"Unauthenticated API method: {api_name} {method} {res.get('path','')}",
                                        severity=Severity.HIGH, region=region,
                                        resource_id=api_id,
                                        description=f"API Gateway {api_name} method {method} {res.get('path','')} has no authorization",
                                        recommended_action="Add IAM, Cognito, or Lambda authorizer to this API method",
                                        metadata={"internet_exposed": True, "api_name": api_name, "path": res.get("path", "")},
                                    ))
                            except Exception:
                                pass
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"API Gateway auth check failed in {region}: {e}")
        return findings

    # 10. Lambda Public URL ────────────────────────────────────────────────
    def _check_lambda_public_url(self, region=None, profile=None, **kw):
        findings = []
        try:
            lam = get_client("lambda", region, profile)
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []):
                    fn_name = fn["FunctionName"]
                    try:
                        urls = lam.list_function_url_configs(FunctionName=fn_name).get("FunctionUrlConfigs", [])
                        for url_cfg in urls:
                            if url_cfg.get("AuthType") == "NONE":
                                findings.append(Finding(
                                    skill=self.name,
                                    title=f"Public Lambda URL (no auth): {fn_name}",
                                    severity=Severity.HIGH, region=region,
                                    resource_id=fn_name,
                                    description=f"Lambda function {fn_name} has a public URL with AuthType NONE",
                                    recommended_action="Set AuthType to AWS_IAM or add a Lambda authorizer",
                                    metadata={"internet_exposed": True, "url": url_cfg.get("FunctionUrl", "")},
                                ))
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"Lambda public URL check failed in {region}: {e}")
        return findings

    # ══════════════════════════════════════════════════════════════════════
    # NETWORK CONFIGURATION CHECKS (11, 24)
    # ══════════════════════════════════════════════════════════════════════

    # 11. Security Groups Open Non-Web Ports ───────────────────────────────
    def _check_sg_open_non_web(self, region=None, profile=None, **kw):
        findings = []
        try:
            ec2 = get_client("ec2", region, profile)
            sgs = ec2.describe_security_groups().get("SecurityGroups", [])
            for sg in sgs:
                for perm in sg.get("IpPermissions", []):
                    is_open = False
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            is_open = True
                    for ip6 in perm.get("Ipv6Ranges", []):
                        if ip6.get("CidrIpv6") == "::/0":
                            is_open = True
                    if not is_open:
                        continue
                    from_port = perm.get("FromPort", 0)
                    to_port = perm.get("ToPort", 0)
                    protocol = perm.get("IpProtocol", "")
                    # Skip if rule is exclusively for web ports 80/443
                    if protocol == "-1":
                        # All traffic — flag it
                        pass
                    elif from_port == to_port and from_port in (80, 443):
                        continue
                    elif from_port == 80 and to_port == 443:
                        continue
                    else:
                        pass
                    port_desc = f"all traffic" if protocol == "-1" else f"port {from_port}-{to_port}"
                    findings.append(Finding(
                        skill=self.name,
                        title=f"Open SG {port_desc}: {sg['GroupId']}",
                        severity=Severity.HIGH, region=region,
                        resource_id=sg["GroupId"],
                        description=f"Security group '{sg.get('GroupName','')}' allows 0.0.0.0/0 on {port_desc}",
                        recommended_action="Restrict inbound rules to specific IP ranges",
                        metadata={"internet_exposed": False, "from_port": from_port, "to_port": to_port},
                    ))
        except Exception as e:
            logger.debug(f"SG open ports check failed in {region}: {e}")
        return findings

    # 24. Default VPC In Use ───────────────────────────────────────────────
    def _check_default_vpc_in_use(self, region=None, profile=None, **kw):
        findings = []
        try:
            ec2 = get_client("ec2", region, profile)
            vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}]).get("Vpcs", [])
            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                # Check for active resources in default VPC
                instances = ec2.describe_instances(
                    Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "instance-state-name", "Values": ["running"]}]
                ).get("Reservations", [])
                has_resources = any(r.get("Instances") for r in instances)
                if not has_resources:
                    try:
                        rds = get_client("rds", region, profile)
                        dbs = rds.describe_db_instances().get("DBInstances", [])
                        has_resources = any(db.get("DBSubnetGroup", {}).get("VpcId") == vpc_id for db in dbs)
                    except Exception:
                        pass
                if has_resources:
                    findings.append(Finding(
                        skill=self.name,
                        title=f"Default VPC in use: {vpc_id}",
                        severity=Severity.MEDIUM, region=region,
                        resource_id=vpc_id,
                        description=f"Default VPC {vpc_id} in {region} has active resources — use custom VPCs for better isolation",
                        recommended_action="Migrate resources to a custom VPC with proper network segmentation",
                        metadata={"internet_exposed": False},
                    ))
        except Exception as e:
            logger.debug(f"Default VPC check failed in {region}: {e}")
        return findings

    # ══════════════════════════════════════════════════════════════════════
    # ENCRYPTION CHECKS (12-14)
    # ══════════════════════════════════════════════════════════════════════

    # 12. EBS Unencrypted ──────────────────────────────────────────────────
    def _check_ebs_unencrypted(self, region=None, profile=None, **kw):
        findings = []
        try:
            ec2 = get_client("ec2", region, profile)
            volumes = ec2.describe_volumes(
                Filters=[{"Name": "encrypted", "Values": ["false"]}]
            ).get("Volumes", [])
            for vol in volumes:
                findings.append(Finding(
                    skill=self.name,
                    title=f"Unencrypted EBS volume: {vol['VolumeId']}",
                    severity=Severity.MEDIUM, region=region,
                    resource_id=vol["VolumeId"],
                    description=f"EBS volume {vol['VolumeId']} ({vol.get('Size',0)} GB, {vol.get('State','')}) is not encrypted",
                    recommended_action="Create an encrypted copy of this volume and replace the original",
                    metadata={"internet_exposed": False, "size_gb": vol.get("Size", 0)},
                ))
        except Exception as e:
            logger.debug(f"EBS encryption check failed in {region}: {e}")
        return findings

    # 13. S3 No Encryption ─────────────────────────────────────────────────
    def _check_s3_no_encryption(self, profile=None, **kw):
        findings = []
        try:
            s3 = get_client("s3", "us-east-1", profile)
            buckets = self._get_s3_buckets(profile)
            for bucket in buckets:
                name = bucket["Name"]
                try:
                    s3.get_bucket_encryption(Bucket=name)
                except Exception as e:
                    if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                        findings.append(Finding(
                            skill=self.name,
                            title=f"S3 bucket without encryption: {name}",
                            severity=Severity.MEDIUM,
                            resource_id=name,
                            description=f"S3 bucket {name} does not have default server-side encryption configured",
                            recommended_action="Enable default SSE-S3 or SSE-KMS encryption on this bucket",
                            metadata={"internet_exposed": False},
                        ))
                    else:
                        logger.debug(f"S3 encryption check skipped for {name}: {e}")
        except Exception as e:
            logger.warning(f"S3 encryption check failed: {e}")
        return findings

    # 14. RDS Unencrypted ──────────────────────────────────────────────────
    def _check_rds_unencrypted(self, region=None, profile=None, **kw):
        findings = []
        try:
            rds = get_client("rds", region, profile)
            instances = rds.describe_db_instances().get("DBInstances", [])
            for db in instances:
                if not db.get("StorageEncrypted", False):
                    findings.append(Finding(
                        skill=self.name,
                        title=f"Unencrypted RDS instance: {db['DBInstanceIdentifier']}",
                        severity=Severity.HIGH, region=region,
                        resource_id=db["DBInstanceIdentifier"],
                        description=f"RDS instance {db['DBInstanceIdentifier']} ({db.get('Engine','')}) storage is not encrypted",
                        recommended_action="Create an encrypted snapshot and restore to a new encrypted instance",
                        metadata={"internet_exposed": False, "engine": db.get("Engine", "")},
                    ))
        except Exception as e:
            logger.debug(f"RDS encryption check failed in {region}: {e}")
        return findings

    # ══════════════════════════════════════════════════════════════════════
    # IAM HYGIENE CHECKS (15-19)
    # ══════════════════════════════════════════════════════════════════════

    # 15. IAM User No MFA ──────────────────────────────────────────────────
    def _check_iam_user_no_mfa(self, profile=None, **kw):
        findings = []
        try:
            iam = get_client("iam", "us-east-1", profile)
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]
                    # Check if user has console access
                    try:
                        iam.get_login_profile(UserName=username)
                    except Exception as e:
                        if "NoSuchEntity" in str(e):
                            continue  # No console access — skip
                        continue
                    # Check MFA devices
                    mfa = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                    if not mfa:
                        findings.append(Finding(
                            skill=self.name,
                            title=f"IAM user without MFA: {username}",
                            severity=Severity.HIGH,
                            resource_id=username,
                            description=f"IAM user {username} has console access but no MFA device enabled",
                            recommended_action="Enable MFA for this IAM user immediately",
                            metadata={"internet_exposed": False},
                        ))
        except Exception as e:
            logger.warning(f"IAM user MFA check failed: {e}")
        return findings

    # 16. IAM Root No MFA ──────────────────────────────────────────────────
    def _check_iam_root_no_mfa(self, profile=None, **kw):
        findings = []
        try:
            iam = get_client("iam", "us-east-1", profile)
            summary = iam.get_account_summary().get("SummaryMap", {})
            if summary.get("AccountMFAEnabled", 0) == 0:
                findings.append(Finding(
                    skill=self.name,
                    title="Root account MFA not enabled",
                    severity=Severity.CRITICAL,
                    resource_id="root",
                    description="The AWS root account does not have MFA enabled — this is the highest-risk IAM finding",
                    recommended_action="Enable MFA on the root account using a hardware security key or virtual MFA device",
                    metadata={"internet_exposed": False},
                ))
        except Exception as e:
            logger.warning(f"Root MFA check failed: {e}")
        return findings

    # 17. IAM Old Access Keys ──────────────────────────────────────────────
    def _check_iam_old_access_keys(self, profile=None, max_age_days=90, **kw):
        findings = []
        try:
            iam = get_client("iam", "us-east-1", profile)
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    keys = iam.list_access_keys(UserName=user["UserName"]).get("AccessKeyMetadata", [])
                    for key in keys:
                        if key["Status"] != "Active":
                            continue
                        age = (datetime.now(timezone.utc) - key["CreateDate"]).days
                        if age > max_age_days:
                            findings.append(Finding(
                                skill=self.name,
                                title=f"Old access key: {user['UserName']} ({age} days)",
                                severity=Severity.MEDIUM,
                                resource_id=key["AccessKeyId"],
                                description=f"Access key for {user['UserName']} is {age} days old (threshold: {max_age_days})",
                                recommended_action="Rotate or deactivate this access key",
                                metadata={"internet_exposed": False, "user": user["UserName"], "age_days": age},
                            ))
        except Exception as e:
            logger.warning(f"IAM old access keys check failed: {e}")
        return findings

    # 18. IAM Overly Permissive Policies ───────────────────────────────────
    def _check_iam_overly_permissive(self, profile=None, **kw):
        findings = []
        try:
            iam = get_client("iam", "us-east-1", profile)
            paginator = iam.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local", OnlyAttached=False):
                for policy in page["Policies"]:
                    try:
                        version_id = policy["DefaultVersionId"]
                        doc = iam.get_policy_version(
                            PolicyArn=policy["Arn"], VersionId=version_id
                        )["PolicyVersion"]["Document"]
                        if isinstance(doc, str):
                            doc = json.loads(doc)
                        statements = doc.get("Statement", [])
                        if isinstance(statements, dict):
                            statements = [statements]
                        for stmt in statements:
                            if stmt.get("Effect") != "Allow":
                                continue
                            actions = stmt.get("Action", [])
                            resources = stmt.get("Resource", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            if isinstance(resources, str):
                                resources = [resources]
                            if "*" in actions and "*" in resources:
                                findings.append(Finding(
                                    skill=self.name,
                                    title=f"Overly permissive policy: {policy['PolicyName']}",
                                    severity=Severity.CRITICAL,
                                    resource_id=policy["Arn"],
                                    description=f"Policy {policy['PolicyName']} grants Action:* on Resource:* — full admin access",
                                    recommended_action="Replace with least-privilege policy scoped to specific actions and resources",
                                    metadata={"internet_exposed": False, "policy_name": policy["PolicyName"]},
                                ))
                                break
                    except Exception:
                        pass
        except Exception as e:
            logger.warning(f"IAM overly permissive check failed: {e}")
        return findings

    # 19. IAM Weak Password Policy ─────────────────────────────────────────
    def _check_iam_weak_password_policy(self, profile=None, **kw):
        findings = []
        try:
            iam = get_client("iam", "us-east-1", profile)
            try:
                pp = iam.get_account_password_policy()["PasswordPolicy"]
            except Exception as e:
                if "NoSuchEntity" in str(e):
                    findings.append(Finding(
                        skill=self.name,
                        title="No password policy configured",
                        severity=Severity.MEDIUM,
                        resource_id="password-policy",
                        description="The account has no custom password policy — AWS defaults are weak",
                        recommended_action="Configure a strong password policy with min 14 chars, complexity, and 90-day rotation",
                        metadata={"internet_exposed": False},
                    ))
                    return findings
                raise
            weaknesses = []
            if pp.get("MinimumPasswordLength", 0) < 14:
                weaknesses.append(f"min length {pp.get('MinimumPasswordLength', 0)} < 14")
            if not pp.get("RequireUppercaseCharacters", False):
                weaknesses.append("no uppercase requirement")
            if not pp.get("RequireLowercaseCharacters", False):
                weaknesses.append("no lowercase requirement")
            if not pp.get("RequireSymbols", False):
                weaknesses.append("no symbol requirement")
            if not pp.get("RequireNumbers", False):
                weaknesses.append("no number requirement")
            max_age = pp.get("MaxPasswordAge", 0)
            if max_age > 90 or max_age == 0:
                weaknesses.append(f"max age {max_age} days (should be ≤90)")
            if weaknesses:
                findings.append(Finding(
                    skill=self.name,
                    title="Weak password policy",
                    severity=Severity.MEDIUM,
                    resource_id="password-policy",
                    description=f"Password policy weaknesses: {'; '.join(weaknesses)}",
                    recommended_action="Strengthen password policy: min 14 chars, require upper/lower/symbol/number, max 90-day age",
                    metadata={"internet_exposed": False, "weaknesses": weaknesses},
                ))
        except Exception as e:
            logger.warning(f"Password policy check failed: {e}")
        return findings

    # ══════════════════════════════════════════════════════════════════════
    # LOGGING & MONITORING CHECKS (20-23)
    # ══════════════════════════════════════════════════════════════════════

    # 20. CloudTrail Disabled ──────────────────────────────────────────────
    def _check_cloudtrail_disabled(self, region=None, profile=None, **kw):
        findings = []
        try:
            ct = get_client("cloudtrail", region, profile)
            trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
            has_multiregion = False
            for trail in trails:
                if trail.get("IsMultiRegionTrail"):
                    try:
                        status = ct.get_trail_status(Name=trail["TrailARN"])
                        if status.get("IsLogging"):
                            has_multiregion = True
                            break
                    except Exception:
                        pass
            if not has_multiregion:
                findings.append(Finding(
                    skill=self.name,
                    title=f"No active multi-region CloudTrail in {region}",
                    severity=Severity.CRITICAL, region=region,
                    resource_id="cloudtrail",
                    description=f"No multi-region CloudTrail trail is enabled and logging in {region}",
                    recommended_action="Create a multi-region CloudTrail trail with logging enabled",
                    metadata={"internet_exposed": False},
                ))
        except Exception as e:
            logger.debug(f"CloudTrail check failed in {region}: {e}")
        return findings

    # 21. GuardDuty Findings ───────────────────────────────────────────────
    def _check_guardduty_findings(self, region=None, profile=None, **kw):
        findings = []
        try:
            gd = get_client("guardduty", region, profile)
            detectors = gd.list_detectors().get("DetectorIds", [])
            if not detectors:
                return findings
            detector_id = detectors[0]
            criteria = {"Criterion": {"severity": {"Gte": 4}, "service.archived": {"Eq": ["false"]}}}
            finding_ids = gd.list_findings(
                DetectorId=detector_id, FindingCriteria=criteria, MaxResults=20
            ).get("FindingIds", [])
            if not finding_ids:
                return findings
            details = gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids).get("Findings", [])
            for d in details:
                score = d["Severity"]
                if score >= 8:
                    sev = Severity.CRITICAL
                elif score >= 5:
                    sev = Severity.HIGH
                else:
                    sev = Severity.MEDIUM
                findings.append(Finding(
                    skill=self.name,
                    title=d.get("Title", "GuardDuty Finding"),
                    severity=sev, region=region,
                    description=d.get("Description", "")[:200],
                    resource_id=d.get("Resource", {}).get("ResourceType", ""),
                    recommended_action="Investigate and remediate per GuardDuty recommendation",
                    metadata={"internet_exposed": False, "type": d.get("Type"), "severity_score": score},
                ))
        except Exception as e:
            logger.debug(f"GuardDuty findings check failed in {region}: {e}")
        return findings

    # 22. GuardDuty Disabled ───────────────────────────────────────────────
    def _check_guardduty_disabled(self, region=None, profile=None, **kw):
        findings = []
        try:
            gd = get_client("guardduty", region, profile)
            detectors = gd.list_detectors().get("DetectorIds", [])
            if not detectors:
                findings.append(Finding(
                    skill=self.name,
                    title=f"GuardDuty not enabled in {region}",
                    severity=Severity.HIGH, region=region,
                    resource_id="guardduty",
                    description=f"GuardDuty is not enabled in {region} — no threat detection active",
                    recommended_action="Enable GuardDuty in this region for threat detection",
                    metadata={"internet_exposed": False},
                ))
        except Exception as e:
            logger.debug(f"GuardDuty disabled check failed in {region}: {e}")
        return findings

    # 23. Security Hub Findings ────────────────────────────────────────────
    def _check_securityhub_findings(self, region=None, profile=None, **kw):
        findings = []
        try:
            sh = get_client("securityhub", region, profile)
            resp = sh.get_findings(
                Filters={
                    "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}, {"Value": "NOTIFIED", "Comparison": "EQUALS"}],
                    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                    "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
                },
                MaxResults=100,
                SortCriteria=[{"Field": "SeverityLabel", "SortOrder": "desc"}],
            )
            controls_seen = {}
            for f in resp.get("Findings", []):
                control_id = f.get("Compliance", {}).get("SecurityControlId", "") or f.get("GeneratorId", "").split("/")[-1]
                sev_label = f.get("Severity", {}).get("Label", "INFORMATIONAL")
                title = f.get("Title", "")
                resource_id = ""
                resources = f.get("Resources", [])
                if resources:
                    resource_id = resources[0].get("Id", "").split("/")[-1]
                if control_id not in controls_seen:
                    controls_seen[control_id] = {"title": title, "severity": sev_label, "resources": [], "count": 0}
                controls_seen[control_id]["count"] += 1
                if len(controls_seen[control_id]["resources"]) < 5:
                    controls_seen[control_id]["resources"].append(resource_id)

            for control_id, info in controls_seen.items():
                sev = SEVERITY_MAP.get(info["severity"], Severity.INFO)
                remediation = CONTROL_REMEDIATION.get(control_id, "Review in Security Hub console")
                resource_list = ", ".join(info["resources"][:3])
                if info["count"] > 3:
                    resource_list += f" (+{info['count']-3} more)"
                findings.append(Finding(
                    skill=self.name,
                    title=f"SecHub {control_id}: {info['title'][:55]}",
                    severity=sev, region=region,
                    resource_id=resource_list,
                    description=f"{info['count']} resource(s) failing this control",
                    recommended_action=remediation,
                    metadata={"internet_exposed": False, "control_id": control_id,
                              "failing_count": info["count"], "resources": info["resources"]},
                ))
        except Exception as e:
            logger.debug(f"Security Hub check failed in {region}: {e}")
        return findings

    # ══════════════════════════════════════════════════════════════════════
    # CONTAINER SECURITY CHECK (25)
    # ══════════════════════════════════════════════════════════════════════

    # 25. ECR Image Vulnerabilities ────────────────────────────────────────
    def _check_ecr_image_vulns(self, region=None, profile=None, **kw):
        findings = []
        try:
            ecr = get_client("ecr", region, profile)
            repos = ecr.describe_repositories().get("repositories", [])
            for repo in repos:
                repo_name = repo["repositoryName"]
                scan_on_push = repo.get("imageScanningConfiguration", {}).get("scanOnPush", False)
                if not scan_on_push:
                    findings.append(Finding(
                        skill=self.name,
                        title=f"ECR scan-on-push disabled: {repo_name}",
                        severity=Severity.MEDIUM, region=region,
                        resource_id=repo_name,
                        description=f"ECR repository {repo_name} does not have scan-on-push enabled",
                        recommended_action="Enable image scanning on push for this ECR repository",
                        metadata={"internet_exposed": False},
                    ))
                # Check most recent image for vulns
                try:
                    images = ecr.describe_images(
                        repositoryName=repo_name,
                        filter={"tagStatus": "TAGGED"},
                        maxResults=1,
                    ).get("imageDetails", [])
                    if not images:
                        continue
                    img = images[0]
                    digest = img["imageDigest"]
                    try:
                        scan = ecr.describe_image_scan_findings(
                            repositoryName=repo_name,
                            imageId={"imageDigest": digest},
                            maxResults=10,
                        )
                        counts = scan.get("imageScanFindings", {}).get("findingSeverityCounts", {})
                        crit = counts.get("CRITICAL", 0)
                        high = counts.get("HIGH", 0)
                        if crit > 0 or high > 0:
                            findings.append(Finding(
                                skill=self.name,
                                title=f"ECR image vulns: {repo_name} ({crit}C/{high}H)",
                                severity=Severity.CRITICAL if crit > 0 else Severity.HIGH,
                                region=region,
                                resource_id=repo_name,
                                description=f"Latest image in {repo_name} has {crit} critical and {high} high vulnerabilities",
                                recommended_action="Update base image and dependencies to patch known vulnerabilities",
                                metadata={"internet_exposed": False, "critical_count": crit, "high_count": high},
                            ))
                    except Exception as e:
                        if "ScanNotFoundException" in str(e):
                            logger.debug(f"No scan results for {repo_name}: {e}")
                        else:
                            raise
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"ECR image vulns check failed in {region}: {e}")
        return findings

    # ══════════════════════════════════════════════════════════════════════
    # TRUST BOUNDARIES CHECKS (cross-account)
    # ══════════════════════════════════════════════════════════════════════

    def _check_cross_account_iam_trust(self, profile=None, account_id=None, **kw):
        """Detect IAM roles with trust policies allowing external accounts."""
        findings = []
        acct = account_id or get_account_id(profile)
        try:
            iam = get_client("iam", "us-east-1", profile)
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page["Roles"]:
                    trust = role.get("AssumeRolePolicyDocument", {})
                    if isinstance(trust, str):
                        trust = json.loads(trust)
                    external_accounts = []
                    has_external_id = False
                    for stmt in trust.get("Statement", []):
                        if stmt.get("Effect") != "Allow":
                            continue
                        principals = stmt.get("Principal", {})
                        aws_principals = principals.get("AWS", []) if isinstance(principals, dict) else []
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]
                        for p in aws_principals:
                            # Extract account ID from ARN or raw account ID
                            parts = p.split(":")
                            p_acct = parts[4] if len(parts) > 4 else p
                            if p_acct and p_acct != acct and p_acct != "*":
                                external_accounts.append(p_acct)
                        # Check for ExternalId condition
                        conditions = stmt.get("Condition", {})
                        for cond_op in conditions.values():
                            if "sts:ExternalId" in cond_op:
                                has_external_id = True
                    if external_accounts:
                        findings.append(Finding(
                            skill=self.name,
                            title=f"Cross-account trust: {role['RoleName']}",
                            severity=Severity.HIGH,
                            resource_id=role["RoleName"],
                            description=f"Role {role['RoleName']} trusts external accounts: {', '.join(set(external_accounts))}",
                            recommended_action="Verify cross-account trust is intentional and add ExternalId condition if missing",
                            metadata={
                                "internet_exposed": False,
                                "role_name": role["RoleName"],
                                "external_accounts": list(set(external_accounts)),
                                "has_external_id": has_external_id,
                            },
                        ))
        except Exception as e:
            logger.warning(f"Cross-account IAM trust check failed: {e}")
        return findings

    def _check_cross_account_s3_policy(self, profile=None, account_id=None, **kw):
        """Detect S3 bucket policies granting access to external accounts."""
        findings = []
        acct = account_id or get_account_id(profile)
        try:
            s3 = get_client("s3", "us-east-1", profile)
            buckets = s3.list_buckets().get("Buckets", [])
            for bucket in buckets[:100]:
                name = bucket["Name"]
                try:
                    policy_str = s3.get_bucket_policy(Bucket=name)["Policy"]
                    policy = json.loads(policy_str)
                    external_accounts = set()
                    for stmt in policy.get("Statement", []):
                        if stmt.get("Effect") != "Allow":
                            continue
                        principal = stmt.get("Principal", {})
                        aws_principals = []
                        if isinstance(principal, dict):
                            aws_principals = principal.get("AWS", [])
                            if isinstance(aws_principals, str):
                                aws_principals = [aws_principals]
                        for p in aws_principals:
                            parts = p.split(":")
                            p_acct = parts[4] if len(parts) > 4 else ""
                            if p_acct and p_acct != acct and p_acct != "*":
                                external_accounts.add(p_acct)
                    if external_accounts:
                        findings.append(Finding(
                            skill=self.name,
                            title=f"Cross-account S3 access: {name}",
                            severity=Severity.HIGH,
                            resource_id=name,
                            description=f"Bucket {name} policy grants access to external accounts: {', '.join(external_accounts)}",
                            recommended_action="Verify cross-account S3 access is intentional and restrict to specific principals",
                            metadata={"internet_exposed": False, "external_accounts": list(external_accounts)},
                        ))
                except Exception as e:
                    if "NoSuchBucketPolicy" in str(e):
                        continue
                    logger.debug(f"S3 cross-account check skipped for {name}: {e}")
        except Exception as e:
            logger.warning(f"Cross-account S3 policy check failed: {e}")
        return findings


# ---------------------------------------------------------------------------
# Register skill
# ---------------------------------------------------------------------------
SkillRegistry.register(SecurityPostureSkill())
