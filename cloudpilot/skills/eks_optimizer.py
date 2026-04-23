"""EKS & Container Optimization — cluster health, node group optimization,
ECR security, image sprawl, security config, cost allocation."""
import logging
import time
from collections import Counter

from cloudpilot.core import BaseSkill, Finding, Severity, SkillResult, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions

logger = logging.getLogger(__name__)

LATEST_EKS_VERSION = "1.31"
ALL_LOG_TYPES = {"api", "audit", "authenticator", "controllerManager", "scheduler"}
GRAVITON_MAP = {"m5": "m7g", "c5": "c7g", "r5": "r7g", "t3": "t4g", "m6i": "m7g", "c6i": "c7g", "r6i": "r7g"}
REQUIRED_COST_TAGS = ["Environment", "Team", "Owner"]
ECR_STORAGE_RATE_PER_GB = 0.10
OVER_PROVISION_THRESHOLD = 10
IMAGE_SPRAWL_THRESHOLD = 100


class EKSOptimizerSkill(BaseSkill):
    name = "eks-optimizer"
    description = "EKS cluster health, node group optimization, ECR security, container cost allocation"
    version = "0.1.0"

    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        acct = account_id or get_account_id(profile)
        region_results = parallel_regions(
            lambda r, p: self._collect_region_data(r, p), regions, profile=profile)
        data = self._merge_region_data(region_results)
        findings = self._run_checks(data)
        for f in findings:
            f.account_id = acct
        summary = self._build_summary(data, findings)
        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=time.time() - start,
            accounts_scanned=1, regions_scanned=len(regions),
            errors=data.get("errors", []), metadata=summary)

    # ── Data Collection ───────────────────────────────────────────────
    def _collect_region_data(self, region, profile=None):
        data = {"region": region, "clusters": [], "ecr_repos": [], "errors": []}
        self._collect_eks_clusters(data, region, profile)
        self._collect_ecr_repos(data, region, profile)
        return data

    def _collect_eks_clusters(self, data, region, profile):
        try:
            eks = get_client("eks", region, profile)
            names = eks.list_clusters().get("clusters", [])
            for name in names:
                try:
                    c = eks.describe_cluster(name=name).get("cluster", {})
                    # Extract logging
                    log_types = []
                    for lc in c.get("logging", {}).get("clusterLogging", []):
                        if lc.get("enabled"):
                            log_types.extend(lc.get("types", []))
                    # Extract endpoint
                    vpc_cfg = c.get("resourcesVpcConfig", {})
                    endpoint = {
                        "public": vpc_cfg.get("endpointPublicAccess", True),
                        "private": vpc_cfg.get("endpointPrivateAccess", False),
                        "public_cidrs": vpc_cfg.get("publicAccessCidrs", ["0.0.0.0/0"]),
                    }
                    # Extract encryption
                    enc_config = c.get("encryptionConfig", [])
                    # Extract OIDC
                    oidc_issuer = c.get("identity", {}).get("oidc", {}).get("issuer", "")
                    cluster = {
                        "name": name, "arn": c.get("arn", ""), "version": c.get("version", ""),
                        "region": region, "logging": {"types": log_types},
                        "encryption_config": enc_config, "endpoint": endpoint,
                        "identity": {"oidc": {"issuer": oidc_issuer}},
                        "platform_version": c.get("platformVersion", ""),
                        "tags": c.get("tags", {}),
                        "node_groups": [], "fargate_profiles": [],
                    }
                    # Node groups
                    try:
                        ng_names = eks.list_nodegroups(clusterName=name).get("nodegroups", [])
                        for ng_name in ng_names:
                            try:
                                ng = eks.describe_nodegroup(clusterName=name, nodegroupName=ng_name).get("nodegroup", {})
                                sc = ng.get("scalingConfig", {})
                                cluster["node_groups"].append({
                                    "name": ng_name,
                                    "instance_types": ng.get("instanceTypes", []),
                                    "scaling": {"min": sc.get("minSize", 0), "max": sc.get("maxSize", 0), "desired": sc.get("desiredSize", 0)},
                                    "ami_type": ng.get("amiType", ""),
                                    "release_version": ng.get("releaseVersion", ""),
                                })
                            except Exception as e:
                                data["errors"].append(f"describe_nodegroup {ng_name}: {e}")
                    except Exception as e:
                        data["errors"].append(f"list_nodegroups {name}: {e}")
                    # Fargate profiles
                    try:
                        fp_names = eks.list_fargate_profiles(clusterName=name).get("fargateProfileNames", [])
                        for fp_name in fp_names:
                            try:
                                fp = eks.describe_fargate_profile(clusterName=name, fargateProfileName=fp_name).get("fargateProfile", {})
                                cluster["fargate_profiles"].append({
                                    "name": fp_name,
                                    "selectors": fp.get("selectors", []),
                                    "status": fp.get("status", ""),
                                })
                            except Exception as e:
                                data["errors"].append(f"describe_fargate_profile {fp_name}: {e}")
                    except Exception as e:
                        data["errors"].append(f"list_fargate_profiles {name}: {e}")
                    data["clusters"].append(cluster)
                except Exception as e:
                    data["errors"].append(f"describe_cluster {name} in {region}: {e}")
        except Exception as e:
            logger.warning("EKS list_clusters in %s: %s", region, e)
            data["errors"].append(f"eks list_clusters in {region}: {e}")

    def _collect_ecr_repos(self, data, region, profile):
        try:
            ecr = get_client("ecr", region, profile)
            repos = ecr.describe_repositories().get("repositories", [])
            for repo in repos:
                rname = repo.get("repositoryName", "")
                scan_on_push = repo.get("imageScanningConfiguration", {}).get("scanOnPush", False)
                # Lifecycle policy
                has_lifecycle = False
                try:
                    ecr.get_lifecycle_policy(repositoryName=rname)
                    has_lifecycle = True
                except Exception:
                    pass
                # Image counts
                image_count, untagged_count, total_size = 0, 0, 0
                try:
                    imgs = ecr.list_images(repositoryName=rname).get("imageIds", [])
                    image_count = len(imgs)
                    untagged_count = sum(1 for i in imgs if not i.get("imageTag"))
                except Exception:
                    pass
                try:
                    details = ecr.describe_images(repositoryName=rname, maxResults=100).get("imageDetails", [])
                    total_size = sum(d.get("imageSizeInBytes", 0) for d in details)
                except Exception:
                    pass
                # Latest scan
                latest_scan = None
                if scan_on_push:
                    try:
                        scan_resp = ecr.describe_image_scan_findings(
                            repositoryName=rname, imageId={"imageTag": "latest"})
                        counts = scan_resp.get("imageScanFindings", {}).get("findingSeverityCounts", {})
                        latest_scan = {
                            "status": scan_resp.get("imageScanStatus", {}).get("status", ""),
                            "critical_count": counts.get("CRITICAL", 0),
                            "high_count": counts.get("HIGH", 0),
                            "image_tag": "latest",
                        }
                    except Exception:
                        latest_scan = None
                data["ecr_repos"].append({
                    "name": rname, "uri": repo.get("repositoryUri", ""), "region": region,
                    "scan_on_push": scan_on_push, "has_lifecycle_policy": has_lifecycle,
                    "image_count": image_count, "untagged_count": untagged_count,
                    "total_size_bytes": total_size, "latest_scan": latest_scan,
                })
        except Exception as e:
            logger.warning("ECR in %s: %s", region, e)
            data["errors"].append(f"ecr in {region}: {e}")

    def _merge_region_data(self, region_results):
        merged = {"clusters": [], "ecr_repos": [], "errors": []}
        for rd in (region_results if isinstance(region_results, list) else []):
            if not isinstance(rd, dict):
                continue
            for k in merged:
                merged[k].extend(rd.get(k, []))
        return merged

    def _run_checks(self, data):
        findings = []
        for cluster in data.get("clusters", []):
            for checker in [self._check_cluster_version, self._check_cluster_logging,
                            self._check_cluster_encryption_endpoint, self._check_node_groups,
                            self._check_eks_security_config, self._check_cost_allocation_tags]:
                try:
                    findings.extend(checker(cluster))
                except Exception as e:
                    logger.warning("Checker failed for cluster %s: %s", cluster.get("name"), e)
        for repo in data.get("ecr_repos", []):
            for checker in [self._check_ecr_security, self._check_ecr_sprawl]:
                try:
                    findings.extend(checker(repo))
                except Exception as e:
                    logger.warning("Checker failed for repo %s: %s", repo.get("name"), e)
        return findings

    def _build_summary(self, data, findings):
        clusters = data.get("clusters", [])
        ng_count = sum(len(c.get("node_groups", [])) for c in clusters)
        fp_count = sum(len(c.get("fargate_profiles", [])) for c in clusters)
        sev_counts = Counter(f.severity.value for f in findings)
        return {
            "total_clusters": len(clusters), "total_node_groups": ng_count,
            "total_fargate_profiles": fp_count, "total_ecr_repos": len(data.get("ecr_repos", [])),
            "findings_by_severity": dict(sev_counts),
        }

    # ── Checkers ──────────────────────────────────────────────────────
    def _check_cluster_version(self, cluster):
        findings = []
        gap = self._get_version_gap(cluster.get("version", ""))
        name, region = cluster["name"], cluster["region"]
        meta = {"cluster_name": name, "current_version": cluster.get("version", ""),
                "latest_version": LATEST_EKS_VERSION, "region": region}
        if gap >= 2:
            findings.append(Finding(skill=self.name, title=f"Outdated EKS version: {name}",
                severity=Severity.HIGH, resource_id=name, region=region,
                description=f"Cluster {name} runs K8s {cluster.get('version')} ({gap} versions behind {LATEST_EKS_VERSION})",
                recommended_action=f"Upgrade to EKS {LATEST_EKS_VERSION}", metadata=meta))
        elif gap == 1:
            findings.append(Finding(skill=self.name, title=f"EKS version one behind: {name}",
                severity=Severity.MEDIUM, resource_id=name, region=region,
                description=f"Cluster {name} runs K8s {cluster.get('version')} (1 version behind)",
                recommended_action=f"Plan upgrade to EKS {LATEST_EKS_VERSION}", metadata=meta))
        else:
            findings.append(Finding(skill=self.name, title=f"EKS version current: {name}",
                severity=Severity.INFO, resource_id=name, region=region,
                description=f"Cluster {name} runs latest K8s {cluster.get('version')}", metadata=meta))
        return findings

    def _check_cluster_logging(self, cluster):
        findings = []
        enabled = set(cluster.get("logging", {}).get("types", []))
        name, region = cluster["name"], cluster["region"]
        missing = ALL_LOG_TYPES - enabled
        if len(enabled) == 0:
            findings.append(Finding(skill=self.name, title=f"No EKS logging: {name}",
                severity=Severity.HIGH, resource_id=name, region=region,
                description=f"Cluster {name} has no control plane logging enabled",
                recommended_action="Enable all 5 EKS control plane log types",
                metadata={"cluster_name": name, "enabled_types": [], "missing_types": sorted(missing)}))
        elif missing:
            findings.append(Finding(skill=self.name, title=f"Partial EKS logging: {name}",
                severity=Severity.MEDIUM, resource_id=name, region=region,
                description=f"Cluster {name} missing log types: {', '.join(sorted(missing))}",
                recommended_action=f"Enable missing log types: {', '.join(sorted(missing))}",
                metadata={"cluster_name": name, "enabled_types": sorted(enabled), "missing_types": sorted(missing)}))
        else:
            findings.append(Finding(skill=self.name, title=f"Full EKS logging: {name}",
                severity=Severity.INFO, resource_id=name, region=region,
                description=f"Cluster {name} has all 5 log types enabled",
                metadata={"cluster_name": name, "enabled_types": sorted(enabled), "missing_types": []}))
        return findings

    def _check_cluster_encryption_endpoint(self, cluster):
        findings = []
        name, region = cluster["name"], cluster["region"]
        # Secrets encryption
        enc_configs = cluster.get("encryption_config", [])
        has_secrets_enc = any("secrets" in (ec.get("resources", []) if isinstance(ec.get("resources"), list) else []) for ec in enc_configs)
        if not has_secrets_enc:
            findings.append(Finding(skill=self.name, title=f"EKS secrets not encrypted: {name}",
                severity=Severity.HIGH, resource_id=name, region=region,
                description=f"Cluster {name} does not have Kubernetes secrets encryption enabled",
                recommended_action="Enable envelope encryption for secrets using a KMS key",
                metadata={"cluster_name": name, "secrets_encryption": False}))
        # Endpoint
        ep = cluster.get("endpoint", {})
        pub, priv = ep.get("public", True), ep.get("private", False)
        cidrs = ep.get("public_cidrs", ["0.0.0.0/0"])
        if pub and cidrs == ["0.0.0.0/0"]:
            findings.append(Finding(skill=self.name, title=f"EKS public API unrestricted: {name}",
                severity=Severity.CRITICAL, resource_id=name, region=region,
                description=f"Cluster {name} has public API endpoint open to 0.0.0.0/0",
                recommended_action="Restrict publicAccessCidrs or disable public endpoint",
                metadata={"cluster_name": name, "public": pub, "private": priv, "public_cidrs": cidrs}))
        elif pub and cidrs != ["0.0.0.0/0"]:
            findings.append(Finding(skill=self.name, title=f"EKS public API restricted: {name}",
                severity=Severity.LOW, resource_id=name, region=region,
                description=f"Cluster {name} has public endpoint with CIDR restrictions",
                metadata={"cluster_name": name, "public": pub, "private": priv, "public_cidrs": cidrs}))
        elif not pub and priv:
            findings.append(Finding(skill=self.name, title=f"EKS private-only API: {name}",
                severity=Severity.INFO, resource_id=name, region=region,
                description=f"Cluster {name} uses private-only API endpoint",
                metadata={"cluster_name": name, "public": pub, "private": priv}))
        return findings

    def _check_node_groups(self, cluster):
        findings = []
        name, region = cluster["name"], cluster["region"]
        for ng in cluster.get("node_groups", []):
            ng_name = ng.get("name", "")
            # Graviton eligibility
            for itype in ng.get("instance_types", []):
                grav = self._get_graviton_equivalent(itype)
                if grav:
                    findings.append(Finding(skill=self.name, title=f"Graviton eligible: {ng_name}",
                        severity=Severity.MEDIUM, resource_id=f"{name}/{ng_name}", region=region,
                        description=f"Node group {ng_name} uses {itype}, migrate to {grav} for ~20% savings",
                        recommended_action=f"Migrate to {grav} instance type",
                        metadata={"cluster": name, "node_group": ng_name, "current_type": itype,
                                  "graviton_type": grav, "estimated_savings_pct": 20}))
            # Over-provisioned
            if self._is_over_provisioned(ng):
                sc = ng.get("scaling", {})
                findings.append(Finding(skill=self.name, title=f"Over-provisioned node group: {ng_name}",
                    severity=Severity.MEDIUM, resource_id=f"{name}/{ng_name}", region=region,
                    description=f"Node group {ng_name} has {sc.get('desired')} nodes with min==max (no autoscaling)",
                    recommended_action="Enable autoscaling or reduce node count",
                    metadata={"cluster": name, "node_group": ng_name, **sc}))
        return findings

    def _check_ecr_security(self, repo):
        findings = []
        rname, region = repo["name"], repo["region"]
        if not repo.get("scan_on_push"):
            findings.append(Finding(skill=self.name, title=f"ECR scan disabled: {rname}",
                severity=Severity.HIGH, resource_id=rname, region=region,
                description=f"ECR repo {rname} does not have scan-on-push enabled",
                recommended_action="Enable image scanning on push",
                metadata={"repository": rname, "scan_on_push": False}))
        else:
            scan = repo.get("latest_scan")
            if scan is None:
                findings.append(Finding(skill=self.name, title=f"ECR no scan results: {rname}",
                    severity=Severity.MEDIUM, resource_id=rname, region=region,
                    description=f"ECR repo {rname} has scan-on-push but no scan results for latest image",
                    recommended_action="Push a new image to trigger a scan",
                    metadata={"repository": rname}))
            elif scan.get("critical_count", 0) > 0:
                findings.append(Finding(skill=self.name, title=f"ECR critical vulns: {rname}",
                    severity=Severity.CRITICAL, resource_id=rname, region=region,
                    description=f"ECR repo {rname} latest image has {scan['critical_count']} CRITICAL vulnerabilities",
                    recommended_action="Rebuild image with patched base and redeploy",
                    metadata={"repository": rname, "image_tag": scan.get("image_tag", "latest"),
                              "critical_count": scan["critical_count"], "high_count": scan.get("high_count", 0)}))
            elif scan.get("high_count", 0) > 0:
                findings.append(Finding(skill=self.name, title=f"ECR high vulns: {rname}",
                    severity=Severity.HIGH, resource_id=rname, region=region,
                    description=f"ECR repo {rname} latest image has {scan['high_count']} HIGH vulnerabilities",
                    recommended_action="Review and patch HIGH vulnerabilities",
                    metadata={"repository": rname, "image_tag": scan.get("image_tag", "latest"),
                              "critical_count": 0, "high_count": scan["high_count"]}))
        return findings

    def _check_ecr_sprawl(self, repo):
        findings = []
        rname, region = repo["name"], repo["region"]
        has_lp = repo.get("has_lifecycle_policy", False)
        img_count = repo.get("image_count", 0)
        cost = self._calculate_ecr_storage_cost(repo.get("total_size_bytes", 0))
        if not has_lp and img_count > IMAGE_SPRAWL_THRESHOLD:
            findings.append(Finding(skill=self.name, title=f"ECR image sprawl: {rname}",
                severity=Severity.HIGH, resource_id=rname, region=region,
                description=f"ECR repo {rname} has {img_count} images with no lifecycle policy",
                recommended_action="Add a lifecycle policy to automatically expire old images",
                metadata={"repository": rname, "image_count": img_count, "estimated_monthly_cost": cost}))
        elif not has_lp:
            findings.append(Finding(skill=self.name, title=f"ECR no lifecycle policy: {rname}",
                severity=Severity.MEDIUM, resource_id=rname, region=region,
                description=f"ECR repo {rname} has no lifecycle policy for automatic image cleanup",
                recommended_action="Add a lifecycle policy",
                metadata={"repository": rname, "image_count": img_count}))
        if repo.get("untagged_count", 0) > 0:
            findings.append(Finding(skill=self.name, title=f"ECR untagged images: {rname}",
                severity=Severity.LOW, resource_id=rname, region=region,
                description=f"ECR repo {rname} has {repo['untagged_count']} untagged images",
                recommended_action="Clean up untagged images or add lifecycle rules",
                metadata={"repository": rname, "untagged_count": repo["untagged_count"]}))
        return findings

    def _check_eks_security_config(self, cluster):
        findings = []
        name, region = cluster["name"], cluster["region"]
        ep = cluster.get("endpoint", {})
        # Public endpoint without private + unrestricted
        if ep.get("public") and not ep.get("private") and ep.get("public_cidrs") == ["0.0.0.0/0"]:
            findings.append(Finding(skill=self.name, title=f"EKS API exposed: {name}",
                severity=Severity.CRITICAL, resource_id=name, region=region,
                description=f"Cluster {name} API is public without CIDR restrictions and no private endpoint",
                recommended_action="Enable private endpoint and restrict public access CIDRs",
                metadata={"cluster_name": name}))
        # IRSA / OIDC
        oidc = cluster.get("identity", {}).get("oidc", {}).get("issuer", "")
        if not oidc:
            findings.append(Finding(skill=self.name, title=f"IRSA not configured: {name}",
                severity=Severity.HIGH, resource_id=name, region=region,
                description=f"Cluster {name} has no OIDC provider — pods use node instance role",
                recommended_action="Associate an OIDC provider to enable IAM Roles for Service Accounts",
                metadata={"cluster_name": name, "irsa_available": False}))
        else:
            findings.append(Finding(skill=self.name, title=f"IRSA available: {name}",
                severity=Severity.INFO, resource_id=name, region=region,
                description=f"Cluster {name} has OIDC provider for fine-grained IAM access",
                metadata={"cluster_name": name, "irsa_available": True, "oidc_issuer": oidc}))
        return findings

    def _check_cost_allocation_tags(self, cluster):
        findings = []
        name, region = cluster["name"], cluster["region"]
        tags = cluster.get("tags", {})
        missing = [t for t in REQUIRED_COST_TAGS if t not in tags]
        if len(missing) == len(REQUIRED_COST_TAGS):
            findings.append(Finding(skill=self.name, title=f"No cost tags: {name}",
                severity=Severity.HIGH, resource_id=name, region=region,
                description=f"Cluster {name} has no cost allocation tags",
                recommended_action=f"Add tags: {', '.join(REQUIRED_COST_TAGS)}",
                metadata={"cluster_name": name, "missing_tags": missing}))
        elif missing:
            for tag in missing:
                sev = Severity.LOW if tag == "Owner" else Severity.MEDIUM
                findings.append(Finding(skill=self.name, title=f"Missing {tag} tag: {name}",
                    severity=sev, resource_id=name, region=region,
                    description=f"Cluster {name} missing {tag} tag",
                    recommended_action=f"Add {tag} tag for cost allocation",
                    metadata={"cluster_name": name, "missing_tag": tag}))
        else:
            findings.append(Finding(skill=self.name, title=f"Cost tags complete: {name}",
                severity=Severity.INFO, resource_id=name, region=region,
                description=f"Cluster {name} has all required cost allocation tags",
                metadata={"cluster_name": name, "tags": tags}))
        return findings

    # ── Helpers ───────────────────────────────────────────────────────
    def _get_version_gap(self, cluster_version):
        try:
            latest_minor = int(LATEST_EKS_VERSION.split(".")[1])
            cluster_minor = int(cluster_version.split(".")[1])
            return max(latest_minor - cluster_minor, 0)
        except (ValueError, IndexError):
            return 0

    def _get_graviton_equivalent(self, instance_type):
        family = instance_type.split(".")[0] if "." in instance_type else ""
        grav_family = GRAVITON_MAP.get(family)
        if grav_family:
            size = instance_type.split(".")[1] if "." in instance_type else "xlarge"
            return f"{grav_family}.{size}"
        return None

    def _is_over_provisioned(self, node_group):
        sc = node_group.get("scaling", {})
        return sc.get("desired", 0) > OVER_PROVISION_THRESHOLD and sc.get("min", 0) == sc.get("max", 0)

    def _calculate_ecr_storage_cost(self, total_size_bytes):
        return round((total_size_bytes / 1_000_000_000) * ECR_STORAGE_RATE_PER_GB, 2)


SkillRegistry.register(EKSOptimizerSkill())
