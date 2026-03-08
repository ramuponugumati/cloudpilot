"""Architecture Mapper — discovers AWS resources and generates visual architecture diagrams.
Enhanced from aws-ops-agent arch-diagram with full resource inventory for IaC generation."""
import json
import logging
import time
from typing import Optional
from cloudpilot.core import (
    BaseSkill, SkillRegistry, SkillResult, Finding, Severity,
    AntiPattern, ServiceRecommendation, ResourceConnection,
)
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions

logger = logging.getLogger(__name__)

# Resource types to discover
RESOURCE_SCANNERS = {
    "ec2": "_discover_ec2",
    "rds": "_discover_rds",
    "lambda": "_discover_lambda",
    "s3": "_discover_s3",
    "ecs": "_discover_ecs",
    "vpc": "_discover_vpc",
    "dynamodb": "_discover_dynamodb",
    "sqs": "_discover_sqs",
    "sns": "_discover_sns",
    "apigateway": "_discover_apigw",
    "cloudfront": "_discover_cloudfront",
    "elb": "_discover_elb",
}


class ArchMapper(BaseSkill):
    name = "arch-diagram"
    description = "Discover AWS resources and generate architecture diagrams + resource inventory"
    version = "0.2.0"

    def scan(self, regions, profile=None, **kwargs) -> SkillResult:
        start = time.time()
        result = self.discover(regions, profile)
        resources = result.get("resources", [])
        findings = [Finding(
            skill=self.name, title=f"Architecture: {len(resources)} resources discovered",
            severity=Severity.INFO,
            description=f"Services: {', '.join(set(r['service'] for r in resources))}",
            recommended_action="Use generate_iac to create Infrastructure as Code",
            metadata={"resource_count": len(resources)},
        )]
        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=time.time() - start,
            regions_scanned=len(regions),
        )

    def discover(self, regions, profile=None) -> dict:
        """Full resource discovery with parallel scanning and smart region selection.
        If >5 regions, auto-narrows to top 5 by Cost Explorer spend."""
        import concurrent.futures

        resources = []
        errors = []
        acct = get_account_id(profile)

        # Smart region selection: narrow to top 5 by spend
        if len(regions) > 5:
            active = self._get_active_regions(profile, max_regions=5)
            if active:
                logger.info(f"Narrowed {len(regions)} regions to top {len(active)} by spend: {active}")
                regions = active

        # Global resources (S3, CloudFront) — parallel
        global_scanners = [("s3", self._discover_s3), ("cloudfront", self._discover_cloudfront)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = {pool.submit(fn, profile): name for name, fn in global_scanners}
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                try:
                    resources.extend(future.result())
                except Exception as e:
                    logger.warning(f"Discovery error for {name} (global): {e}")
                    errors.append(f"{name}/global: {e}")

        # Regional resources — all service×region combos in parallel
        regional_scanners = [
            ("ec2", self._discover_ec2), ("rds", self._discover_rds),
            ("lambda", self._discover_lambda), ("ecs", self._discover_ecs),
            ("vpc", self._discover_vpc), ("dynamodb", self._discover_dynamodb),
            ("sqs", self._discover_sqs), ("sns", self._discover_sns),
            ("apigateway", self._discover_apigw), ("elb", self._discover_elb),
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            futures = {}
            for svc_name, scanner in regional_scanners:
                for region in regions:
                    future = pool.submit(scanner, region, profile)
                    futures[future] = f"{svc_name}/{region}"
            for future in concurrent.futures.as_completed(futures):
                label = futures[future]
                try:
                    resources.extend(future.result())
                except Exception as e:
                    logger.warning(f"Discovery error for {label}: {e}")
                    errors.append(f"{label}: {e}")

        # Enrich resources
        for r in resources:
            r["account_id"] = acct
            r.setdefault("metadata", {})
            r.setdefault("tags", {})
            r["layer"] = self.classify_layer(r)

        # Analysis passes
        anti_patterns = self.detect_anti_patterns(resources)
        service_recommendations = self.detect_service_recommendations(resources)
        connections = self.map_connections(resources)
        conn_dicts = [c.to_dict() if hasattr(c, "to_dict") else c for c in connections]
        diagram = self._generate_mermaid(resources, conn_dicts)

        by_service: dict[str, int] = {}
        for r in resources:
            svc = r.get("service", "unknown")
            by_service[svc] = by_service.get(svc, 0) + 1

        return {
            "resources": resources,
            "anti_patterns": [ap.to_dict() if hasattr(ap, "to_dict") else ap for ap in anti_patterns],
            "service_recommendations": [sr.to_dict() if hasattr(sr, "to_dict") else sr for sr in service_recommendations],
            "connections": conn_dicts,
            "diagram": diagram,
            "errors": errors,
            "summary": {
                "total_resources": len(resources),
                "by_service": by_service,
                "regions_scanned": list(regions),
                "account_id": acct,
            },
        }

    def _get_active_regions(self, profile=None, max_regions=5) -> list[str]:
        """Query Cost Explorer for top regions by spend in the last 30 days."""
        try:
            from datetime import datetime, timedelta
            ce = get_client("ce", profile=profile, region="us-east-1")
            now = datetime.utcnow()
            resp = ce.get_cost_and_usage(
                TimePeriod={
                    "Start": (now - timedelta(days=30)).strftime("%Y-%m-%d"),
                    "End": now.strftime("%Y-%m-%d"),
                },
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
                GroupBy=[{"Type": "DIMENSION", "Key": "REGION"}],
            )
            region_costs: dict[str, float] = {}
            for period in resp.get("ResultsByTime", []):
                for group in period.get("Groups", []):
                    region = group["Keys"][0]
                    cost = float(group["Metrics"]["UnblendedCost"]["Amount"])
                    if region and cost > 0 and region != "global" and not region.startswith("No "):
                        region_costs[region] = region_costs.get(region, 0) + cost
            sorted_regions = sorted(region_costs.items(), key=lambda x: x[1], reverse=True)
            top = [r for r, _ in sorted_regions[:max_regions]]
            return top if top else []
        except Exception as e:
            logger.warning(f"Could not get active regions from Cost Explorer: {e}")
            return []

    def _discover_ec2(self, region, profile=None):
        resources = []
        ec2 = get_client("ec2", profile=profile, region=region)
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    if inst["State"]["Name"] == "terminated":
                        continue
                    name = ""
                    for tag in inst.get("Tags", []):
                        if tag["Key"] == "Name":
                            name = tag["Value"]
                    resources.append({
                        "service": "ec2", "type": "instance",
                        "id": inst["InstanceId"], "name": name,
                        "region": region, "state": inst["State"]["Name"],
                        "instance_type": inst["InstanceType"],
                        "vpc_id": inst.get("VpcId", ""),
                        "subnet_id": inst.get("SubnetId", ""),
                        "security_groups": [sg["GroupId"] for sg in inst.get("SecurityGroups", [])],
                        "tags": {t["Key"]: t["Value"] for t in inst.get("Tags", [])},
                    })
        return resources

    def _discover_rds(self, region, profile=None):
        resources = []
        rds = get_client("rds", profile=profile, region=region)
        for db in rds.describe_db_instances().get("DBInstances", []):
            resources.append({
                "service": "rds", "type": "db_instance",
                "id": db["DBInstanceIdentifier"], "name": db["DBInstanceIdentifier"],
                "region": region, "engine": db["Engine"],
                "engine_version": db.get("EngineVersion", ""),
                "instance_class": db["DBInstanceClass"],
                "multi_az": db.get("MultiAZ", False),
                "vpc_id": db.get("DBSubnetGroup", {}).get("VpcId", ""),
                "storage": db.get("AllocatedStorage", 0),
                "tags": {t["Key"]: t["Value"] for t in db.get("TagList", [])},
            })
        return resources

    def _discover_lambda(self, region, profile=None):
        resources = []
        lam = get_client("lambda", profile=profile, region=region)
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page["Functions"]:
                resources.append({
                    "service": "lambda", "type": "function",
                    "id": fn["FunctionName"], "name": fn["FunctionName"],
                    "region": region, "runtime": fn.get("Runtime", ""),
                    "memory": fn.get("MemorySize", 128),
                    "timeout": fn.get("Timeout", 3),
                    "handler": fn.get("Handler", ""),
                    "role": fn.get("Role", ""),
                    "vpc_config": fn.get("VpcConfig", {}),
                    "tags": fn.get("Tags", {}),
                })
        return resources

    def _discover_s3(self, profile=None):
        resources = []
        s3 = get_client("s3", profile=profile, region="us-east-1")
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket.get("BucketName") or bucket.get("Name", "")
            try:
                loc = s3.get_bucket_location(Bucket=name)
                region = loc.get("LocationConstraint") or "us-east-1"
            except Exception:
                region = "us-east-1"
            resources.append({
                "service": "s3", "type": "bucket",
                "id": name, "name": name, "region": region,
            })
        return resources

    def _discover_ecs(self, region, profile=None):
        resources = []
        ecs = get_client("ecs", profile=profile, region=region)
        clusters = ecs.list_clusters().get("clusterArns", [])
        if clusters:
            details = ecs.describe_clusters(clusters=clusters[:10]).get("clusters", [])
            for c in details:
                resources.append({
                    "service": "ecs", "type": "cluster",
                    "id": c["clusterName"], "name": c["clusterName"],
                    "region": region,
                    "running_tasks": c.get("runningTasksCount", 0),
                    "services_count": c.get("activeServicesCount", 0),
                })
        return resources

    def _discover_vpc(self, region, profile=None):
        resources = []
        ec2 = get_client("ec2", profile=profile, region=region)
        for vpc in ec2.describe_vpcs().get("Vpcs", []):
            name = ""
            for tag in vpc.get("Tags", []):
                if tag["Key"] == "Name":
                    name = tag["Value"]
            resources.append({
                "service": "vpc", "type": "vpc",
                "id": vpc["VpcId"], "name": name,
                "region": region, "cidr": vpc["CidrBlock"],
                "is_default": vpc.get("IsDefault", False),
            })
        # Subnets
        for sub in ec2.describe_subnets().get("Subnets", []):
            name = ""
            for tag in sub.get("Tags", []):
                if tag["Key"] == "Name":
                    name = tag["Value"]
            resources.append({
                "service": "vpc", "type": "subnet",
                "id": sub["SubnetId"], "name": name,
                "region": region, "vpc_id": sub["VpcId"],
                "cidr": sub["CidrBlock"], "az": sub["AvailabilityZone"],
                "public": sub.get("MapPublicIpOnLaunch", False),
            })
        return resources

    def _discover_dynamodb(self, region, profile=None):
        resources = []
        ddb = get_client("dynamodb", profile=profile, region=region)
        tables = ddb.list_tables().get("TableNames", [])
        for tname in tables[:20]:
            try:
                desc = ddb.describe_table(TableName=tname)["Table"]
                resources.append({
                    "service": "dynamodb", "type": "table",
                    "id": tname, "name": tname, "region": region,
                    "billing_mode": desc.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED"),
                    "key_schema": desc.get("KeySchema", []),
                })
            except Exception:
                pass
        return resources

    def _discover_sqs(self, region, profile=None):
        resources = []
        sqs = get_client("sqs", profile=profile, region=region)
        urls = sqs.list_queues().get("QueueUrls", [])
        for url in urls[:20]:
            name = url.split("/")[-1]
            resources.append({
                "service": "sqs", "type": "queue",
                "id": name, "name": name, "region": region, "url": url,
            })
        return resources

    def _discover_sns(self, region, profile=None):
        resources = []
        sns = get_client("sns", profile=profile, region=region)
        for topic in sns.list_topics().get("Topics", []):
            arn = topic["TopicArn"]
            name = arn.split(":")[-1]
            resources.append({
                "service": "sns", "type": "topic",
                "id": name, "name": name, "region": region, "arn": arn,
            })
        return resources

    def _discover_apigw(self, region, profile=None):
        resources = []
        apigw = get_client("apigateway", profile=profile, region=region)
        for api in apigw.get_rest_apis().get("items", []):
            resources.append({
                "service": "apigateway", "type": "rest_api",
                "id": api["id"], "name": api.get("name", ""),
                "region": region,
            })
        return resources

    def _discover_cloudfront(self, profile=None):
        resources = []
        cf = get_client("cloudfront", profile=profile, region="us-east-1")
        for dist in cf.list_distributions().get("DistributionList", {}).get("Items", []):
            resources.append({
                "service": "cloudfront", "type": "distribution",
                "id": dist["Id"], "name": dist.get("Comment", dist["Id"]),
                "region": "global", "domain": dist["DomainName"],
            })
        return resources

    def _discover_elb(self, region, profile=None):
        resources = []
        elbv2 = get_client("elbv2", profile=profile, region=region)
        for lb in elbv2.describe_load_balancers().get("LoadBalancers", []):
            resources.append({
                "service": "elb", "type": lb.get("Type", "application"),
                "id": lb["LoadBalancerName"], "name": lb["LoadBalancerName"],
                "region": region, "vpc_id": lb.get("VpcId", ""),
                "scheme": lb.get("Scheme", ""),
                "dns": lb.get("DNSName", ""),
            })
        return resources

    # ── Anti-pattern detection ──────────────────────────────────────────

    # Lambda runtimes that AWS has deprecated or is end-of-life
    DEPRECATED_RUNTIMES = {
        "python3.7", "python3.8", "nodejs14.x", "nodejs16.x",
        "dotnetcore3.1", "ruby2.7",
    }

    # Standard web ports that are acceptable for 0.0.0.0/0 ingress
    STANDARD_PUBLIC_PORTS = {80, 443}

    def detect_anti_patterns(self, resources: list[dict]) -> list[AntiPattern]:
        """Analyze resources for AWS Well-Architected anti-patterns.

        Detects: single-AZ RDS, missing backup retention, public subnet DBs,
        open security groups on non-standard ports, EC2 without IMDSv2,
        unencrypted S3, and deprecated Lambda runtimes.
        """
        patterns: list[AntiPattern] = []

        # Build a lookup of public subnets for the public-database check
        public_subnets: set[str] = set()
        for r in resources:
            if r.get("service") == "vpc" and r.get("type") == "subnet":
                if r.get("public") or r.get("metadata", {}).get("public"):
                    public_subnets.add(r.get("id", ""))

        for r in resources:
            svc = r.get("service", "")
            meta = r.get("metadata", {})
            rid = r.get("id", "")
            region = r.get("region", "")

            # ── RDS checks ───────────────────────────────────────────
            if svc == "rds":
                multi_az = r.get("multi_az", meta.get("multi_az"))
                if multi_az is False:
                    patterns.append(AntiPattern(
                        pattern_type="single-az-rds",
                        severity=Severity.HIGH,
                        resource_id=rid,
                        region=region,
                        description=f"RDS instance '{rid}' is deployed in a single AZ — no automatic failover.",
                        recommendation="Enable Multi-AZ for automatic failover and improved availability.",
                        well_architected_pillar="reliability",
                    ))

                backup_ret = r.get("backup_retention", meta.get("backup_retention"))
                if backup_ret is not None and int(backup_ret) == 0:
                    patterns.append(AntiPattern(
                        pattern_type="missing-backup",
                        severity=Severity.HIGH,
                        resource_id=rid,
                        region=region,
                        description=f"RDS instance '{rid}' has backup retention set to 0 — no automated backups.",
                        recommendation="Set backup retention to at least 7 days.",
                        well_architected_pillar="reliability",
                    ))

                # Public subnet containing a database
                subnet_id = r.get("subnet_id", meta.get("subnet_id", ""))
                vpc_id = r.get("vpc_id", meta.get("vpc_id", ""))
                publicly_accessible = r.get("publicly_accessible", meta.get("publicly_accessible"))
                if publicly_accessible or (subnet_id and subnet_id in public_subnets):
                    patterns.append(AntiPattern(
                        pattern_type="public-database",
                        severity=Severity.CRITICAL,
                        resource_id=rid,
                        region=region,
                        description=f"RDS instance '{rid}' is in a public subnet or publicly accessible.",
                        recommendation="Move the database to a private subnet and disable public accessibility.",
                        well_architected_pillar="security",
                    ))

            # ── Security group checks ────────────────────────────────
            if svc == "vpc" and r.get("type") == "security_group":
                ingress_rules = r.get("ingress", meta.get("ingress", []))
                for rule in ingress_rules:
                    cidr = rule.get("cidr", "")
                    from_port = rule.get("from_port", 0)
                    to_port = rule.get("to_port", 0)
                    if cidr == "0.0.0.0/0":
                        # Flag if any port in the range is non-standard
                        ports_in_range = set(range(int(from_port), int(to_port) + 1)) if from_port and to_port else set()
                        if not ports_in_range or not ports_in_range.issubset(self.STANDARD_PUBLIC_PORTS):
                            patterns.append(AntiPattern(
                                pattern_type="open-security-group",
                                severity=Severity.HIGH,
                                resource_id=rid,
                                region=region,
                                description=(
                                    f"Security group '{rid}' allows 0.0.0.0/0 ingress "
                                    f"on port(s) {from_port}-{to_port}."
                                ),
                                recommendation="Restrict ingress to specific CIDR ranges or security groups.",
                                well_architected_pillar="security",
                            ))

            # ── EC2 IMDSv2 check ─────────────────────────────────────
            if svc == "ec2":
                imdsv2 = r.get("imdsv2", meta.get("imdsv2"))
                http_tokens = r.get("http_tokens", meta.get("http_tokens", ""))
                if imdsv2 is False or http_tokens == "optional":
                    patterns.append(AntiPattern(
                        pattern_type="no-imdsv2",
                        severity=Severity.MEDIUM,
                        resource_id=rid,
                        region=region,
                        description=f"EC2 instance '{rid}' does not enforce IMDSv2.",
                        recommendation="Enforce IMDSv2 by setting HttpTokens to 'required'.",
                        well_architected_pillar="security",
                    ))

            # ── S3 encryption check ──────────────────────────────────
            if svc == "s3":
                encryption = r.get("encryption", meta.get("encryption"))
                if encryption is False or encryption == "none" or encryption is None:
                    patterns.append(AntiPattern(
                        pattern_type="unencrypted-s3",
                        severity=Severity.MEDIUM,
                        resource_id=rid,
                        region=region,
                        description=f"S3 bucket '{rid}' does not have server-side encryption enabled.",
                        recommendation="Enable default SSE-S3 or SSE-KMS encryption on the bucket.",
                        well_architected_pillar="security",
                    ))

            # ── Lambda deprecated runtime check ──────────────────────
            if svc == "lambda":
                runtime = r.get("runtime", meta.get("runtime", ""))
                if runtime in self.DEPRECATED_RUNTIMES:
                    patterns.append(AntiPattern(
                        pattern_type="deprecated-runtime",
                        severity=Severity.MEDIUM,
                        resource_id=rid,
                        region=region,
                        description=f"Lambda function '{rid}' uses deprecated runtime '{runtime}'.",
                        recommendation=f"Upgrade from '{runtime}' to a supported runtime version.",
                        well_architected_pillar="operational",
                    ))

        return patterns

    # ── Service recommendation detection ─────────────────────────────

    # Mapping of workload keywords → (display name, recommended AWS service, rationale)
    SERVICE_MAPPINGS: dict[str, tuple[str, str, str]] = {
        "redis": (
            "Redis",
            "Amazon ElastiCache",
            "ElastiCache provides managed Redis with automatic failover, patching, and backups.",
        ),
        "postgres": (
            "PostgreSQL",
            "Amazon RDS for PostgreSQL",
            "RDS handles backups, patching, Multi-AZ failover, and read replicas.",
        ),
        "postgresql": (
            "PostgreSQL",
            "Amazon RDS for PostgreSQL",
            "RDS handles backups, patching, Multi-AZ failover, and read replicas.",
        ),
        "mysql": (
            "MySQL",
            "Amazon RDS for MySQL",
            "RDS handles backups, patching, Multi-AZ failover, and read replicas.",
        ),
        "rabbitmq": (
            "RabbitMQ",
            "Amazon MQ",
            "Amazon MQ provides managed RabbitMQ with automatic broker maintenance.",
        ),
        "mongodb": (
            "MongoDB",
            "Amazon DocumentDB",
            "DocumentDB is MongoDB-compatible with managed scaling and backups.",
        ),
        "kafka": (
            "Kafka",
            "Amazon MSK",
            "MSK provides managed Apache Kafka with automatic broker provisioning.",
        ),
        "elasticsearch": (
            "Elasticsearch",
            "Amazon OpenSearch Service",
            "OpenSearch Service provides managed Elasticsearch-compatible search and analytics.",
        ),
        "opensearch": (
            "OpenSearch",
            "Amazon OpenSearch Service",
            "OpenSearch Service provides managed search and analytics.",
        ),
        "cron": (
            "Cron Scheduler",
            "Amazon EventBridge Scheduler",
            "EventBridge Scheduler provides serverless cron with no infrastructure to manage.",
        ),
        "scheduler": (
            "Scheduler",
            "Amazon EventBridge Scheduler",
            "EventBridge Scheduler provides serverless scheduling with no infrastructure to manage.",
        ),
    }

    def detect_service_recommendations(self, resources: list[dict]) -> list[ServiceRecommendation]:
        """Identify self-managed services running on EC2 and recommend managed alternatives.

        Checks EC2 instance name tags and metadata for patterns matching
        known self-managed workloads (Redis, PostgreSQL, MySQL, RabbitMQ,
        MongoDB, Kafka, Elasticsearch, cron schedulers).
        """
        recommendations: list[ServiceRecommendation] = []

        for r in resources:
            if r.get("service") != "ec2":
                continue

            rid = r.get("id", "")
            name = r.get("name", "")
            region = r.get("region", "")
            meta = r.get("metadata", {})
            tags = r.get("tags", {})

            # Build a searchable text from name, tags, and metadata
            search_text = " ".join([
                name.lower(),
                " ".join(str(v).lower() for v in tags.values()),
                " ".join(str(v).lower() for v in meta.values() if isinstance(v, str)),
            ])

            for keyword, (workload_name, service, rationale) in self.SERVICE_MAPPINGS.items():
                if keyword in search_text:
                    recommendations.append(ServiceRecommendation(
                        ec2_instance_id=rid,
                        ec2_instance_name=name,
                        detected_workload=workload_name,
                        detection_method="name_tag",
                        recommended_service=service,
                        migration_rationale=rationale,
                        region=region,
                    ))
                    break  # One recommendation per instance

        return recommendations

    # ── Layer classification ─────────────────────────────────────────

    # Deterministic service → layer mapping
    LAYER_MAP: dict[str, str] = {
        "cloudfront": "Edge",
        "apigateway": "Edge",
        "elb": "Load_Balancing",
        "ec2": "Compute",
        "lambda": "Compute",
        "ecs": "Compute",
        "rds": "Data",
        "dynamodb": "Data",
        "elasticache": "Data",
        "s3": "Storage",
        "ebs": "Storage",
        "efs": "Storage",
        "vpc": "Networking",
        "subnet": "Networking",
        "nat_gateway": "Networking",
        "igw": "Networking",
        "security_group": "Security",
        "nacl": "Security",
        "iam": "Security",
        "sqs": "Messaging",
        "sns": "Messaging",
        "eventbridge": "Messaging",
    }

    def classify_layer(self, resource: dict) -> str:
        """Classify a resource into an architecture layer.

        Returns one of: Edge, Load_Balancing, Compute, Data, Storage,
        Networking, Security, Messaging.  Falls back to the service name
        if no mapping exists.
        """
        svc = resource.get("service", "")
        rtype = resource.get("type", "")

        # Check service first, then resource type for finer-grained matches
        # (e.g. vpc service with type=subnet → Networking, type=security_group → Security)
        layer = self.LAYER_MAP.get(rtype) or self.LAYER_MAP.get(svc, svc)
        return layer

    # ── Connection mapping ───────────────────────────────────────────

    def map_connections(self, resources: list[dict]) -> list[ResourceConnection]:
        """Map connections between resources by analyzing VPC membership,
        security group references, subnet placement, and ELB target groups.
        """
        connections: list[ResourceConnection] = []
        seen: set[tuple[str, str, str]] = set()  # (source, target, type) dedup

        def _add(src: str, tgt: str, ctype: str, meta: dict | None = None):
            key = (src, tgt, ctype)
            if key not in seen and src != tgt:
                seen.add(key)
                connections.append(ResourceConnection(
                    source_id=src,
                    target_id=tgt,
                    connection_type=ctype,
                    metadata=meta or {},
                ))

        # Index resources by VPC, subnet, and security groups
        vpc_members: dict[str, list[str]] = {}   # vpc_id → [resource_ids]
        subnet_members: dict[str, list[str]] = {}  # subnet_id → [resource_ids]

        for r in resources:
            rid = r.get("id", "")
            meta = r.get("metadata", {})

            # VPC membership
            vpc_id = r.get("vpc_id", meta.get("vpc_id", ""))
            if vpc_id:
                vpc_members.setdefault(vpc_id, []).append(rid)

            # Subnet placement
            subnet_id = r.get("subnet_id", meta.get("subnet_id", ""))
            if subnet_id:
                subnet_members.setdefault(subnet_id, []).append(rid)
                _add(subnet_id, rid, "subnet_placement")

            # Security group references
            sgs = r.get("security_groups", meta.get("security_groups", []))
            if isinstance(sgs, list):
                for sg in sgs:
                    _add(sg, rid, "security_group_ref")

            # ELB target groups (if target info is in metadata)
            targets = r.get("targets", meta.get("targets", []))
            if isinstance(targets, list):
                for target_id in targets:
                    _add(rid, target_id, "elb_target")

        # VPC membership connections — link resources sharing the same VPC
        for vpc_id, members in vpc_members.items():
            for member_id in members:
                _add(vpc_id, member_id, "vpc_member")

        return connections

    def _generate_mermaid(self, resources, connections=None, view_type="default") -> str:
        """Generate a Mermaid architecture diagram from discovered resources."""
        return generate_diagram(resources, connections or [], view_type)


# --- Standalone diagram generation with 5 view types ---

ICONS = {
    "ec2": "🖥️", "rds": "🗄️", "lambda": "⚡", "s3": "📦",
    "ecs": "🐳", "vpc": "🌐", "dynamodb": "📊", "sqs": "📬",
    "sns": "📢", "apigateway": "🚪", "cloudfront": "🌍", "elb": "⚖️",
    "subnet": "🔲", "nat_gateway": "🔀", "igw": "🚪",
}

LAYER_ORDER = ["Edge", "Load_Balancing", "Compute", "Data", "Storage", "Networking", "Security", "Messaging"]


def _safe_id(resource_id: str) -> str:
    """Make a resource ID safe for Mermaid node names."""
    return resource_id.replace("-", "_").replace(".", "_").replace("/", "_").replace(":", "_")[:30]


def _node(r: dict) -> tuple[str, str]:
    """Return (safe_id, label) for a resource."""
    sid = _safe_id(r.get("id", "unknown"))
    icon = ICONS.get(r.get("service", ""), "📎")
    name = r.get("name") or r.get("id", "")
    return sid, f"{icon} {name}"


def _collapse_if_needed(items: list[dict], threshold: int = 50) -> tuple[list[dict], list[dict]]:
    """If more than threshold items of same type, collapse into summary nodes."""
    if len(items) <= threshold:
        return items, []
    # Keep items that have connections, collapse the rest
    connected = [r for r in items if r.get("vpc_id") or r.get("security_groups")]
    rest = [r for r in items if r not in connected]
    if len(connected) > threshold:
        connected = connected[:threshold]
    return connected, rest


def generate_diagram(resources: list[dict], connections: list = None,
                     view_type: str = "default") -> str:
    """Generate Mermaid diagram from resource inventory with multiple view types.

    Args:
        resources: Resource inventory from ArchMapper.discover()
        connections: Resource connections (dicts or ResourceConnection objects)
        view_type: One of: default, security, cost, multi-region, traffic-flow

    Returns:
        Mermaid diagram string
    """
    if not resources:
        return "graph TB\n    empty[No resources discovered]"

    # Normalize connections to dicts
    norm_conns = []
    for c in (connections or []):
        if hasattr(c, 'to_dict'):
            norm_conns.append(c.to_dict())
        elif isinstance(c, dict):
            norm_conns.append(c)
        else:
            norm_conns.append({"source_id": getattr(c, "source_id", ""), "target_id": getattr(c, "target_id", ""), "connection_type": getattr(c, "connection_type", "")})

    views = {
        "default": _view_default,
        "security": _view_security,
        "cost": _view_cost,
        "multi-region": _view_multi_region,
        "traffic-flow": _view_traffic_flow,
    }
    fn = views.get(view_type, _view_default)
    return fn(resources, norm_conns)


def _view_default(resources: list[dict], connections: list[dict]) -> str:
    """Mind-map style architecture overview — layers → services → resource counts."""
    lines = ["mindmap"]
    lines.append("  root((☁️ AWS Architecture))")

    # Group by layer, then by service
    by_layer: dict[str, dict[str, list[dict]]] = {}
    for r in resources:
        layer = r.get("layer", "Other")
        svc = r.get("service", "other")
        by_layer.setdefault(layer, {}).setdefault(svc, []).append(r)

    for layer in LAYER_ORDER:
        services = by_layer.get(layer, {})
        if not services:
            continue
        total = sum(len(v) for v in services.values())
        layer_label = layer.replace("_", " ")
        lines.append(f"    {layer_label}")
        for svc, items in sorted(services.items(), key=lambda x: -len(x[1])):
            icon = ICONS.get(svc, "📎")
            count = len(items)
            # Show service with count and top 3 named resources
            lines.append(f"      {icon} {svc.upper()} x{count}")
            named = [r.get("name") or r.get("id", "") for r in items if r.get("name")][:3]
            for n in named:
                clean = n[:20].replace("(", "").replace(")", "").replace('"', "")
                lines.append(f"        {clean}")

    return "\n".join(lines)


def _view_security(resources: list[dict], connections: list[dict]) -> str:
    """Security view: SGs, NACLs, IAM boundaries with allow/deny."""
    lines = ["graph LR"]

    # Collect security-relevant resources
    sgs = [r for r in resources if r.get("type") == "security_group" or r.get("service") == "vpc" and "sg-" in r.get("id", "")]
    compute = [r for r in resources if r.get("layer") in ("Compute", "Data", "Load_Balancing")]
    vpcs = [r for r in resources if r.get("service") == "vpc" and r.get("type") == "vpc"]

    # VPC boundaries
    for vpc in vpcs:
        vid = _safe_id(vpc["id"])
        vname = vpc.get("name") or vpc["id"]
        lines.append(f'    subgraph {vid}["🌐 {vname}"]')

        # Resources in this VPC
        vpc_resources = [r for r in compute if r.get("vpc_id") == vpc["id"]]
        for r in vpc_resources[:20]:
            sid, label = _node(r)
            lines.append(f'        {sid}["{label}"]')

        lines.append("    end")

    # Internet boundary
    lines.append('    Internet(("🌍 Internet"))')

    # SG connections from connection data
    for conn in connections:
        if conn.get("connection_type") == "security_group_ref":
            src = _safe_id(conn["source_id"])
            tgt = _safe_id(conn["target_id"])
            lines.append(f"    {src} -.->|allow| {tgt}")

    # Public-facing resources connect to Internet
    for r in resources:
        if r.get("scheme") == "internet-facing" or r.get("service") == "cloudfront":
            sid = _safe_id(r["id"])
            lines.append(f"    Internet -->|HTTPS| {sid}")
        if r.get("service") == "apigateway":
            sid = _safe_id(r["id"])
            lines.append(f"    Internet -->|API| {sid}")

    # Open security group warnings
    for r in resources:
        sgs_list = r.get("security_groups", [])
        if isinstance(sgs_list, list) and sgs_list:
            sid = _safe_id(r["id"])
            for sg in sgs_list[:3]:
                sg_id = _safe_id(sg)
                lines.append(f"    {sg_id}[/🛡️ {sg}/] -.-> {sid}")

    return "\n".join(lines)


def _view_cost(resources: list[dict], connections: list[dict]) -> str:
    """Cost view: resources annotated with estimated monthly cost, top contributors highlighted."""
    lines = ["graph TB"]

    # Rough cost estimates by service/type
    cost_map = {
        "ec2": 50, "rds": 100, "elb": 25, "ecs": 40, "lambda": 5,
        "s3": 3, "dynamodb": 10, "cloudfront": 15, "sqs": 2, "sns": 1,
        "vpc": 0, "apigateway": 8,
    }

    # Calculate costs and sort
    costed = []
    for r in resources:
        svc = r.get("service", "")
        est = cost_map.get(svc, 5)
        # Adjust by instance type if available
        itype = r.get("instance_type", r.get("instance_class", ""))
        if "xlarge" in itype:
            est *= 3
        elif "large" in itype:
            est *= 2
        costed.append((r, est))

    costed.sort(key=lambda x: x[1], reverse=True)
    total = sum(c for _, c in costed)

    lines.append(f'    total["💰 Total Est: ~${total:,.0f}/mo"]')
    lines.append(f'    style total fill:#ff9100,color:#fff,stroke:#ff6d00')

    # Group by layer, annotate with cost
    by_layer: dict[str, list[tuple]] = {}
    for r, cost in costed:
        layer = r.get("layer", "Other")
        by_layer.setdefault(layer, []).append((r, cost))

    for layer in LAYER_ORDER:
        items = by_layer.get(layer, [])
        if not items:
            continue
        layer_cost = sum(c for _, c in items)
        lines.append(f'    subgraph {layer}["${layer_cost:,.0f}/mo — {layer.replace("_", " ")}"]')
        for r, cost in items[:15]:
            sid, label = _node(r)
            cost_label = f"${cost}/mo"
            lines.append(f'        {sid}["{label}<br/>{cost_label}"]')
        lines.append("    end")
        lines.append(f"    total --> {layer}")

    return "\n".join(lines)


def _view_multi_region(resources: list[dict], connections: list[dict]) -> str:
    """Multi-region view: resources grouped by region subgraphs."""
    lines = ["graph TB"]

    by_region: dict[str, list[dict]] = {}
    for r in resources:
        region = r.get("region", "unknown")
        by_region.setdefault(region, []).append(r)

    # Sort regions: global first, then alphabetical
    sorted_regions = sorted(by_region.keys(), key=lambda x: ("0" if x == "global" else "1") + x)

    for region in sorted_regions:
        items = by_region[region]
        safe_region = region.replace("-", "_")
        lines.append(f'    subgraph {safe_region}["🌎 {region} ({len(items)} resources)"]')

        # Sub-group by service within region
        by_svc: dict[str, list[dict]] = {}
        for r in items:
            by_svc.setdefault(r.get("service", ""), []).append(r)

        for svc, svc_items in by_svc.items():
            if len(svc_items) > 10:
                icon = ICONS.get(svc, "📎")
                lines.append(f'        {safe_region}_{svc}["{icon} {len(svc_items)} {svc}"]')
            else:
                for r in svc_items:
                    sid, label = _node(r)
                    lines.append(f'        {sid}["{label}"]')

        lines.append("    end")

    # Cross-region connections
    for conn in connections:
        src_r = next((r for r in resources if r.get("id") == conn.get("source_id")), None)
        tgt_r = next((r for r in resources if r.get("id") == conn.get("target_id")), None)
        if src_r and tgt_r and src_r.get("region") != tgt_r.get("region"):
            src = _safe_id(conn["source_id"])
            tgt = _safe_id(conn["target_id"])
            lines.append(f"    {src} -.->|cross-region| {tgt}")

    return "\n".join(lines)


def _view_traffic_flow(resources: list[dict], connections: list[dict]) -> str:
    """Traffic flow view: edge → load balancing → compute → data request path."""
    lines = ["graph LR"]

    # Collect resources by layer for the flow
    edge = [r for r in resources if r.get("layer") == "Edge"]
    lbs = [r for r in resources if r.get("layer") == "Load_Balancing"]
    compute = [r for r in resources if r.get("layer") == "Compute"]
    data = [r for r in resources if r.get("layer") == "Data"]
    storage = [r for r in resources if r.get("layer") == "Storage"]
    messaging = [r for r in resources if r.get("layer") == "Messaging"]

    lines.append('    User(("👤 User"))')

    def _add_layer(name, items, max_show=8):
        if not items:
            return
        lines.append(f'    subgraph {name}["{name.replace("_", " ")}"]')
        for r in items[:max_show]:
            sid, label = _node(r)
            lines.append(f'        {sid}["{label}"]')
        if len(items) > max_show:
            lines.append(f'        {name}_more["... +{len(items) - max_show} more"]')
        lines.append("    end")

    _add_layer("Edge", edge)
    _add_layer("Load_Balancing", lbs)
    _add_layer("Compute", compute)
    _add_layer("Data", data)
    _add_layer("Storage", storage)
    _add_layer("Messaging", messaging)

    # Flow arrows between layers
    flow = [("User", "Edge"), ("Edge", "Load_Balancing"), ("Load_Balancing", "Compute"),
            ("Compute", "Data"), ("Compute", "Storage"), ("Compute", "Messaging")]
    for src, tgt in flow:
        src_items = {"User": [], "Edge": edge, "Load_Balancing": lbs, "Compute": compute,
                     "Data": data, "Storage": storage, "Messaging": messaging}
        if src == "User" and (edge or lbs or compute):
            target = "Edge" if edge else "Load_Balancing" if lbs else "Compute"
            lines.append(f"    User -->|request| {target}")
        elif src_items.get(src) and src_items.get(tgt):
            lines.append(f"    {src} -->|flow| {tgt}")

    return "\n".join(lines)


SkillRegistry.register(ArchMapper())
