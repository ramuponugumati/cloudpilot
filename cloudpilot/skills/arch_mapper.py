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
        """Full resource discovery with anti-pattern detection, service recommendations,
        layer classification, and connection mapping.

        Returns:
            dict with keys: resources, anti_patterns, service_recommendations,
            connections, diagram, summary.
        """
        resources = []
        errors = []
        acct = get_account_id(profile)

        # Global resources (S3, CloudFront)
        for scanner_name, scanner_fn in [("s3", self._discover_s3), ("cloudfront", self._discover_cloudfront)]:
            try:
                resources.extend(scanner_fn(profile))
            except Exception as e:
                logger.warning(f"Discovery error for {scanner_name} (global): {e}")
                errors.append(f"{scanner_name}/global: {e}")

        # Regional resources
        regional_scanners = [
            ("ec2", self._discover_ec2),
            ("rds", self._discover_rds),
            ("lambda", self._discover_lambda),
            ("ecs", self._discover_ecs),
            ("vpc", self._discover_vpc),
            ("dynamodb", self._discover_dynamodb),
            ("sqs", self._discover_sqs),
            ("sns", self._discover_sns),
            ("apigateway", self._discover_apigw),
            ("elb", self._discover_elb),
        ]
        for svc_name, scanner in regional_scanners:
            for region in regions:
                try:
                    resources.extend(scanner(region, profile))
                except Exception as e:
                    logger.warning(f"Discovery error for {svc_name} in {region}: {e}")
                    errors.append(f"{svc_name}/{region}: {e}")

        # Enrich resources with account_id and layer classification
        for r in resources:
            r["account_id"] = acct
            r.setdefault("metadata", {})
            r.setdefault("tags", {})
            r["layer"] = self.classify_layer(r)

        # Run analysis passes
        anti_patterns = self.detect_anti_patterns(resources)
        service_recommendations = self.detect_service_recommendations(resources)
        connections = self.map_connections(resources)
        diagram = self._generate_mermaid(resources)

        # Build summary
        by_service: dict[str, int] = {}
        for r in resources:
            svc = r.get("service", "unknown")
            by_service[svc] = by_service.get(svc, 0) + 1

        return {
            "resources": resources,
            "anti_patterns": [ap.to_dict() if hasattr(ap, "to_dict") else ap for ap in anti_patterns],
            "service_recommendations": [sr.to_dict() if hasattr(sr, "to_dict") else sr for sr in service_recommendations],
            "connections": [c.to_dict() if hasattr(c, "to_dict") else c for c in connections],
            "diagram": diagram,
            "errors": errors,
            "summary": {
                "total_resources": len(resources),
                "by_service": by_service,
                "regions_scanned": list(regions),
                "account_id": acct,
            },
        }

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
            name = bucket["BucketName"]
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

    def _generate_mermaid(self, resources) -> str:
        """Generate a Mermaid architecture diagram from discovered resources."""
        lines = ["graph TB"]
        by_service = {}
        for r in resources:
            svc = r["service"]
            by_service.setdefault(svc, []).append(r)

        icons = {
            "ec2": "🖥️", "rds": "🗄️", "lambda": "⚡", "s3": "📦",
            "ecs": "🐳", "vpc": "🌐", "dynamodb": "📊", "sqs": "📬",
            "sns": "📢", "apigateway": "🚪", "cloudfront": "🌍", "elb": "⚖️",
        }

        for svc, items in by_service.items():
            icon = icons.get(svc, "📎")
            lines.append(f'    subgraph {svc.upper()}["{icon} {svc.upper()}"]')
            for item in items[:10]:
                safe_id = item["id"].replace("-", "_").replace(".", "_")[:30]
                label = item.get("name") or item["id"]
                lines.append(f'        {safe_id}["{label}"]')
            lines.append("    end")

        # Add relationships
        for r in resources:
            if r["service"] == "ec2" and r.get("vpc_id"):
                vpc_id = r["vpc_id"].replace("-", "_")
                ec2_id = r["id"].replace("-", "_")[:30]
                lines.append(f"    {vpc_id} --> {ec2_id}")
            if r["service"] == "rds" and r.get("vpc_id"):
                vpc_id = r["vpc_id"].replace("-", "_")
                rds_id = r["id"].replace("-", "_")[:30]
                lines.append(f"    {vpc_id} --> {rds_id}")

        return "\n".join(lines)


SkillRegistry.register(ArchMapper())
