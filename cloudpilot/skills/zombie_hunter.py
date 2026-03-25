"""Zombie Hunter skill — wraps the standalone zombie-hunter scanners."""
import time
from cloudpilot.core import BaseSkill, SkillResult, Finding, Severity, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions


class ZombieHunterSkill(BaseSkill):
    name = "zombie-hunter"
    description = "Detect 20 types of wasted resources: idle EC2/RDS/ECS, unattached EBS, unused EIPs/NATs/ELBs/VPC endpoints, old snapshots/AMIs, idle SageMaker/ElastiCache/Redshift/OpenSearch, unused KMS/Secrets/log groups"
    version = "0.2.0"

    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        findings = []
        errors = []
        acct = account_id or get_account_id(profile)
        cpu_threshold = kwargs.get("cpu_threshold", 2.0)
        snapshot_days = kwargs.get("days", 180)

        scanners = [
            ("ebs", self._scan_ebs),
            ("eip", self._scan_eip),
            ("nat", self._scan_nat),
            ("idle_ec2", lambda r, p: self._scan_idle_ec2(r, p, cpu_threshold)),
            ("idle_rds", self._scan_idle_rds),
            ("old_snapshots", lambda r, p: self._scan_old_snapshots(r, p, snapshot_days)),
            ("unused_elb", self._scan_unused_elb),
            ("stopped_ec2_ebs", self._scan_stopped_ec2_ebs),
            ("idle_sagemaker", self._scan_idle_sagemaker),
            ("unused_vpc_endpoints", self._scan_unused_vpc_endpoints),
            ("idle_elasticache", self._scan_idle_elasticache),
            ("unused_amis", self._scan_unused_amis),
            ("idle_redshift", self._scan_idle_redshift),
            ("unused_kms", self._scan_unused_kms),
            ("unused_secrets", self._scan_unused_secrets),
            ("idle_ecs", self._scan_idle_ecs),
            ("unused_log_groups", self._scan_unused_log_groups),
            ("idle_opensearch", self._scan_idle_opensearch),
            ("unused_r53_zones", self._scan_unused_r53_zones),
            ("idle_kinesis", self._scan_idle_kinesis),
        ]

        for name, scanner_fn in scanners:
            try:
                results = parallel_regions(scanner_fn, regions, profile=profile)
                findings.extend(results)
            except Exception as e:
                errors.append(f"{name}: {e}")

        for f in findings:
            f.account_id = acct

        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=time.time() - start,
            accounts_scanned=1, regions_scanned=len(regions), errors=errors,
        )

    def _scan_ebs(self, region, profile):
        findings = []
        ec2 = get_client("ec2", region, profile)
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}]):
            for vol in page["Volumes"]:
                size = vol["Size"]
                cost = size * 0.08
                findings.append(Finding(
                    skill=self.name, title=f"Unattached EBS: {vol['VolumeId']}",
                    severity=Severity.LOW, region=region, resource_id=vol["VolumeId"],
                    description=f"{vol['VolumeType']} | {size}GB",
                    monthly_impact=round(cost, 2),
                    recommended_action="Delete or snapshot+delete",
                ))
        return findings

    def _scan_eip(self, region, profile):
        findings = []
        ec2 = get_client("ec2", region, profile)
        for addr in ec2.describe_addresses().get("Addresses", []):
            if not addr.get("InstanceId") and not addr.get("NetworkInterfaceId"):
                findings.append(Finding(
                    skill=self.name, title=f"Unused EIP: {addr.get('PublicIp')}",
                    severity=Severity.LOW, region=region,
                    resource_id=addr.get("AllocationId", ""),
                    description=f"IP: {addr.get('PublicIp')}",
                    monthly_impact=3.60, recommended_action="Release",
                ))
        return findings

    def _scan_nat(self, region, profile):
        from datetime import datetime, timedelta, timezone
        findings = []
        ec2 = get_client("ec2", region, profile)
        cw = get_client("cloudwatch", region, profile)
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=7)
        for gw in ec2.describe_nat_gateways(Filter=[{"Name": "state", "Values": ["available"]}]).get("NatGateways", []):
            gw_id = gw["NatGatewayId"]
            try:
                resp = cw.get_metric_statistics(
                    Namespace="AWS/NATGateway", MetricName="BytesOutToDestination",
                    Dimensions=[{"Name": "NatGatewayId", "Value": gw_id}],
                    StartTime=start, EndTime=end, Period=604800, Statistics=["Sum"],
                )
                total = resp["Datapoints"][0]["Sum"] if resp["Datapoints"] else 0
            except Exception:
                total = 0
            if total == 0:
                findings.append(Finding(
                    skill=self.name, title=f"Unused NAT GW: {gw_id}",
                    severity=Severity.MEDIUM, region=region, resource_id=gw_id,
                    description=f"VPC: {gw.get('VpcId')} | 0 bytes in 7 days",
                    monthly_impact=32.85, recommended_action="Delete if unused",
                ))
        return findings

    def _scan_idle_ec2(self, region, profile, cpu_threshold):
        from datetime import datetime, timedelta, timezone
        findings = []
        ec2 = get_client("ec2", region, profile)
        cw = get_client("cloudwatch", region, profile)
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=7)
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    iid = inst["InstanceId"]
                    try:
                        resp = cw.get_metric_statistics(
                            Namespace="AWS/EC2", MetricName="CPUUtilization",
                            Dimensions=[{"Name": "InstanceId", "Value": iid}],
                            StartTime=start, EndTime=end, Period=86400, Statistics=["Average"],
                        )
                        pts = resp.get("Datapoints", [])
                        if not pts:
                            continue
                        avg = sum(p["Average"] for p in pts) / len(pts)
                        if avg < cpu_threshold:
                            findings.append(Finding(
                                skill=self.name, title=f"Idle EC2: {iid}",
                                severity=Severity.MEDIUM, region=region, resource_id=iid,
                                description=f"{inst['InstanceType']} | CPU: {avg:.1f}%",
                                monthly_impact=73.0, recommended_action="Stop or terminate",
                            ))
                    except Exception:
                        pass
        return findings

    def _scan_idle_rds(self, region, profile):
        from datetime import datetime, timedelta, timezone
        findings = []
        rds = get_client("rds", region, profile)
        cw = get_client("cloudwatch", region, profile)
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=7)
        for db in rds.describe_db_instances().get("DBInstances", []):
            if db["DBInstanceStatus"] != "available":
                continue
            dbid = db["DBInstanceIdentifier"]
            try:
                resp = cw.get_metric_statistics(
                    Namespace="AWS/RDS", MetricName="DatabaseConnections",
                    Dimensions=[{"Name": "DBInstanceIdentifier", "Value": dbid}],
                    StartTime=start, EndTime=end, Period=86400, Statistics=["Average"],
                )
                pts = resp.get("Datapoints", [])
                if pts and sum(p["Average"] for p in pts) / len(pts) < 1:
                    findings.append(Finding(
                        skill=self.name, title=f"Idle RDS: {dbid}",
                        severity=Severity.MEDIUM, region=region, resource_id=dbid,
                        description=f"{db['DBInstanceClass']} | {db['Engine']} | 0 connections",
                        monthly_impact=73.0, recommended_action="Stop or delete",
                    ))
            except Exception:
                pass
        return findings

    # --- Scanners 6-20: Additional zombie resource types ---

    def _scan_old_snapshots(self, region, profile, days):
        from datetime import datetime, timedelta, timezone
        findings = []
        ec2 = get_client("ec2", region, profile)
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        paginator = ec2.get_paginator("describe_snapshots")
        for page in paginator.paginate(OwnerIds=["self"]):
            for snap in page["Snapshots"]:
                start_time = snap.get("StartTime")
                if start_time and start_time < cutoff:
                    size = snap.get("VolumeSize", 0)
                    cost = size * 0.05
                    age_days = (datetime.now(timezone.utc) - start_time).days
                    findings.append(Finding(
                        skill=self.name, title=f"Old snapshot: {snap['SnapshotId']}",
                        severity=Severity.LOW, region=region, resource_id=snap["SnapshotId"],
                        description=f"{size}GB | {age_days} days old",
                        monthly_impact=round(cost, 2), recommended_action="Delete if no longer needed",
                    ))
        return findings

    def _scan_unused_elb(self, region, profile):
        findings = []
        elbv2 = get_client("elbv2", region, profile)
        for lb in elbv2.describe_load_balancers().get("LoadBalancers", []):
            lb_arn = lb["LoadBalancerArn"]
            lb_name = lb["LoadBalancerName"]
            tgs = elbv2.describe_target_groups(LoadBalancerArn=lb_arn).get("TargetGroups", [])
            has_healthy = False
            for tg in tgs:
                try:
                    health = elbv2.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
                    if any(t["TargetHealth"]["State"] == "healthy" for t in health.get("TargetHealthDescriptions", [])):
                        has_healthy = True
                        break
                except Exception:
                    pass
            if not has_healthy:
                findings.append(Finding(
                    skill=self.name, title=f"Unused ELB: {lb_name}",
                    severity=Severity.MEDIUM, region=region, resource_id=lb_name,
                    description=f"{lb.get('Type', 'application')} | 0 healthy targets",
                    monthly_impact=16.20, recommended_action="Delete if no longer needed",
                ))
        return findings

    def _scan_stopped_ec2_ebs(self, region, profile):
        findings = []
        ec2 = get_client("ec2", region, profile)
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]):
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    iid = inst["InstanceId"]
                    total_gb = sum(b.get("Ebs", {}).get("VolumeSize", 0) for b in inst.get("BlockDeviceMappings", []) if "Ebs" in b)
                    if total_gb > 0:
                        cost = total_gb * 0.08
                        name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), "")
                        findings.append(Finding(
                            skill=self.name, title=f"Stopped EC2 with EBS: {name or iid}",
                            severity=Severity.MEDIUM, region=region, resource_id=iid,
                            description=f"{inst['InstanceType']} | {total_gb}GB EBS attached",
                            monthly_impact=round(cost, 2), recommended_action="Terminate or detach volumes",
                        ))
        return findings

    def _scan_idle_sagemaker(self, region, profile):
        from datetime import datetime, timedelta, timezone
        findings = []
        try:
            sm = get_client("sagemaker", region, profile)
            cw = get_client("cloudwatch", region, profile)
            end = datetime.now(timezone.utc)
            start = end - timedelta(days=7)
            for ep in sm.list_endpoints(StatusEquals="InService").get("Endpoints", []):
                ep_name = ep["EndpointName"]
                try:
                    resp = cw.get_metric_statistics(
                        Namespace="AWS/SageMaker", MetricName="Invocations",
                        Dimensions=[{"Name": "EndpointName", "Value": ep_name}],
                        StartTime=start, EndTime=end, Period=604800, Statistics=["Sum"],
                    )
                    total = resp["Datapoints"][0]["Sum"] if resp["Datapoints"] else 0
                    if total == 0:
                        findings.append(Finding(
                            skill=self.name, title=f"Idle SageMaker endpoint: {ep_name}",
                            severity=Severity.HIGH, region=region, resource_id=ep_name,
                            description="0 invocations in 7 days",
                            monthly_impact=100.0, recommended_action="Delete endpoint",
                        ))
                except Exception:
                    pass
        except Exception:
            pass
        return findings

    def _scan_unused_vpc_endpoints(self, region, profile):
        findings = []
        ec2 = get_client("ec2", region, profile)
        for ep in ec2.describe_vpc_endpoints().get("VpcEndpoints", []):
            if ep["State"] == "available" and ep["VpcEndpointType"] == "Interface":
                findings.append(Finding(
                    skill=self.name, title=f"VPC Endpoint: {ep['VpcEndpointId']}",
                    severity=Severity.LOW, region=region, resource_id=ep["VpcEndpointId"],
                    description=f"{ep.get('ServiceName', '')} | Verify if in use",
                    monthly_impact=7.30, recommended_action="Delete if unused",
                ))
        return findings

    def _scan_idle_elasticache(self, region, profile):
        from datetime import datetime, timedelta, timezone
        findings = []
        try:
            ec = get_client("elasticache", region, profile)
            cw = get_client("cloudwatch", region, profile)
            end = datetime.now(timezone.utc)
            start = end - timedelta(days=7)
            for cluster in ec.describe_cache_clusters().get("CacheClusters", []):
                cid = cluster["CacheClusterId"]
                try:
                    resp = cw.get_metric_statistics(
                        Namespace="AWS/ElastiCache", MetricName="CurrConnections",
                        Dimensions=[{"Name": "CacheClusterId", "Value": cid}],
                        StartTime=start, EndTime=end, Period=86400, Statistics=["Average"],
                    )
                    pts = resp.get("Datapoints", [])
                    if pts and sum(p["Average"] for p in pts) / len(pts) < 1:
                        findings.append(Finding(
                            skill=self.name, title=f"Idle ElastiCache: {cid}",
                            severity=Severity.MEDIUM, region=region, resource_id=cid,
                            description=f"{cluster.get('CacheNodeType', '')} | 0 connections",
                            monthly_impact=50.0, recommended_action="Delete if unused",
                        ))
                except Exception:
                    pass
        except Exception:
            pass
        return findings

    def _scan_unused_amis(self, region, profile):
        findings = []
        ec2 = get_client("ec2", region, profile)
        amis = ec2.describe_images(Owners=["self"]).get("Images", [])
        used_amis = set()
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    used_amis.add(inst.get("ImageId", ""))
        for ami in amis:
            if ami["ImageId"] not in used_amis:
                snap_size = sum(b.get("Ebs", {}).get("VolumeSize", 0) for b in ami.get("BlockDeviceMappings", []) if "Ebs" in b)
                cost = snap_size * 0.05
                findings.append(Finding(
                    skill=self.name, title=f"Unused AMI: {ami.get('Name', ami['ImageId'])}",
                    severity=Severity.LOW, region=region, resource_id=ami["ImageId"],
                    description=f"{snap_size}GB snapshots | Not used by any instance",
                    monthly_impact=round(cost, 2), recommended_action="Deregister AMI + delete snapshots",
                ))
        return findings

    def _scan_idle_redshift(self, region, profile):
        from datetime import datetime, timedelta, timezone
        findings = []
        try:
            rs = get_client("redshift", region, profile)
            cw = get_client("cloudwatch", region, profile)
            end = datetime.now(timezone.utc)
            start = end - timedelta(days=7)
            for cluster in rs.describe_clusters().get("Clusters", []):
                cid = cluster["ClusterIdentifier"]
                try:
                    resp = cw.get_metric_statistics(
                        Namespace="AWS/Redshift", MetricName="DatabaseConnections",
                        Dimensions=[{"Name": "ClusterIdentifier", "Value": cid}],
                        StartTime=start, EndTime=end, Period=86400, Statistics=["Average"],
                    )
                    pts = resp.get("Datapoints", [])
                    if pts and sum(p["Average"] for p in pts) / len(pts) < 1:
                        findings.append(Finding(
                            skill=self.name, title=f"Idle Redshift: {cid}",
                            severity=Severity.HIGH, region=region, resource_id=cid,
                            description=f"{cluster.get('NodeType', '')} x{cluster.get('NumberOfNodes', 1)} | 0 connections",
                            monthly_impact=200.0, recommended_action="Pause or delete cluster",
                        ))
                except Exception:
                    pass
        except Exception:
            pass
        return findings

    def _scan_unused_kms(self, region, profile):
        findings = []
        try:
            kms = get_client("kms", region, profile)
            for key in kms.list_keys().get("Keys", []):
                try:
                    meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                    if meta["KeyManager"] == "CUSTOMER" and meta["KeyState"] == "Enabled":
                        findings.append(Finding(
                            skill=self.name, title=f"KMS key: {meta.get('Description', key['KeyId'][:12])}",
                            severity=Severity.LOW, region=region, resource_id=key["KeyId"],
                            description="Customer-managed key — verify if in use",
                            monthly_impact=1.0, recommended_action="Disable or schedule deletion if unused",
                        ))
                except Exception:
                    pass
        except Exception:
            pass
        return findings

    def _scan_unused_secrets(self, region, profile):
        from datetime import datetime, timedelta, timezone
        findings = []
        try:
            sm = get_client("secretsmanager", region, profile)
            cutoff = datetime.now(timezone.utc) - timedelta(days=90)
            for secret in sm.list_secrets().get("SecretList", []):
                last_accessed = secret.get("LastAccessedDate")
                if last_accessed and last_accessed < cutoff:
                    days_unused = (datetime.now(timezone.utc) - last_accessed).days
                    findings.append(Finding(
                        skill=self.name, title=f"Unused secret: {secret['Name']}",
                        severity=Severity.LOW, region=region, resource_id=secret.get("ARN", secret["Name"]),
                        description=f"Last accessed {days_unused} days ago",
                        monthly_impact=0.40, recommended_action="Delete if no longer needed",
                    ))
        except Exception:
            pass
        return findings

    def _scan_idle_ecs(self, region, profile):
        findings = []
        try:
            ecs = get_client("ecs", region, profile)
            clusters = ecs.list_clusters().get("clusterArns", [])
            for cluster_arn in clusters[:10]:
                services = ecs.list_services(cluster=cluster_arn).get("serviceArns", [])
                if services:
                    details = ecs.describe_services(cluster=cluster_arn, services=services[:10]).get("services", [])
                    for svc in details:
                        if svc.get("desiredCount", 0) == 0 and svc.get("runningCount", 0) == 0:
                            findings.append(Finding(
                                skill=self.name, title=f"Empty ECS service: {svc['serviceName']}",
                                severity=Severity.LOW, region=region, resource_id=svc["serviceName"],
                                description=f"Cluster: {cluster_arn.split('/')[-1]} | 0 tasks",
                                monthly_impact=0, recommended_action="Delete if no longer needed",
                            ))
        except Exception:
            pass
        return findings

    def _scan_unused_log_groups(self, region, profile):
        from datetime import datetime, timedelta, timezone
        findings = []
        try:
            logs = get_client("logs", region, profile)
            cutoff_ms = int((datetime.now(timezone.utc) - timedelta(days=90)).timestamp() * 1000)
            paginator = logs.get_paginator("describe_log_groups")
            for page in paginator.paginate():
                for lg in page["logGroups"]:
                    stored = lg.get("storedBytes", 0)
                    if stored > 0 and lg.get("creationTime", 0) < cutoff_ms:
                        cost = (stored / (1024**3)) * 0.03
                        findings.append(Finding(
                            skill=self.name, title=f"Stale log group: {lg['logGroupName'][:40]}",
                            severity=Severity.LOW, region=region, resource_id=lg["logGroupName"],
                            description=f"{stored / (1024**2):.0f}MB stored",
                            monthly_impact=round(cost, 2), recommended_action="Set retention or delete",
                        ))
        except Exception:
            pass
        return findings

    def _scan_idle_opensearch(self, region, profile):
        from datetime import datetime, timedelta, timezone
        findings = []
        try:
            os_client = get_client("opensearch", region, profile)
            cw = get_client("cloudwatch", region, profile)
            end = datetime.now(timezone.utc)
            start = end - timedelta(days=7)
            for d in os_client.list_domain_names().get("DomainNames", []):
                dname = d["DomainName"]
                try:
                    resp = cw.get_metric_statistics(
                        Namespace="AWS/ES", MetricName="SearchRate",
                        Dimensions=[{"Name": "DomainName", "Value": dname}, {"Name": "ClientId", "Value": get_account_id(profile)}],
                        StartTime=start, EndTime=end, Period=604800, Statistics=["Sum"],
                    )
                    total = resp["Datapoints"][0]["Sum"] if resp["Datapoints"] else 0
                    if total == 0:
                        findings.append(Finding(
                            skill=self.name, title=f"Idle OpenSearch: {dname}",
                            severity=Severity.HIGH, region=region, resource_id=dname,
                            description="0 search requests in 7 days",
                            monthly_impact=150.0, recommended_action="Delete if unused",
                        ))
                except Exception:
                    pass
        except Exception:
            pass
        return findings

    def _scan_unused_r53_zones(self, region, profile):
        findings = []
        if region != "us-east-1":
            return findings
        try:
            r53 = get_client("route53", region, profile)
            for zone in r53.list_hosted_zones().get("HostedZones", []):
                if zone.get("ResourceRecordSetCount", 0) <= 2:
                    findings.append(Finding(
                        skill=self.name, title=f"Empty R53 zone: {zone['Name']}",
                        severity=Severity.LOW, region="global", resource_id=zone["Id"].split("/")[-1],
                        description=f"{zone.get('ResourceRecordSetCount', 0)} records (SOA+NS only)",
                        monthly_impact=0.50, recommended_action="Delete if unused",
                    ))
        except Exception:
            pass
        return findings

    def _scan_idle_kinesis(self, region, profile):
        from datetime import datetime, timedelta, timezone
        findings = []
        try:
            kinesis = get_client("kinesis", region, profile)
            cw = get_client("cloudwatch", region, profile)
            end = datetime.now(timezone.utc)
            start = end - timedelta(days=7)
            for stream in kinesis.list_streams().get("StreamNames", [])[:10]:
                try:
                    resp = cw.get_metric_statistics(
                        Namespace="AWS/Kinesis", MetricName="IncomingRecords",
                        Dimensions=[{"Name": "StreamName", "Value": stream}],
                        StartTime=start, EndTime=end, Period=604800, Statistics=["Sum"],
                    )
                    total = resp["Datapoints"][0]["Sum"] if resp["Datapoints"] else 0
                    if total == 0:
                        desc = kinesis.describe_stream_summary(StreamName=stream)["StreamDescriptionSummary"]
                        shards = desc.get("OpenShardCount", 1)
                        cost = shards * 0.015 * 24 * 30
                        findings.append(Finding(
                            skill=self.name, title=f"Idle Kinesis: {stream}",
                            severity=Severity.MEDIUM, region=region, resource_id=stream,
                            description=f"{shards} shards | 0 records in 7 days",
                            monthly_impact=round(cost, 2), recommended_action="Delete if unused",
                        ))
                except Exception:
                    pass
        except Exception:
            pass
        return findings


SkillRegistry.register(ZombieHunterSkill())
