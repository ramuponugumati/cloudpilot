"""Shared network discovery helpers used by all network intelligence skills.

All functions use get_client from aws_client.py, catch exceptions gracefully
(log warning, return empty list or None), and make only read-only API calls.
"""
import logging
from cloudpilot.aws_client import get_client

logger = logging.getLogger(__name__)


def discover_security_groups(region: str, profile: str = None) -> list[dict]:
    """Discover all security groups in a region.

    Returns list of dicts:
        [{group_id, vpc_id, group_name, inbound_rules, outbound_rules, associated_resources}]
    """
    try:
        ec2 = get_client("ec2", region=region, profile=profile)
        sgs = []
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                inbound_rules = _parse_sg_rules(sg.get("IpPermissions", []))
                outbound_rules = _parse_sg_rules(sg.get("IpPermissionsEgress", []))
                sgs.append({
                    "group_id": sg["GroupId"],
                    "vpc_id": sg.get("VpcId", ""),
                    "group_name": sg.get("GroupName", ""),
                    "inbound_rules": inbound_rules,
                    "outbound_rules": outbound_rules,
                    "associated_resources": [],
                })
        # Enrich with associated ENIs to find resource associations
        _enrich_sg_associations(ec2, sgs)
        return sgs
    except Exception as e:
        logger.warning(f"discover_security_groups failed in {region}: {e}")
        return []


def _parse_sg_rules(ip_permissions: list) -> list[dict]:
    """Parse boto3 IpPermissions into simplified rule dicts."""
    rules = []
    for perm in ip_permissions:
        protocol = perm.get("IpProtocol", "-1")
        from_port = perm.get("FromPort", 0)
        to_port = perm.get("ToPort", 0)
        if protocol == "-1":
            from_port = 0
            to_port = 65535

        for ip_range in perm.get("IpRanges", []):
            rules.append({
                "protocol": protocol,
                "from_port": from_port,
                "to_port": to_port,
                "source": ip_range["CidrIp"],
                "source_type": "cidr",
            })
        for ipv6_range in perm.get("Ipv6Ranges", []):
            rules.append({
                "protocol": protocol,
                "from_port": from_port,
                "to_port": to_port,
                "source": ipv6_range["CidrIpv6"],
                "source_type": "cidr_ipv6",
            })
        for group_pair in perm.get("UserIdGroupPairs", []):
            rules.append({
                "protocol": protocol,
                "from_port": from_port,
                "to_port": to_port,
                "source": group_pair.get("GroupId", ""),
                "source_type": "security_group",
            })
    return rules


def _enrich_sg_associations(ec2_client, sgs: list[dict]):
    """Enrich SG dicts with associated resource IDs via ENI lookup."""
    try:
        sg_map = {sg["group_id"]: sg for sg in sgs}
        paginator = ec2_client.get_paginator("describe_network_interfaces")
        for page in paginator.paginate():
            for eni in page["NetworkInterfaces"]:
                instance_id = eni.get("Attachment", {}).get("InstanceId", "")
                resource_id = instance_id or eni.get("NetworkInterfaceId", "")
                for group in eni.get("Groups", []):
                    gid = group["GroupId"]
                    if gid in sg_map and resource_id:
                        if resource_id not in sg_map[gid]["associated_resources"]:
                            sg_map[gid]["associated_resources"].append(resource_id)
    except Exception as e:
        logger.warning(f"_enrich_sg_associations failed: {e}")


def discover_nacls(region: str, profile: str = None) -> list[dict]:
    """Discover all network ACLs in a region.

    Returns list of dicts:
        [{nacl_id, vpc_id, subnet_associations, inbound_rules, outbound_rules}]
    Each rule: {rule_number, protocol, port_range, cidr, action}
    """
    try:
        ec2 = get_client("ec2", region=region, profile=profile)
        nacls = []
        paginator = ec2.get_paginator("describe_network_acls")
        for page in paginator.paginate():
            for nacl in page["NetworkAcls"]:
                subnet_associations = [
                    assoc["SubnetId"]
                    for assoc in nacl.get("Associations", [])
                ]
                inbound_rules = []
                outbound_rules = []
                for entry in nacl.get("Entries", []):
                    rule = {
                        "rule_number": entry["RuleNumber"],
                        "protocol": entry.get("Protocol", "-1"),
                        "port_range": _format_port_range(entry.get("PortRange")),
                        "cidr": entry.get("CidrBlock", entry.get("Ipv6CidrBlock", "")),
                        "action": "allow" if entry["RuleAction"] == "allow" else "deny",
                    }
                    if entry.get("Egress", False):
                        outbound_rules.append(rule)
                    else:
                        inbound_rules.append(rule)
                nacls.append({
                    "nacl_id": nacl["NetworkAclId"],
                    "vpc_id": nacl.get("VpcId", ""),
                    "subnet_associations": subnet_associations,
                    "inbound_rules": sorted(inbound_rules, key=lambda r: r["rule_number"]),
                    "outbound_rules": sorted(outbound_rules, key=lambda r: r["rule_number"]),
                })
        return nacls
    except Exception as e:
        logger.warning(f"discover_nacls failed in {region}: {e}")
        return []


def _format_port_range(port_range: dict | None) -> str:
    """Format a PortRange dict to a string like '443' or '1024-65535'."""
    if not port_range:
        return "all"
    from_port = port_range.get("From", 0)
    to_port = port_range.get("To", 0)
    if from_port == to_port:
        return str(from_port)
    return f"{from_port}-{to_port}"


def discover_route_tables(region: str, profile: str = None) -> list[dict]:
    """Discover all route tables in a region.

    Returns list of dicts:
        [{route_table_id, vpc_id, subnet_associations, routes}]
    Each route: {destination_cidr, target_type, target_id}
    """
    try:
        ec2 = get_client("ec2", region=region, profile=profile)
        route_tables = []
        paginator = ec2.get_paginator("describe_route_tables")
        for page in paginator.paginate():
            for rt in page["RouteTables"]:
                subnet_associations = [
                    assoc["SubnetId"]
                    for assoc in rt.get("Associations", [])
                    if assoc.get("SubnetId")
                ]
                routes = []
                for route in rt.get("Routes", []):
                    dest = route.get("DestinationCidrBlock", route.get("DestinationIpv6CidrBlock", ""))
                    target_type, target_id = _resolve_route_target(route)
                    if dest:
                        routes.append({
                            "destination_cidr": dest,
                            "target_type": target_type,
                            "target_id": target_id,
                        })
                route_tables.append({
                    "route_table_id": rt["RouteTableId"],
                    "vpc_id": rt.get("VpcId", ""),
                    "subnet_associations": subnet_associations,
                    "routes": routes,
                })
        return route_tables
    except Exception as e:
        logger.warning(f"discover_route_tables failed in {region}: {e}")
        return []


def _resolve_route_target(route: dict) -> tuple[str, str]:
    """Extract target type and ID from a boto3 route dict."""
    target_map = [
        ("GatewayId", "gateway"),
        ("NatGatewayId", "nat-gateway"),
        ("VpcPeeringConnectionId", "vpc-peering"),
        ("TransitGatewayId", "transit-gateway"),
        ("NetworkInterfaceId", "network-interface"),
        ("InstanceId", "instance"),
        ("LocalGatewayId", "local-gateway"),
    ]
    for key, target_type in target_map:
        val = route.get(key)
        if val:
            # Distinguish internet gateway from virtual private gateway
            if key == "GatewayId":
                if val.startswith("igw-"):
                    target_type = "internet-gateway"
                elif val.startswith("vgw-"):
                    target_type = "vpn-gateway"
                elif val == "local":
                    target_type = "local"
            return target_type, val
    return "unknown", ""


def discover_vpc_peerings(region: str, profile: str = None) -> list[dict]:
    """Discover all VPC peering connections in a region.

    Returns list of dicts:
        [{peering_id, requester_vpc_id, accepter_vpc_id, status}]
    """
    try:
        ec2 = get_client("ec2", region=region, profile=profile)
        peerings = []
        paginator = ec2.get_paginator("describe_vpc_peering_connections")
        for page in paginator.paginate():
            for pcx in page["VpcPeeringConnections"]:
                peerings.append({
                    "peering_id": pcx["VpcPeeringConnectionId"],
                    "requester_vpc_id": pcx.get("RequesterVpcInfo", {}).get("VpcId", ""),
                    "accepter_vpc_id": pcx.get("AccepterVpcInfo", {}).get("VpcId", ""),
                    "status": pcx.get("Status", {}).get("Code", "unknown"),
                })
        return peerings
    except Exception as e:
        logger.warning(f"discover_vpc_peerings failed in {region}: {e}")
        return []


def discover_internet_gateways(region: str, profile: str = None) -> list[dict]:
    """Discover all internet gateways in a region.

    Returns list of dicts:
        [{igw_id, vpc_id}]
    """
    try:
        ec2 = get_client("ec2", region=region, profile=profile)
        igws = []
        paginator = ec2.get_paginator("describe_internet_gateways")
        for page in paginator.paginate():
            for igw in page["InternetGateways"]:
                vpc_id = ""
                attachments = igw.get("Attachments", [])
                if attachments:
                    vpc_id = attachments[0].get("VpcId", "")
                igws.append({
                    "igw_id": igw["InternetGatewayId"],
                    "vpc_id": vpc_id,
                })
        return igws
    except Exception as e:
        logger.warning(f"discover_internet_gateways failed in {region}: {e}")
        return []


def discover_nat_gateways(region: str, profile: str = None) -> list[dict]:
    """Discover all NAT gateways in a region.

    Returns list of dicts:
        [{nat_gw_id, vpc_id, subnet_id, state}]
    """
    try:
        ec2 = get_client("ec2", region=region, profile=profile)
        nat_gws = []
        paginator = ec2.get_paginator("describe_nat_gateways")
        for page in paginator.paginate():
            for ngw in page["NatGateways"]:
                nat_gws.append({
                    "nat_gw_id": ngw["NatGatewayId"],
                    "vpc_id": ngw.get("VpcId", ""),
                    "subnet_id": ngw.get("SubnetId", ""),
                    "state": ngw.get("State", "unknown"),
                })
        return nat_gws
    except Exception as e:
        logger.warning(f"discover_nat_gateways failed in {region}: {e}")
        return []


def resolve_resource_network_info(resource_id: str, region: str, profile: str = None) -> dict | None:
    """Resolve a resource ID to its VPC, subnet, and security groups.

    Dispatches based on prefix:
        i-*       → EC2 instance
        db-*      → RDS instance
        Lambda function name → Lambda
        ECS task pattern → ECS
        ELB ARN   → ELBv2

    Returns:
        {resource_id, resource_type, vpc_id, subnet_id, security_group_ids, private_ip}
        or None if resource not found or unsupported type.
    """
    try:
        if resource_id.startswith("i-"):
            return _resolve_ec2(resource_id, region, profile)
        elif resource_id.startswith("db-"):
            return _resolve_rds(resource_id, region, profile)
        elif resource_id.startswith("arn:") and ":loadbalancer/" in resource_id:
            return _resolve_elb(resource_id, region, profile)
        elif resource_id.startswith("arn:") and ":task/" in resource_id:
            return _resolve_ecs_task(resource_id, region, profile)
        elif not resource_id.startswith("arn:") and not resource_id.startswith("i-") and not resource_id.startswith("db-"):
            # Treat as Lambda function name
            return _resolve_lambda(resource_id, region, profile)
        else:
            logger.warning(f"Unsupported resource ID format: {resource_id}")
            return None
    except Exception as e:
        logger.warning(f"resolve_resource_network_info failed for {resource_id} in {region}: {e}")
        return None


def _resolve_ec2(instance_id: str, region: str, profile: str = None) -> dict | None:
    """Resolve EC2 instance to network info."""
    try:
        ec2 = get_client("ec2", region=region, profile=profile)
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        reservations = resp.get("Reservations", [])
        if not reservations:
            return None
        instance = reservations[0]["Instances"][0]
        sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
        return {
            "resource_id": instance_id,
            "resource_type": "ec2",
            "vpc_id": instance.get("VpcId", ""),
            "subnet_id": instance.get("SubnetId", ""),
            "security_group_ids": sg_ids,
            "private_ip": instance.get("PrivateIpAddress", ""),
        }
    except Exception as e:
        logger.warning(f"_resolve_ec2 failed for {instance_id}: {e}")
        return None


def _resolve_rds(db_instance_id: str, region: str, profile: str = None) -> dict | None:
    """Resolve RDS instance to network info."""
    try:
        rds = get_client("rds", region=region, profile=profile)
        resp = rds.describe_db_instances(DBInstanceIdentifier=db_instance_id)
        instances = resp.get("DBInstances", [])
        if not instances:
            return None
        db = instances[0]
        sg_ids = [
            sg["VpcSecurityGroupId"]
            for sg in db.get("VpcSecurityGroups", [])
        ]
        subnet_group = db.get("DBSubnetGroup", {})
        subnets = subnet_group.get("Subnets", [])
        subnet_id = subnets[0]["SubnetIdentifier"] if subnets else ""
        vpc_id = subnet_group.get("VpcId", "")
        endpoint = db.get("Endpoint", {})
        private_ip = endpoint.get("Address", "")
        return {
            "resource_id": db_instance_id,
            "resource_type": "rds",
            "vpc_id": vpc_id,
            "subnet_id": subnet_id,
            "security_group_ids": sg_ids,
            "private_ip": private_ip,
        }
    except Exception as e:
        logger.warning(f"_resolve_rds failed for {db_instance_id}: {e}")
        return None


def _resolve_lambda(function_name: str, region: str, profile: str = None) -> dict | None:
    """Resolve Lambda function to network info (VPC-attached only)."""
    try:
        lam = get_client("lambda", region=region, profile=profile)
        resp = lam.get_function_configuration(FunctionName=function_name)
        vpc_config = resp.get("VpcConfig", {})
        vpc_id = vpc_config.get("VpcId", "")
        if not vpc_id:
            # Lambda not attached to a VPC
            return {
                "resource_id": function_name,
                "resource_type": "lambda",
                "vpc_id": "",
                "subnet_id": "",
                "security_group_ids": [],
                "private_ip": "",
            }
        subnet_ids = vpc_config.get("SubnetIds", [])
        sg_ids = vpc_config.get("SecurityGroupIds", [])
        return {
            "resource_id": function_name,
            "resource_type": "lambda",
            "vpc_id": vpc_id,
            "subnet_id": subnet_ids[0] if subnet_ids else "",
            "security_group_ids": sg_ids,
            "private_ip": "",
        }
    except Exception as e:
        logger.warning(f"_resolve_lambda failed for {function_name}: {e}")
        return None


def _resolve_ecs_task(task_arn: str, region: str, profile: str = None) -> dict | None:
    """Resolve ECS task ARN to network info."""
    try:
        ecs = get_client("ecs", region=region, profile=profile)
        # Extract cluster from ARN: arn:aws:ecs:region:account:task/cluster-name/task-id
        arn_parts = task_arn.split("/")
        cluster = arn_parts[1] if len(arn_parts) >= 3 else "default"
        task_id = arn_parts[-1]

        resp = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])
        tasks = resp.get("tasks", [])
        if not tasks:
            return None
        task = tasks[0]

        # Get network info from attachments
        vpc_id = ""
        subnet_id = ""
        private_ip = ""
        sg_ids = []
        for attachment in task.get("attachments", []):
            if attachment.get("type") == "ElasticNetworkInterface":
                for detail in attachment.get("details", []):
                    name = detail.get("name", "")
                    value = detail.get("value", "")
                    if name == "subnetId":
                        subnet_id = value
                    elif name == "privateIPv4Address":
                        private_ip = value

        # Get SGs from network configuration in overrides or task definition
        for container in task.get("containers", []):
            for ni in container.get("networkInterfaces", []):
                if ni.get("privateIpv4Address"):
                    private_ip = private_ip or ni["privateIpv4Address"]

        # Try to get VPC from subnet
        if subnet_id:
            try:
                ec2 = get_client("ec2", region=region, profile=profile)
                subnet_resp = ec2.describe_subnets(SubnetIds=[subnet_id])
                subnets = subnet_resp.get("Subnets", [])
                if subnets:
                    vpc_id = subnets[0].get("VpcId", "")
            except Exception:
                pass

        return {
            "resource_id": task_arn,
            "resource_type": "ecs",
            "vpc_id": vpc_id,
            "subnet_id": subnet_id,
            "security_group_ids": sg_ids,
            "private_ip": private_ip,
        }
    except Exception as e:
        logger.warning(f"_resolve_ecs_task failed for {task_arn}: {e}")
        return None


def _resolve_elb(elb_arn: str, region: str, profile: str = None) -> dict | None:
    """Resolve ELBv2 (ALB/NLB) ARN to network info."""
    try:
        elbv2 = get_client("elbv2", region=region, profile=profile)
        resp = elbv2.describe_load_balancers(LoadBalancerArns=[elb_arn])
        lbs = resp.get("LoadBalancers", [])
        if not lbs:
            return None
        lb = lbs[0]
        vpc_id = lb.get("VpcId", "")
        azs = lb.get("AvailabilityZones", [])
        subnet_id = azs[0].get("SubnetId", "") if azs else ""
        sg_ids = lb.get("SecurityGroups", [])

        # Get private IP from AZ info
        private_ip = ""
        if azs:
            addresses = azs[0].get("LoadBalancerAddresses", [])
            if addresses:
                private_ip = addresses[0].get("PrivateIPv4Address", "")

        return {
            "resource_id": elb_arn,
            "resource_type": "elb",
            "vpc_id": vpc_id,
            "subnet_id": subnet_id,
            "security_group_ids": sg_ids,
            "private_ip": private_ip,
        }
    except Exception as e:
        logger.warning(f"_resolve_elb failed for {elb_arn}: {e}")
        return None
