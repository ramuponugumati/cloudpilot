"""Network Topology Visualizer — generate Mermaid diagrams of VPC infrastructure.

Discovers VPCs, subnets, route tables, NAT gateways, internet gateways,
and VPC peering connections across regions, then produces a Mermaid diagram
showing the topology.

All API calls are read-only (describe/list/get).
"""
import time
import logging

from cloudpilot.core import (
    BaseSkill, Finding, Severity, SkillResult, SkillRegistry,
)
from cloudpilot.aws_client import get_account_id, get_client, get_regions, parallel_regions
from cloudpilot.skills.network_helpers import (
    discover_route_tables,
    discover_vpc_peerings,
    discover_internet_gateways,
    discover_nat_gateways,
)

logger = logging.getLogger(__name__)


class NetworkTopologyVisualizer(BaseSkill):
    name = "network-topology"
    description = "Generate Mermaid network topology diagrams of VPC infrastructure"
    version = "0.1.0"

    def scan(self, regions=None, profile=None, account_id=None, **kwargs) -> SkillResult:
        """Discover network components and generate Mermaid diagram."""
        start = time.time()
        findings: list[Finding] = []
        errors: list[str] = []
        acct = account_id or ""

        try:
            acct = acct or get_account_id(profile)
        except Exception:
            pass

        scan_regions = regions or get_regions(profile=profile)

        # Discover topology across all regions in parallel
        try:
            def _discover_for_region(region, profile=None):
                return self._discover_topology(region, profile)

            all_topologies = parallel_regions(
                _discover_for_region, scan_regions, profile=profile,
            )
        except Exception as e:
            errors.append(f"parallel_regions topology discovery: {e}")
            all_topologies = []

        # Merge topologies from all regions
        merged = {
            "vpcs": [],
            "subnets": [],
            "route_tables": [],
            "nat_gateways": [],
            "internet_gateways": [],
            "peerings": [],
        }
        for topo in all_topologies:
            if isinstance(topo, dict):
                for key in merged:
                    merged[key].extend(topo.get(key, []))

        # Generate Mermaid diagram
        try:
            mermaid = self._generate_mermaid(merged)
        except Exception as e:
            mermaid = "graph LR\n    error[Diagram generation failed]"
            errors.append(f"_generate_mermaid: {e}")

        # Build component summary
        summary = {
            "vpcs": len(merged["vpcs"]),
            "subnets": len(merged["subnets"]),
            "route_tables": len(merged["route_tables"]),
            "nat_gateways": len(merged["nat_gateways"]),
            "internet_gateways": len(merged["internet_gateways"]),
            "peerings": len(merged["peerings"]),
        }

        findings.append(Finding(
            skill=self.name,
            title="Network Topology Diagram",
            severity=Severity.INFO,
            description=(
                f"Generated network topology diagram covering {summary['vpcs']} VPC(s), "
                f"{summary['subnets']} subnet(s), {summary['route_tables']} route table(s), "
                f"{summary['nat_gateways']} NAT gateway(s), "
                f"{summary['internet_gateways']} internet gateway(s), "
                f"and {summary['peerings']} VPC peering connection(s)."
            ),
            resource_id="",
            account_id=acct,
            region=",".join(scan_regions),
            recommended_action="Review the topology diagram for architecture validation.",
            metadata={
                "mermaid_diagram": mermaid,
                "component_summary": summary,
            },
        ))

        duration = time.time() - start
        return SkillResult(
            skill_name=self.name,
            findings=findings,
            duration_seconds=duration,
            accounts_scanned=1,
            regions_scanned=len(scan_regions),
            errors=errors,
        )

    def _discover_topology(self, region: str, profile: str = None) -> dict:
        """Discover all network components in a region.

        Returns dict with keys: vpcs, subnets, route_tables, nat_gateways,
        internet_gateways, peerings.
        """
        topology: dict = {
            "vpcs": [],
            "subnets": [],
            "route_tables": [],
            "nat_gateways": [],
            "internet_gateways": [],
            "peerings": [],
        }

        # Discover VPCs
        try:
            ec2 = get_client("ec2", region=region, profile=profile)
            paginator = ec2.get_paginator("describe_vpcs")
            for page in paginator.paginate():
                for vpc in page["Vpcs"]:
                    name = ""
                    for tag in vpc.get("Tags", []):
                        if tag["Key"] == "Name":
                            name = tag["Value"]
                            break
                    topology["vpcs"].append({
                        "vpc_id": vpc["VpcId"],
                        "cidr": vpc.get("CidrBlock", ""),
                        "name": name,
                        "region": region,
                    })
        except Exception as e:
            logger.warning(f"discover_vpcs failed in {region}: {e}")

        # Discover subnets
        try:
            ec2 = get_client("ec2", region=region, profile=profile)
            paginator = ec2.get_paginator("describe_subnets")
            for page in paginator.paginate():
                for subnet in page["Subnets"]:
                    name = ""
                    for tag in subnet.get("Tags", []):
                        if tag["Key"] == "Name":
                            name = tag["Value"]
                            break
                    topology["subnets"].append({
                        "subnet_id": subnet["SubnetId"],
                        "vpc_id": subnet.get("VpcId", ""),
                        "cidr": subnet.get("CidrBlock", ""),
                        "availability_zone": subnet.get("AvailabilityZone", ""),
                        "name": name,
                        "region": region,
                    })
        except Exception as e:
            logger.warning(f"discover_subnets failed in {region}: {e}")

        # Use shared helpers for the rest
        try:
            topology["route_tables"] = discover_route_tables(region, profile)
        except Exception as e:
            logger.warning(f"discover_route_tables failed in {region}: {e}")

        try:
            topology["nat_gateways"] = discover_nat_gateways(region, profile)
        except Exception as e:
            logger.warning(f"discover_nat_gateways failed in {region}: {e}")

        try:
            topology["internet_gateways"] = discover_internet_gateways(region, profile)
        except Exception as e:
            logger.warning(f"discover_internet_gateways failed in {region}: {e}")

        try:
            topology["peerings"] = discover_vpc_peerings(region, profile)
        except Exception as e:
            logger.warning(f"discover_vpc_peerings failed in {region}: {e}")

        return topology

    def _generate_mermaid(self, topology: dict) -> str:
        """Generate Mermaid diagram string from topology data.

        VPCs as top-level subgraphs, subnets as nested subgraphs,
        route table associations as labeled edges, VPC peering as
        bidirectional edges, NAT GWs and IGWs as distinct nodes.
        """
        lines: list[str] = ["graph TB"]

        vpcs = topology.get("vpcs", [])
        subnets = topology.get("subnets", [])
        route_tables = topology.get("route_tables", [])
        nat_gateways = topology.get("nat_gateways", [])
        internet_gateways = topology.get("internet_gateways", [])
        peerings = topology.get("peerings", [])

        collapse = self._should_collapse(subnets)

        # Build lookup maps
        subnets_by_vpc: dict[str, list[dict]] = {}
        for s in subnets:
            vpc_id = s.get("vpc_id", "")
            subnets_by_vpc.setdefault(vpc_id, []).append(s)

        nat_gw_by_vpc: dict[str, list[dict]] = {}
        for ngw in nat_gateways:
            vpc_id = ngw.get("vpc_id", "")
            nat_gw_by_vpc.setdefault(vpc_id, []).append(ngw)

        igw_by_vpc: dict[str, dict] = {}
        for igw in internet_gateways:
            vpc_id = igw.get("vpc_id", "")
            if vpc_id:
                igw_by_vpc[vpc_id] = igw

        rt_by_vpc: dict[str, list[dict]] = {}
        for rt in route_tables:
            vpc_id = rt.get("vpc_id", "")
            rt_by_vpc.setdefault(vpc_id, []).append(rt)

        # Sanitize ID for Mermaid (replace dashes with underscores)
        def mid(aws_id: str) -> str:
            return aws_id.replace("-", "_")

        # Generate VPC subgraphs
        for vpc in vpcs:
            vpc_id = vpc.get("vpc_id", "")
            vpc_name = vpc.get("name") or vpc_id
            vpc_cidr = vpc.get("cidr", "")
            label = f"{vpc_name} ({vpc_cidr})" if vpc_cidr else vpc_name

            lines.append(f"    subgraph {mid(vpc_id)}[\"{label}\"]")

            # Internet gateway node
            igw = igw_by_vpc.get(vpc_id)
            if igw:
                igw_id = igw["igw_id"]
                lines.append(f"        {mid(igw_id)}[/IGW: {igw_id}/]")

            # NAT gateway nodes
            for ngw in nat_gw_by_vpc.get(vpc_id, []):
                ngw_id = ngw["nat_gw_id"]
                lines.append(f"        {mid(ngw_id)}[\\NAT: {ngw_id}\\]")

            # Subnets
            vpc_subnets = subnets_by_vpc.get(vpc_id, [])
            if collapse:
                # Collapse by AZ
                az_counts: dict[str, dict] = {}
                for s in vpc_subnets:
                    az = s.get("availability_zone", "unknown")
                    classification = self._classify_subnet(s, route_tables, internet_gateways)
                    key = az
                    if key not in az_counts:
                        az_counts[key] = {"total": 0, "public": 0, "private": 0}
                    az_counts[key]["total"] += 1
                    if classification == "Public":
                        az_counts[key]["public"] += 1
                    else:
                        az_counts[key]["private"] += 1

                for az, counts in sorted(az_counts.items()):
                    az_label = (
                        f"{az}: {counts['total']} subnets "
                        f"({counts['public']} Public, {counts['private']} Private)"
                    )
                    az_node = mid(f"{vpc_id}_{az}")
                    lines.append(f"        {az_node}[\"{az_label}\"]")
            else:
                # Individual subnet subgraphs
                for s in vpc_subnets:
                    subnet_id = s.get("subnet_id", "")
                    subnet_name = s.get("name") or subnet_id
                    az = s.get("availability_zone", "")
                    classification = self._classify_subnet(s, route_tables, internet_gateways)
                    subnet_label = f"{classification}: {subnet_name} ({az})"
                    lines.append(f"        subgraph {mid(subnet_id)}[\"{subnet_label}\"]")
                    lines.append(f"            {mid(subnet_id)}_node[\"{s.get('cidr', '')}\"]")
                    lines.append("        end")

            lines.append("    end")

        # Route table association edges
        for rt in route_tables:
            rt_id = rt.get("route_table_id", "")
            for subnet_id in rt.get("subnet_associations", []):
                for route in rt.get("routes", []):
                    target_type = route.get("target_type", "")
                    target_id = route.get("target_id", "")
                    dest = route.get("destination_cidr", "")

                    if target_type == "local" or not target_id:
                        continue

                    lines.append(
                        f"    {mid(subnet_id)} -->|\"rt:{rt_id} dest:{dest}\"| {mid(target_id)}"
                    )

        # VPC peering bidirectional edges
        for pcx in peerings:
            peering_id = pcx.get("peering_id", "")
            req_vpc = pcx.get("requester_vpc_id", "")
            acc_vpc = pcx.get("accepter_vpc_id", "")
            status = pcx.get("status", "")
            if req_vpc and acc_vpc:
                lines.append(
                    f"    {mid(req_vpc)} <-->|\"Peering: {peering_id} ({status})\"| {mid(acc_vpc)}"
                )

        return "\n".join(lines)

    def _should_collapse(self, subnets: list[dict]) -> bool:
        """Return True when subnet count > 30 (triggers AZ-level collapse)."""
        return len(subnets) > 30

    def _classify_subnet(self, subnet: dict, route_tables: list[dict],
                         igws: list[dict]) -> str:
        """Return 'Public' if route table has 0.0.0.0/0 via IGW, 'Private' otherwise."""
        subnet_id = subnet.get("subnet_id", "")
        vpc_id = subnet.get("vpc_id", "")

        # Build set of IGW IDs for this VPC
        igw_ids = set()
        for igw in igws:
            if igw.get("vpc_id") == vpc_id:
                igw_ids.add(igw.get("igw_id", ""))

        if not igw_ids:
            return "Private"

        # Find the route table for this subnet
        rt = self._find_route_table_for_subnet(subnet_id, vpc_id, route_tables)
        if not rt:
            return "Private"

        # Check if any route points to 0.0.0.0/0 via an IGW
        for route in rt.get("routes", []):
            dest = route.get("destination_cidr", "")
            target_id = route.get("target_id", "")
            target_type = route.get("target_type", "")
            if dest == "0.0.0.0/0" and (
                target_type == "internet-gateway" or target_id in igw_ids
            ):
                return "Public"

        return "Private"

    def _find_route_table_for_subnet(self, subnet_id: str, vpc_id: str,
                                     route_tables: list[dict]) -> dict | None:
        """Find the route table associated with a subnet, or the VPC main RT."""
        # Explicit association
        for rt in route_tables:
            if subnet_id and subnet_id in rt.get("subnet_associations", []):
                return rt
        # Main route table (no explicit subnet associations) for the VPC
        for rt in route_tables:
            if rt.get("vpc_id") == vpc_id and not rt.get("subnet_associations"):
                return rt
        # Fallback: any RT in the VPC
        for rt in route_tables:
            if rt.get("vpc_id") == vpc_id:
                return rt
        return None


# ---------------------------------------------------------------------------
# Auto-register
# ---------------------------------------------------------------------------
SkillRegistry.register(NetworkTopologyVisualizer())
