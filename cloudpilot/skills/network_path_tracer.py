"""VPC Path Tracer — trace network connectivity between two AWS resources.

Discovers VPCs, subnets, route tables, VPC peerings, IGWs, and NAT GWs,
then constructs an ordered path of hops and evaluates reachability.

All API calls are read-only (describe/list/get).
"""
import time
import logging

from cloudpilot.core import (
    BaseSkill, Finding, Severity, SkillResult, SkillRegistry,
    PathHop, PathResult,
)
from cloudpilot.aws_client import get_account_id
from cloudpilot.skills.network_helpers import (
    resolve_resource_network_info,
    discover_route_tables,
    discover_vpc_peerings,
    discover_internet_gateways,
    discover_nat_gateways,
)

logger = logging.getLogger(__name__)


class NetworkPathTracer(BaseSkill):
    name = "network-path-tracer"
    description = "Trace network connectivity path between two AWS resources"
    version = "0.1.0"

    def scan(self, regions=None, profile=None, account_id=None,
             source=None, destination=None, **kwargs) -> SkillResult:
        """Trace path from source to destination resource.

        Returns SkillResult with one Finding per path:
          - INFO  = reachable
          - HIGH  = blocked
          - LOW   = unsupported / missing resource
        """
        start = time.time()
        findings: list[Finding] = []
        errors: list[str] = []
        acct = account_id or ""
        region = regions[0] if regions else "us-east-1"

        try:
            acct = acct or get_account_id(profile)
        except Exception:
            pass

        # --- Validate inputs ---
        if not source or not destination:
            findings.append(Finding(
                skill=self.name,
                title="Missing source or destination",
                severity=Severity.LOW,
                description="Both source and destination resource IDs are required for path tracing.",
                resource_id="",
                account_id=acct,
                region=region,
                recommended_action="Provide both source and destination resource IDs.",
            ))
            return SkillResult(
                skill_name=self.name, findings=findings,
                duration_seconds=time.time() - start,
                accounts_scanned=1, regions_scanned=1, errors=errors,
            )

        # --- Resolve source and destination ---
        source_info = resolve_resource_network_info(source, region, profile)
        dest_info = resolve_resource_network_info(destination, region, profile)

        if source_info is None:
            findings.append(Finding(
                skill=self.name,
                title=f"Unsupported or missing resource: {source}",
                severity=Severity.LOW,
                description=f"Could not resolve network info for resource '{source}'. "
                            "It may be an unsupported resource type or does not exist.",
                resource_id=source,
                account_id=acct,
                region=region,
                recommended_action="Verify the resource ID and ensure it is a supported type "
                                   "(EC2 i-*, RDS db-*, Lambda function name, ECS task ARN, ELB ARN).",
            ))
        if dest_info is None:
            findings.append(Finding(
                skill=self.name,
                title=f"Unsupported or missing resource: {destination}",
                severity=Severity.LOW,
                description=f"Could not resolve network info for resource '{destination}'. "
                            "It may be an unsupported resource type or does not exist.",
                resource_id=destination,
                account_id=acct,
                region=region,
                recommended_action="Verify the resource ID and ensure it is a supported type "
                                   "(EC2 i-*, RDS db-*, Lambda function name, ECS task ARN, ELB ARN).",
            ))

        if source_info is None or dest_info is None:
            return SkillResult(
                skill_name=self.name, findings=findings,
                duration_seconds=time.time() - start,
                accounts_scanned=1, regions_scanned=1, errors=errors,
            )

        # --- Discover network components ---
        try:
            route_tables = discover_route_tables(region, profile)
        except Exception as e:
            route_tables = []
            errors.append(f"discover_route_tables: {e}")

        try:
            peerings = discover_vpc_peerings(region, profile)
        except Exception as e:
            peerings = []
            errors.append(f"discover_vpc_peerings: {e}")

        try:
            igws = discover_internet_gateways(region, profile)
        except Exception as e:
            igws = []
            errors.append(f"discover_internet_gateways: {e}")

        try:
            nat_gws = discover_nat_gateways(region, profile)
        except Exception as e:
            nat_gws = []
            errors.append(f"discover_nat_gateways: {e}")

        # --- Build and evaluate path ---
        hops = self._build_path(source_info, dest_info, route_tables, peerings, igws, nat_gws)
        reachable = self._evaluate_hops(hops)

        path_result = PathResult(
            source_id=source,
            destination_id=destination,
            hops=hops,
            reachable=reachable,
            blocked_at=next((h.component_id for h in hops if not h.allowed), ""),
        )

        if reachable:
            findings.append(Finding(
                skill=self.name,
                title=f"Path reachable: {source} → {destination}",
                severity=Severity.INFO,
                description=f"Network path from {source} to {destination} is reachable "
                            f"through {len(hops)} hop(s).",
                resource_id=source,
                account_id=acct,
                region=region,
                recommended_action="No action required — path is open.",
                metadata={
                    "path_result": path_result.to_dict(),
                    "hop_count": len(hops),
                    "source_vpc": source_info.get("vpc_id", ""),
                    "destination_vpc": dest_info.get("vpc_id", ""),
                },
            ))
        else:
            blocked_hop = next((h for h in hops if not h.allowed), None)
            blocked_desc = ""
            if blocked_hop:
                blocked_desc = (f" Blocked at {blocked_hop.component_type} "
                                f"({blocked_hop.component_id}): {blocked_hop.reason}")
            findings.append(Finding(
                skill=self.name,
                title=f"Path blocked: {source} → {destination}",
                severity=Severity.HIGH,
                description=f"Network path from {source} to {destination} is blocked.{blocked_desc}",
                resource_id=source,
                account_id=acct,
                region=region,
                recommended_action="Review the blocked component and update route tables or peering connections.",
                metadata={
                    "path_result": path_result.to_dict(),
                    "hop_count": len(hops),
                    "blocked_at": path_result.blocked_at,
                    "source_vpc": source_info.get("vpc_id", ""),
                    "destination_vpc": dest_info.get("vpc_id", ""),
                },
            ))

        duration = time.time() - start
        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=duration,
            accounts_scanned=1, regions_scanned=1, errors=errors,
        )

    def _build_path(self, source_info: dict, dest_info: dict,
                    route_tables: list[dict], peerings: list[dict],
                    igws: list[dict], nat_gws: list[dict]) -> list[PathHop]:
        """Construct ordered list of PathHop objects from source to destination.

        Same-VPC: source subnet → route table → destination subnet
        Cross-VPC with peering: source subnet → route table → vpc_peering → route table → dest subnet
        Cross-VPC no peering: returns single unreachable hop
        """
        hops: list[PathHop] = []
        src_vpc = source_info.get("vpc_id", "")
        dst_vpc = dest_info.get("vpc_id", "")
        src_subnet = source_info.get("subnet_id", "")
        dst_subnet = dest_info.get("subnet_id", "")

        # Source subnet hop
        if src_subnet:
            hops.append(PathHop(
                component_type="subnet",
                component_id=src_subnet,
                component_name=f"Source subnet ({src_subnet})",
                allowed=True,
                reason="Traffic originates here",
            ))

        if src_vpc == dst_vpc and src_vpc:
            # --- Same VPC path ---
            # Find route table for source subnet
            src_rt = self._find_route_table(src_subnet, src_vpc, route_tables)
            if src_rt:
                # Check if local route covers destination
                has_local = any(
                    r.get("target_type") == "local"
                    for r in src_rt.get("routes", [])
                )
                hops.append(PathHop(
                    component_type="route_table",
                    component_id=src_rt["route_table_id"],
                    component_name=f"Route table ({src_rt['route_table_id']})",
                    allowed=has_local,
                    reason="Local route for intra-VPC traffic" if has_local else "No local route found",
                ))
            else:
                hops.append(PathHop(
                    component_type="route_table",
                    component_id="unknown",
                    component_name="Route table (not found)",
                    allowed=False,
                    reason="No route table associated with source subnet",
                ))

        elif src_vpc and dst_vpc and src_vpc != dst_vpc:
            # --- Cross-VPC path ---
            # Find active peering between the two VPCs
            peering = self._find_peering(src_vpc, dst_vpc, peerings)

            # Source route table
            src_rt = self._find_route_table(src_subnet, src_vpc, route_tables)
            if src_rt:
                has_peering_route = any(
                    r.get("target_type") == "vpc-peering"
                    for r in src_rt.get("routes", [])
                )
                hops.append(PathHop(
                    component_type="route_table",
                    component_id=src_rt["route_table_id"],
                    component_name=f"Route table ({src_rt['route_table_id']})",
                    allowed=has_peering_route,
                    reason="Route to VPC peering found" if has_peering_route else "No peering route in source route table",
                ))
            else:
                hops.append(PathHop(
                    component_type="route_table",
                    component_id="unknown",
                    component_name="Route table (not found)",
                    allowed=False,
                    reason="No route table associated with source subnet",
                ))

            if peering:
                hops.append(PathHop(
                    component_type="vpc_peering",
                    component_id=peering["peering_id"],
                    component_name=f"VPC Peering ({peering['peering_id']})",
                    allowed=peering.get("status") == "active",
                    reason=f"Peering status: {peering.get('status', 'unknown')}",
                ))
            else:
                hops.append(PathHop(
                    component_type="vpc_peering",
                    component_id="none",
                    component_name="VPC Peering (not found)",
                    allowed=False,
                    reason=f"No peering connection between {src_vpc} and {dst_vpc}",
                ))

            # Destination route table
            dst_rt = self._find_route_table(dst_subnet, dst_vpc, route_tables)
            if dst_rt:
                has_peering_route = any(
                    r.get("target_type") == "vpc-peering"
                    for r in dst_rt.get("routes", [])
                )
                hops.append(PathHop(
                    component_type="route_table",
                    component_id=dst_rt["route_table_id"],
                    component_name=f"Route table ({dst_rt['route_table_id']})",
                    allowed=has_peering_route,
                    reason="Return route via peering found" if has_peering_route else "No peering route in destination route table",
                ))

        else:
            # No VPC info — can't determine path
            hops.append(PathHop(
                component_type="vpc",
                component_id="unknown",
                component_name="VPC (unknown)",
                allowed=False,
                reason="Unable to determine VPC for source or destination",
            ))

        # Destination subnet hop
        if dst_subnet:
            hops.append(PathHop(
                component_type="subnet",
                component_id=dst_subnet,
                component_name=f"Destination subnet ({dst_subnet})",
                allowed=True,
                reason="Traffic terminates here",
            ))

        return hops

    def _evaluate_hops(self, hops: list[PathHop]) -> bool:
        """Return True if all hops allow traffic, False if any hop blocks."""
        if not hops:
            return False
        return all(hop.allowed for hop in hops)

    def _find_route_table(self, subnet_id: str, vpc_id: str,
                          route_tables: list[dict]) -> dict | None:
        """Find the route table associated with a subnet, or the VPC main route table."""
        # First: explicit subnet association
        for rt in route_tables:
            if subnet_id and subnet_id in rt.get("subnet_associations", []):
                return rt
        # Fallback: main route table for the VPC (no explicit subnet associations)
        for rt in route_tables:
            if rt.get("vpc_id") == vpc_id and not rt.get("subnet_associations"):
                return rt
        # Last resort: any route table in the VPC
        for rt in route_tables:
            if rt.get("vpc_id") == vpc_id:
                return rt
        return None

    def _find_peering(self, vpc_a: str, vpc_b: str,
                      peerings: list[dict]) -> dict | None:
        """Find an active VPC peering connection between two VPCs."""
        for p in peerings:
            req = p.get("requester_vpc_id", "")
            acc = p.get("accepter_vpc_id", "")
            if (req == vpc_a and acc == vpc_b) or (req == vpc_b and acc == vpc_a):
                return p
        return None


# ---------------------------------------------------------------------------
# Auto-register
# ---------------------------------------------------------------------------
SkillRegistry.register(NetworkPathTracer())
