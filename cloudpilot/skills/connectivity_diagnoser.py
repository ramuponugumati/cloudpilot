"""Connectivity Diagnoser — diagnose why one resource cannot reach another.

Evaluates security groups (egress/ingress), NACLs, route tables, VPC peering,
NAT gateways, and internet gateways independently and returns one Finding per
blocking issue (CRITICAL) or a single INFO Finding when all checks pass.

All API calls are read-only (describe/list/get).
"""
import ipaddress
import time
import logging

from cloudpilot.core import (
    BaseSkill, Finding, Severity, SkillResult, SkillRegistry,
)
from cloudpilot.aws_client import get_account_id
from cloudpilot.skills.network_helpers import (
    resolve_resource_network_info,
    discover_security_groups,
    discover_nacls,
    discover_route_tables,
    discover_vpc_peerings,
    discover_internet_gateways,
    discover_nat_gateways,
)

logger = logging.getLogger(__name__)


class ConnectivityDiagnoser(BaseSkill):
    name = "connectivity-diagnoser"
    description = "Diagnose why one resource cannot reach another"
    version = "0.1.0"

    def scan(self, regions=None, profile=None, account_id=None,
             source=None, destination=None,
             protocol="tcp", port=443, **kwargs) -> SkillResult:
        """Run all connectivity checks and return findings per issue."""
        start = time.time()
        findings: list[Finding] = []
        errors: list[str] = []
        acct = account_id or ""
        region = regions[0] if regions else "us-east-1"

        # Defaults for protocol/port
        if not protocol:
            protocol = "tcp"
        try:
            port = int(port)
        except (TypeError, ValueError):
            port = 443

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
                description="Both source and destination resource IDs are required.",
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
                title=f"Cannot resolve source: {source}",
                severity=Severity.CRITICAL,
                description=f"Could not resolve network info for source '{source}'.",
                resource_id=source,
                account_id=acct,
                region=region,
                recommended_action="Verify the resource ID exists and is a supported type.",
                metadata={"component_id": source, "recommended_action": "Verify resource ID"},
            ))
        if dest_info is None:
            findings.append(Finding(
                skill=self.name,
                title=f"Cannot resolve destination: {destination}",
                severity=Severity.CRITICAL,
                description=f"Could not resolve network info for destination '{destination}'.",
                resource_id=destination,
                account_id=acct,
                region=region,
                recommended_action="Verify the resource ID exists and is a supported type.",
                metadata={"component_id": destination, "recommended_action": "Verify resource ID"},
            ))

        if source_info is None or dest_info is None:
            return SkillResult(
                skill_name=self.name, findings=findings,
                duration_seconds=time.time() - start,
                accounts_scanned=1, regions_scanned=1, errors=errors,
            )

        # --- Discover network components (independently, errors don't block others) ---
        sgs = self._safe_discover(discover_security_groups, region, profile, errors, "security_groups")
        nacls = self._safe_discover(discover_nacls, region, profile, errors, "nacls")
        route_tables = self._safe_discover(discover_route_tables, region, profile, errors, "route_tables")
        peerings = self._safe_discover(discover_vpc_peerings, region, profile, errors, "vpc_peerings")
        igws = self._safe_discover(discover_internet_gateways, region, profile, errors, "igws")
        nat_gws = self._safe_discover(discover_nat_gateways, region, profile, errors, "nat_gws")

        source_ip = source_info.get("private_ip", "")
        dest_ip = dest_info.get("private_ip", "")
        src_vpc = source_info.get("vpc_id", "")
        dst_vpc = dest_info.get("vpc_id", "")
        src_subnet = source_info.get("subnet_id", "")
        dst_subnet = dest_info.get("subnet_id", "")

        # --- Run all checks independently ---
        # 1. SG egress on source
        f = self._check_sg_egress(source_info, sgs, dest_ip, protocol, port)
        if f:
            f.account_id = acct
            f.region = region
            findings.append(f)

        # 2. SG ingress on destination
        f = self._check_sg_ingress(dest_info, sgs, source_ip, protocol, port)
        if f:
            f.account_id = acct
            f.region = region
            findings.append(f)

        # 3. NACL on source subnet (outbound)
        f = self._check_nacl(src_subnet, nacls, dest_ip, protocol, port, "outbound")
        if f:
            f.account_id = acct
            f.region = region
            findings.append(f)

        # 4. NACL on destination subnet (inbound)
        f = self._check_nacl(dst_subnet, nacls, source_ip, protocol, port, "inbound")
        if f:
            f.account_id = acct
            f.region = region
            findings.append(f)

        # 5. Route table check
        f = self._check_route(source_info, dest_ip, route_tables)
        if f:
            f.account_id = acct
            f.region = region
            findings.append(f)

        # 6. Cross-VPC peering check
        if src_vpc and dst_vpc and src_vpc != dst_vpc:
            f = self._check_peering(src_vpc, dst_vpc, peerings)
            if f:
                f.account_id = acct
                f.region = region
                findings.append(f)

        # 7. NAT gateway check (private subnet → internet)
        if dest_ip and self._is_public_ip(dest_ip):
            f = self._check_nat_gateway(source_info, route_tables, nat_gws)
            if f:
                f.account_id = acct
                f.region = region
                findings.append(f)

        # 8. IGW check (public subnet → internet)
        if dest_ip and self._is_public_ip(dest_ip):
            f = self._check_igw(src_vpc, igws, route_tables, src_subnet)
            if f:
                f.account_id = acct
                f.region = region
                findings.append(f)

        # --- Summary ---
        blocking = [ff for ff in findings if ff.severity == Severity.CRITICAL]
        if not blocking:
            findings.append(Finding(
                skill=self.name,
                title=f"Connectivity OK: {source} → {destination}",
                severity=Severity.INFO,
                description=(
                    f"All checks passed for {protocol.upper()}/{port} from "
                    f"{source} to {destination}. The path appears open."
                ),
                resource_id=source,
                account_id=acct,
                region=region,
                recommended_action="No action required — connectivity appears healthy.",
                metadata={
                    "component_id": "all",
                    "recommended_action": "No action required",
                    "protocol": protocol,
                    "port": port,
                    "source_vpc": src_vpc,
                    "destination_vpc": dst_vpc,
                },
            ))

        duration = time.time() - start
        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=duration,
            accounts_scanned=1, regions_scanned=1, errors=errors,
        )

    # ------------------------------------------------------------------
    # Helper: safe discovery wrapper
    # ------------------------------------------------------------------
    def _safe_discover(self, fn, region, profile, errors, label):
        """Call a discover function, catch errors, append to errors list."""
        try:
            return fn(region, profile)
        except Exception as e:
            errors.append(f"{label}: {e}")
            return []

    # ------------------------------------------------------------------
    # Check: Security Group Egress
    # ------------------------------------------------------------------
    def _check_sg_egress(self, source_info: dict, sgs: list[dict],
                         dest_ip: str, protocol: str, port: int) -> Finding | None:
        """Check source SG egress rules allow traffic to destination.

        Returns None if at least one egress rule matches (no issue).
        Returns a CRITICAL Finding if no egress rule allows the traffic.
        """
        src_sg_ids = source_info.get("security_group_ids", [])
        if not src_sg_ids:
            return None  # No SGs to check

        # Collect all egress rules from source SGs
        for sg in sgs:
            if sg["group_id"] in src_sg_ids:
                for rule in sg.get("outbound_rules", []):
                    if self._rule_matches(rule, dest_ip, protocol, port):
                        return None  # Traffic allowed

        # No matching egress rule found
        return Finding(
            skill=self.name,
            title=f"SG egress blocks traffic to {dest_ip}:{port}",
            severity=Severity.CRITICAL,
            description=(
                f"No egress rule in source security groups {src_sg_ids} allows "
                f"{protocol.upper()}/{port} to {dest_ip}."
            ),
            resource_id=source_info.get("resource_id", ""),
            recommended_action=(
                f"Add an outbound rule allowing {protocol.upper()}/{port} to "
                f"the destination IP or CIDR."
            ),
            metadata={
                "component_id": ",".join(src_sg_ids),
                "recommended_action": f"Add egress rule for {protocol}/{port} to {dest_ip}",
            },
        )

    # ------------------------------------------------------------------
    # Check: Security Group Ingress
    # ------------------------------------------------------------------
    def _check_sg_ingress(self, dest_info: dict, sgs: list[dict],
                          source_ip: str, protocol: str, port: int) -> Finding | None:
        """Check destination SG ingress rules allow traffic from source.

        Returns None if at least one ingress rule matches (no issue).
        Returns a CRITICAL Finding if no ingress rule allows the traffic.
        """
        dst_sg_ids = dest_info.get("security_group_ids", [])
        if not dst_sg_ids:
            return None

        for sg in sgs:
            if sg["group_id"] in dst_sg_ids:
                for rule in sg.get("inbound_rules", []):
                    if self._rule_matches(rule, source_ip, protocol, port):
                        return None

        return Finding(
            skill=self.name,
            title=f"SG ingress blocks traffic from {source_ip}:{port}",
            severity=Severity.CRITICAL,
            description=(
                f"No ingress rule in destination security groups {dst_sg_ids} allows "
                f"{protocol.upper()}/{port} from {source_ip}."
            ),
            resource_id=dest_info.get("resource_id", ""),
            recommended_action=(
                f"Add an inbound rule allowing {protocol.upper()}/{port} from "
                f"the source IP or CIDR."
            ),
            metadata={
                "component_id": ",".join(dst_sg_ids),
                "recommended_action": f"Add ingress rule for {protocol}/{port} from {source_ip}",
            },
        )

    # ------------------------------------------------------------------
    # Check: NACL
    # ------------------------------------------------------------------
    def _check_nacl(self, subnet_id: str, nacls: list[dict],
                    remote_ip: str, protocol: str, port: int,
                    direction: str) -> Finding | None:
        """Check NACL rules for a subnet in the given direction.

        Evaluates rules in ascending rule_number order, returns the action
        of the first matching rule. If no rule matches, returns a blocking Finding.
        """
        if not subnet_id:
            return None

        # Find the NACL associated with this subnet
        nacl = None
        for n in nacls:
            if subnet_id in n.get("subnet_associations", []):
                nacl = n
                break

        if nacl is None:
            return None  # No NACL found — default VPC NACL allows all

        rules_key = "inbound_rules" if direction == "inbound" else "outbound_rules"
        rules = nacl.get(rules_key, [])

        # Rules are already sorted by rule_number from the helper
        for rule in sorted(rules, key=lambda r: r.get("rule_number", 32767)):
            if self._nacl_rule_matches(rule, remote_ip, protocol, port):
                if rule.get("action") == "allow":
                    return None  # Allowed
                else:
                    # Denied by explicit rule
                    return Finding(
                        skill=self.name,
                        title=f"NACL {direction} denies traffic (rule {rule.get('rule_number')})",
                        severity=Severity.CRITICAL,
                        description=(
                            f"NACL {nacl['nacl_id']} rule {rule.get('rule_number')} denies "
                            f"{direction} {protocol.upper()}/{port} for {remote_ip}."
                        ),
                        resource_id=nacl["nacl_id"],
                        recommended_action=(
                            f"Add an allow rule with a lower rule number for "
                            f"{protocol.upper()}/{port} in the {direction} direction."
                        ),
                        metadata={
                            "component_id": nacl["nacl_id"],
                            "recommended_action": f"Add allow rule for {protocol}/{port} {direction}",
                        },
                    )

        # No matching rule — implicit deny
        return Finding(
            skill=self.name,
            title=f"NACL {direction} implicit deny",
            severity=Severity.CRITICAL,
            description=(
                f"No NACL rule in {nacl['nacl_id']} matches {direction} "
                f"{protocol.upper()}/{port} for {remote_ip}. Implicit deny applies."
            ),
            resource_id=nacl["nacl_id"],
            recommended_action=(
                f"Add an allow rule for {protocol.upper()}/{port} in the {direction} direction."
            ),
            metadata={
                "component_id": nacl["nacl_id"],
                "recommended_action": f"Add allow rule for {protocol}/{port} {direction}",
            },
        )

    # ------------------------------------------------------------------
    # Check: Route Table
    # ------------------------------------------------------------------
    def _check_route(self, source_info: dict, dest_ip: str,
                     route_tables: list[dict]) -> Finding | None:
        """Check route table has a route to the destination CIDR.

        Uses longest prefix match. Returns None if a matching route exists.
        """
        src_subnet = source_info.get("subnet_id", "")
        src_vpc = source_info.get("vpc_id", "")

        if not dest_ip:
            return None

        rt = self._find_route_table(src_subnet, src_vpc, route_tables)
        if rt is None:
            return Finding(
                skill=self.name,
                title="No route table found for source subnet",
                severity=Severity.CRITICAL,
                description=(
                    f"No route table associated with subnet {src_subnet} in VPC {src_vpc}."
                ),
                resource_id=src_subnet or src_vpc,
                recommended_action="Associate a route table with the source subnet.",
                metadata={
                    "component_id": src_subnet or src_vpc,
                    "recommended_action": "Associate route table with subnet",
                },
            )

        # Check for a matching route (longest prefix match)
        try:
            dest_addr = ipaddress.ip_address(dest_ip)
        except ValueError:
            return None

        best_match = None
        best_prefix_len = -1

        for route in rt.get("routes", []):
            dest_cidr = route.get("destination_cidr", "")
            if not dest_cidr:
                continue
            try:
                network = ipaddress.ip_network(dest_cidr, strict=False)
                if dest_addr in network and network.prefixlen > best_prefix_len:
                    best_match = route
                    best_prefix_len = network.prefixlen
            except ValueError:
                continue

        if best_match is not None:
            return None  # Route exists

        return Finding(
            skill=self.name,
            title=f"No route to {dest_ip}",
            severity=Severity.CRITICAL,
            description=(
                f"Route table {rt['route_table_id']} has no route matching "
                f"destination {dest_ip}."
            ),
            resource_id=rt["route_table_id"],
            recommended_action=f"Add a route for the destination CIDR to the route table.",
            metadata={
                "component_id": rt["route_table_id"],
                "recommended_action": f"Add route for {dest_ip}",
            },
        )

    # ------------------------------------------------------------------
    # Check: VPC Peering
    # ------------------------------------------------------------------
    def _check_peering(self, source_vpc: str, dest_vpc: str,
                       peerings: list[dict]) -> Finding | None:
        """Check VPC peering exists and is active between two VPCs.

        Returns None if an active peering exists.
        """
        for p in peerings:
            req = p.get("requester_vpc_id", "")
            acc = p.get("accepter_vpc_id", "")
            if (req == source_vpc and acc == dest_vpc) or (req == dest_vpc and acc == source_vpc):
                if p.get("status") == "active":
                    return None  # Active peering exists
                else:
                    return Finding(
                        skill=self.name,
                        title=f"VPC peering not active: {p['peering_id']}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"VPC peering {p['peering_id']} between {source_vpc} and "
                            f"{dest_vpc} exists but status is '{p.get('status', 'unknown')}'."
                        ),
                        resource_id=p["peering_id"],
                        recommended_action="Accept or activate the VPC peering connection.",
                        metadata={
                            "component_id": p["peering_id"],
                            "recommended_action": "Activate VPC peering connection",
                        },
                    )

        return Finding(
            skill=self.name,
            title=f"No VPC peering: {source_vpc} ↔ {dest_vpc}",
            severity=Severity.CRITICAL,
            description=(
                f"No VPC peering connection found between {source_vpc} and {dest_vpc}."
            ),
            resource_id=source_vpc,
            recommended_action="Create a VPC peering connection between the two VPCs.",
            metadata={
                "component_id": f"{source_vpc},{dest_vpc}",
                "recommended_action": "Create VPC peering connection",
            },
        )

    # ------------------------------------------------------------------
    # Check: NAT Gateway
    # ------------------------------------------------------------------
    def _check_nat_gateway(self, source_info: dict, route_tables: list[dict],
                           nat_gws: list[dict]) -> Finding | None:
        """Check NAT gateway route exists for private subnet → internet.

        Only relevant when destination is a public IP and source is in a
        private subnet (no IGW route). Returns None if NAT GW route exists.
        """
        src_subnet = source_info.get("subnet_id", "")
        src_vpc = source_info.get("vpc_id", "")

        rt = self._find_route_table(src_subnet, src_vpc, route_tables)
        if rt is None:
            return None  # Already reported by _check_route

        # Check if this is a public subnet (has IGW route) — if so, NAT not needed
        has_igw_route = any(
            r.get("target_type") == "internet-gateway"
            and r.get("destination_cidr") == "0.0.0.0/0"
            for r in rt.get("routes", [])
        )
        if has_igw_route:
            return None  # Public subnet — IGW handles internet access

        # Private subnet — check for NAT gateway route
        has_nat_route = any(
            r.get("target_type") == "nat-gateway"
            and r.get("destination_cidr") == "0.0.0.0/0"
            for r in rt.get("routes", [])
        )
        if has_nat_route:
            return None  # NAT GW route exists

        return Finding(
            skill=self.name,
            title=f"No NAT gateway route for private subnet {src_subnet}",
            severity=Severity.CRITICAL,
            description=(
                f"Subnet {src_subnet} has no route to 0.0.0.0/0 via a NAT gateway. "
                f"Internet-bound traffic from this private subnet will fail."
            ),
            resource_id=src_subnet,
            recommended_action="Add a route to 0.0.0.0/0 via a NAT gateway in the route table.",
            metadata={
                "component_id": rt["route_table_id"],
                "recommended_action": "Add NAT gateway route for 0.0.0.0/0",
            },
        )

    # ------------------------------------------------------------------
    # Check: Internet Gateway
    # ------------------------------------------------------------------
    def _check_igw(self, vpc_id: str, igws: list[dict],
                   route_tables: list[dict], subnet_id: str) -> Finding | None:
        """Check IGW attached and route exists for public subnet → internet.

        Returns None if IGW is attached and a route to 0.0.0.0/0 via IGW exists.
        """
        if not vpc_id:
            return None

        # Check if IGW is attached to the VPC
        igw_attached = any(igw.get("vpc_id") == vpc_id for igw in igws)

        rt = self._find_route_table(subnet_id, vpc_id, route_tables)

        # Check if this subnet even has an IGW route (i.e., is it a public subnet?)
        has_igw_route = False
        if rt:
            has_igw_route = any(
                r.get("target_type") == "internet-gateway"
                and r.get("destination_cidr") == "0.0.0.0/0"
                for r in rt.get("routes", [])
            )

        # If the subnet doesn't have an IGW route, this check is not relevant
        # (NAT gateway check handles private subnets)
        if not has_igw_route:
            return None

        if not igw_attached:
            return Finding(
                skill=self.name,
                title=f"No internet gateway attached to VPC {vpc_id}",
                severity=Severity.CRITICAL,
                description=(
                    f"VPC {vpc_id} has no internet gateway attached, but subnet "
                    f"{subnet_id} has a route to 0.0.0.0/0 via IGW."
                ),
                resource_id=vpc_id,
                recommended_action="Attach an internet gateway to the VPC.",
                metadata={
                    "component_id": vpc_id,
                    "recommended_action": "Attach internet gateway to VPC",
                },
            )

        return None  # IGW attached and route exists

    # ------------------------------------------------------------------
    # Matching helpers
    # ------------------------------------------------------------------
    def _rule_matches(self, rule: dict, ip: str, protocol: str, port: int) -> bool:
        """Check if a SG rule matches the given IP, protocol, and port."""
        rule_protocol = str(rule.get("protocol", ""))
        # Protocol -1 means all traffic
        if rule_protocol != "-1" and rule_protocol != protocol:
            return False

        # Port range check (skip for protocol -1 which covers all ports)
        if rule_protocol != "-1":
            from_port = rule.get("from_port", 0)
            to_port = rule.get("to_port", 0)
            try:
                if not (int(from_port) <= port <= int(to_port)):
                    return False
            except (ValueError, TypeError):
                return False

        # Source/destination CIDR check
        source = rule.get("source", "")
        source_type = rule.get("source_type", "")

        if source_type == "security_group":
            # SG references always match (the SG membership is the filter)
            return True

        if not ip or not source:
            return False

        try:
            network = ipaddress.ip_network(source, strict=False)
            addr = ipaddress.ip_address(ip)
            return addr in network
        except ValueError:
            return False

    def _nacl_rule_matches(self, rule: dict, ip: str, protocol: str, port: int) -> bool:
        """Check if a NACL rule matches the given IP, protocol, and port."""
        rule_protocol = str(rule.get("protocol", ""))
        # Protocol -1 means all traffic
        if rule_protocol != "-1" and rule_protocol != protocol:
            # Map protocol numbers: 6=tcp, 17=udp
            proto_map = {"6": "tcp", "17": "udp", "1": "icmp"}
            rule_proto_name = proto_map.get(rule_protocol, rule_protocol)
            if rule_proto_name != protocol:
                return False

        # Port range check
        if rule_protocol != "-1":
            port_range = rule.get("port_range", "all")
            if port_range != "all":
                try:
                    if "-" in str(port_range):
                        parts = str(port_range).split("-")
                        from_p, to_p = int(parts[0]), int(parts[1])
                    else:
                        from_p = to_p = int(port_range)
                    if not (from_p <= port <= to_p):
                        return False
                except (ValueError, IndexError):
                    return False

        # CIDR check
        cidr = rule.get("cidr", "")
        if not ip or not cidr:
            # If no CIDR specified, rule matches all
            return not cidr

        try:
            network = ipaddress.ip_network(cidr, strict=False)
            addr = ipaddress.ip_address(ip)
            return addr in network
        except ValueError:
            return False

    def _find_route_table(self, subnet_id: str, vpc_id: str,
                          route_tables: list[dict]) -> dict | None:
        """Find the route table associated with a subnet, or the VPC main route table."""
        # Explicit subnet association
        for rt in route_tables:
            if subnet_id and subnet_id in rt.get("subnet_associations", []):
                return rt
        # Main route table (no explicit subnet associations)
        for rt in route_tables:
            if rt.get("vpc_id") == vpc_id and not rt.get("subnet_associations"):
                return rt
        # Any route table in the VPC
        for rt in route_tables:
            if rt.get("vpc_id") == vpc_id:
                return rt
        return None

    def _is_public_ip(self, ip: str) -> bool:
        """Return True if the IP address is a public (non-private) address."""
        try:
            addr = ipaddress.ip_address(ip)
            return not addr.is_private
        except ValueError:
            return False


# ---------------------------------------------------------------------------
# Auto-register
# ---------------------------------------------------------------------------
SkillRegistry.register(ConnectivityDiagnoser())
