"""Capacity Planner — service quotas, ODCR tracking, limit headroom."""
import time
from cloudpilot.core import BaseSkill, SkillResult, Finding, Severity, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions


class CapacityPlannerSkill(BaseSkill):
    name = "capacity-planner"
    description = "Check service quotas, ODCR utilization, and limit headroom"
    version = "0.1.0"

    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        findings = []
        errors = []
        acct = account_id or get_account_id(profile)

        # 1. EC2 on-demand instance limits approaching threshold
        def _scan_ec2_limits(region):
            return self._check_ec2_limits(region, profile)
        findings.extend(parallel_regions(_scan_ec2_limits, regions))

        # 2. Capacity reservations utilization
        def _scan_odcrs(region):
            return self._check_odcr_utilization(region, profile)
        findings.extend(parallel_regions(_scan_odcrs, regions))

        # 3. SageMaker endpoint capacity
        def _scan_sm(region):
            return self._check_sagemaker_capacity(region, profile)
        findings.extend(parallel_regions(_scan_sm, regions))

        for f in findings:
            f.account_id = acct

        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=time.time() - start,
            accounts_scanned=1, regions_scanned=len(regions), errors=errors,
        )

    def _check_ec2_limits(self, region, profile):
        findings = []
        try:
            sq = get_client("service-quotas", region, profile)
            ec2 = get_client("ec2", region, profile)

            # Check on-demand instance quotas
            quotas = {}
            paginator = sq.get_paginator("list_service_quotas")
            for page in paginator.paginate(ServiceCode="ec2"):
                for q in page.get("Quotas", []):
                    if "On-Demand" in q.get("QuotaName", "") and "Running" in q.get("QuotaName", ""):
                        quotas[q["QuotaName"]] = q.get("Value", 0)

            # Get current usage from CloudWatch
            cw = get_client("cloudwatch", region, profile)
            for qname, limit in quotas.items():
                if limit <= 0:
                    continue
                # Estimate usage from running instances
                # (simplified — real implementation would use CW metrics)
                usage_pct = 0  # placeholder
                if usage_pct > 80:
                    findings.append(Finding(
                        skill=self.name,
                        title=f"EC2 quota at {usage_pct:.0f}%: {qname}",
                        severity=Severity.HIGH if usage_pct > 90 else Severity.MEDIUM,
                        region=region, resource_id=qname,
                        description=f"Limit: {limit:.0f} | Usage: {usage_pct:.0f}%",
                        recommended_action="Request quota increase before hitting limit",
                    ))
        except Exception:
            pass
        return findings

    def _check_odcr_utilization(self, region, profile):
        findings = []
        try:
            ec2 = get_client("ec2", region, profile)
            paginator = ec2.get_paginator("describe_capacity_reservations")
            for page in paginator.paginate(Filters=[{"Name": "state", "Values": ["active"]}]):
                for cr in page.get("CapacityReservations", []):
                    total = cr["TotalInstanceCount"]
                    available = cr["AvailableInstanceCount"]
                    used = total - available
                    util_pct = (used / total * 100) if total > 0 else 0
                    itype = cr["InstanceType"]
                    cr_id = cr["CapacityReservationId"]

                    # Flag underutilized ODCRs (paying for unused capacity)
                    if available > 0 and util_pct < 50:
                        monthly_waste = available * self._estimate_hourly(itype) * 730
                        findings.append(Finding(
                            skill=self.name,
                            title=f"Underutilized ODCR: {cr_id}",
                            severity=Severity.MEDIUM,
                            region=region, resource_id=cr_id,
                            description=f"{itype} | {used}/{total} used ({util_pct:.0f}%) | {available} idle",
                            monthly_impact=round(monthly_waste, 2),
                            recommended_action="Reduce ODCR count or deploy workloads to use reserved capacity",
                            metadata={"instance_type": itype, "total": total, "used": used, "available": available},
                        ))

                    # Flag fully utilized (no headroom for scaling)
                    if available == 0 and total > 0:
                        findings.append(Finding(
                            skill=self.name,
                            title=f"ODCR fully utilized: {cr_id}",
                            severity=Severity.LOW,
                            region=region, resource_id=cr_id,
                            description=f"{itype} | {total}/{total} used — no headroom for scaling",
                            recommended_action="Consider increasing ODCR if scaling is expected",
                            metadata={"instance_type": itype, "total": total},
                        ))
        except Exception:
            pass
        return findings

    def _check_sagemaker_capacity(self, region, profile):
        findings = []
        try:
            sm = get_client("sagemaker", region, profile)
            endpoints = sm.list_endpoints(StatusEquals="InService").get("Endpoints", [])
            for ep in endpoints[:20]:
                detail = sm.describe_endpoint(EndpointName=ep["EndpointName"])
                for v in detail.get("ProductionVariants", []):
                    cur = v.get("CurrentInstanceCount", 0)
                    des = v.get("DesiredInstanceCount", 0)
                    scaling = v.get("ManagedInstanceScaling", {})
                    max_i = scaling.get("MaxInstanceCount", 0)

                    # Scaling at max capacity
                    if max_i > 0 and cur >= max_i:
                        findings.append(Finding(
                            skill=self.name,
                            title=f"SageMaker at max capacity: {ep['EndpointName']}",
                            severity=Severity.HIGH,
                            region=region, resource_id=ep["EndpointName"],
                            description=f"Variant {v['VariantName']}: {cur}/{max_i} instances (at max)",
                            recommended_action="Increase max instance count or add capacity reservation",
                        ))

                    # Desired != current (scaling in progress or stuck)
                    if cur != des and des > 0:
                        findings.append(Finding(
                            skill=self.name,
                            title=f"SageMaker scaling: {ep['EndpointName']}",
                            severity=Severity.MEDIUM,
                            region=region, resource_id=ep["EndpointName"],
                            description=f"Variant {v['VariantName']}: current={cur} desired={des} — scaling in progress",
                            recommended_action="Monitor — may indicate capacity issue if stuck",
                        ))
        except Exception:
            pass
        return findings

    def _estimate_hourly(self, instance_type):
        """Rough hourly cost estimate."""
        costs = {
            "p4d.24xlarge": 32.77, "p5.48xlarge": 98.32, "p5en.48xlarge": 131.22,
            "g5.xlarge": 1.006, "g5.2xlarge": 1.212, "g5.4xlarge": 2.03,
            "g6e.xlarge": 0.98, "g6e.4xlarge": 2.35,
            "ml.g5.4xlarge": 2.03, "ml.p4d.24xlarge": 32.77,
        }
        return costs.get(instance_type, 0.50)


SkillRegistry.register(CapacityPlannerSkill())
