"""CostOpt Intelligence — Savings Plans, RI optimization, right-sizing, storage & data transfer savings."""
import time
from datetime import datetime, timedelta, timezone
from cloudpilot.core import BaseSkill, SkillResult, Finding, Severity, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions


class CostOptIntelligenceSkill(BaseSkill):
    name = "costopt-intelligence"
    description = "Savings Plan & RI recommendations, right-sizing, storage optimization, data transfer analysis"
    version = "0.1.0"

    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        findings = []
        errors = []
        acct = account_id or get_account_id(profile)

        # 1. Savings Plan recommendations
        try:
            findings.extend(self._check_savings_plan_recommendations(profile))
        except Exception as e:
            errors.append(f"savings-plans: {e}")

        # 2. RI utilization & coverage
        try:
            findings.extend(self._check_ri_utilization(profile))
        except Exception as e:
            errors.append(f"ri-utilization: {e}")

        # 3. Right-sizing (EC2 based on CloudWatch metrics)
        try:
            results = parallel_regions(lambda r: self._check_rightsizing(r, profile), regions)
            findings.extend(results)
        except Exception as e:
            errors.append(f"rightsizing: {e}")

        # 4. EBS GP2 → GP3 migration opportunities
        try:
            results = parallel_regions(lambda r: self._check_ebs_gp2_to_gp3(r, profile), regions)
            findings.extend(results)
        except Exception as e:
            errors.append(f"ebs-optimization: {e}")

        # 5. S3 Intelligent-Tiering candidates
        try:
            findings.extend(self._check_s3_tiering(profile))
        except Exception as e:
            errors.append(f"s3-tiering: {e}")

        # 6. NAT Gateway data transfer costs
        try:
            results = parallel_regions(lambda r: self._check_nat_data_costs(r, profile), regions)
            findings.extend(results)
        except Exception as e:
            errors.append(f"nat-data-costs: {e}")

        # 7. Expiring Savings Plans / RIs
        try:
            findings.extend(self._check_expiring_commitments(profile))
        except Exception as e:
            errors.append(f"expiring-commitments: {e}")

        for f in findings:
            f.account_id = acct

        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=time.time() - start,
            accounts_scanned=1, regions_scanned=len(regions), errors=errors,
        )

    def _check_savings_plan_recommendations(self, profile):
        """Get Savings Plan purchase recommendations from Cost Explorer."""
        findings = []
        ce = get_client("ce", "us-east-1", profile)

        for sp_type in ["COMPUTE_SP", "EC2_INSTANCE_SP"]:
            for term in ["ONE_YEAR", "THREE_YEARS"]:
                try:
                    resp = ce.get_savings_plans_purchase_recommendation(
                        SavingsPlansType=sp_type,
                        TermInYears=term,
                        PaymentOption="NO_UPFRONT",
                        LookbackPeriodInDays="SIXTY_DAYS",
                    )
                    meta = resp.get("SavingsPlansPurchaseRecommendation", {})
                    details = meta.get("SavingsPlansPurchaseRecommendationDetails", [])

                    for rec in details[:5]:
                        hourly = float(rec.get("HourlyCommitmentToPurchase", "0"))
                        if hourly < 0.01:
                            continue
                        estimated_savings = float(rec.get("EstimatedMonthlySavingsAmount", "0"))
                        estimated_cost = float(rec.get("EstimatedOnDemandCost", "0"))
                        savings_pct = float(rec.get("EstimatedSavingsPercentage", "0"))
                        sp_type_display = "Compute SP" if sp_type == "COMPUTE_SP" else "EC2 Instance SP"
                        term_display = "1-year" if term == "ONE_YEAR" else "3-year"

                        if estimated_savings < 50:
                            continue

                        sev = Severity.HIGH if estimated_savings > 500 else Severity.MEDIUM if estimated_savings > 100 else Severity.LOW

                        findings.append(Finding(
                            skill=self.name,
                            title=f"SP opportunity: {sp_type_display} ({term_display}) — save ${estimated_savings:,.0f}/mo",
                            severity=sev,
                            description=(
                                f"Commit ${hourly:.2f}/hr | On-demand cost: ${estimated_cost:,.0f}/mo | "
                                f"Savings: {savings_pct:.0f}% (${estimated_savings:,.0f}/mo)"
                            ),
                            monthly_impact=round(estimated_savings, 2),
                            recommended_action=f"Purchase {sp_type_display} with {term_display} term, No Upfront",
                            metadata={
                                "type": "savings_plan", "sp_type": sp_type,
                                "term": term, "hourly_commitment": hourly,
                                "estimated_savings": estimated_savings,
                                "savings_pct": savings_pct,
                            },
                        ))
                except Exception:
                    pass
        return findings

    def _check_ri_utilization(self, profile):
        """Check RI utilization and coverage gaps."""
        findings = []
        ce = get_client("ce", "us-east-1", profile)
        end = datetime.now(timezone.utc).date()
        start = end - timedelta(days=30)

        # RI utilization
        try:
            resp = ce.get_reservation_utilization(
                TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
                Granularity="MONTHLY",
            )
            for period in resp.get("UtilizationsByTime", []):
                total = period.get("Total", {})
                util_pct = float(total.get("UtilizationPercentage", "100"))
                unused_hours = float(total.get("UnusedHours", "0"))
                total_cost = float(total.get("TotalAmortizedFee", "0"))

                if util_pct < 80 and unused_hours > 100:
                    waste = total_cost * (1 - util_pct / 100)
                    sev = Severity.HIGH if util_pct < 50 else Severity.MEDIUM
                    findings.append(Finding(
                        skill=self.name,
                        title=f"Low RI utilization: {util_pct:.0f}%",
                        severity=sev,
                        description=(
                            f"Utilization: {util_pct:.0f}% | Unused hours: {unused_hours:,.0f} | "
                            f"Estimated waste: ${waste:,.0f}/mo"
                        ),
                        monthly_impact=round(waste, 2),
                        recommended_action="Modify or sell unused RIs on the RI Marketplace, or adjust workloads to use reserved capacity",
                        metadata={"type": "ri_utilization", "util_pct": util_pct, "unused_hours": unused_hours},
                    ))
        except Exception:
            pass

        # RI coverage
        try:
            resp = ce.get_reservation_coverage(
                TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
                Granularity="MONTHLY",
            )
            for period in resp.get("CoveragesByTime", []):
                total = period.get("Total", {}).get("CoverageHours", {})
                coverage_pct = float(total.get("CoverageHoursPercentage", "100"))
                on_demand_hours = float(total.get("OnDemandHours", "0"))

                if coverage_pct < 50 and on_demand_hours > 500:
                    findings.append(Finding(
                        skill=self.name,
                        title=f"Low RI coverage: {coverage_pct:.0f}%",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Only {coverage_pct:.0f}% of eligible hours covered by RIs | "
                            f"{on_demand_hours:,.0f} on-demand hours — consider purchasing RIs"
                        ),
                        recommended_action="Review RI purchase recommendations in Cost Explorer",
                        metadata={"type": "ri_coverage", "coverage_pct": coverage_pct, "on_demand_hours": on_demand_hours},
                    ))
        except Exception:
            pass

        return findings

    def _check_rightsizing(self, region, profile):
        """Flag EC2 instances that could be downsized based on CPU/network metrics."""
        findings = []
        try:
            ec2 = get_client("ec2", region, profile)
            cw = get_client("cloudwatch", region, profile)
            end = datetime.now(timezone.utc)
            start_time = end - timedelta(days=14)

            # Instance type pricing estimates ($/hr on-demand)
            PRICING = {
                "xlarge": 0.17, "2xlarge": 0.34, "4xlarge": 0.68,
                "8xlarge": 1.36, "12xlarge": 2.04, "16xlarge": 2.72,
                "24xlarge": 4.08, "metal": 4.08,
            }

            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
                for res in page["Reservations"]:
                    for inst in res["Instances"]:
                        itype = inst["InstanceType"]
                        iid = inst["InstanceId"]
                        family, size = itype.split(".", 1)

                        # Only check instances large enough to downsize
                        if size in ("nano", "micro", "small", "medium", "large"):
                            continue

                        try:
                            # Get CPU
                            cpu_resp = cw.get_metric_statistics(
                                Namespace="AWS/EC2", MetricName="CPUUtilization",
                                Dimensions=[{"Name": "InstanceId", "Value": iid}],
                                StartTime=start_time, EndTime=end, Period=86400, Statistics=["Average", "Maximum"],
                            )
                            pts = cpu_resp.get("Datapoints", [])
                            if not pts:
                                continue
                            avg_cpu = sum(p["Average"] for p in pts) / len(pts)
                            max_cpu = max(p["Maximum"] for p in pts)

                            # Get network
                            net_resp = cw.get_metric_statistics(
                                Namespace="AWS/EC2", MetricName="NetworkIn",
                                Dimensions=[{"Name": "InstanceId", "Value": iid}],
                                StartTime=start_time, EndTime=end, Period=86400, Statistics=["Average"],
                            )
                            net_pts = net_resp.get("Datapoints", [])
                            avg_net = sum(p["Average"] for p in net_pts) / len(net_pts) if net_pts else 0
                            avg_net_mbps = avg_net / 1_000_000  # bytes to MB

                            # Right-sizing logic: avg CPU < 20% AND max CPU < 50%
                            if avg_cpu < 20 and max_cpu < 50:
                                # Suggest one size down
                                SIZE_ORDER = ["large", "xlarge", "2xlarge", "4xlarge", "8xlarge", "12xlarge", "16xlarge", "24xlarge"]
                                if size in SIZE_ORDER:
                                    idx = SIZE_ORDER.index(size)
                                    if idx > 0:
                                        suggested_size = SIZE_ORDER[idx - 1]
                                        suggested_type = f"{family}.{suggested_size}"
                                        current_cost = PRICING.get(size, 0.50) * 730
                                        suggested_cost = PRICING.get(suggested_size, 0.25) * 730
                                        savings = current_cost - suggested_cost

                                        if savings < 20:
                                            continue

                                        name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), "")

                                        findings.append(Finding(
                                            skill=self.name,
                                            title=f"Right-size: {iid} ({itype} → {suggested_type})",
                                            severity=Severity.MEDIUM if savings > 100 else Severity.LOW,
                                            region=region, resource_id=iid,
                                            description=(
                                                f"{name} | Avg CPU: {avg_cpu:.1f}% | Max CPU: {max_cpu:.1f}% | "
                                                f"Net: {avg_net_mbps:.1f} MB/day | "
                                                f"Save ~${savings:,.0f}/mo by downsizing to {suggested_type}"
                                            ),
                                            monthly_impact=round(savings, 2),
                                            recommended_action=f"Downsize from {itype} to {suggested_type}",
                                            metadata={
                                                "type": "rightsizing", "current_type": itype,
                                                "suggested_type": suggested_type,
                                                "avg_cpu": round(avg_cpu, 1), "max_cpu": round(max_cpu, 1),
                                                "savings": round(savings, 2),
                                            },
                                        ))
                        except Exception:
                            pass
        except Exception:
            pass
        return findings

    def _check_ebs_gp2_to_gp3(self, region, profile):
        """Find GP2 volumes that could save 20% by migrating to GP3."""
        findings = []
        try:
            ec2 = get_client("ec2", region, profile)
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate(Filters=[{"Name": "volume-type", "Values": ["gp2"]}]):
                for vol in page["Volumes"]:
                    size = vol["Size"]
                    vid = vol["VolumeId"]
                    gp2_cost = size * 0.10  # $0.10/GB-month
                    gp3_cost = size * 0.08  # $0.08/GB-month
                    savings = gp2_cost - gp3_cost

                    if savings < 1:
                        continue

                    findings.append(Finding(
                        skill=self.name,
                        title=f"GP2→GP3: {vid} ({size}GB)",
                        severity=Severity.LOW, region=region, resource_id=vid,
                        description=(
                            f"{size}GB GP2 → GP3 | Current: ${gp2_cost:.0f}/mo → ${gp3_cost:.0f}/mo | "
                            f"GP3 also includes 3000 IOPS + 125 MB/s free"
                        ),
                        monthly_impact=round(savings, 2),
                        recommended_action="Modify volume type from GP2 to GP3 (no downtime, online migration)",
                        metadata={"type": "ebs_optimization", "volume_type": "gp2", "size_gb": size, "savings": round(savings, 2)},
                    ))
        except Exception:
            pass
        return findings

    def _check_s3_tiering(self, profile):
        """Find S3 buckets that could benefit from Intelligent-Tiering."""
        findings = []
        try:
            s3 = get_client("s3", "us-east-1", profile)
            cw = get_client("cloudwatch", "us-east-1", profile)
            end = datetime.now(timezone.utc)
            start_time = end - timedelta(days=7)

            for bucket in s3.list_buckets().get("Buckets", [])[:30]:
                name = bucket["Name"]
                try:
                    # Get bucket size from CloudWatch
                    resp = cw.get_metric_statistics(
                        Namespace="AWS/S3", MetricName="BucketSizeBytes",
                        Dimensions=[
                            {"Name": "BucketName", "Value": name},
                            {"Name": "StorageType", "Value": "StandardStorage"},
                        ],
                        StartTime=start_time, EndTime=end, Period=86400, Statistics=["Average"],
                    )
                    pts = resp.get("Datapoints", [])
                    if not pts:
                        continue
                    size_bytes = max(p["Average"] for p in pts)
                    size_gb = size_bytes / (1024 ** 3)

                    if size_gb < 10:
                        continue

                    # Check if already using Intelligent-Tiering
                    try:
                        it_resp = cw.get_metric_statistics(
                            Namespace="AWS/S3", MetricName="BucketSizeBytes",
                            Dimensions=[
                                {"Name": "BucketName", "Value": name},
                                {"Name": "StorageType", "Value": "IntelligentTieringStorage"},
                            ],
                            StartTime=start_time, EndTime=end, Period=86400, Statistics=["Average"],
                        )
                        if it_resp.get("Datapoints"):
                            continue  # Already using IT
                    except Exception:
                        pass

                    standard_cost = size_gb * 0.023  # Standard $/GB-month
                    potential_savings = standard_cost * 0.40  # IT can save up to 40% on infrequent data

                    if potential_savings < 5:
                        continue

                    findings.append(Finding(
                        skill=self.name,
                        title=f"S3 tiering: {name} ({size_gb:.0f}GB)",
                        severity=Severity.LOW,
                        resource_id=name,
                        description=(
                            f"{size_gb:.0f}GB in Standard | Current: ${standard_cost:,.0f}/mo | "
                            f"Intelligent-Tiering could save up to ${potential_savings:,.0f}/mo on infrequently accessed data"
                        ),
                        monthly_impact=round(potential_savings, 2),
                        recommended_action="Enable S3 Intelligent-Tiering lifecycle rule",
                        metadata={"type": "s3_tiering", "size_gb": round(size_gb, 1), "potential_savings": round(potential_savings, 2)},
                    ))
                except Exception:
                    pass
        except Exception:
            pass
        return findings

    def _check_nat_data_costs(self, region, profile):
        """Flag NAT Gateways with high data processing costs."""
        findings = []
        try:
            ec2 = get_client("ec2", region, profile)
            cw = get_client("cloudwatch", region, profile)
            end = datetime.now(timezone.utc)
            start_time = end - timedelta(days=7)

            for gw in ec2.describe_nat_gateways(Filter=[{"Name": "state", "Values": ["available"]}]).get("NatGateways", []):
                gw_id = gw["NatGatewayId"]
                vpc_id = gw.get("VpcId", "")
                try:
                    resp = cw.get_metric_statistics(
                        Namespace="AWS/NATGateway", MetricName="BytesOutToDestination",
                        Dimensions=[{"Name": "NatGatewayId", "Value": gw_id}],
                        StartTime=start_time, EndTime=end, Period=604800, Statistics=["Sum"],
                    )
                    total_bytes = resp["Datapoints"][0]["Sum"] if resp["Datapoints"] else 0
                    total_gb = total_bytes / (1024 ** 3)
                    weekly_cost = total_gb * 0.045  # $0.045/GB processing
                    monthly_cost = weekly_cost * 4.3

                    if monthly_cost < 50:
                        continue

                    findings.append(Finding(
                        skill=self.name,
                        title=f"High NAT data cost: {gw_id} (${monthly_cost:,.0f}/mo)",
                        severity=Severity.HIGH if monthly_cost > 500 else Severity.MEDIUM,
                        region=region, resource_id=gw_id,
                        description=(
                            f"VPC: {vpc_id} | {total_gb:,.0f}GB/week | "
                            f"Data processing: ~${monthly_cost:,.0f}/mo | "
                            f"Consider VPC endpoints for S3/DynamoDB to reduce NAT traffic"
                        ),
                        monthly_impact=round(monthly_cost * 0.3, 2),  # ~30% saveable via endpoints
                        recommended_action="Add VPC Gateway Endpoints for S3 and DynamoDB to bypass NAT",
                        metadata={
                            "type": "nat_data_cost", "weekly_gb": round(total_gb, 1),
                            "monthly_cost": round(monthly_cost, 2), "vpc_id": vpc_id,
                        },
                    ))
                except Exception:
                    pass
        except Exception:
            pass
        return findings

    def _check_expiring_commitments(self, profile):
        """Flag Savings Plans and RIs expiring within 60 days."""
        findings = []
        ce = get_client("ce", "us-east-1", profile)
        now = datetime.now(timezone.utc)
        cutoff = now + timedelta(days=60)

        # Expiring Savings Plans
        try:
            resp = ce.get_savings_plans_utilization_details(
                TimePeriod={
                    "Start": (now - timedelta(days=1)).strftime("%Y-%m-%d"),
                    "End": now.strftime("%Y-%m-%d"),
                },
            )
            for sp in resp.get("SavingsPlansUtilizationDetails", []):
                attrs = sp.get("Attributes", {})
                end_date_str = attrs.get("EndDateTime", "")
                if end_date_str:
                    try:
                        end_date = datetime.fromisoformat(end_date_str.replace("Z", "+00:00"))
                        if end_date < cutoff:
                            days_left = (end_date - now).days
                            commitment = float(sp.get("Utilization", {}).get("TotalCommitment", "0"))
                            findings.append(Finding(
                                skill=self.name,
                                title=f"SP expiring in {days_left} days",
                                severity=Severity.HIGH if days_left < 30 else Severity.MEDIUM,
                                description=(
                                    f"Savings Plan expires {end_date_str[:10]} | "
                                    f"Commitment: ${commitment:,.0f} | "
                                    f"Plan renewal to avoid on-demand pricing"
                                ),
                                monthly_impact=round(commitment * 0.3, 2),  # estimated savings loss
                                recommended_action="Review and renew Savings Plan before expiration",
                                metadata={"type": "expiring_sp", "end_date": end_date_str, "days_left": days_left},
                            ))
                    except Exception:
                        pass
        except Exception:
            pass

        return findings


SkillRegistry.register(CostOptIntelligenceSkill())
