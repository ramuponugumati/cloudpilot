"""Cost Anomaly Detection — spending spikes, week-over-week changes, new services,
and 3-month spend summary with top-5 service bar chart."""
import logging
from datetime import datetime, timedelta
from cloudpilot.core import BaseSkill, SkillRegistry, SkillResult, Finding, Severity
from cloudpilot.aws_client import get_client

logger = logging.getLogger(__name__)


class CostAnomalySkill(BaseSkill):
    name = "cost-anomaly"
    description = "Detect cost spikes, week-over-week changes, new services, and 3-month spend overview"
    version = "0.3.0"

    def scan(self, regions, profile=None, **kwargs) -> SkillResult:
        findings = []
        metadata = {}
        try:
            findings.extend(self._check_anomalies(profile))
            findings.extend(self._check_week_over_week(profile))
            findings.extend(self._check_new_services(profile))
            spend_summary = self._get_monthly_spend_summary(profile)
            if spend_summary:
                metadata["spend_summary"] = spend_summary
                findings.insert(0, self._build_spend_overview_finding(spend_summary))
        except Exception as e:
            logger.warning(f"Cost anomaly scan error: {e}")
            return SkillResult(skill_name=self.name, errors=[str(e)])
        return SkillResult(skill_name=self.name, findings=findings, regions_scanned=1, metadata=metadata)

    def _check_anomalies(self, profile):
        findings = []
        try:
            ce = get_client("ce", profile=profile, region="us-east-1")
            resp = ce.get_anomalies(
                DateInterval={"StartDate": (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%d"),
                              "EndDate": datetime.utcnow().strftime("%Y-%m-%d")},
                MaxResults=20,
            )
            for a in resp.get("Anomalies", []):
                impact = a.get("Impact", {})
                amount = float(impact.get("MaxImpact", 0))
                if amount < 10:
                    continue
                sev = Severity.CRITICAL if amount > 500 else Severity.HIGH if amount > 100 else Severity.MEDIUM
                findings.append(Finding(
                    skill=self.name, title=f"Cost anomaly: ${amount:.0f} impact",
                    severity=sev, description=f"Service: {a.get('DimensionValue', 'Unknown')}",
                    monthly_impact=amount, recommended_action="Investigate unexpected spend",
                ))
        except Exception as e:
            logger.debug(f"Anomaly check: {e}")
        return findings

    def _check_week_over_week(self, profile):
        findings = []
        try:
            ce = get_client("ce", profile=profile, region="us-east-1")
            now = datetime.utcnow()
            this_week_start = (now - timedelta(days=7)).strftime("%Y-%m-%d")
            last_week_start = (now - timedelta(days=14)).strftime("%Y-%m-%d")
            last_week_end = (now - timedelta(days=7)).strftime("%Y-%m-%d")
            today = now.strftime("%Y-%m-%d")

            def get_cost(start, end):
                r = ce.get_cost_and_usage(
                    TimePeriod={"Start": start, "End": end},
                    Granularity="DAILY", Metrics=["UnblendedCost"],
                    GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
                )
                totals = {}
                for day in r.get("ResultsByTime", []):
                    for g in day.get("Groups", []):
                        svc = g["Keys"][0]
                        amt = float(g["Metrics"]["UnblendedCost"]["Amount"])
                        totals[svc] = totals.get(svc, 0) + amt
                return totals

            this_week = get_cost(this_week_start, today)
            last_week = get_cost(last_week_start, last_week_end)

            for svc, cost in this_week.items():
                prev = last_week.get(svc, 0)
                if prev > 5 and cost > prev * 1.5:
                    increase = cost - prev
                    pct = ((cost - prev) / prev) * 100
                    findings.append(Finding(
                        skill=self.name,
                        title=f"WoW spike: {svc} +{pct:.0f}%",
                        severity=Severity.HIGH if increase > 100 else Severity.MEDIUM,
                        description=f"${prev:.2f} → ${cost:.2f} (+${increase:.2f})",
                        monthly_impact=increase * 4,
                        recommended_action=f"Investigate {svc} cost increase",
                    ))
        except Exception as e:
            logger.debug(f"WoW check: {e}")
        return findings

    def _check_new_services(self, profile):
        findings = []
        try:
            ce = get_client("ce", profile=profile, region="us-east-1")
            now = datetime.utcnow()
            recent = ce.get_cost_and_usage(
                TimePeriod={"Start": (now - timedelta(days=7)).strftime("%Y-%m-%d"),
                            "End": now.strftime("%Y-%m-%d")},
                Granularity="DAILY", Metrics=["UnblendedCost"],
                GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
            )
            older = ce.get_cost_and_usage(
                TimePeriod={"Start": (now - timedelta(days=37)).strftime("%Y-%m-%d"),
                            "End": (now - timedelta(days=7)).strftime("%Y-%m-%d")},
                Granularity="MONTHLY", Metrics=["UnblendedCost"],
                GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
            )
            old_services = set()
            for day in older.get("ResultsByTime", []):
                for g in day.get("Groups", []):
                    if float(g["Metrics"]["UnblendedCost"]["Amount"]) > 0:
                        old_services.add(g["Keys"][0])
            for day in recent.get("ResultsByTime", []):
                for g in day.get("Groups", []):
                    svc = g["Keys"][0]
                    amt = float(g["Metrics"]["UnblendedCost"]["Amount"])
                    if svc not in old_services and amt > 1:
                        findings.append(Finding(
                            skill=self.name, title=f"New service: {svc}",
                            severity=Severity.MEDIUM,
                            description=f"First seen this week, ${amt:.2f}/day",
                            monthly_impact=amt * 30,
                            recommended_action="Verify this service is expected",
                        ))
        except Exception as e:
            logger.debug(f"New services check: {e}")
        return findings

    # --- 3-Month Spend Summary with Top-5 Service Bar Chart ---

    def _get_monthly_spend_summary(self, profile) -> dict | None:
        """Fetch last 3 months of total cost and per-service breakdown from Cost Explorer.
        Returns structured summary with monthly totals, top 5 services, and aggregates."""
        try:
            ce = get_client("ce", profile=profile, region="us-east-1")
            now = datetime.utcnow()

            # Calculate 3-month window: first day of 3 months ago → first day of current month
            # e.g., if today is March 7, window is Dec 1 → Mar 1 (Dec, Jan, Feb complete months)
            current_first = now.replace(day=1)
            # Go back 3 months
            month = current_first.month - 3
            year = current_first.year
            while month <= 0:
                month += 12
                year -= 1
            start_date = datetime(year, month, 1)

            start_str = start_date.strftime("%Y-%m-%d")
            end_str = current_first.strftime("%Y-%m-%d")

            # Total cost per month
            total_resp = ce.get_cost_and_usage(
                TimePeriod={"Start": start_str, "End": end_str},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
            )

            monthly_totals = {}
            for period in total_resp.get("ResultsByTime", []):
                month_label = period["TimePeriod"]["Start"][:7]  # "2025-12"
                amount = float(period.get("Total", {}).get("UnblendedCost", {}).get("Amount", 0))
                monthly_totals[month_label] = round(amount, 2)

            # Per-service cost per month (for top-5 identification)
            svc_resp = ce.get_cost_and_usage(
                TimePeriod={"Start": start_str, "End": end_str},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
                GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
            )

            # Accumulate per-service totals across all months
            service_totals: dict[str, float] = {}
            # Per-service per-month breakdown
            service_monthly: dict[str, dict[str, float]] = {}

            for period in svc_resp.get("ResultsByTime", []):
                month_label = period["TimePeriod"]["Start"][:7]
                for group in period.get("Groups", []):
                    svc = group["Keys"][0]
                    amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
                    if amount < 0.01:
                        continue
                    service_totals[svc] = service_totals.get(svc, 0) + amount
                    service_monthly.setdefault(svc, {})[month_label] = round(amount, 2)

            # Top 5 services by total spend
            top5 = sorted(service_totals.items(), key=lambda x: x[1], reverse=True)[:5]
            top5_names = [name for name, _ in top5]

            # Build month labels sorted chronologically
            months_sorted = sorted(monthly_totals.keys())

            # Build top-5 service data per month
            top5_monthly = {}
            for svc in top5_names:
                top5_monthly[svc] = {
                    m: service_monthly.get(svc, {}).get(m, 0) for m in months_sorted
                }

            # Aggregates
            total_sum = sum(monthly_totals.values())
            total_avg = total_sum / len(monthly_totals) if monthly_totals else 0
            num_months = len(months_sorted)

            return {
                "months": months_sorted,
                "monthly_totals": monthly_totals,
                "top5_services": top5_names,
                "top5_monthly": top5_monthly,
                "top5_totals": {name: round(total, 2) for name, total in top5},
                "total_sum": round(total_sum, 2),
                "total_avg": round(total_avg, 2),
                "num_months": num_months,
            }
        except Exception as e:
            logger.warning(f"Monthly spend summary failed: {e}")
            return None

    def _build_spend_overview_finding(self, summary: dict) -> Finding:
        """Build a Finding that contains the 3-month spend overview with Mermaid bar chart."""
        months = summary["months"]
        monthly_totals = summary["monthly_totals"]
        top5 = summary["top5_services"]
        top5_monthly = summary["top5_monthly"]
        total_sum = summary["total_sum"]
        total_avg = summary["total_avg"]
        num_months = summary["num_months"]

        # Format month labels for display (e.g., "2025-01" → "Jan 2025")
        month_names = []
        for m in months:
            dt = datetime.strptime(m, "%Y-%m")
            month_names.append(dt.strftime("%b %Y"))

        # Build description with summary heading
        lines = [
            f"📊 {num_months}-Month Cost Overview",
            f"Total Spend: ${total_sum:,.2f} | Average/Month: ${total_avg:,.2f}",
            "",
            "Monthly Totals:",
        ]
        for m, label in zip(months, month_names):
            lines.append(f"  {label}: ${monthly_totals[m]:,.2f}")

        lines.append("")
        lines.append("Top 5 Services:")
        for svc in top5:
            svc_total = summary["top5_totals"][svc]
            svc_avg = svc_total / num_months if num_months else 0
            # Shorten long service names for readability
            short = self._shorten_service_name(svc)
            lines.append(f"  {short}: ${svc_total:,.2f} total (${svc_avg:,.2f}/mo avg)")

        # Build Mermaid xychart bar chart
        lines.append("")
        lines.append("```mermaid")
        lines.append("xychart-beta")
        lines.append(f'    title "Monthly Spend — Top 5 Services ({num_months}-Month View)"')
        x_labels = ", ".join(f'"{n}"' for n in month_names)
        lines.append(f"    x-axis [{x_labels}]")
        lines.append('    y-axis "Cost (USD)"')

        for svc in top5:
            short = self._shorten_service_name(svc)
            values = [top5_monthly[svc].get(m, 0) for m in months]
            val_str = ", ".join(f"{v:.2f}" for v in values)
            lines.append(f'    bar [{val_str}]')

        lines.append("```")

        # Add legend since xychart-beta doesn't label bars by series
        lines.append("")
        lines.append("Bar order (left to right per month):")
        for i, svc in enumerate(top5, 1):
            short = self._shorten_service_name(svc)
            lines.append(f"  {i}. {short}")

        description = "\n".join(lines)

        return Finding(
            skill=self.name,
            title=f"💰 {num_months}-Month Spend: ${total_sum:,.2f} total, ${total_avg:,.2f}/mo avg",
            severity=Severity.INFO,
            description=description,
            monthly_impact=total_avg,
            recommended_action="Review top services for optimization opportunities",
            metadata={
                "spend_summary": summary,
                "chart_type": "xychart-beta",
            },
        )

    @staticmethod
    def _shorten_service_name(name: str) -> str:
        """Shorten verbose AWS service names for chart labels."""
        replacements = {
            "Amazon Elastic Compute Cloud - Compute": "EC2",
            "Amazon Simple Storage Service": "S3",
            "Amazon Relational Database Service": "RDS",
            "AWS Lambda": "Lambda",
            "Amazon DynamoDB": "DynamoDB",
            "Amazon CloudFront": "CloudFront",
            "Amazon Simple Notification Service": "SNS",
            "Amazon Simple Queue Service": "SQS",
            "Amazon Elastic Container Service": "ECS",
            "Amazon ElastiCache": "ElastiCache",
            "Amazon Virtual Private Cloud": "VPC",
            "Amazon Elastic Block Store": "EBS",
            "Amazon API Gateway": "API Gateway",
            "Amazon Elastic Load Balancing": "ELB",
            "AWS Key Management Service": "KMS",
            "Amazon CloudWatch": "CloudWatch",
            "AWS CloudTrail": "CloudTrail",
            "Amazon Route 53": "Route 53",
            "Amazon Elastic File System": "EFS",
            "AWS Config": "Config",
            "Amazon Kinesis": "Kinesis",
            "Amazon OpenSearch Service": "OpenSearch",
            "Amazon Managed Streaming for Apache Kafka": "MSK",
            "AWS Secrets Manager": "Secrets Manager",
            "AWS Systems Manager": "Systems Manager",
            "Amazon Bedrock": "Bedrock",
            "Amazon SageMaker": "SageMaker",
            "AWS Step Functions": "Step Functions",
            "Amazon EventBridge": "EventBridge",
            "AWS CodeBuild": "CodeBuild",
            "AWS CodePipeline": "CodePipeline",
            "Amazon Elastic Kubernetes Service": "EKS",
            "Amazon Managed Workflows for Apache Airflow": "MWAA",
            "AWS Glue": "Glue",
            "Amazon Athena": "Athena",
            "Amazon Redshift": "Redshift",
            "Amazon Neptune": "Neptune",
            "Amazon DocumentDB (with MongoDB compatibility)": "DocumentDB",
            "Amazon Timestream": "Timestream",
            "Amazon Managed Service for Prometheus": "AMP",
            "Amazon Managed Grafana": "AMG",
        }
        if name in replacements:
            return replacements[name]
        # Fallback: strip "Amazon " / "AWS " prefix, truncate
        short = name.replace("Amazon ", "").replace("AWS ", "")
        if len(short) > 25:
            short = short[:22] + "..."
        return short


SkillRegistry.register(CostAnomalySkill())
