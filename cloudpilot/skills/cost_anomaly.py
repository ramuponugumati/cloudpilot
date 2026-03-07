"""Cost Anomaly Detection — spending spikes, week-over-week changes, new services."""
import logging
from datetime import datetime, timedelta
from cloudpilot.core import BaseSkill, SkillRegistry, SkillResult, Finding, Severity
from cloudpilot.aws_client import get_client

logger = logging.getLogger(__name__)


class CostAnomalySkill(BaseSkill):
    name = "cost-anomaly"
    description = "Detect cost spikes, week-over-week changes, and new services"
    version = "0.2.0"

    def scan(self, regions, profile=None, **kwargs) -> SkillResult:
        findings = []
        try:
            findings.extend(self._check_anomalies(profile))
            findings.extend(self._check_week_over_week(profile))
            findings.extend(self._check_new_services(profile))
        except Exception as e:
            logger.warning(f"Cost anomaly scan error: {e}")
            return SkillResult(skill_name=self.name, errors=[str(e)])
        return SkillResult(skill_name=self.name, findings=findings, regions_scanned=1)

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


SkillRegistry.register(CostAnomalySkill())
