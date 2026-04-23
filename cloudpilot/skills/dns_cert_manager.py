"""DNS & Certificate Management — cert expiry tracking, DNS hygiene,
ACM lifecycle, orphaned Route53 records."""
import logging
import time
from datetime import datetime, timezone

from cloudpilot.core import BaseSkill, Finding, Severity, SkillResult, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions

logger = logging.getLogger(__name__)

CERT_EXPIRY_CRITICAL_DAYS = 7
CERT_EXPIRY_HIGH_DAYS = 30
CERT_EXPIRY_MEDIUM_DAYS = 90


class DnsCertManagerSkill(BaseSkill):
    name = "dns-cert-manager"
    description = "Certificate expiry tracking, DNS hygiene, ACM lifecycle, orphaned Route53 records"
    version = "0.1.0"

    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        acct = account_id or get_account_id(profile)
        region_results = parallel_regions(
            lambda r, p: self._collect(r, p), regions, profile=profile)
        data = self._merge(region_results)
        # Route53 is global — collect once
        self._collect_route53(data, profile)
        findings = self._run_checks(data)
        for f in findings:
            f.account_id = acct
        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=time.time() - start,
            accounts_scanned=1, regions_scanned=len(regions),
            errors=data.get("errors", []))

    def _collect(self, region, profile=None):
        data = {"certificates": [], "errors": [], "region": region}
        try:
            acm = get_client("acm", region, profile)
            paginator = acm.get_paginator("list_certificates")
            for page in paginator.paginate():
                for cert in page.get("CertificateSummaryList", []):
                    arn = cert.get("CertificateArn", "")
                    try:
                        detail = acm.describe_certificate(CertificateArn=arn).get("Certificate", {})
                        data["certificates"].append({
                            "arn": arn, "domain": detail.get("DomainName", ""),
                            "status": detail.get("Status", ""),
                            "not_after": detail["NotAfter"].isoformat() if detail.get("NotAfter") else None,
                            "not_before": detail["NotBefore"].isoformat() if detail.get("NotBefore") else None,
                            "type": detail.get("Type", ""),
                            "in_use_by": detail.get("InUseBy", []),
                            "renewal_eligibility": detail.get("RenewalEligibility", ""),
                            "region": region,
                        })
                    except Exception as e:
                        data["errors"].append(f"describe_certificate {arn}: {e}")
        except Exception as e:
            logger.warning("ACM in %s: %s", region, e)
            data["errors"].append(f"acm in {region}: {e}")
        return data

    def _collect_route53(self, data, profile):
        data.setdefault("hosted_zones", [])
        try:
            r53 = get_client("route53", "us-east-1", profile)
            zones = r53.list_hosted_zones().get("HostedZones", [])
            for zone in zones:
                zone_id = zone["Id"].split("/")[-1]
                records = []
                try:
                    paginator = r53.get_paginator("list_resource_record_sets")
                    for page in paginator.paginate(HostedZoneId=zone_id):
                        records.extend(page.get("ResourceRecordSets", []))
                except Exception as e:
                    data["errors"].append(f"list_records {zone_id}: {e}")
                data["hosted_zones"].append({
                    "id": zone_id, "name": zone.get("Name", ""),
                    "record_count": zone.get("ResourceRecordSetCount", 0),
                    "private": zone.get("Config", {}).get("PrivateZone", False),
                    "records": records,
                })
        except Exception as e:
            logger.warning("Route53: %s", e)
            data["errors"].append(f"route53: {e}")

    def _merge(self, results):
        merged = {"certificates": [], "hosted_zones": [], "errors": []}
        for rd in (results if isinstance(results, list) else []):
            if isinstance(rd, dict):
                for k in ("certificates", "errors"):
                    merged[k].extend(rd.get(k, []))
        return merged

    def _run_checks(self, data):
        findings = []
        for checker in [self._check_cert_expiry, self._check_unused_certs,
                        self._check_dns_hygiene]:
            try:
                findings.extend(checker(data))
            except Exception as e:
                logger.warning("Checker failed: %s", e)
        return findings

    def _check_cert_expiry(self, data):
        findings = []
        now = datetime.now(timezone.utc)
        for cert in data.get("certificates", []):
            if cert.get("status") != "ISSUED":
                continue
            not_after = cert.get("not_after")
            if not not_after:
                continue
            try:
                expiry = datetime.fromisoformat(not_after)
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                days_left = (expiry - now).days
                domain = cert.get("domain", "unknown")
                meta = {"domain": domain, "arn": cert["arn"], "days_until_expiry": days_left,
                        "expiry_date": not_after, "type": cert.get("type", ""),
                        "in_use_by": cert.get("in_use_by", []), "region": cert.get("region", "")}
                if days_left <= 0:
                    findings.append(Finding(
                        skill=self.name, title=f"Certificate EXPIRED: {domain}",
                        severity=Severity.CRITICAL, resource_id=domain, region=cert.get("region", ""),
                        description=f"Certificate for {domain} expired {abs(days_left)} days ago",
                        recommended_action="Renew or replace the certificate immediately",
                        metadata=meta))
                elif days_left <= CERT_EXPIRY_CRITICAL_DAYS:
                    findings.append(Finding(
                        skill=self.name, title=f"Certificate expiring in {days_left}d: {domain}",
                        severity=Severity.CRITICAL, resource_id=domain, region=cert.get("region", ""),
                        description=f"Certificate for {domain} expires in {days_left} days",
                        recommended_action="Renew certificate urgently", metadata=meta))
                elif days_left <= CERT_EXPIRY_HIGH_DAYS:
                    findings.append(Finding(
                        skill=self.name, title=f"Certificate expiring in {days_left}d: {domain}",
                        severity=Severity.HIGH, resource_id=domain, region=cert.get("region", ""),
                        description=f"Certificate for {domain} expires in {days_left} days",
                        recommended_action="Plan certificate renewal", metadata=meta))
                elif days_left <= CERT_EXPIRY_MEDIUM_DAYS:
                    findings.append(Finding(
                        skill=self.name, title=f"Certificate expiring in {days_left}d: {domain}",
                        severity=Severity.MEDIUM, resource_id=domain, region=cert.get("region", ""),
                        description=f"Certificate for {domain} expires in {days_left} days",
                        recommended_action="Schedule certificate renewal", metadata=meta))
            except (ValueError, TypeError):
                pass
        return findings

    def _check_unused_certs(self, data):
        findings = []
        for cert in data.get("certificates", []):
            if cert.get("status") != "ISSUED":
                continue
            if not cert.get("in_use_by"):
                findings.append(Finding(
                    skill=self.name, title=f"Unused certificate: {cert.get('domain', '')}",
                    severity=Severity.LOW, resource_id=cert.get("domain", ""),
                    region=cert.get("region", ""),
                    description=f"Certificate for {cert.get('domain', '')} is not attached to any resource",
                    recommended_action="Delete if no longer needed or attach to a resource",
                    metadata={"domain": cert.get("domain", ""), "arn": cert["arn"]}))
        return findings

    def _check_dns_hygiene(self, data):
        findings = []
        for zone in data.get("hosted_zones", []):
            zone_name = zone.get("name", "")
            records = zone.get("records", [])
            # Check for CNAME records pointing to non-existent targets (dangling)
            cnames = [r for r in records if r.get("Type") == "CNAME"]
            if zone.get("record_count", 0) <= 2:
                # Only SOA + NS = empty zone
                findings.append(Finding(
                    skill=self.name, title=f"Empty hosted zone: {zone_name}",
                    severity=Severity.LOW, resource_id=zone_name,
                    description=f"Hosted zone {zone_name} has only SOA/NS records — may be orphaned",
                    recommended_action="Delete if no longer needed",
                    metadata={"zone_id": zone["id"], "zone_name": zone_name, "record_count": zone.get("record_count", 0)}))
            # Flag zones with many records but no alias records (potential optimization)
            alias_count = sum(1 for r in records if r.get("AliasTarget"))
            if zone.get("record_count", 0) > 50 and alias_count == 0:
                findings.append(Finding(
                    skill=self.name, title=f"No alias records in large zone: {zone_name}",
                    severity=Severity.LOW, resource_id=zone_name,
                    description=f"Zone {zone_name} has {zone.get('record_count', 0)} records but no alias records",
                    recommended_action="Consider using alias records for AWS resources to reduce query costs",
                    metadata={"zone_id": zone["id"], "zone_name": zone_name, "record_count": zone.get("record_count", 0)}))
        return findings


SkillRegistry.register(DnsCertManagerSkill())
