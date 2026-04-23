"""Database Deep Optimization — DynamoDB capacity, GSI analysis, RDS right-sizing,
dev/staging DB shutdown recommendations."""
import logging
import time

from cloudpilot.core import BaseSkill, Finding, Severity, SkillResult, SkillRegistry
from cloudpilot.aws_client import get_client, get_account_id, parallel_regions

logger = logging.getLogger(__name__)

GRAVITON_RDS_MAP = {"db.m5": "db.m7g", "db.r5": "db.r7g", "db.t3": "db.t4g", "db.m6i": "db.m7g", "db.r6i": "db.r7g"}


class DatabaseOptimizerSkill(BaseSkill):
    name = "database-optimizer"
    description = "DynamoDB capacity optimization, GSI analysis, RDS right-sizing, dev DB shutdown"
    version = "0.1.0"

    def scan(self, regions, profile=None, account_id=None, **kwargs) -> SkillResult:
        start = time.time()
        acct = account_id or get_account_id(profile)
        region_results = parallel_regions(
            lambda r, p: self._collect(r, p), regions, profile=profile)
        data = self._merge(region_results)
        findings = self._run_checks(data)
        for f in findings:
            f.account_id = acct
        return SkillResult(
            skill_name=self.name, findings=findings,
            duration_seconds=time.time() - start,
            accounts_scanned=1, regions_scanned=len(regions),
            errors=data.get("errors", []))

    def _collect(self, region, profile=None):
        data = {"dynamodb_tables": [], "rds_instances": [], "errors": [], "region": region}
        # DynamoDB
        try:
            ddb = get_client("dynamodb", region, profile)
            table_names = ddb.list_tables().get("TableNames", [])
            for tname in table_names:
                try:
                    desc = ddb.describe_table(TableName=tname).get("Table", {})
                    billing = desc.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED")
                    gsis = []
                    for gsi in desc.get("GlobalSecondaryIndexes", []):
                        gsis.append({
                            "name": gsi.get("IndexName", ""),
                            "status": gsi.get("IndexStatus", ""),
                            "item_count": gsi.get("ItemCount", 0),
                            "size_bytes": gsi.get("IndexSizeBytes", 0),
                            "provisioned_rcu": gsi.get("ProvisionedThroughput", {}).get("ReadCapacityUnits", 0),
                            "provisioned_wcu": gsi.get("ProvisionedThroughput", {}).get("WriteCapacityUnits", 0),
                        })
                    data["dynamodb_tables"].append({
                        "name": tname, "arn": desc.get("TableArn", ""),
                        "billing_mode": billing,
                        "item_count": desc.get("ItemCount", 0),
                        "size_bytes": desc.get("TableSizeBytes", 0),
                        "provisioned_rcu": desc.get("ProvisionedThroughput", {}).get("ReadCapacityUnits", 0),
                        "provisioned_wcu": desc.get("ProvisionedThroughput", {}).get("WriteCapacityUnits", 0),
                        "gsi_count": len(gsis), "gsis": gsis,
                        "region": region,
                    })
                except Exception as e:
                    data["errors"].append(f"describe_table {tname}: {e}")
        except Exception as e:
            logger.warning("DynamoDB in %s: %s", region, e)
            data["errors"].append(f"dynamodb in {region}: {e}")
        # RDS
        try:
            rds = get_client("rds", region, profile)
            for page in rds.get_paginator("describe_db_instances").paginate():
                for db in page.get("DBInstances", []):
                    tags = {}
                    try:
                        tag_list = rds.list_tags_for_resource(ResourceName=db.get("DBInstanceArn", "")).get("TagList", [])
                        tags = {t["Key"]: t["Value"] for t in tag_list}
                    except Exception:
                        pass
                    data["rds_instances"].append({
                        "id": db["DBInstanceIdentifier"], "engine": db.get("Engine", ""),
                        "instance_class": db.get("DBInstanceClass", ""),
                        "multi_az": db.get("MultiAZ", False),
                        "storage_type": db.get("StorageType", ""),
                        "allocated_storage": db.get("AllocatedStorage", 0),
                        "tags": tags, "region": region,
                    })
        except Exception as e:
            logger.warning("RDS in %s: %s", region, e)
            data["errors"].append(f"rds in {region}: {e}")
        return data

    def _merge(self, results):
        merged = {"dynamodb_tables": [], "rds_instances": [], "errors": []}
        for rd in (results if isinstance(results, list) else []):
            if isinstance(rd, dict):
                for k in merged:
                    merged[k].extend(rd.get(k, []))
        return merged

    def _run_checks(self, data):
        findings = []
        for checker in [self._check_ddb_billing, self._check_ddb_gsi,
                        self._check_rds_graviton, self._check_rds_dev_shutdown]:
            try:
                findings.extend(checker(data))
            except Exception as e:
                logger.warning("Checker failed: %s", e)
        return findings

    def _check_ddb_billing(self, data):
        """Flag provisioned tables that might benefit from on-demand, and vice versa."""
        findings = []
        for tbl in data.get("dynamodb_tables", []):
            name, region = tbl["name"], tbl["region"]
            billing = tbl.get("billing_mode", "PROVISIONED")
            rcu = tbl.get("provisioned_rcu", 0)
            wcu = tbl.get("provisioned_wcu", 0)
            if billing == "PROVISIONED" and (rcu <= 5 and wcu <= 5):
                findings.append(Finding(
                    skill=self.name, title=f"DynamoDB low-traffic provisioned: {name}",
                    severity=Severity.MEDIUM, resource_id=name, region=region,
                    description=f"Table {name} is provisioned with {rcu} RCU / {wcu} WCU — consider on-demand for low-traffic tables",
                    recommended_action="Switch to on-demand billing mode for cost savings on low-traffic tables",
                    metadata={"table": name, "billing_mode": billing, "rcu": rcu, "wcu": wcu}))
            elif billing == "PAY_PER_REQUEST" and tbl.get("item_count", 0) > 1_000_000:
                findings.append(Finding(
                    skill=self.name, title=f"DynamoDB high-volume on-demand: {name}",
                    severity=Severity.LOW, resource_id=name, region=region,
                    description=f"Table {name} has {tbl['item_count']:,} items on on-demand — provisioned may be cheaper",
                    recommended_action="Evaluate provisioned capacity with auto-scaling for predictable workloads",
                    metadata={"table": name, "billing_mode": billing, "item_count": tbl["item_count"]}))
        return findings

    def _check_ddb_gsi(self, data):
        """Flag tables with many GSIs or empty GSIs."""
        findings = []
        for tbl in data.get("dynamodb_tables", []):
            name, region = tbl["name"], tbl["region"]
            gsis = tbl.get("gsis", [])
            if len(gsis) >= 5:
                findings.append(Finding(
                    skill=self.name, title=f"DynamoDB many GSIs: {name}",
                    severity=Severity.MEDIUM, resource_id=name, region=region,
                    description=f"Table {name} has {len(gsis)} GSIs (max 20) — each GSI adds cost",
                    recommended_action="Review if all GSIs are actively used",
                    metadata={"table": name, "gsi_count": len(gsis)}))
            for gsi in gsis:
                if gsi.get("item_count", 0) == 0 and gsi.get("size_bytes", 0) == 0:
                    findings.append(Finding(
                        skill=self.name, title=f"DynamoDB empty GSI: {name}/{gsi['name']}",
                        severity=Severity.LOW, resource_id=f"{name}/{gsi['name']}", region=region,
                        description=f"GSI {gsi['name']} on table {name} has 0 items — may be unused",
                        recommended_action="Delete if not needed to save provisioned capacity costs",
                        metadata={"table": name, "gsi_name": gsi["name"]}))
        return findings

    def _check_rds_graviton(self, data):
        """Flag RDS instances eligible for Graviton migration."""
        findings = []
        for inst in data.get("rds_instances", []):
            iclass = inst.get("instance_class", "")
            family = ".".join(iclass.split(".")[:2]) if "." in iclass else ""
            grav = GRAVITON_RDS_MAP.get(family)
            if grav:
                size = iclass.split(".")[-1] if "." in iclass else "xlarge"
                new_class = f"{grav}.{size}"
                findings.append(Finding(
                    skill=self.name, title=f"RDS Graviton eligible: {inst['id']}",
                    severity=Severity.MEDIUM, resource_id=inst["id"], region=inst["region"],
                    description=f"RDS {inst['id']} uses {iclass} — migrate to {new_class} for ~20% savings",
                    recommended_action=f"Modify instance class to {new_class}",
                    metadata={"instance": inst["id"], "current_class": iclass, "graviton_class": new_class,
                              "engine": inst.get("engine", ""), "estimated_savings_pct": 20}))
        return findings

    def _check_rds_dev_shutdown(self, data):
        """Flag dev/staging RDS instances that could be stopped."""
        findings = []
        dev_patterns = {"dev", "development", "staging", "stage", "test", "qa", "sandbox", "demo"}
        for inst in data.get("rds_instances", []):
            name = inst["id"].lower()
            tags = inst.get("tags", {})
            env_tag = tags.get("Environment", tags.get("environment", tags.get("Env", ""))).lower()
            is_dev = any(p in name for p in dev_patterns) or env_tag in dev_patterns
            if is_dev:
                findings.append(Finding(
                    skill=self.name, title=f"Dev/staging DB running: {inst['id']}",
                    severity=Severity.MEDIUM, resource_id=inst["id"], region=inst["region"],
                    description=f"RDS {inst['id']} appears to be a dev/staging instance — consider scheduled stop",
                    recommended_action="Stop during non-business hours or use EventBridge for scheduled start/stop",
                    metadata={"instance": inst["id"], "engine": inst.get("engine", ""),
                              "instance_class": inst.get("instance_class", ""), "environment": env_tag or "inferred"}))
        return findings


SkillRegistry.register(DatabaseOptimizerSkill())
