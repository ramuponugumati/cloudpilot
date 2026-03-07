"""IaC Generator — generates CDK Python, CloudFormation YAML, or Terraform HCL
from discovered AWS resources. Uses Bedrock for contextual code generation
with fallback templates when Bedrock is unavailable."""
import json
import logging
import os
from typing import Optional

import boto3

logger = logging.getLogger(__name__)

MODEL_ID = os.environ.get("CLOUDPILOT_MODEL", "us.anthropic.claude-sonnet-4-20250514-v1:0")
BEDROCK_REGION = os.environ.get("CLOUDPILOT_BEDROCK_REGION", "us-east-1")


class IaCGenerator:
    """Generate Infrastructure as Code from discovered resource inventory."""

    def generate(self, resources: list[dict], fmt: str, scope: str = "all") -> dict:
        """Generate IaC code.
        Args:
            resources: Resource inventory from ArchMapper.discover()
            fmt: 'cdk-python', 'cloudformation', or 'terraform'
            scope: 'all', a service name like 'ec2', or a specific resource ID
        Returns:
            dict with format, scope, resource_count, code, services, warnings
        """
        if not resources:
            return {"format": fmt, "code": "", "error": "No resources found. Run discovery first.",
                    "resource_count": 0}

        # Filter by scope
        if scope and scope != "all":
            filtered = [r for r in resources if r.get("service") == scope or r.get("id") == scope]
        else:
            filtered = resources

        if not filtered:
            return {"format": fmt, "code": "", "error": f"No resources match scope '{scope}'",
                    "resource_count": 0}

        prompt = self._build_prompt(filtered, fmt)

        try:
            bedrock = boto3.client("bedrock-runtime", region_name=BEDROCK_REGION)
            response = bedrock.converse(
                modelId=MODEL_ID,
                messages=[{"role": "user", "content": [{"text": prompt}]}],
                system=[{"text": self._system_prompt(fmt)}],
            )
            code = response["output"]["message"]["content"][0]["text"]
            return {
                "format": fmt, "scope": scope,
                "resource_count": len(filtered), "code": code,
                "services": list(set(r.get("service", "") for r in filtered)),
                "warnings": self._get_warnings(filtered),
            }
        except Exception as e:
            logger.warning(f"Bedrock IaC generation failed: {e}, using fallback")
            code = self._fallback_generate(filtered, fmt)
            return {
                "format": fmt, "scope": scope,
                "resource_count": len(filtered), "code": code,
                "services": list(set(r.get("service", "") for r in filtered)),
                "warnings": ["Generated using fallback template (Bedrock unavailable)"],
            }

    def _system_prompt(self, fmt: str) -> str:
        names = {"cdk-python": "AWS CDK v2 Python", "cloudformation": "CloudFormation YAML",
                 "terraform": "Terraform HCL (AWS provider)"}
        return (f"You are an expert AWS infrastructure engineer. Generate {names.get(fmt, fmt)} code "
                f"from the provided resource inventory. Include comments explaining each resource. "
                f"Use best practices (encryption, tagging, least privilege). "
                f"Parameterize configurable values. Return ONLY the code.")

    def _build_prompt(self, resources: list[dict], fmt: str) -> str:
        by_service = {}
        for r in resources:
            by_service.setdefault(r.get("service", "unknown"), []).append(r)
        parts = [f"Generate {fmt} code to recreate this AWS infrastructure:\n"]
        for svc, items in by_service.items():
            parts.append(f"\n## {svc.upper()} ({len(items)} resources)")
            for item in items[:15]:
                clean = {k: v for k, v in item.items() if k not in ("account_id",) and v}
                parts.append(f"- {json.dumps(clean, default=str)}")
        parts.append(f"\nTotal: {len(resources)} resources across {len(by_service)} services.")
        return "\n".join(parts)

    def _get_warnings(self, resources) -> list[str]:
        warnings = []
        services = set(r.get("service", "") for r in resources)
        if "vpc" not in services and any(r.get("vpc_id") or r.get("metadata", {}).get("vpc_id") for r in resources):
            warnings.append("Resources reference VPCs not in inventory — consider adding VPC discovery")
        if len(resources) > 50:
            warnings.append("Large infrastructure — consider splitting into multiple stacks/modules")
        return warnings

    def _fallback_generate(self, resources: list[dict], fmt: str) -> str:
        """Generate basic IaC template without Bedrock."""
        if fmt == "cloudformation":
            return self._fallback_cfn(resources)
        elif fmt == "terraform":
            return self._fallback_terraform(resources)
        elif fmt == "cdk-python":
            return self._fallback_cdk(resources)
        return "# Unsupported format"

    def _fallback_cfn(self, resources) -> str:
        lines = ["AWSTemplateFormatVersion: '2010-09-09'",
                 f"Description: CloudPilot generated — {len(resources)} resources", "",
                 "Resources:"]
        for r in resources[:30]:
            rid = r.get("id", "unknown").replace("-", "").replace(".", "")[:20]
            svc = r.get("service", "")
            lines.append(f"  # {svc}: {r.get('name', r.get('id', ''))}")
            lines.append(f"  {rid}:")
            lines.append(f"    Type: AWS::CloudFormation::WaitConditionHandle  # TODO: replace with actual type")
        return "\n".join(lines)

    def _fallback_terraform(self, resources) -> str:
        lines = ['# CloudPilot generated Terraform', f'# {len(resources)} resources discovered', '',
                 'provider "aws" {', '  region = var.region', '}', '',
                 'variable "region" {', '  default = "us-east-1"', '}', '']
        for r in resources[:30]:
            rid = r.get("id", "unknown").replace("-", "_").replace(".", "_")[:30]
            svc = r.get("service", "")
            lines.append(f'# {svc}: {r.get("name", r.get("id", ""))}')
            lines.append(f'# resource "aws_{svc}_{r.get("type", "resource")}" "{rid}" {{')
            lines.append(f'#   # TODO: add configuration')
            lines.append(f'# }}')
            lines.append('')
        return "\n".join(lines)

    def _fallback_cdk(self, resources) -> str:
        lines = ['# CloudPilot generated CDK Python', f'# {len(resources)} resources discovered', '',
                 'from aws_cdk import Stack, aws_ec2 as ec2, aws_rds as rds, aws_s3 as s3',
                 'from constructs import Construct', '', '',
                 'class CloudPilotStack(Stack):', '    def __init__(self, scope: Construct, id: str, **kwargs):',
                 '        super().__init__(scope, id, **kwargs)', '']
        for r in resources[:30]:
            svc = r.get("service", "")
            lines.append(f'        # {svc}: {r.get("name", r.get("id", ""))}')
            lines.append(f'        # TODO: add {svc} construct')
        return "\n".join(lines)
