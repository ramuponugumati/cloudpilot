"""Tool definitions for the CloudPilot agent loop.
Each tool maps to a skill or capability the agent can invoke via Bedrock Converse tool_use."""

TOOL_DEFINITIONS = [
    {
        "toolSpec": {
            "name": "run_skill",
            "description": "Run a CloudPilot scanning skill against the AWS account. Available skills: cost-anomaly, zombie-hunter, security-posture, capacity-planner, event-analysis, resiliency-gaps, tag-enforcer, lifecycle-tracker, health-monitor, quota-guardian, costopt-intelligence, arch-diagram.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "skill_name": {"type": "string", "description": "Name of the skill to run"},
                        "regions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "AWS regions to scan. Omit for all regions.",
                        },
                    },
                    "required": ["skill_name"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "run_all_skills",
            "description": "Run all CloudPilot scanning skills in parallel across the AWS account.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "regions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "AWS regions to scan. Omit for all regions.",
                        },
                    },
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "remediate_finding",
            "description": "Execute a one-click remediation for a specific finding. Requires user confirmation.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "finding": {"type": "object", "description": "The finding dict to remediate"},
                    },
                    "required": ["finding"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "discover_architecture",
            "description": "Discover all AWS resources in the account and generate an architecture map. Returns a Mermaid diagram and resource inventory.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "regions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Regions to discover. Omit for all.",
                        },
                        "include_relationships": {
                            "type": "boolean",
                            "description": "Include resource relationships from Config/CloudTrail",
                            "default": True,
                        },
                    },
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "generate_iac",
            "description": "Generate Infrastructure as Code from discovered architecture. Supports CDK Python, CloudFormation YAML, and Terraform HCL.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "format": {
                            "type": "string",
                            "enum": ["cdk-python", "cloudformation", "terraform"],
                            "description": "IaC output format",
                        },
                        "resources": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "Resource inventory from discover_architecture. If omitted, runs discovery first.",
                        },
                        "scope": {
                            "type": "string",
                            "description": "Filter: 'all', a specific service like 'ec2', or a resource ID",
                            "default": "all",
                        },
                    },
                    "required": ["format"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "get_findings_summary",
            "description": "Get a summary of current scan findings — counts by severity, top impactful findings, skills run.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {},
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "list_skills",
            "description": "List all available CloudPilot skills with descriptions.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {},
                }
            },
        }
    },
]
