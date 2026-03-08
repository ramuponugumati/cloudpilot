"""Tool definitions for the CloudPilot agent loop.
Each tool maps to a skill or capability the agent can invoke via Bedrock Converse tool_use."""

TOOL_DEFINITIONS = [
    {
        "toolSpec": {
            "name": "run_skill",
            "description": "Run a CloudPilot scanning skill against the AWS account. Available skills: cost-radar, zombie-hunter, security-posture, capacity-planner, event-analysis, resiliency-gaps, tag-enforcer, lifecycle-tracker, health-monitor, quota-guardian, costopt-intelligence, arch-diagram.",
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
    {
        "toolSpec": {
            "name": "aws_docs_search",
            "description": "Search official AWS documentation for authoritative technical details, service guides, API references, best practices, quotas, and limits. Use this when you need to verify specifics or cite official AWS guidance.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query for AWS documentation (e.g., 'Lambda concurrency limits', 'S3 lifecycle policies', 'VPC peering vs Transit Gateway')"},
                        "max_results": {"type": "integer", "description": "Maximum results to return (default 5)", "default": 5},
                    },
                    "required": ["query"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "aws_blog_search",
            "description": "Search AWS blog posts for latest service launches, feature announcements, architecture patterns, and best practices. Use this when users ask about new features, recent launches, or want to know what's new in a service.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query for AWS blog (e.g., 'Bedrock agents launch', 'new S3 features 2025', 'Aurora Serverless v2')"},
                        "max_results": {"type": "integer", "description": "Maximum results to return (default 5)", "default": 5},
                    },
                    "required": ["query"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "generate_diagram",
            "description": "Generate a Mermaid architecture diagram from discovered resources. Supports 5 view types: default (full architecture by layer), security (SGs, NACLs, IAM boundaries), cost (resources annotated with estimated monthly cost), multi-region (grouped by region), traffic-flow (edge→compute→data request path).",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "view_type": {
                            "type": "string",
                            "enum": ["default", "security", "cost", "multi-region", "traffic-flow"],
                            "description": "Diagram view type",
                            "default": "default",
                        },
                        "resources": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "Resource inventory. If omitted, uses previously discovered resources.",
                        },
                    },
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "detect_drift",
            "description": "Detect infrastructure drift between live AWS resources and IaC definitions. COMING SOON in Phase 2 — will support IaC drift, configuration drift, and baseline drift detection.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "scope": {"type": "string", "description": "Scope of drift detection"},
                    },
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "trace_network_path",
            "description": "Trace network connectivity path between two AWS resources. COMING SOON in Phase 2 — will support path tracing, security group chain analysis, and connectivity diagnosis.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "source": {"type": "string", "description": "Source resource ID"},
                        "destination": {"type": "string", "description": "Destination resource ID"},
                    },
                }
            },
        }
    },
]
