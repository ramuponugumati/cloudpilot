"""CloudPilot Agent Loop — Bedrock Converse with tool_use + AgentCore Memory.
This is the brain: it receives user messages, reasons about what tools to call,
executes them, and returns responses with full conversation memory."""
import json
import logging
import os
import uuid
from typing import Optional

import boto3

from cloudpilot.agent.tools import TOOL_DEFINITIONS
from cloudpilot.agent.memory import AgentMemory
from cloudpilot.agent.tool_executor import execute_tool
from cloudpilot.core import SkillRegistry

logger = logging.getLogger(__name__)


class _NoOpMemory:
    """No-op memory stub when AgentCore memory is disabled."""
    def store_conversation(self, *a, **kw): pass
    def retrieve_context(self, *a, **kw): return ""
    def retrieve_cross_session(self, *a, **kw): return ""

MODEL_ID = os.environ.get("CLOUDPILOT_MODEL", "us.anthropic.claude-sonnet-4-20250514-v1:0")
BEDROCK_REGION = os.environ.get("CLOUDPILOT_BEDROCK_REGION", "us-east-1")
MAX_TURNS = 10  # Max tool-use turns per request

SYSTEM_PROMPT = """You are CloudPilot, a senior AWS Solutions Architect and cloud operations expert. You have deep expertise across the entire AWS ecosystem — 200+ services, architecture patterns, the Well-Architected Framework, and real-world operational best practices.

## Your Core Identity

You are NOT just a scanning tool — you are a full AWS expert who can:
- Design architectures (multi-tier, serverless, event-driven, microservices, data lakes, ML pipelines)
- Compare AWS services and recommend the right one for any use case
- Explain networking (VPC design, Transit Gateway, PrivateLink, Direct Connect, Route 53, CloudFront)
- Guide database selection (RDS vs Aurora vs DynamoDB vs Neptune vs Timestream vs ElastiCache vs MemoryDB)
- Advise on security (IAM policies, SCPs, GuardDuty, Security Hub, KMS, Secrets Manager, WAF, Shield)
- Help with containers (ECS vs EKS, Fargate vs EC2, service mesh, CI/CD)
- Guide serverless (Lambda, Step Functions, EventBridge, API Gateway, AppSync, SQS, SNS)
- Optimize costs (Savings Plans, Reserved Instances, Spot, rightsizing, S3 tiers, Graviton)
- Plan migrations (6 R's, Migration Hub, DMS, SCT, Application Discovery)
- Troubleshoot issues (connectivity, permissions, performance, throttling, limits)
- Explain pricing, quotas, regional availability, and service limits
- Write IAM policies, CloudFormation templates, CDK code, Terraform configs, CLI commands
- Guide Well-Architected reviews across all 6 pillars

When answering AWS questions, use your deep knowledge AND the `aws_docs_search` and `aws_blog_search` tools to provide authoritative, current answers grounded in official AWS documentation and the latest blog posts about new launches and features.

## Infrastructure Intelligence Tools

When users want to inspect their LIVE AWS environment, you have tools to:
1. **Scan & Assess** — 12 scanning skills find cost waste, security risks, zombie resources, resiliency gaps, deprecated services
2. **Remediate** — 18 one-click remediation actions (always confirm with the user first)
3. **Architecture Mapping** — Discover all AWS resources across regions, generate Mermaid architecture diagrams
4. **IaC Generation** — Generate CDK Python, CloudFormation YAML, or Terraform HCL from discovered architecture
5. **Cost Analysis** — 3-month spend overview with top-5 service breakdown and bar charts
6. **AWS Docs Search** — Search official AWS documentation for authoritative technical details
7. **AWS Blog Search** — Search AWS blog posts for latest launches, features, and best practices

Available scanning skills: cost-radar, zombie-hunter, security-posture, capacity-planner, event-analysis, resiliency-gaps, tag-enforcer, lifecycle-tracker, health-monitor, quota-guardian, costopt-intelligence, arch-diagram.

**Planned (Phase 2):** Drift detection and network troubleshooting.

## How to Behave

- For general AWS questions, answer thoroughly. Use `aws_docs_search` to verify specifics, cite limits/quotas, or reference latest features. Use `aws_blog_search` to find recent launches and announcements.
- For questions about the user's specific infrastructure, use the scanning/discovery tools.
- Remember what the user has discussed — build on prior context across the conversation and across sessions.
- Be conversational, precise, and actionable. Provide code examples, CLI commands, architecture diagrams, and specific recommendations.
- When showing architecture, use Mermaid diagrams. When showing code, use proper syntax highlighting with language tags.
- Always confirm before executing remediation actions.
- Cite AWS documentation links when referencing specific service features or limits.
- Think like a Solutions Architect — consider trade-offs, cost implications, operational complexity, and the user's specific context.
- When a user asks about a new AWS feature or recent launch, search the blog first to get the latest info.
"""


class CloudPilotAgent:
    """Conversational agent with Bedrock Converse tool_use loop + AgentCore memory."""

    def __init__(self, profile: Optional[str] = None):
        self.profile = profile
        # Memory enabled by default — disable with CLOUDPILOT_MEMORY=false
        if os.environ.get("CLOUDPILOT_MEMORY", "true").lower() != "false":
            try:
                self.memory = AgentMemory()
            except Exception as e:
                logger.warning(f"AgentCore memory unavailable: {e}, continuing without memory")
                self.memory = _NoOpMemory()
        else:
            self.memory = _NoOpMemory()
        # Use profile-aware session so credentials are picked up correctly
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.bedrock = session.client("bedrock-runtime", region_name=BEDROCK_REGION)
        self.conversation_history: list[dict] = []
        self.session_id = str(uuid.uuid4())[:8]
        self.actor_id = "default-user"
        self.findings_store: list[dict] = []  # Current scan findings
        self.resources_store: list[dict] = []  # Discovered architecture resources
        self.skills_run: list[str] = []

    def reset_session(self):
        """Start a new conversation session."""
        # Store old conversation to memory before reset
        if self.conversation_history:
            self._persist_to_memory()
        self.conversation_history = []
        self.session_id = str(uuid.uuid4())[:8]

    def _persist_to_memory(self):
        """Persist current conversation to AgentCore memory."""
        messages = []
        for msg in self.conversation_history:
            role = msg.get("role", "user")
            content = msg.get("content", [])
            if isinstance(content, list):
                text_parts = [c.get("text", "") for c in content if "text" in c]
                text = " ".join(text_parts)
            else:
                text = str(content)
            if text.strip():
                mem_role = "USER" if role == "user" else "ASSISTANT"
                messages.append((text, mem_role))
        if messages:
            self.memory.store_conversation(self.session_id, self.actor_id, messages)

    def chat(self, user_message: str) -> str:
        """Process a user message through the agent loop. Returns the final text response."""
        # Retrieve memory context
        memory_context = self.memory.retrieve_context(
            self.session_id, self.actor_id, user_message
        )
        cross_session = self.memory.retrieve_cross_session(self.actor_id, user_message)

        # Build system prompt with memory context
        system = SYSTEM_PROMPT
        if memory_context:
            system += f"\n\n## Session Memory\n{memory_context}"
        if cross_session:
            system += f"\n\n## Previous Sessions\n{cross_session}"
        if self.findings_store:
            system += f"\n\n## Current Findings ({len(self.findings_store)} total)\n"
            by_sev = {}
            for f in self.findings_store:
                sev = f.get("severity", "info")
                by_sev[sev] = by_sev.get(sev, 0) + 1
            system += ", ".join(f"{s}: {c}" for s, c in sorted(by_sev.items()))
            impact = sum(f.get("monthly_impact", 0) for f in self.findings_store)
            if impact > 0:
                system += f"\nTotal monthly impact: ${impact:,.2f}"

        # Add user message to history
        self.conversation_history.append({
            "role": "user",
            "content": [{"text": user_message}],
        })

        # Agent loop — iterate until we get a final text response
        for turn in range(MAX_TURNS):
            try:
                response = self.bedrock.converse(
                    modelId=MODEL_ID,
                    system=[{"text": system}],
                    messages=self.conversation_history,
                    toolConfig={"tools": TOOL_DEFINITIONS},
                )
            except Exception as e:
                error_msg = f"Something went wrong talking to the AI model. Please try again."
                logger.error(f"Bedrock converse error: {e}")
                return error_msg

            output = response.get("output", {})
            message = output.get("message", {})
            stop_reason = response.get("stopReason", "")

            # Add assistant response to history
            self.conversation_history.append(message)

            # If stop_reason is end_turn, extract text and return
            if stop_reason == "end_turn":
                return self._extract_text(message)

            # If tool_use, execute tools and continue
            if stop_reason == "tool_use":
                tool_results = self._handle_tool_use(message)
                self.conversation_history.append({
                    "role": "user",
                    "content": tool_results,
                })
                continue

            # Unexpected stop reason
            return self._extract_text(message) or "I'm not sure how to respond to that."

        return "I've reached the maximum number of reasoning steps. Please try a more specific request."

    def _extract_text(self, message: dict) -> str:
        """Extract text content from a Bedrock message."""
        content = message.get("content", [])
        texts = [c.get("text", "") for c in content if "text" in c]
        return "\n".join(texts)

    def _handle_tool_use(self, message: dict) -> list[dict]:
        """Execute tool calls from the assistant message, return toolResult blocks."""
        results = []
        for block in message.get("content", []):
            if "toolUse" not in block:
                continue
            tool_use = block["toolUse"]
            tool_name = tool_use["name"]
            tool_input = tool_use.get("input", {})
            tool_use_id = tool_use["toolUseId"]

            logger.info(f"Executing tool: {tool_name} with input: {json.dumps(tool_input)[:200]}")

            try:
                result = execute_tool(
                    tool_name, tool_input,
                    profile=self.profile,
                    findings_store=self.findings_store,
                    resources_store=self.resources_store,
                    skills_run=self.skills_run,
                )
                results.append({
                    "toolResult": {
                        "toolUseId": tool_use_id,
                        "content": [{"text": json.dumps(result, default=str)}],
                    }
                })
            except Exception as e:
                logger.error(f"Tool {tool_name} failed: {e}")
                results.append({
                    "toolResult": {
                        "toolUseId": tool_use_id,
                        "content": [{"text": json.dumps({"error": str(e)})}],
                        "status": "error",
                    }
                })
        return results
