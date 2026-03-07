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

SYSTEM_PROMPT = """You are CloudPilot, an AI-powered AWS operations assistant. You help users:

1. **Scan & Assess** — Run scanning skills to find cost waste, security risks, zombie resources, resiliency gaps, deprecated services, and more across their AWS accounts.
2. **Remediate** — Fix findings with one-click remediation actions (always confirm with the user first).
3. **Architecture Mapping** — Discover all AWS resources and generate visual architecture diagrams.
4. **IaC Generation** — Generate CDK Python, CloudFormation YAML, or Terraform HCL from discovered architecture.
5. **Advise** — Explain findings, recommend priorities, and guide best practices.

Available skills: cost-anomaly, zombie-hunter, security-posture, capacity-planner, event-analysis, resiliency-gaps, tag-enforcer, lifecycle-tracker, health-monitor, quota-guardian, costopt-intelligence, arch-diagram.

Rules:
- Always confirm before executing remediation actions
- Reference actual resource IDs and findings data
- When generating IaC, include comments explaining each resource
- For architecture diagrams, use Mermaid syntax
- Be concise and actionable
- If you don't have scan results yet, suggest running a scan first
"""


class CloudPilotAgent:
    """Conversational agent with Bedrock Converse tool_use loop + AgentCore memory."""

    def __init__(self, profile: Optional[str] = None):
        self.profile = profile
        # Memory is optional — disabled by default, enable with CLOUDPILOT_MEMORY=true
        if os.environ.get("CLOUDPILOT_MEMORY", "").lower() == "true":
            self.memory = AgentMemory()
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
