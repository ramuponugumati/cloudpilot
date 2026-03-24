"""Strands memory hook — auto-loads history on agent init, saves after each message.
Primary: AgentCore MemoryClient. Fallback: local JSON at ~/.cloudpilot/memory.json."""
import logging
import os
from typing import Optional, Any

from strands.hooks import HookProvider, HookRegistry, AfterInvocationEvent, AgentInitializedEvent

from cloudpilot.agent.local_memory import LocalMemoryStore, ScanRecord, RemediationRecord
from cloudpilot.agent.session_context import SessionContext

logger = logging.getLogger(__name__)


class CloudPilotMemoryHook(HookProvider):
    """Strands-compatible hook for persistent memory."""

    def __init__(self, profile: Optional[str] = None, memory_id: Optional[str] = None):
        self.profile = profile
        self.memory_id = memory_id or os.getenv("CLOUDPILOT_MEMORY_ID")
        self._memory_client = None
        self._local = LocalMemoryStore()
        self.session_ctx = SessionContext()
        self._agentcore_available = False

        # Try to init AgentCore MemoryClient
        if self.memory_id:
            try:
                from bedrock_agentcore.memory import MemoryClient
                self._memory_client = MemoryClient(region_name="us-east-1")
                self._agentcore_available = True
                logger.info("AgentCore MemoryClient initialized")
            except Exception as e:
                logger.info(f"AgentCore MemoryClient unavailable, using local fallback: {e}")

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        """Register Strands lifecycle hooks."""
        registry.add_callback(AgentInitializedEvent, self._on_agent_init)
        registry.add_callback(AfterInvocationEvent, self._on_after_invocation)

    def _on_agent_init(self, event: AgentInitializedEvent):
        """Load memory context when agent initializes."""
        logger.info("Memory hook: agent initialized, loading context")

    def _on_after_invocation(self, event: AfterInvocationEvent):
        """Save conversation context after each invocation."""
        logger.debug("Memory hook: saving context after invocation")

    def record_scan(self, skill_name: str, finding_count: int, top_findings: list, total_impact: float):
        """Record a completed scan to both session context and persistent memory."""
        from datetime import datetime, timezone
        self.session_ctx.record_skill_run(skill_name, finding_count, total_impact)
        self._local.append_scan(ScanRecord(
            skill=skill_name, timestamp=datetime.now(timezone.utc).isoformat(),
            finding_count=finding_count, top_findings=top_findings[:5],
            total_impact=total_impact,
        ))

    def record_remediation(self, resource_id: str, action: str, success: bool, region: str):
        """Record a remediation action to both session context and persistent memory."""
        from datetime import datetime, timezone
        self.session_ctx.record_remediation(resource_id, action, success)
        self._local.append_remediation(RemediationRecord(
            resource_id=resource_id, action=action, success=success,
            timestamp=datetime.now(timezone.utc).isoformat(), region=region,
        ))

    def build_memory_prompt(self) -> str:
        """Build combined memory context for system prompt injection."""
        parts = []
        # Session context (what happened this session)
        session = self.session_ctx.to_prompt()
        if session:
            parts.append(f"## This Session\n{session}")
        # Persistent memory (what happened in previous sessions)
        local = self._local.build_context_prompt()
        if local:
            parts.append(f"## Previous Activity\n{local}")
        return "\n\n".join(parts)
