"""AgentCore Memory integration — persistent conversation context across sessions."""
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

MEMORY_NAME = "CloudPilotAgentMemory"
MEMORY_REGION = os.environ.get("CLOUDPILOT_MEMORY_REGION", "us-east-1")


class AgentMemory:
    """Wraps Bedrock AgentCore MemoryClient for session + long-term memory."""

    def __init__(self, region: str = MEMORY_REGION):
        self.region = region
        self._client = None
        self._memory_id: Optional[str] = None

    @property
    def client(self):
        if self._client is None:
            try:
                from bedrock_agentcore.memory import MemoryClient
                self._client = MemoryClient(region_name=self.region)
            except ImportError:
                logger.warning("bedrock-agentcore not installed — memory disabled")
                return None
            except Exception as e:
                logger.warning(f"Failed to init AgentCore MemoryClient: {e}")
                return None
        return self._client

    @property
    def memory_id(self) -> Optional[str]:
        if self._memory_id:
            return self._memory_id
        if not self.client:
            return None
        try:
            # Try to find existing memory
            memories = self.client.list_memories()
            # Handle both dict and list responses
            mem_list = memories.get("memories", []) if isinstance(memories, dict) else memories if isinstance(memories, list) else []
            for m in mem_list:
                name = m.get("name", "") if isinstance(m, dict) else ""
                if name == MEMORY_NAME:
                    self._memory_id = m["id"] if isinstance(m, dict) else None
                    return self._memory_id
            # Create new memory with summary strategy
            mem = self.client.create_memory(
                name=MEMORY_NAME,
                description="CloudPilot agent conversation memory with session summaries",
                strategies=[{
                    "summaryMemoryStrategy": {
                        "name": "SessionSummarizer",
                        "namespaces": ["/summaries/{actorId}/{sessionId}/"],
                    }
                }],
            )
            self._memory_id = mem["id"]
            return self._memory_id
        except Exception as e:
            logger.warning(f"Memory setup failed: {e}")
            return None

    def store_conversation(self, session_id: str, actor_id: str, messages: list[tuple[str, str]]):
        """Store conversation messages. messages = [(content, role), ...]"""
        if not self.memory_id:
            return
        try:
            self.client.create_event(
                memory_id=self.memory_id,
                actor_id=actor_id,
                session_id=session_id,
                messages=messages,
            )
        except Exception as e:
            logger.warning(f"Failed to store conversation: {e}")

    def retrieve_context(self, session_id: str, actor_id: str, query: str) -> str:
        """Retrieve relevant memories for the current query."""
        if not self.memory_id:
            return ""
        try:
            result = self.client.retrieve_memories(
                memory_id=self.memory_id,
                namespace=f"/summaries/{actor_id}/{session_id}/",
                query=query,
            )
            memories = result.get("memories", [])
            if not memories:
                return ""
            context_parts = []
            for m in memories[:5]:
                content = m.get("content", "")
                if content:
                    context_parts.append(content)
            return "\n".join(context_parts)
        except Exception as e:
            logger.warning(f"Memory retrieval failed: {e}")
            return ""

    def retrieve_cross_session(self, actor_id: str, query: str) -> str:
        """Retrieve memories across all sessions for a user."""
        if not self.memory_id:
            return ""
        try:
            result = self.client.retrieve_memories(
                memory_id=self.memory_id,
                namespace=f"/summaries/{actor_id}/",
                query=query,
            )
            memories = result.get("memories", [])
            return "\n".join(m.get("content", "") for m in memories[:5] if m.get("content"))
        except Exception as e:
            logger.warning(f"Cross-session retrieval failed: {e}")
            return ""
