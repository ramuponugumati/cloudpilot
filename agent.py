"""AgentCore Runtime entry point — exposes CloudPilot as a managed Strands agent.

Deploy to AgentCore Runtime:
    agentcore deploy --entry-point agent.py
"""
import os
from cloudpilot.agent.strands_agent import create_agent

# AgentCore Runtime picks up the agent from module-level
profile = os.environ.get("AWS_PROFILE")
memory_id = os.environ.get("CLOUDPILOT_MEMORY_ID")

agent = create_agent(profile=profile, memory_id=memory_id)
