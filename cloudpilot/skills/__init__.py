"""CloudPilot Skills — auto-register all scanning skills on import.
Skills carried forward from aws-ops-agent + new CloudPilot capabilities."""

# Import all skill modules to trigger registration
from cloudpilot.skills import (
    cost_radar,
    zombie_hunter,
    security_posture,
    capacity_planner,
    event_analysis,
    resiliency_gaps,
    tag_enforcer,
    lifecycle_tracker,
    health_monitor,
    quota_guardian,
    costopt_intelligence,
    arch_mapper,
    network_path_tracer,
    sg_chain_analyzer,
    connectivity_diagnoser,
    network_topology,
    drift_detector,
    backup_dr_posture,
    data_security,
)
