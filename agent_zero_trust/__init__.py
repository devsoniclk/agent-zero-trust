"""
Agent Zero-Trust: Formal Microsegmentation & Capability Attenuation for Autonomous AI Agent Swarms.
"""

from agent_zero_trust.circuit import AnomalyDetector, SwarmCircuitBreaker
from agent_zero_trust.firewall import SwarmRPCGate, SwarmRuntimeGuard
from agent_zero_trust.models import (
    ALLOWED_RPC_MATRIX,
    THREAT_CATALOG,
    AgentIsolationState,
    Caveat,
    DelegationToken,
    SwarmTier,
)
from agent_zero_trust.sandbox import SandboxPolicyVerifier
from agent_zero_trust.tokens import TokenAuthority

__version__ = "0.1.0"
__all__ = [
    "SwarmTier",
    "AgentIsolationState",
    "Caveat",
    "DelegationToken",
    "THREAT_CATALOG",
    "ALLOWED_RPC_MATRIX",
    "TokenAuthority",
    "AnomalyDetector",
    "SwarmCircuitBreaker",
    "SandboxPolicyVerifier",
    "SwarmRPCGate",
    "SwarmRuntimeGuard",
]
