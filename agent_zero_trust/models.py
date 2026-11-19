"""
Data models, enums, threat catalog, and delegation token specifications for agent-zero-trust.
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


# ==============================================================================
# Security Threat Models & CVSS v3.1 Registry
# ==============================================================================

THREAT_CATALOG: Dict[str, Dict[str, Any]] = {
    "ZTM-001": {
        "title": "Unauthenticated Inter-Agent RPC Call",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "RPC dispatched without a valid cryptographic delegation token.",
        "remediation": "Mandate valid HMAC-chained biscuit/macaroon token on all inter-agent endpoints."
    },
    "ZTM-002": {
        "title": "Token Signature Chain Tampering / Forgery",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "Token signature does not cryptographically match the accumulated caveat chain.",
        "remediation": "Reject token immediately; verify HMAC signature chain at each attenuation hop."
    },
    "ZTM-003": {
        "title": "Unauthorized Cross-Tier Lateral Movement",
        "cvss": 9.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
        "description": "Lower-tier agent (e.g., Tier 3 sandbox/web) attempts direct RPC to higher-tier agent (e.g., Tier 0 root/KMS).",
        "remediation": "Enforce strict tier-boundary firewall rules; block Tier 3 -> Tier 0/1 direct routing."
    },
    "ZTM-004": {
        "title": "Capability Widening / Attenuation Bypass",
        "cvss": 8.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "description": "Delegated sub-token attempts to claim permissions or tools broader than its parent token.",
        "remediation": "Enforce monotonic restriction invariant: caveats can only narrow, never expand capabilities."
    },
    "ZTM-005": {
        "title": "Stale / Replayed Delegation Token",
        "cvss": 8.1,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "description": "Expired token or reused one-time nonce presented in inter-agent communication.",
        "remediation": "Validate token TTL, enforce strict expiration windows, and reject replayed nonces."
    },
    "ZTM-006": {
        "title": "Permissive macOS Seatbelt Sandbox Profile",
        "cvss": 8.6,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
        "description": "Seatbelt SBPL profile allows global filesystem write or unconstrained Mach IPC services.",
        "remediation": "Restrict sandbox profiles to isolated agent workspaces; deny default mach-lookup."
    },
    "ZTM-007": {
        "title": "Permissive eBPF / seccomp Syscall Whitelist",
        "cvss": 8.5,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
        "description": "eBPF/seccomp filter permits dangerous syscalls (ptrace, bpf, sys_chroot, socket_raw).",
        "remediation": "Enforce strict seccomp-BPF whitelist rejecting process debugging and raw packet creation."
    },
    "ZTM-008": {
        "title": "Prompt Injection / Lateral Pivoting Payload",
        "cvss": 8.9,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N",
        "description": "Inter-agent RPC payload contains adversarial prompt injection attempting to coerce recipient agent.",
        "remediation": "Implement bidirectional input sanitization, structural schema validation, and quarantine circuit breaker."
    },
    "ZTM-009": {
        "title": "Failure to Sever Mesh Links on Agent Compromise",
        "cvss": 9.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "description": "Quarantined agent continues to receive or dispatch messages due to missing mesh revocation.",
        "remediation": "Propagate instant token revocation to all swarm gateways and trip automated isolation circuit breaker."
    },
    "ZTM-010": {
        "title": "Unauthenticated Token Caveat Stripping",
        "cvss": 9.3,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "description": "Attacker strips downstream caveats from token to revert to root permissions without detection.",
        "remediation": "HMAC chaining binds final signature to full caveat history; signature verification fails if caveats are stripped."
    }
}


# ==============================================================================
# Swarm Security Tiers & States
# ==============================================================================

class SwarmTier(Enum):
    """Hierarchical operational security tiers for autonomous agents."""
    TIER_0_ROOT_KMS = "Tier_0_Root_KMS"       # Root coordinators, KMS, secret custodians, release veto officers
    TIER_1_DOMAIN_CORE = "Tier_1_Domain_Core"   # Financial engines, core business logic, code generation
    TIER_2_TOOL_RUNNER = "Tier_2_Tool_Runner"   # Task workers, subagents, CLI tool execution, DB adapters
    TIER_3_SANDBOX_WEB = "Tier_3_Sandbox_Web"   # Untrusted ingress, web scraping, external API consumers


class AgentIsolationState(Enum):
    """Quarantine containment lifecycle states for monitored swarm agents."""
    ACTIVE = "ACTIVE"
    SUSPECT = "SUSPECT"
    QUARANTINED = "QUARANTINED"
    ISOLATED = "ISOLATED"


# Matrix defining allowed direct RPC invocations: Caller Tier -> Allowed Target Tiers
ALLOWED_RPC_MATRIX: Dict[SwarmTier, Set[SwarmTier]] = {
    SwarmTier.TIER_0_ROOT_KMS: {
        SwarmTier.TIER_0_ROOT_KMS,
        SwarmTier.TIER_1_DOMAIN_CORE,
        SwarmTier.TIER_2_TOOL_RUNNER,
        SwarmTier.TIER_3_SANDBOX_WEB
    },
    SwarmTier.TIER_1_DOMAIN_CORE: {
        SwarmTier.TIER_1_DOMAIN_CORE,
        SwarmTier.TIER_2_TOOL_RUNNER
    },
    SwarmTier.TIER_2_TOOL_RUNNER: {
        SwarmTier.TIER_2_TOOL_RUNNER,
        SwarmTier.TIER_3_SANDBOX_WEB,
        SwarmTier.TIER_1_DOMAIN_CORE  # Only with explicit task delegation token
    },
    SwarmTier.TIER_3_SANDBOX_WEB: {
        SwarmTier.TIER_3_SANDBOX_WEB,
        SwarmTier.TIER_2_TOOL_RUNNER  # Must report back to mediator only
    }
}


# ==============================================================================
# Capability-Attenuated Delegation Tokens (Macaroon/Biscuit Architecture)
# ==============================================================================

@dataclass
class Caveat:
    """A first-party execution predicate restricting delegation token usage."""
    predicate: str  # e.g., "tool", "valid_until", "target_agent", "max_depth", "repo_path"
    operator: str   # e.g., "==", "!=", "<=", ">=", "in", "startswith", "endswith", "regex"
    value: Any

    def evaluate(self, context: Dict[str, Any]) -> bool:
        """Evaluates whether the caveat is satisfied by the invocation context."""
        ctx_val = context.get(self.predicate)
        if ctx_val is None:
            if self.predicate in ("valid_until", "time", "timestamp"):
                import time
                ctx_val = context.get("time", context.get("valid_until", time.time()))
            else:
                return False

        if self.operator == "==":
            return str(ctx_val) == str(self.value)
        elif self.operator == "!=":
            return str(ctx_val) != str(self.value)
        elif self.operator == "<=":
            try:
                return float(ctx_val) <= float(self.value)
            except (ValueError, TypeError):
                return False
        elif self.operator == ">=":
            try:
                return float(ctx_val) >= float(self.value)
            except (ValueError, TypeError):
                return False
        elif self.operator == "in":
            if isinstance(self.value, list):
                return ctx_val in self.value
            return str(ctx_val) in str(self.value)
        elif self.operator == "startswith":
            return str(ctx_val).startswith(str(self.value))
        elif self.operator == "endswith":
            return str(ctx_val).endswith(str(self.value))
        elif self.operator == "regex":
            try:
                return bool(re.search(str(self.value), str(ctx_val)))
            except re.error:
                return False
        return False

    def to_string(self) -> str:
        return f"{self.predicate} {self.operator} {json.dumps(self.value, sort_keys=True)}"

    @classmethod
    def from_string(cls, raw: str) -> "Caveat":
        parts = raw.split(" ", 2)
        if len(parts) != 3:
            raise ValueError(f"Malformed caveat string: {raw}")
        return cls(predicate=parts[0], operator=parts[1], value=json.loads(parts[2]))


@dataclass
class DelegationToken:
    """Cryptographic capability-attenuated delegation token."""
    token_id: str
    issuer_agent: str
    subject_agent: str
    issuer_tier: str
    subject_tier: str
    capabilities: List[str]
    created_at: float
    expires_at: float
    nonce: str
    root_capabilities: List[str] = field(default_factory=list)
    caveats: List[Caveat] = field(default_factory=list)
    signature: str = ""

    def __post_init__(self):
        if not self.root_capabilities:
            self.root_capabilities = list(self.capabilities)

    def serialize_payload(self) -> str:
        """Serializes base token payload for initial HMAC signing."""
        payload = {
            "token_id": self.token_id,
            "issuer_agent": self.issuer_agent,
            "subject_agent": self.subject_agent,
            "issuer_tier": self.issuer_tier,
            "subject_tier": self.subject_tier,
            "root_capabilities": sorted(self.root_capabilities),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce
        }
        return json.dumps(payload, sort_keys=True)

    def to_dict(self) -> Dict[str, Any]:
        """Converts token to JSON-serializable dictionary."""
        return {
            "token_id": self.token_id,
            "issuer_agent": self.issuer_agent,
            "subject_agent": self.subject_agent,
            "issuer_tier": self.issuer_tier,
            "subject_tier": self.subject_tier,
            "capabilities": list(self.capabilities),
            "root_capabilities": list(self.root_capabilities),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "caveats": [c.to_string() for c in self.caveats],
            "signature": self.signature
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DelegationToken":
        """Instantiates token from serialized dictionary."""
        token = cls(
            token_id=data["token_id"],
            issuer_agent=data["issuer_agent"],
            subject_agent=data["subject_agent"],
            issuer_tier=data["issuer_tier"],
            subject_tier=data["subject_tier"],
            capabilities=data["capabilities"],
            root_capabilities=data.get("root_capabilities", data["capabilities"]),
            created_at=data["created_at"],
            expires_at=data["expires_at"],
            nonce=data["nonce"],
            signature=data.get("signature", "")
        )
        token.caveats = [Caveat.from_string(c) for c in data.get("caveats", [])]
        return token
