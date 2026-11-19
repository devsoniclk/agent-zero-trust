"""
Model Context Protocol (MCP) server for agent-zero-trust microsegmentation.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from agent_zero_trust.circuit import AnomalyDetector, SwarmCircuitBreaker
from agent_zero_trust.firewall import SwarmRPCGate, SwarmRuntimeGuard
from agent_zero_trust.models import (
    THREAT_CATALOG,
    AgentIsolationState,
    Caveat,
    DelegationToken,
    SwarmTier,
)
from agent_zero_trust.sandbox import SandboxPolicyVerifier
from agent_zero_trust.tokens import TokenAuthority

_AUTHORITY = TokenAuthority()
_BREAKER = SwarmCircuitBreaker(_AUTHORITY)
_GATE = SwarmRPCGate(_AUTHORITY, _BREAKER)
_GUARD = SwarmRuntimeGuard(_AUTHORITY, _BREAKER)


def _parse_tier(tier_str: str) -> SwarmTier:
    try:
        return SwarmTier(tier_str)
    except ValueError:
        pass
    try:
        return SwarmTier[tier_str]
    except KeyError:
        pass
    for t in SwarmTier:
        if t.name.lower() == tier_str.lower() or t.value.lower() == tier_str.lower():
            return t
    raise ValueError(f"Unknown SwarmTier: {tier_str}")


def tool_create_root_token(
    issuer_agent: str,
    subject_agent: str,
    issuer_tier: str,
    subject_tier: str,
    capabilities: List[str],
    ttl_seconds: float = 3600.0,
) -> str:
    """Creates a root capability-attenuated delegation token."""
    try:
        it = _parse_tier(issuer_tier)
        st = _parse_tier(subject_tier)
    except ValueError as e:
        return json.dumps({"error": f"Invalid tier: {str(e)}"})

    token = _AUTHORITY.create_root_token(
        issuer_agent=issuer_agent,
        subject_agent=subject_agent,
        issuer_tier=it,
        subject_tier=st,
        capabilities=capabilities,
        ttl_seconds=ttl_seconds
    )
    return json.dumps({"status": "SUCCESS", "token": token.to_dict()})


def tool_attenuate_token(
    token_json: str,
    new_caveats: List[Dict[str, Any]],
    restricted_capabilities: Optional[List[str]] = None,
) -> str:
    """Attenuates a token by appending caveats and chaining HMAC signatures."""
    try:
        data = json.loads(token_json) if isinstance(token_json, str) else token_json
        parent = DelegationToken.from_dict(data)
        caveats = [Caveat(c["predicate"], c["operator"], c["value"]) for c in new_caveats]
        attenuated = _AUTHORITY.attenuate_token(
            token=parent,
            new_caveats=caveats,
            restricted_capabilities=restricted_capabilities
        )
        return json.dumps({"status": "SUCCESS", "token": attenuated.to_dict()})
    except Exception as e:
        return json.dumps({"error": f"Attenuation failed: {str(e)}"})


def tool_verify_token(
    token_json: str,
    context: Dict[str, Any]
) -> str:
    """Verifies token signature chain, expiration, nonces, and caveat satisfaction."""
    try:
        data = json.loads(token_json) if isinstance(token_json, str) else token_json
        token = DelegationToken.from_dict(data)
        valid, code, reason = _AUTHORITY.verify_token(token, context)
        return json.dumps({
            "valid": valid,
            "threat_code": code,
            "reason": reason
        })
    except Exception as e:
        return json.dumps({"error": f"Verification error: {str(e)}"})


def tool_dispatch_rpc(
    caller_id: str,
    target_id: str,
    caller_tier: str,
    target_tier: str,
    method: str,
    payload: Dict[str, Any],
    token_json: Optional[str] = None
) -> str:
    """Dispatches an inter-agent RPC invocation through the zero-trust microsegmentation gate."""
    try:
        ct = _parse_tier(caller_tier)
        tt = _parse_tier(target_tier)
    except ValueError as e:
        return json.dumps({"error": f"Invalid tier: {str(e)}"})

    token = None
    if token_json:
        data = json.loads(token_json) if isinstance(token_json, str) else token_json
        token = DelegationToken.from_dict(data)

    success, code, msg, res = _GATE.dispatch_rpc(
        caller_id=caller_id,
        target_id=target_id,
        caller_tier=ct,
        target_tier=tt,
        method=method,
        payload=payload,
        token=token
    )
    return json.dumps({
        "success": success,
        "status_code": code,
        "message": msg,
        "response": res
    })


def tool_audit_seatbelt(sbpl_content: str) -> str:
    """Audits a macOS Seatbelt SBPL sandbox profile for security vulnerabilities."""
    findings = SandboxPolicyVerifier.audit_seatbelt_profile(sbpl_content)
    return json.dumps({
        "findings_count": len(findings),
        "status": "VETOED" if findings else "PASSED",
        "findings": findings
    })


def tool_audit_seccomp(allowed_syscalls: List[str]) -> str:
    """Audits a Linux seccomp/eBPF whitelist for dangerous syscalls."""
    findings = SandboxPolicyVerifier.audit_seccomp_whitelist(allowed_syscalls)
    return json.dumps({
        "findings_count": len(findings),
        "status": "VETOED" if findings else "PASSED",
        "findings": findings
    })


def tool_get_agent_state(agent_id: str) -> str:
    """Retrieves current isolation state and accumulated anomaly score for an agent."""
    state = _BREAKER.get_state(agent_id)
    score = _BREAKER.get_score(agent_id)
    return json.dumps({
        "agent_id": agent_id,
        "state": state.value,
        "anomaly_score": score
    })


def tool_reset_agent(agent_id: str) -> str:
    """Resets an agent's anomaly score and restores it to ACTIVE state."""
    _BREAKER.reset_agent(agent_id)
    return json.dumps({
        "status": "SUCCESS",
        "agent_id": agent_id,
        "new_state": AgentIsolationState.ACTIVE.value
    })


def tool_revoke_token(token_id: str) -> str:
    """Revokes a delegation token immediately across the swarm."""
    _AUTHORITY.revoke_token(token_id)
    return json.dumps({
        "status": "SUCCESS",
        "revoked_token_id": token_id
    })


def tool_get_threat_catalog() -> str:
    """Returns the full zero-trust threat catalog with CVSS v3.1 rankings and remediations."""
    return json.dumps(THREAT_CATALOG, indent=2)
