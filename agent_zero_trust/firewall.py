"""
Inter-agent RPC gatekeeper, inter-tier firewalling, and runtime guard middleware.
"""

import time
from typing import Any, Callable, Dict, Optional, Tuple

from agent_zero_trust.circuit import AnomalyDetector, SwarmCircuitBreaker
from agent_zero_trust.models import (
    ALLOWED_RPC_MATRIX,
    AgentIsolationState,
    Caveat,
    DelegationToken,
    SwarmTier,
)
from agent_zero_trust.tokens import TokenAuthority


class SwarmRPCGate:
    """Inter-agent RPC gatekeeper enforcing token authentication, tier boundaries, and circuit breaking."""

    def __init__(self, token_authority: TokenAuthority, circuit_breaker: SwarmCircuitBreaker):
        self.token_authority = token_authority
        self.circuit_breaker = circuit_breaker

    def dispatch_rpc(
        self,
        caller_id: str,
        target_id: str,
        caller_tier: SwarmTier,
        target_tier: SwarmTier,
        method: str,
        payload: Dict[str, Any],
        token: Optional[DelegationToken]
    ) -> Tuple[bool, int, str, Optional[Dict[str, Any]]]:
        """
        Dispatches an RPC call through the zero-trust microsegmentation gate.
        Returns: (success, status_code, message, response_data)
        """
        # 1. Check Circuit Breaker for Caller and Target
        caller_state = self.circuit_breaker.get_state(caller_id)
        if caller_state in (AgentIsolationState.QUARANTINED, AgentIsolationState.ISOLATED):
            return False, 403, f"RPC blocked: Caller {caller_id} is {caller_state.value}", None

        target_state = self.circuit_breaker.get_state(target_id)
        if target_state in (AgentIsolationState.QUARANTINED, AgentIsolationState.ISOLATED):
            return False, 403, f"RPC blocked: Target {target_id} is {target_state.value}", None

        # 2. Check Inter-Tier Firewall Boundary Matrix
        allowed_targets = ALLOWED_RPC_MATRIX.get(caller_tier, set())
        if target_tier not in allowed_targets:
            self.circuit_breaker.record_violation(
                caller_id, severity_weight=6.0,
                reason=f"Illegal cross-tier lateral movement attempt from {caller_tier.value} to {target_tier.value}"
            )
            return False, 403, f"Violation ZTM-003: Lateral movement from {caller_tier.value} to {target_tier.value} forbidden.", None

        # 3. Check Token Authentication
        if token is None:
            self.circuit_breaker.record_violation(
                caller_id, severity_weight=5.0,
                reason="Unauthenticated RPC call missing delegation token"
            )
            return False, 401, "Violation ZTM-001: Missing cryptographic delegation token.", None

        # 4. Verify Token Cryptography & Caveats
        now = time.time()
        context = {
            "tool": method,
            "target_agent": target_id,
            "caller_agent": caller_id,
            "caller_tier": caller_tier.value,
            "target_tier": target_tier.value,
            "valid_until": now,
            "current_time": now,
            **payload
        }
        is_valid, threat_code, failure_reason = self.token_authority.verify_token(token, context)
        if not is_valid:
            weight = 8.0 if threat_code == "ZTM-002" else 4.0
            self.circuit_breaker.record_violation(caller_id, severity_weight=weight, reason=failure_reason or "")
            return False, 403, f"Violation {threat_code}: {failure_reason}", None

        # 5. Scan Payload for Injection or Traversal Anomaly
        is_malicious, anomaly_msg = AnomalyDetector.scan_payload(payload)
        if is_malicious:
            new_state = self.circuit_breaker.record_violation(caller_id, severity_weight=8.0, reason=anomaly_msg or "")
            return False, 400, f"Violation ZTM-008: {anomaly_msg} (Agent transitioned to {new_state.value})", None

        # All checks passed
        return True, 200, "RPC authorized by Zero-Trust Swarm Gate", {"status": "SUCCESS", "result": "Execution completed"}


class SwarmRuntimeGuard:
    """
    Middleware intercepting inter-agent RPC calls, verifying capability-attenuated tokens,
    enforcing tier isolation boundaries, and triggering automated circuit breaking.
    """

    def __init__(self, token_authority: TokenAuthority, circuit_breaker: SwarmCircuitBreaker):
        self.token_authority = token_authority
        self.circuit_breaker = circuit_breaker
        self.rpc_gate = SwarmRPCGate(token_authority, circuit_breaker)
        self.metrics = {
            "authorized_calls": 0,
            "blocked_calls": 0,
            "anomalies_detected": 0,
            "circuit_breaker_trips": 0
        }

    def execute_inter_agent_call(
        self,
        caller_id: str,
        target_id: str,
        caller_tier: SwarmTier,
        target_tier: SwarmTier,
        method: str,
        payload: Dict[str, Any],
        token: Optional[DelegationToken],
        handler: Optional[Callable[[Dict[str, Any]], Any]] = None
    ) -> Tuple[bool, int, str, Any]:
        """
        Intercepts and evaluates an inter-agent invocation before delegating to handler.
        """
        allowed, status_code, message, response_data = self.rpc_gate.dispatch_rpc(
            caller_id=caller_id,
            target_id=target_id,
            caller_tier=caller_tier,
            target_tier=target_tier,
            method=method,
            payload=payload,
            token=token
        )

        if not allowed:
            self.metrics["blocked_calls"] += 1
            if "ZTM-008" in message:
                self.metrics["anomalies_detected"] += 1
            if "QUARANTINED" in message or "ISOLATED" in message:
                self.metrics["circuit_breaker_trips"] += 1
            return False, status_code, message, None

        self.metrics["authorized_calls"] += 1

        # If a downstream execution handler was provided, execute it in verified context
        result = None
        if handler:
            try:
                result = handler(payload)
            except Exception as e:
                return False, 500, f"Downstream handler failed: {str(e)}", None

        return True, 200, "Invocation authorized and executed successfully", result or response_data

    def create_delegated_task_token(
        self,
        parent_token: DelegationToken,
        target_subagent_id: str,
        target_subagent_tier: SwarmTier,
        tool_name: str,
        max_duration_seconds: float = 300.0,
        extra_caveats: Optional[Dict[str, Any]] = None
    ) -> DelegationToken:
        """
        Helper for agents to safely attenuate their own token before launching subagents.
        Enforces least privilege by binding the sub-token to the specific tool, subagent, and short TTL.
        """
        now = time.time()
        new_caveats = [
            Caveat(predicate="tool", operator="==", value=tool_name),
            Caveat(predicate="target_agent", operator="==", value=target_subagent_id),
            Caveat(predicate="valid_until", operator="<=", value=now + max_duration_seconds)
        ]

        if extra_caveats:
            for pred, val in extra_caveats.items():
                new_caveats.append(Caveat(predicate=pred, operator="==", value=val))

        attenuated = self.token_authority.attenuate_token(
            token=parent_token,
            new_caveats=new_caveats,
            restricted_capabilities=[tool_name]
        )
        return attenuated
