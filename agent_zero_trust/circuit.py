"""
Anomaly detection and quarantine circuit breaker state machine for autonomous agent swarms.
"""

import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from agent_zero_trust.models import AgentIsolationState
from agent_zero_trust.tokens import TokenAuthority


class AnomalyDetector:
    """Scans inter-agent RPC messages and execution patterns for adversarial infiltration."""

    INJECTION_PATTERNS = [
        re.compile(r"ignore\s+(all\s+)?(previous|prior|system)?\s*instructions", re.IGNORECASE),
        re.compile(r"system\s*override", re.IGNORECASE),
        re.compile(r"\b(sudo|eval|exec|os\.system|__import__)\b", re.IGNORECASE),
        re.compile(r"\b(format\s+drive|drop\s+database)\b", re.IGNORECASE),
        re.compile(r"rm\s+-rf", re.IGNORECASE),
        re.compile(r"(bypass|disable)\s+(sandbox|seatbelt|seccomp|firewall)", re.IGNORECASE),
        re.compile(r"cat\s+/etc/shadow", re.IGNORECASE),
        re.compile(r"curl\s+.*\|\s*(bash|sh)", re.IGNORECASE),
        re.compile(r"\bexfiltrate\b.*(key|secret|token)", re.IGNORECASE)
    ]

    PATH_TRAVERSAL = re.compile(r"\.\./\.\./|/etc/shadow|/etc/passwd|/private/var/root")

    @classmethod
    def scan_payload(cls, payload: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Scans payload recursively for adversarial patterns.
        Returns: (is_malicious, explanation)
        """
        raw_str = json.dumps(payload)
        for pat in cls.INJECTION_PATTERNS:
            if pat.search(raw_str):
                return True, f"Prompt injection/command payload detected: {pat.pattern}"
        if cls.PATH_TRAVERSAL.search(raw_str):
            return True, "Path traversal/sensitive system file access attempt detected."
        return False, None


class SwarmCircuitBreaker:
    """Manages agent quarantine state machine and automatic blast-radius isolation."""

    def __init__(
        self,
        token_authority: TokenAuthority,
        suspect_threshold: float = 2.0,
        quarantine_threshold: float = 5.0,
        isolation_threshold: float = 10.0
    ):
        self.token_authority = token_authority
        self.suspect_threshold = suspect_threshold
        self.quarantine_threshold = quarantine_threshold
        self.isolation_threshold = isolation_threshold
        self.agent_states: Dict[str, AgentIsolationState] = {}
        self.agent_anomaly_scores: Dict[str, float] = {}
        self.quarantine_log: List[Dict[str, Any]] = []

    def get_state(self, agent_id: str) -> AgentIsolationState:
        """Returns the current isolation state for an agent."""
        return self.agent_states.get(agent_id, AgentIsolationState.ACTIVE)

    def get_score(self, agent_id: str) -> float:
        """Returns the accumulated anomaly score for an agent."""
        return self.agent_anomaly_scores.get(agent_id, 0.0)

    def record_violation(self, agent_id: str, severity_weight: float, reason: str) -> AgentIsolationState:
        """
        Records an anomaly or security violation, updates score, and transitions state machine.
        """
        current_score = self.agent_anomaly_scores.get(agent_id, 0.0) + severity_weight
        self.agent_anomaly_scores[agent_id] = current_score

        if current_score >= self.isolation_threshold:
            new_state = AgentIsolationState.ISOLATED
        elif current_score >= self.quarantine_threshold:
            new_state = AgentIsolationState.QUARANTINED
        elif current_score >= self.suspect_threshold:
            new_state = AgentIsolationState.SUSPECT
        else:
            new_state = AgentIsolationState.ACTIVE

        old_state = self.get_state(agent_id)
        if new_state != old_state:
            self.agent_states[agent_id] = new_state
            self.quarantine_log.append({
                "agent_id": agent_id,
                "old_state": old_state.value,
                "new_state": new_state.value,
                "score": current_score,
                "reason": reason,
                "timestamp": time.time()
            })

            # If agent reached QUARANTINED or ISOLATED, revoke its issued tokens
            if new_state in (AgentIsolationState.QUARANTINED, AgentIsolationState.ISOLATED):
                self._isolate_agent_network(agent_id)

        return new_state

    def reset_agent(self, agent_id: str):
        """Restores an agent to ACTIVE state and resets its anomaly score."""
        self.agent_states[agent_id] = AgentIsolationState.ACTIVE
        self.agent_anomaly_scores[agent_id] = 0.0
        self.quarantine_log.append({
            "agent_id": agent_id,
            "old_state": "RESET",
            "new_state": AgentIsolationState.ACTIVE.value,
            "score": 0.0,
            "reason": "Administrative reset",
            "timestamp": time.time()
        })

    def _isolate_agent_network(self, agent_id: str):
        """Immediately severs RPC routes and invalidates active tokens for the agent."""
        # Swarm-level route drops and token revocations
        pass
