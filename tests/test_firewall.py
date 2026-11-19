"""
Tests for SwarmRPCGate and SwarmRuntimeGuard inter-tier firewalling and middleware.
"""

import pytest

from agent_zero_trust.circuit import SwarmCircuitBreaker
from agent_zero_trust.firewall import SwarmRPCGate, SwarmRuntimeGuard
from agent_zero_trust.models import AgentIsolationState, Caveat, SwarmTier
from agent_zero_trust.tokens import TokenAuthority


def test_tier_0_to_tier_1_rpc_allowed():
    auth = TokenAuthority()
    breaker = SwarmCircuitBreaker(auth)
    gate = SwarmRPCGate(auth, breaker)

    token = auth.create_root_token(
        issuer_agent="aegis-t0",
        subject_agent="forge-t1",
        issuer_tier=SwarmTier.TIER_0_ROOT_KMS,
        subject_tier=SwarmTier.TIER_1_DOMAIN_CORE,
        capabilities=["orchestrate"]
    )

    success, code, msg, res = gate.dispatch_rpc(
        caller_id="aegis-t0",
        target_id="forge-t1",
        caller_tier=SwarmTier.TIER_0_ROOT_KMS,
        target_tier=SwarmTier.TIER_1_DOMAIN_CORE,
        method="orchestrate",
        payload={"task": "deploy"},
        token=token
    )
    assert success is True
    assert code == 200
    assert "authorized" in msg.lower()


def test_tier_1_to_tier_2_rpc_allowed():
    auth = TokenAuthority()
    breaker = SwarmCircuitBreaker(auth)
    gate = SwarmRPCGate(auth, breaker)

    token = auth.create_root_token(
        issuer_agent="forge-t1",
        subject_agent="worker-t2",
        issuer_tier=SwarmTier.TIER_1_DOMAIN_CORE,
        subject_tier=SwarmTier.TIER_2_TOOL_RUNNER,
        capabilities=["run_tests"]
    )

    success, code, msg, res = gate.dispatch_rpc(
        caller_id="forge-t1",
        target_id="worker-t2",
        caller_tier=SwarmTier.TIER_1_DOMAIN_CORE,
        target_tier=SwarmTier.TIER_2_TOOL_RUNNER,
        method="run_tests",
        payload={"suite": "unit"},
        token=token
    )
    assert success is True
    assert code == 200


def test_tier_3_to_tier_0_lateral_movement_blocked():
    auth = TokenAuthority()
    breaker = SwarmCircuitBreaker(auth)
    gate = SwarmRPCGate(auth, breaker)

    # Scraper (Tier 3) attempting to invoke Aegis (Tier 0)
    success, code, msg, res = gate.dispatch_rpc(
        caller_id="scraper-t3",
        target_id="aegis-t0",
        caller_tier=SwarmTier.TIER_3_SANDBOX_WEB,
        target_tier=SwarmTier.TIER_0_ROOT_KMS,
        method="dump_root_key",
        payload={},
        token=None
    )
    assert success is False
    assert code == 403
    assert "ZTM-003" in msg
    # Caller should be marked suspect or quarantined
    assert breaker.get_score("scraper-t3") >= 6.0


def test_tier_3_to_tier_1_lateral_movement_blocked():
    auth = TokenAuthority()
    breaker = SwarmCircuitBreaker(auth)
    gate = SwarmRPCGate(auth, breaker)

    success, code, msg, res = gate.dispatch_rpc(
        caller_id="scraper-t3",
        target_id="forge-t1",
        caller_tier=SwarmTier.TIER_3_SANDBOX_WEB,
        target_tier=SwarmTier.TIER_1_DOMAIN_CORE,
        method="update_code",
        payload={},
        token=None
    )
    assert success is False
    assert code == 403
    assert "ZTM-003" in msg


def test_missing_token_blocked():
    auth = TokenAuthority()
    breaker = SwarmCircuitBreaker(auth)
    gate = SwarmRPCGate(auth, breaker)

    success, code, msg, res = gate.dispatch_rpc(
        caller_id="forge-t1",
        target_id="worker-t2",
        caller_tier=SwarmTier.TIER_1_DOMAIN_CORE,
        target_tier=SwarmTier.TIER_2_TOOL_RUNNER,
        method="run_tests",
        payload={},
        token=None
    )
    assert success is False
    assert code == 401
    assert "ZTM-001" in msg


def test_quarantined_caller_rpc_rejected():
    auth = TokenAuthority()
    breaker = SwarmCircuitBreaker(auth)
    gate = SwarmRPCGate(auth, breaker)

    breaker.record_violation("compromised-agent", 10.0, "sandbox escape detected")
    token = auth.create_root_token(
        "compromised-agent", "target", SwarmTier.TIER_1_DOMAIN_CORE, SwarmTier.TIER_2_TOOL_RUNNER, ["read"]
    )

    success, code, msg, res = gate.dispatch_rpc(
        caller_id="compromised-agent",
        target_id="target",
        caller_tier=SwarmTier.TIER_1_DOMAIN_CORE,
        target_tier=SwarmTier.TIER_2_TOOL_RUNNER,
        method="read",
        payload={},
        token=token
    )
    assert success is False
    assert code == 403
    assert "Caller compromised-agent is" in msg


def test_quarantined_target_rpc_rejected():
    auth = TokenAuthority()
    breaker = SwarmCircuitBreaker(auth)
    gate = SwarmRPCGate(auth, breaker)

    breaker.record_violation("quarantined-target", 8.0, "adversarial prompt received")
    token = auth.create_root_token(
        "caller", "quarantined-target", SwarmTier.TIER_1_DOMAIN_CORE, SwarmTier.TIER_2_TOOL_RUNNER, ["read"]
    )

    success, code, msg, res = gate.dispatch_rpc(
        caller_id="caller",
        target_id="quarantined-target",
        caller_tier=SwarmTier.TIER_1_DOMAIN_CORE,
        target_tier=SwarmTier.TIER_2_TOOL_RUNNER,
        method="read",
        payload={},
        token=token
    )
    assert success is False
    assert code == 403
    assert "Target quarantined-target is" in msg


def test_runtime_guard_execution_success():
    auth = TokenAuthority()
    breaker = SwarmCircuitBreaker(auth)
    guard = SwarmRuntimeGuard(auth, breaker)

    token = auth.create_root_token(
        "forge-t1", "worker-t2", SwarmTier.TIER_1_DOMAIN_CORE, SwarmTier.TIER_2_TOOL_RUNNER, ["calculate"]
    )

    def dummy_handler(payload):
        return {"result": payload["a"] + payload["b"]}

    ok, status, msg, res = guard.execute_inter_agent_call(
        caller_id="forge-t1",
        target_id="worker-t2",
        caller_tier=SwarmTier.TIER_1_DOMAIN_CORE,
        target_tier=SwarmTier.TIER_2_TOOL_RUNNER,
        method="calculate",
        payload={"a": 10, "b": 20},
        token=token,
        handler=dummy_handler
    )
    assert ok is True
    assert status == 200
    assert res == {"result": 30}
    assert guard.metrics["authorized_calls"] == 1


def test_runtime_guard_subagent_task_attenuation():
    auth = TokenAuthority()
    breaker = SwarmCircuitBreaker(auth)
    guard = SwarmRuntimeGuard(auth, breaker)

    root = auth.create_root_token(
        "aegis-t0", "forge-t1", SwarmTier.TIER_0_ROOT_KMS, SwarmTier.TIER_1_DOMAIN_CORE,
        ["git_commit", "run_test", "web_fetch"]
    )

    sub_token = guard.create_delegated_task_token(
        parent_token=root,
        target_subagent_id="test-runner-t2",
        target_subagent_tier=SwarmTier.TIER_2_TOOL_RUNNER,
        tool_name="run_test",
        max_duration_seconds=300.0,
        extra_caveats={"repo": "agent-zero-trust"}
    )

    assert sub_token.capabilities == ["run_test"]
    assert len(sub_token.caveats) == 4  # tool, target_agent, valid_until, repo


def test_runtime_guard_handler_exception():
    auth = TokenAuthority()
    breaker = SwarmCircuitBreaker(auth)
    guard = SwarmRuntimeGuard(auth, breaker)

    token = auth.create_root_token(
        "forge-t1", "worker-t2", SwarmTier.TIER_1_DOMAIN_CORE, SwarmTier.TIER_2_TOOL_RUNNER, ["fail"]
    )

    def failing_handler(payload):
        raise RuntimeError("Something went wrong internally")

    ok, status, msg, res = guard.execute_inter_agent_call(
        caller_id="forge-t1",
        target_id="worker-t2",
        caller_tier=SwarmTier.TIER_1_DOMAIN_CORE,
        target_tier=SwarmTier.TIER_2_TOOL_RUNNER,
        method="fail",
        payload={},
        token=token,
        handler=failing_handler
    )
    assert ok is False
    assert status == 500
    assert "Downstream handler failed" in msg
