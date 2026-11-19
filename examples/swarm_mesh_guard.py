#!/usr/bin/env python3
"""
Example: Swarm Runtime Guard RPC Interception Middleware
"""

from agent_zero_trust import (
    SwarmCircuitBreaker,
    SwarmRuntimeGuard,
    SwarmTier,
    TokenAuthority,
)

def dummy_task_handler(payload):
    return {"status": "SUCCESS", "records_processed": 42}

def main():
    auth = TokenAuthority()
    breaker = SwarmCircuitBreaker(auth)
    guard = SwarmRuntimeGuard(auth, breaker)

    # 1. Setup Root Token
    root_token = auth.create_root_token(
        issuer_agent="aegis-root",
        subject_agent="forge-core",
        issuer_tier=SwarmTier.TIER_0_ROOT_KMS,
        subject_tier=SwarmTier.TIER_1_DOMAIN_CORE,
        capabilities=["compile", "execute", "audit"],
        ttl_seconds=3600.0
    )

    # 2. Attenuate Token for Task
    task_token = guard.create_delegated_task_token(
        parent_token=root_token,
        target_subagent_id="test-runner-1",
        target_subagent_tier=SwarmTier.TIER_2_TOOL_RUNNER,
        tool_name="execute",
        max_duration_seconds=300.0
    )

    # 3. Intercept & Execute RPC
    success, code, msg, res = guard.execute_inter_agent_call(
        caller_id="forge-core",
        target_id="test-runner-1",
        caller_tier=SwarmTier.TIER_1_DOMAIN_CORE,
        target_tier=SwarmTier.TIER_2_TOOL_RUNNER,
        method="execute",
        payload={"action": "run_benchmarks"},
        token=task_token,
        handler=dummy_task_handler
    )

    print(f"Result: success={success}, code={code}")
    print(f"Message: {msg}")
    print(f"Handler Output: {res}")
    print(f"Guard Metrics: {guard.metrics}")

if __name__ == "__main__":
    main()
