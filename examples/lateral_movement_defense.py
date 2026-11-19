#!/usr/bin/env python3
"""
Example: Inter-Tier Lateral Movement Defense & Quarantine Circuit Breaker
"""

from agent_zero_trust import (
    AgentIsolationState,
    SwarmCircuitBreaker,
    SwarmRPCGate,
    SwarmTier,
    TokenAuthority,
)

def main():
    auth = TokenAuthority()
    breaker = SwarmCircuitBreaker(auth)
    gate = SwarmRPCGate(auth, breaker)

    print("=== Step 1: Tier 3 Scraper attempts illegal direct call to Tier 0 Coordinator ===")
    allowed, status, msg, _ = gate.dispatch_rpc(
        caller_id="untrusted-scraper-4",
        target_id="coordinator-0",
        caller_tier=SwarmTier.TIER_3_SANDBOX_WEB,
        target_tier=SwarmTier.TIER_0_ROOT_KMS,
        method="fetch_keys",
        payload={"target": "aws_secrets"},
        token=None
    )
    print(f"Gate Response: allowed={allowed}, status={status}")
    print(f"Message: {msg}")

    print("\n=== Step 2: Check Circuit Breaker Score for Attacker ===")
    state = breaker.get_state("untrusted-scraper-4")
    score = breaker.get_score("untrusted-scraper-4")
    print(f"Agent state: {state.value}, Anomaly score: {score}")

    print("\n=== Step 3: Repeated violation trips automatic QUARANTINE ===")
    gate.dispatch_rpc(
        caller_id="untrusted-scraper-4",
        target_id="database-t1",
        caller_tier=SwarmTier.TIER_3_SANDBOX_WEB,
        target_tier=SwarmTier.TIER_1_DOMAIN_CORE,
        method="drop_tables",
        payload={"target": "users"},
        token=None
    )
    new_state = breaker.get_state("untrusted-scraper-4")
    new_score = breaker.get_score("untrusted-scraper-4")
    print(f"Agent state: {new_state.value}, Anomaly score: {new_score}")
    print("Quarantine Log Entries:")
    for entry in breaker.quarantine_log:
        print(f" - {entry['agent_id']} transitioned {entry['old_state']} -> {entry['new_state']}: {entry['reason']}")

if __name__ == "__main__":
    main()
