#!/usr/bin/env python3
"""
Example: Basic Token Attenuation (Macaroon/Biscuit Chaining)
"""

import time
from agent_zero_trust import Caveat, DelegationToken, SwarmTier, TokenAuthority

def main():
    auth = TokenAuthority()

    print("=== Step 1: Root Coordinator creates Master Token ===")
    root_token = auth.create_root_token(
        issuer_agent="coordinator-0",
        subject_agent="agent-forge-1",
        issuer_tier=SwarmTier.TIER_0_ROOT_KMS,
        subject_tier=SwarmTier.TIER_1_DOMAIN_CORE,
        capabilities=["compile", "test", "commit", "read_db"],
        ttl_seconds=3600.0
    )
    print(f"Token ID: {root_token.token_id}")
    print(f"Capabilities: {root_token.capabilities}")
    print(f"Signature (HMAC-SHA256): {root_token.signature[:16]}...")

    print("\n=== Step 2: Tier 1 Agent attenuates token to Worker (Task Narrowing) ===")
    worker_token = auth.attenuate_token(
        token=root_token,
        new_caveats=[
            Caveat(predicate="tool", operator="==", value="test"),
            Caveat(predicate="repo_path", operator="startswith", value="/workspace/project")
        ],
        restricted_capabilities=["test"]
    )
    print(f"Worker Token ID: {worker_token.token_id}")
    print(f"Narrowed Capabilities: {worker_token.capabilities}")
    print(f"Caveats: {[c.to_string() for c in worker_token.caveats]}")
    print(f"New Chained Signature: {worker_token.signature[:16]}...")

    print("\n=== Step 3: Verification under Valid Context ===")
    valid_ctx = {"tool": "test", "repo_path": "/workspace/project/tests"}
    valid, err_code, reason = auth.verify_token(worker_token, valid_ctx)
    print(f"Verification: {'PASSED' if valid else 'FAILED'} (Reason: {reason})")

    print("\n=== Step 4: Verification under Unauthorized Context (Path Violation) ===")
    invalid_ctx = {"tool": "test", "repo_path": "/etc/shadow"}
    valid, err_code, reason = auth.verify_token(worker_token, invalid_ctx)
    print(f"Verification: {'PASSED' if valid else 'FAILED'} (Code: {err_code}, Reason: {reason})")

if __name__ == "__main__":
    main()
