#!/usr/bin/env python3
"""
Performance benchmarks for agent-zero-trust cryptographic tokens, caveat verification, and RPC firewall dispatch.
"""

import time
from rich.console import Console
from rich.table import Table

from agent_zero_trust.circuit import SwarmCircuitBreaker
from agent_zero_trust.firewall import SwarmRPCGate
from agent_zero_trust.models import Caveat, SwarmTier
from agent_zero_trust.tokens import TokenAuthority

console = Console()


def benchmark_token_creation(auth: TokenAuthority, iterations: int = 10000):
    start = time.perf_counter()
    for _ in range(iterations):
        auth.create_root_token(
            issuer_agent="aegis-t0",
            subject_agent="forge-t1",
            issuer_tier=SwarmTier.TIER_0_ROOT_KMS,
            subject_tier=SwarmTier.TIER_1_DOMAIN_CORE,
            capabilities=["read", "write", "commit"],
            ttl_seconds=3600.0
        )
    elapsed = time.perf_counter() - start
    ops_sec = iterations / elapsed
    return elapsed, ops_sec


def benchmark_token_attenuation(auth: TokenAuthority, iterations: int = 10000):
    root = auth.create_root_token(
        issuer_agent="aegis-t0",
        subject_agent="forge-t1",
        issuer_tier=SwarmTier.TIER_0_ROOT_KMS,
        subject_tier=SwarmTier.TIER_1_DOMAIN_CORE,
        capabilities=["read", "write", "commit"]
    )
    c1 = Caveat("tool", "==", "write")
    start = time.perf_counter()
    for _ in range(iterations):
        auth.attenuate_token(root, [c1], restricted_capabilities=["write"])
    elapsed = time.perf_counter() - start
    ops_sec = iterations / elapsed
    return elapsed, ops_sec


def benchmark_token_verification(auth: TokenAuthority, iterations: int = 10000):
    root = auth.create_root_token(
        issuer_agent="aegis-t0",
        subject_agent="forge-t1",
        issuer_tier=SwarmTier.TIER_0_ROOT_KMS,
        subject_tier=SwarmTier.TIER_1_DOMAIN_CORE,
        capabilities=["read", "write", "commit"]
    )
    c1 = Caveat("tool", "==", "write")
    attenuated = auth.attenuate_token(root, [c1], restricted_capabilities=["write"])
    ctx = {"tool": "write"}

    start = time.perf_counter()
    for _ in range(iterations):
        auth.verify_token(attenuated, ctx)
    elapsed = time.perf_counter() - start
    ops_sec = iterations / elapsed
    return elapsed, ops_sec


def benchmark_rpc_gate_dispatch(gate: SwarmRPCGate, token, iterations: int = 10000):
    payload = {"query": "test_data"}
    start = time.perf_counter()
    for _ in range(iterations):
        gate.dispatch_rpc(
            caller_id="planner-t1",
            target_id="worker-t2",
            caller_tier=SwarmTier.TIER_1_DOMAIN_CORE,
            target_tier=SwarmTier.TIER_2_TOOL_RUNNER,
            method="write",
            payload=payload,
            token=token
        )
    elapsed = time.perf_counter() - start
    ops_sec = iterations / elapsed
    return elapsed, ops_sec


def run_benchmarks():
    console.print("[bold cyan]=== Agent Zero-Trust Microsegmentation Benchmarks ===[/bold cyan]\n")

    auth = TokenAuthority()
    breaker = SwarmCircuitBreaker(auth)
    gate = SwarmRPCGate(auth, breaker)

    root = auth.create_root_token(
        issuer_agent="planner-t1",
        subject_agent="worker-t2",
        issuer_tier=SwarmTier.TIER_1_DOMAIN_CORE,
        subject_tier=SwarmTier.TIER_2_TOOL_RUNNER,
        capabilities=["write"]
    )
    c1 = Caveat("tool", "==", "write")
    token = auth.attenuate_token(root, [c1], restricted_capabilities=["write"])

    iterations = 5000

    table = Table(title=f"Benchmark Results ({iterations:,} iterations)")
    table.add_column("Operation", style="bold cyan")
    table.add_column("Total Time (s)", justify="right")
    table.add_column("Throughput (ops/sec)", style="bold green", justify="right")
    table.add_column("Latency per Op (µs)", justify="right")

    # 1. Root Token Creation
    t_create, ops_create = benchmark_token_creation(auth, iterations)
    table.add_row("Root Token Creation", f"{t_create:.4f}", f"{ops_create:,.0f}", f"{(t_create/iterations)*1e6:.2f}")

    # 2. Token Attenuation
    t_att, ops_att = benchmark_token_attenuation(auth, iterations)
    table.add_row("HMAC Caveat Attenuation", f"{t_att:.4f}", f"{ops_att:,.0f}", f"{(t_att/iterations)*1e6:.2f}")

    # 3. Token Verification
    t_ver, ops_ver = benchmark_token_verification(auth, iterations)
    table.add_row("Token & Caveat Verification", f"{t_ver:.4f}", f"{ops_ver:,.0f}", f"{(t_ver/iterations)*1e6:.2f}")

    # 4. RPC Gate Dispatch
    t_rpc, ops_rpc = benchmark_rpc_gate_dispatch(gate, token, iterations)
    table.add_row("Full Zero-Trust RPC Dispatch", f"{t_rpc:.4f}", f"{ops_rpc:,.0f}", f"{(t_rpc/iterations)*1e6:.2f}")

    console.print(table)


if __name__ == "__main__":
    run_benchmarks()
