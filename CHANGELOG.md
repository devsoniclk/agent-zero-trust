# Changelog

All notable changes to `agent-zero-trust` will be documented in this file.

## [0.1.0] - 2026-11-19

### Added
- **Capability-Attenuated Delegation Tokens**: HMAC-SHA256 Macaroon/Biscuit-style cumulative attenuation chaining ($S_{i+1} = \text{HMAC}(S_i, c_{new})$).
- **Monotonic Narrowing Invariant**: Sub-tokens can only restrict capabilities and append caveats, preventing privilege escalation.
- **Swarm RPC Isolation Tiers**: 4-Tier security model (Tier 0 Root/KMS, Tier 1 Domain Core, Tier 2 Tool Runner, Tier 3 Sandbox/Web Ingress) with strict firewall boundary matrices.
- **Swarm Anomaly Detector**: Real-time inspection for prompt injections, malicious subshell commands, and filesystem path traversals.
- **Automated Quarantine Circuit Breaker**: Dynamic agent isolation state machine (`ACTIVE` -> `SUSPECT` -> `QUARANTINED` -> `ISOLATED`) with instant route drops and token revocations.
- **OS Sandbox Policy Verifier**: Audits macOS Seatbelt (SBPL) profiles and Linux seccomp-BPF / eBPF syscall whitelists.
- **Production CLI**: Rich CLI supporting token generation, attenuation, verification, policy auditing, and lateral movement simulations.
- **FastMCP Protocol Suite**: Seamless MCP server exposing zero-trust microsegmentation tools directly to LLM runtimes.
- Comprehensive test suite with 100% pass rate.
