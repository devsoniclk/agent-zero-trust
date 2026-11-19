#!/usr/bin/env python3
"""
Cryptographic Macaroon/Biscuit Attenuation Example.
Demonstrates:
  1. Root delegation token signing via HMAC-SHA256.
  2. Multi-hop caveat attenuation with cryptographic HMAC chaining.
  3. Caveat stripping attack detection (signature verification failure).
  4. Context evaluation under runtime predicates.
"""

from rich.console import Console
from rich.table import Table

from agent_zero_trust.models import Caveat, DelegationToken, SwarmTier
from agent_zero_trust.tokens import TokenAuthority

console = Console()


def run_macaroon_example():
    console.print("[bold cyan]=== Capability-Attenuated Macaroon Token Example ===[/bold cyan]\n")

    auth = TokenAuthority()

    # Step 1: Root Token
    root = auth.create_root_token(
        issuer_agent="aegis-t0",
        subject_agent="forge-t1",
        issuer_tier=SwarmTier.TIER_0_ROOT_KMS,
        subject_tier=SwarmTier.TIER_1_DOMAIN_CORE,
        capabilities=["git_commit", "read_db", "invoke_tool"],
        ttl_seconds=3600.0
    )
    console.print(f"[bold green]1. Root Token Created:[/bold green] {root.token_id}")
    console.print(f"   Signature: {root.signature}")
    console.print(f"   Capabilities: {root.capabilities}\n")

    # Step 2: Attenuation Hop 1 (Narrow to git_commit and repo prefix)
    c1 = Caveat(predicate="tool", operator="==", value="git_commit")
    c2 = Caveat(predicate="repo", operator="startswith", value="devsoniclk/")
    hop1 = auth.attenuate_token(
        token=root,
        new_caveats=[c1, c2],
        restricted_capabilities=["git_commit"]
    )
    console.print(f"[bold green]2. Attenuated Hop 1 Token:[/bold green] {hop1.token_id}")
    console.print(f"   New Signature: {hop1.signature}")
    console.print(f"   Capabilities: {hop1.capabilities}")
    console.print(f"   Caveats: {[c.to_string() for c in hop1.caveats]}\n")

    # Step 3: Verify Hop 1 under valid context
    valid, code, err = auth.verify_token(hop1, {"tool": "git_commit", "repo": "devsoniclk/agent-zero-trust"})
    console.print(f"[green]✓ Hop 1 Valid Context Verification:[/green] valid={valid}\n")

    # Step 4: Verify Hop 1 under violating context (wrong repo)
    valid, code, err = auth.verify_token(hop1, {"tool": "git_commit", "repo": "untrusted/repo"})
    console.print(f"[red]✗ Hop 1 Policy Violation Verification:[/red] valid={valid}, code={code}, error={err}\n")

    # Step 5: Simulate Caveat Stripping Attack
    console.print("[bold yellow]3. Simulating Caveat Stripping Attack:[/bold yellow]")
    tampered = DelegationToken.from_dict(hop1.to_dict())
    tampered.caveats = []  # Attacker removes caveats to regain unrestricted access
    valid, code, err = auth.verify_token(tampered, {"tool": "read_db", "repo": "untrusted/repo"})
    console.print(f"[red]✗ Stripped Token Verification:[/red] valid={valid}, code={code}")
    console.print(f"  Reason: {err}\n")

    console.print("[bold green]Macaroon Capability Attenuation Demo Complete.[/bold green]")


if __name__ == "__main__":
    run_macaroon_example()
