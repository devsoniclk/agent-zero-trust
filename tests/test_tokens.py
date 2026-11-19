"""
Tests for cryptographic token creation, attenuation, HMAC chaining, and caveat validation.
"""

import hashlib
import hmac
import json
import secrets
import time
import pytest

from agent_zero_trust.models import Caveat, DelegationToken, SwarmTier
from agent_zero_trust.tokens import TokenAuthority


def test_root_token_creation():
    auth = TokenAuthority()
    token = auth.create_root_token(
        issuer_agent="coordinator-0",
        subject_agent="agent-forge-1",
        issuer_tier=SwarmTier.TIER_0_ROOT_KMS,
        subject_tier=SwarmTier.TIER_1_DOMAIN_CORE,
        capabilities=["compile", "test", "commit"],
        ttl_seconds=3600.0
    )
    assert token.token_id.startswith("tok_")
    assert len(token.signature) == 64
    assert token.issuer_agent == "coordinator-0"
    assert token.subject_agent == "agent-forge-1"
    assert token.issuer_tier == SwarmTier.TIER_0_ROOT_KMS.value
    assert token.subject_tier == SwarmTier.TIER_1_DOMAIN_CORE.value
    assert len(token.caveats) == 0
    assert token.capabilities == ["compile", "test", "commit"]
    assert token.root_capabilities == ["compile", "test", "commit"]


def test_unique_nonces():
    auth = TokenAuthority()
    t1 = auth.create_root_token("coord", "ag1", SwarmTier.TIER_0_ROOT_KMS, SwarmTier.TIER_1_DOMAIN_CORE, ["read"])
    t2 = auth.create_root_token("coord", "ag2", SwarmTier.TIER_0_ROOT_KMS, SwarmTier.TIER_1_DOMAIN_CORE, ["read"])
    assert t1.nonce != t2.nonce
    assert t1.signature != t2.signature


def test_root_token_verification_success():
    auth = TokenAuthority()
    token = auth.create_root_token("coord", "ag1", SwarmTier.TIER_0_ROOT_KMS, SwarmTier.TIER_1_DOMAIN_CORE, ["read"])
    valid, code, err = auth.verify_token(token, context={"action": "read"})
    assert valid is True
    assert code is None
    assert err is None


def test_tampered_payload_detected():
    auth = TokenAuthority()
    token = auth.create_root_token("coord", "ag1", SwarmTier.TIER_0_ROOT_KMS, SwarmTier.TIER_1_DOMAIN_CORE, ["read"])
    # Tamper with subject
    token.subject_agent = "attacker"
    valid, code, err = auth.verify_token(token, context={"action": "read"})
    assert valid is False
    assert code == "ZTM-002"


def test_tampered_signature_detected():
    auth = TokenAuthority()
    token = auth.create_root_token("coord", "ag1", SwarmTier.TIER_0_ROOT_KMS, SwarmTier.TIER_1_DOMAIN_CORE, ["read"])
    token.signature = "a" * 64
    valid, code, err = auth.verify_token(token, context={"action": "read"})
    assert valid is False
    assert code == "ZTM-002"


def test_token_expiration():
    auth = TokenAuthority()
    token = auth.create_root_token(
        "coord", "ag1", SwarmTier.TIER_0_ROOT_KMS, SwarmTier.TIER_1_DOMAIN_CORE, ["read"],
        ttl_seconds=-10.0
    )
    valid, code, err = auth.verify_token(token, context={"action": "read"})
    assert valid is False
    assert code == "ZTM-005"
    assert "expired" in (err or "").lower()


def test_token_revocation():
    auth = TokenAuthority()
    token = auth.create_root_token("coord", "ag1", SwarmTier.TIER_0_ROOT_KMS, SwarmTier.TIER_1_DOMAIN_CORE, ["read"])
    assert auth.is_revoked(token.token_id) is False
    auth.revoke_token(token.token_id)
    assert auth.is_revoked(token.token_id) is True

    valid, code, err = auth.verify_token(token, context={"action": "read"})
    assert valid is False
    assert code == "ZTM-009"


def test_caveat_serialization_roundtrip():
    c1 = Caveat(predicate="tool", operator="==", value="git_commit")
    s = c1.to_string()
    c2 = Caveat.from_string(s)
    assert c1.predicate == c2.predicate
    assert c1.operator == c2.operator
    assert c1.value == c2.value

    with pytest.raises(ValueError):
        Caveat.from_string("malformed")


def test_single_caveat_attenuation():
    auth = TokenAuthority()
    root = auth.create_root_token(
        "coord", "forge", SwarmTier.TIER_0_ROOT_KMS, SwarmTier.TIER_1_DOMAIN_CORE,
        ["git_commit", "read_db"]
    )
    caveat = Caveat(predicate="tool", operator="==", value="git_commit")
    attenuated = auth.attenuate_token(root, new_caveats=[caveat], restricted_capabilities=["git_commit"])

    assert len(attenuated.caveats) == 1
    assert attenuated.capabilities == ["git_commit"]
    assert attenuated.signature != root.signature

    # Valid invocation with matching caveat
    valid, code, err = auth.verify_token(attenuated, context={"tool": "git_commit"})
    assert valid is True
    assert code is None


def test_caveat_evaluation_mismatch():
    auth = TokenAuthority()
    root = auth.create_root_token(
        "coord", "forge", SwarmTier.TIER_0_ROOT_KMS, SwarmTier.TIER_1_DOMAIN_CORE,
        ["git_commit", "read_db"]
    )
    caveat = Caveat(predicate="tool", operator="==", value="git_commit")
    attenuated = auth.attenuate_token(root, new_caveats=[caveat], restricted_capabilities=["git_commit"])

    # Attempt to use tool 'read_db'
    valid, code, err = auth.verify_token(attenuated, context={"tool": "read_db"})
    assert valid is False
    assert code == "ZTM-004"


def test_capability_widening_rejection():
    auth = TokenAuthority()
    root = auth.create_root_token(
        "coord", "forge", SwarmTier.TIER_0_ROOT_KMS, SwarmTier.TIER_1_DOMAIN_CORE,
        ["read_db"]
    )
    with pytest.raises(ValueError, match="Capability widening detected"):
        auth.attenuate_token(
            root,
            new_caveats=[Caveat("tool", "==", "rm_rf")],
            restricted_capabilities=["rm_rf"]
        )


def test_capability_not_in_root_capabilities():
    auth = TokenAuthority()
    root = auth.create_root_token(
        "coord", "forge", SwarmTier.TIER_0_ROOT_KMS, SwarmTier.TIER_1_DOMAIN_CORE,
        ["read_db"]
    )
    # Manually inject unauthorized capability into capabilities list
    root.capabilities.append("delete_root")
    valid, code, err = auth.verify_token(root, context={"tool": "delete_root"})
    assert valid is False
    assert code == "ZTM-002"


def test_caveat_stripping_attack_detected():
    auth = TokenAuthority()
    root = auth.create_root_token(
        "coord", "forge", SwarmTier.TIER_0_ROOT_KMS, SwarmTier.TIER_1_DOMAIN_CORE,
        ["git_commit"]
    )
    caveat = Caveat(predicate="branch", operator="==", value="staging")
    attenuated = auth.attenuate_token(root, new_caveats=[caveat])

    # Attacker tries to strip caveat while preserving attenuated signature
    stripped = DelegationToken.from_dict(attenuated.to_dict())
    stripped.caveats = []
    valid, code, err = auth.verify_token(stripped, context={"branch": "main"})
    assert valid is False
    assert code == "ZTM-002"


def test_multi_hop_delegation_chain():
    auth = TokenAuthority()
    # Hop 0: Root Token (Tier 0 -> Tier 1)
    t0 = auth.create_root_token(
        "coord", "agent1", SwarmTier.TIER_0_ROOT_KMS, SwarmTier.TIER_1_DOMAIN_CORE,
        ["fetch", "parse", "store"]
    )

    # Hop 1: Attenuate (Tier 1 -> Tier 2)
    c1 = Caveat(predicate="max_items", operator="<=", value=100)
    t1 = auth.attenuate_token(t0, [c1], restricted_capabilities=["fetch", "parse"])

    # Hop 2: Attenuate further (Tier 2 -> Tier 3)
    c2 = Caveat(predicate="domain", operator="in", value=["github.com", "python.org"])
    t2 = auth.attenuate_token(t1, [c2], restricted_capabilities=["fetch"])

    assert len(t2.caveats) == 2
    assert t2.capabilities == ["fetch"]

    # Verify Hop 2 token under valid context
    ctx_valid = {"max_items": 50, "domain": "github.com", "tool": "fetch"}
    valid, code, err = auth.verify_token(t2, ctx_valid)
    assert valid is True

    # Violation of Hop 1 caveat
    ctx_violate_h1 = {"max_items": 150, "domain": "github.com", "tool": "fetch"}
    valid, code, err = auth.verify_token(t2, ctx_violate_h1)
    assert valid is False
    assert code == "ZTM-004"

    # Violation of Hop 2 caveat
    ctx_violate_h2 = {"max_items": 50, "domain": "evil.com", "tool": "fetch"}
    valid, code, err = auth.verify_token(t2, ctx_violate_h2)
    assert valid is False
    assert code == "ZTM-004"


def test_caveat_operators_all():
    c_eq = Caveat("val", "==", 42)
    assert c_eq.evaluate({"val": 42}) is True
    assert c_eq.evaluate({"val": 43}) is False
    assert c_eq.evaluate({}) is False

    c_ne = Caveat("val", "!=", 42)
    assert c_ne.evaluate({"val": 43}) is True
    assert c_ne.evaluate({"val": 42}) is False

    c_lte = Caveat("val", "<=", 50)
    assert c_lte.evaluate({"val": 50}) is True
    assert c_lte.evaluate({"val": 49}) is True
    assert c_lte.evaluate({"val": 51}) is False
    assert c_lte.evaluate({"val": "non-num"}) is False

    c_gte = Caveat("val", ">=", 50)
    assert c_gte.evaluate({"val": 50}) is True
    assert c_gte.evaluate({"val": 51}) is True
    assert c_gte.evaluate({"val": 49}) is False
    assert c_gte.evaluate({"val": "non-num"}) is False

    c_in_list = Caveat("env", "in", ["prod", "staging"])
    assert c_in_list.evaluate({"env": "prod"}) is True
    assert c_in_list.evaluate({"env": "dev"}) is False

    c_in_str = Caveat("text", "in", "secret_passcode")
    assert c_in_str.evaluate({"text": "secret"}) is True
    assert c_in_str.evaluate({"text": "other"}) is False

    c_sw = Caveat("path", "startswith", "/workspace")
    assert c_sw.evaluate({"path": "/workspace/data.json"}) is True
    assert c_sw.evaluate({"path": "/etc/passwd"}) is False

    c_ew = Caveat("file", "endswith", ".py")
    assert c_ew.evaluate({"file": "main.py"}) is True
    assert c_ew.evaluate({"file": "main.sh"}) is False

    c_re = Caveat("id", "regex", r"^agent-[a-z0-9]+$")
    assert c_re.evaluate({"id": "agent-123"}) is True
    assert c_re.evaluate({"id": "AGENT_FAIL"}) is False

    c_bad_re = Caveat("id", "regex", r"[bad regex")
    assert c_bad_re.evaluate({"id": "test"}) is False

    c_bad_op = Caveat("id", "unknown_op", "test")
    assert c_bad_op.evaluate({"id": "test"}) is False


def test_empty_attenuation_raises():
    auth = TokenAuthority()
    root = auth.create_root_token("c", "a", SwarmTier.TIER_0_ROOT_KMS, SwarmTier.TIER_1_DOMAIN_CORE, ["read"])
    with pytest.raises(ValueError):
        auth.attenuate_token(root, new_caveats=[])
