"""
Tests for data models, enums, caveats, and delegation token structures.
"""

import json
import pytest
from agent_zero_trust.models import (
    ALLOWED_RPC_MATRIX,
    THREAT_CATALOG,
    AgentIsolationState,
    Caveat,
    DelegationToken,
    SwarmTier,
)


class TestModels:
    def test_swarm_tiers(self):
        assert SwarmTier.TIER_0_ROOT_KMS.value == "Tier_0_Root_KMS"
        assert SwarmTier.TIER_1_DOMAIN_CORE.value == "Tier_1_Domain_Core"
        assert SwarmTier.TIER_2_TOOL_RUNNER.value == "Tier_2_Tool_Runner"
        assert SwarmTier.TIER_3_SANDBOX_WEB.value == "Tier_3_Sandbox_Web"

    def test_agent_isolation_states(self):
        assert AgentIsolationState.ACTIVE.value == "ACTIVE"
        assert AgentIsolationState.SUSPECT.value == "SUSPECT"
        assert AgentIsolationState.QUARANTINED.value == "QUARANTINED"
        assert AgentIsolationState.ISOLATED.value == "ISOLATED"

    def test_threat_catalog(self):
        assert len(THREAT_CATALOG) == 10
        for code, entry in THREAT_CATALOG.items():
            assert code.startswith("ZTM-")
            assert "title" in entry
            assert "cvss" in entry
            assert "vector" in entry
            assert "description" in entry
            assert "remediation" in entry
            assert entry["cvss"] >= 8.0

    def test_allowed_rpc_matrix(self):
        # Tier 0 can call any tier
        assert len(ALLOWED_RPC_MATRIX[SwarmTier.TIER_0_ROOT_KMS]) == 4
        # Tier 3 cannot call Tier 0 or Tier 1 directly
        assert SwarmTier.TIER_0_ROOT_KMS not in ALLOWED_RPC_MATRIX[SwarmTier.TIER_3_SANDBOX_WEB]
        assert SwarmTier.TIER_1_DOMAIN_CORE not in ALLOWED_RPC_MATRIX[SwarmTier.TIER_3_SANDBOX_WEB]

    def test_caveat_equality(self):
        c = Caveat("tool", "==", "compile")
        assert c.evaluate({"tool": "compile"}) is True
        assert c.evaluate({"tool": "delete"}) is False
        assert c.evaluate({}) is False

    def test_caveat_inequality(self):
        c = Caveat("role", "!=", "guest")
        assert c.evaluate({"role": "admin"}) is True
        assert c.evaluate({"role": "guest"}) is False

    def test_caveat_numeric_bounds(self):
        c_le = Caveat("max_cost", "<=", 100.0)
        assert c_le.evaluate({"max_cost": 50.0}) is True
        assert c_le.evaluate({"max_cost": 150.0}) is False
        assert c_le.evaluate({"max_cost": "invalid"}) is False

        c_ge = Caveat("min_version", ">=", 2.0)
        assert c_ge.evaluate({"min_version": 2.5}) is True
        assert c_ge.evaluate({"min_version": 1.0}) is False
        assert c_ge.evaluate({"min_version": "invalid"}) is False

    def test_caveat_in_operator(self):
        c_list = Caveat("domain", "in", ["github.com", "api.github.com"])
        assert c_list.evaluate({"domain": "github.com"}) is True
        assert c_list.evaluate({"domain": "evil.com"}) is False

        c_str = Caveat("tags", "in", "production_verified")
        assert c_str.evaluate({"tags": "prod"}) is True
        assert c_str.evaluate({"tags": "staging"}) is False

    def test_caveat_string_prefixes(self):
        c_start = Caveat("path", "startswith", "/workspace")
        assert c_start.evaluate({"path": "/workspace/agent-1"}) is True
        assert c_start.evaluate({"path": "/etc/shadow"}) is False

        c_end = Caveat("file", "endswith", ".py")
        assert c_end.evaluate({"file": "main.py"}) is True
        assert c_end.evaluate({"file": "script.sh"}) is False

    def test_caveat_regex(self):
        c_regex = Caveat("identifier", "regex", r"^agent-[a-z0-9]+$")
        assert c_regex.evaluate({"identifier": "agent-abc123"}) is True
        assert c_regex.evaluate({"identifier": "USER-ADMIN"}) is False

        c_bad_regex = Caveat("test", "regex", r"[a-z(")
        assert c_bad_regex.evaluate({"test": "val"}) is False

    def test_caveat_unknown_operator(self):
        c = Caveat("field", "UNKNOWN", "val")
        assert c.evaluate({"field": "val"}) is False

    def test_caveat_string_serialization(self):
        c = Caveat("tool", "==", "test_execute")
        s = c.to_string()
        assert s == 'tool == "test_execute"'
        c2 = Caveat.from_string(s)
        assert c2.predicate == c.predicate
        assert c2.operator == c.operator
        assert c2.value == c.value

    def test_caveat_malformed_string(self):
        with pytest.raises(ValueError):
            Caveat.from_string("bad string")

    def test_delegation_token_serialization(self):
        token = DelegationToken(
            token_id="tok_123",
            issuer_agent="a1",
            subject_agent="a2",
            issuer_tier=SwarmTier.TIER_0_ROOT_KMS.value,
            subject_tier=SwarmTier.TIER_1_DOMAIN_CORE.value,
            capabilities=["read", "write"],
            created_at=1000.0,
            expires_at=2000.0,
            nonce="nonce_abc"
        )
        assert token.root_capabilities == ["read", "write"]
        d = token.to_dict()
        assert d["token_id"] == "tok_123"
        assert d["capabilities"] == ["read", "write"]
        assert len(d["caveats"]) == 0

        token_restored = DelegationToken.from_dict(d)
        assert token_restored.token_id == token.token_id
        assert token_restored.capabilities == token.capabilities
        assert token_restored.root_capabilities == token.root_capabilities
