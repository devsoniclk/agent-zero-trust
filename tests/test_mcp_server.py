"""
Tests for FastMCP Server tool endpoints in agent_zero_trust.mcp_server.
"""

import json
from agent_zero_trust.mcp_server import (
    tool_create_root_token,
    tool_attenuate_token,
    tool_verify_token,
    tool_dispatch_rpc,
    tool_audit_seatbelt,
    tool_audit_seccomp,
    tool_get_agent_state,
    tool_reset_agent,
    tool_revoke_token,
    tool_get_threat_catalog,
)


def test_tool_create_root_token():
    res_str = tool_create_root_token(
        issuer_agent="aegis-0",
        subject_agent="forge-1",
        issuer_tier="TIER_0_ROOT_KMS",
        subject_tier="TIER_1_DOMAIN_CORE",
        capabilities=["code_synthesis", "git_commit"],
        ttl_seconds=3600.0
    )
    res = json.loads(res_str)
    assert res["status"] == "SUCCESS"
    assert "token" in res
    assert res["token"]["issuer_agent"] == "aegis-0"
    assert res["token"]["capabilities"] == ["code_synthesis", "git_commit"]


def test_tool_create_root_token_invalid_tier():
    res_str = tool_create_root_token(
        issuer_agent="aegis-0",
        subject_agent="forge-1",
        issuer_tier="INVALID_TIER",
        subject_tier="TIER_1_DOMAIN_CORE",
        capabilities=["test"]
    )
    res = json.loads(res_str)
    assert "error" in res


def test_tool_attenuate_token():
    res_str = tool_create_root_token(
        issuer_agent="aegis-0",
        subject_agent="forge-1",
        issuer_tier="TIER_0_ROOT_KMS",
        subject_tier="TIER_1_DOMAIN_CORE",
        capabilities=["code_synthesis", "git_commit"]
    )
    token_dict = json.loads(res_str)["token"]

    att_str = tool_attenuate_token(
        token_json=json.dumps(token_dict),
        new_caveats=[{"predicate": "tool", "operator": "==", "value": "git_commit"}],
        restricted_capabilities=["git_commit"]
    )
    att_res = json.loads(att_str)
    assert att_res["status"] == "SUCCESS"
    assert att_res["token"]["capabilities"] == ["git_commit"]


def test_tool_verify_token():
    res_str = tool_create_root_token(
        issuer_agent="aegis-0",
        subject_agent="forge-1",
        issuer_tier="TIER_0_ROOT_KMS",
        subject_tier="TIER_1_DOMAIN_CORE",
        capabilities=["git_commit"]
    )
    token_dict = json.loads(res_str)["token"]

    verify_str = tool_verify_token(
        token_json=json.dumps(token_dict),
        context={"tool": "git_commit"}
    )
    v_res = json.loads(verify_str)
    assert v_res["valid"] is True
    assert v_res["threat_code"] is None


def test_tool_dispatch_rpc():
    res_str = tool_create_root_token(
        issuer_agent="aegis-0",
        subject_agent="forge-1",
        issuer_tier="TIER_0_ROOT_KMS",
        subject_tier="TIER_1_DOMAIN_CORE",
        capabilities=["git_commit"]
    )
    token_dict = json.loads(res_str)["token"]

    rpc_str = tool_dispatch_rpc(
        caller_id="aegis-0",
        target_id="forge-1",
        caller_tier="TIER_0_ROOT_KMS",
        target_tier="TIER_1_DOMAIN_CORE",
        method="git_commit",
        payload={"commit_msg": "test commit"},
        token_json=json.dumps(token_dict)
    )
    rpc_res = json.loads(rpc_str)
    assert rpc_res["success"] is True
    assert rpc_res["status_code"] == 200


def test_tool_audit_seatbelt():
    res_str = tool_audit_seatbelt("(version 1)\n(allow default)\n")
    res = json.loads(res_str)
    assert res["status"] == "VETOED"
    assert res["findings_count"] >= 1


def test_tool_audit_seccomp():
    res_str = tool_audit_seccomp(["read", "write", "ptrace"])
    res = json.loads(res_str)
    assert res["status"] == "VETOED"
    assert res["findings_count"] >= 1


def test_tool_get_agent_state_and_reset():
    state_str = tool_get_agent_state("agent-test")
    state_res = json.loads(state_str)
    assert state_res["agent_id"] == "agent-test"
    assert state_res["state"] == "ACTIVE"

    reset_str = tool_reset_agent("agent-test")
    reset_res = json.loads(reset_str)
    assert reset_res["status"] == "SUCCESS"


def test_tool_revoke_token():
    res_str = tool_revoke_token("tok_12345678")
    res = json.loads(res_str)
    assert res["status"] == "SUCCESS"
    assert res["revoked_token_id"] == "tok_12345678"


def test_tool_get_threat_catalog():
    cat_str = tool_get_threat_catalog()
    cat = json.loads(cat_str)
    assert len(cat) == 10
    assert "ZTM-001" in cat
    assert "ZTM-010" in cat
