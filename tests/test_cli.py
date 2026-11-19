"""
Tests for Click CLI commands in agent-zero-trust.
"""

import json
from click.testing import CliRunner

from agent_zero_trust.cli import main


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_cli_audit_default():
    runner = CliRunner()
    result = runner.invoke(main, ["audit"])
    assert result.exit_code == 0
    assert "Agent Zero-Trust Security Audit" in result.output
    assert "ZTM-006" in result.output
    assert "ZTM-007" in result.output


def test_cli_audit_json():
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["status"] == "AUDIT_COMPLETE"
    assert data["findings_count"] > 0
    assert data["threat_catalog_size"] == 10


def test_cli_audit_veto_exits_nonzero():
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "--veto"])
    assert result.exit_code != 0
    assert "RELEASE VETO TRIGGERED" in result.output


def test_cli_threats():
    runner = CliRunner()
    result = runner.invoke(main, ["threats"])
    assert result.exit_code == 0
    assert "ZTM-001" in result.output
    assert "ZTM-010" in result.output


def test_cli_simulate():
    runner = CliRunner()
    result = runner.invoke(main, ["simulate"])
    assert result.exit_code == 0
    assert "Swarm Zero-Trust Lateral Movement Simulation" in result.output
    assert "All lateral attack vectors contained" in result.output
