"""
Tests for SandboxPolicyVerifier auditing macOS Seatbelt (SBPL) and Linux seccomp profiles.
"""

from agent_zero_trust.sandbox import SandboxPolicyVerifier


def test_audit_hardened_seatbelt_clean():
    hardened = """(version 1)
(deny default)
(allow process-exec (literal "/bin/sh") (literal "/usr/bin/python3"))
(allow file-read* (subpath "/Users/lakshithadananjaya/Projects/public repos/agent-zero-trust"))
(allow file-write* (subpath "/Users/lakshithadananjaya/Projects/public repos/agent-zero-trust/workspace"))
(deny mach-lookup)
(deny network*)
(allow network-outbound (literal "/private/var/run/openbot.sock"))
"""
    findings = SandboxPolicyVerifier.audit_seatbelt_profile(hardened)
    assert len(findings) == 0


def test_audit_seatbelt_global_write():
    vulnerable = """(version 1)
(deny default)
(allow file-write* (subpath "/"))
"""
    findings = SandboxPolicyVerifier.audit_seatbelt_profile(vulnerable)
    assert len(findings) >= 1
    assert any(f["id"] == "ZTM-006" and "file-write* (subpath \"/\")" in f["description"] for f in findings)


def test_audit_seatbelt_wildcard_mach_lookup():
    vulnerable = """(version 1)
(deny default)
(allow mach-lookup (global-name "*"))
"""
    findings = SandboxPolicyVerifier.audit_seatbelt_profile(vulnerable)
    assert len(findings) >= 1
    assert any("mach-lookup" in f["description"] for f in findings)


def test_audit_seatbelt_allow_default():
    vulnerable = """(version 1)
(allow default)
"""
    findings = SandboxPolicyVerifier.audit_seatbelt_profile(vulnerable)
    assert len(findings) >= 1
    assert any("allow default" in f["description"] for f in findings)


def test_audit_hardened_seccomp_clean():
    hardened_syscalls = ["read", "write", "openat", "close", "fstat", "exit_group", "futex", "nanosleep"]
    findings = SandboxPolicyVerifier.audit_seccomp_whitelist(hardened_syscalls)
    assert len(findings) == 0


def test_audit_seccomp_dangerous_syscalls():
    dangerous = ["read", "write", "ptrace", "bpf", "sys_chroot", "kexec_load", "process_vm_writev"]
    findings = SandboxPolicyVerifier.audit_seccomp_whitelist(dangerous)
    flagged = {f["syscall"] for f in findings}
    assert "ptrace" in flagged
    assert "bpf" in flagged
    assert "sys_chroot" in flagged
    assert "kexec_load" in flagged
    assert "process_vm_writev" in flagged


def test_generate_hardened_seatbelt_profile():
    profile = SandboxPolicyVerifier.generate_hardened_seatbelt_profile(
        agent_id="agent-worker-1",
        workspace_path="/Users/lakshithadananjaya/Projects/workspace"
    )
    assert "(deny default)" in profile
    assert "(allow file-write*" in profile
    assert "/Users/lakshithadananjaya/Projects/workspace" in profile
    assert "(deny mach-lookup)" in profile
    # Ensure generated profile is clean
    findings = SandboxPolicyVerifier.audit_seatbelt_profile(profile)
    assert len(findings) == 0
