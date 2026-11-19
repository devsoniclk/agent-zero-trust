"""
macOS Seatbelt (SBPL) and Linux eBPF/seccomp policy verifier and hardened generator.
"""

import re
from typing import Any, Dict, List


class SandboxPolicyVerifier:
    """Audits macOS Seatbelt SBPL and Linux seccomp/eBPF profile boundaries."""

    DANGEROUS_SEATBELT_DIRECTIVES = [
        "(allow file-write* (subpath \"/\"))",
        "(allow file* (subpath \"/\"))",
        "(allow mach-lookup (global-name \"*\"))",
        "(allow default)",
        "(allow network* (remote ip \"*\"))"
    ]

    DANGEROUS_SYSCALLS = {
        "ptrace", "bpf", "sys_chroot", "kexec_load", "process_vm_writev",
        "create_module", "init_module", "delete_module", "socket_raw"
    }

    HARDENED_DEFAULT_SYSCALLS = [
        "read", "write", "openat", "close", "fstat", "exit_group", "futex",
        "poll", "select", "nanosleep", "clock_gettime", "brk", "mmap", "munmap"
    ]

    @classmethod
    def audit_seatbelt_profile(cls, sbpl_content: str) -> List[Dict[str, Any]]:
        """
        Audits a macOS Seatbelt (.sb) profile against zero-trust containment requirements.
        """
        findings = []
        for directive in cls.DANGEROUS_SEATBELT_DIRECTIVES:
            if directive in sbpl_content:
                findings.append({
                    "id": "ZTM-006",
                    "severity": "HIGH",
                    "directive": directive,
                    "description": f"Overly permissive Seatbelt directive found: {directive}"
                })

        # Ensure isolated subpath write is enforced
        if "(allow file-write*" in sbpl_content and not re.search(r'\(allow file-write\*\s+\(subpath\s+"[^"]+"\)\)', sbpl_content):
            findings.append({
                "id": "ZTM-006",
                "severity": "CRITICAL",
                "directive": "file-write*",
                "description": "File write permission granted without strict subpath confinement."
            })

        return findings

    @classmethod
    def audit_seccomp_whitelist(cls, allowed_syscalls: List[str]) -> List[Dict[str, Any]]:
        """
        Audits a Linux seccomp-BPF whitelist against dangerous kernel/process hijacking syscalls.
        """
        findings = []
        for sc in allowed_syscalls:
            if sc in cls.DANGEROUS_SYSCALLS:
                findings.append({
                    "id": "ZTM-007",
                    "severity": "CRITICAL",
                    "syscall": sc,
                    "description": f"Dangerous syscall permitted in seccomp/eBPF whitelist: {sc}"
                })
        return findings

    @classmethod
    def generate_hardened_seatbelt_profile(cls, agent_id: str, workspace_path: str) -> str:
        """
        Generates a production-grade default-deny macOS Seatbelt SBPL profile.
        """
        return f"""(version 1)
(deny default)
(allow process-exec (literal "/bin/sh") (literal "/usr/bin/python3"))
(allow file-read*
    (subpath "/usr/lib")
    (subpath "/System/Library")
    (subpath "{workspace_path}"))
(allow file-write*
    (subpath "{workspace_path}"))
(deny file-write* (subpath "/etc") (subpath "/var") (subpath "/Library"))
(deny mach-lookup)
(deny network*)
(allow network-outbound (literal "/private/var/run/openbot.sock"))
"""

    @classmethod
    def generate_hardened_seccomp_whitelist(cls) -> List[str]:
        """
        Returns a vetted list of safe POSIX system calls for agent worker sandboxes.
        """
        return list(cls.HARDENED_DEFAULT_SYSCALLS)
