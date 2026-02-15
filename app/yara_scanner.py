import logging
import os

logger = logging.getLogger("spectreflow.yara")

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.info("yara-python not installed — YARA scanning disabled")

BUILTIN_RULES_SOURCE = r"""
rule Suspicious_UPX_Packed {
    meta:
        description = "Detects UPX packed executables"
        severity = "medium"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and any of ($upx*)
}

rule Suspicious_Shell_Invocation {
    meta:
        description = "Detects embedded shell command invocations"
        severity = "high"
    strings:
        $cmd1 = "cmd.exe /c" ascii nocase
        $cmd2 = "cmd /c" ascii nocase
        $ps1  = "powershell" ascii nocase
        $ps2  = "powershell.exe" ascii nocase
        $ps3  = "-ExecutionPolicy Bypass" ascii nocase
        $ps4  = "-EncodedCommand" ascii nocase
        $bash = "/bin/sh" ascii
        $bash2 = "/bin/bash" ascii
    condition:
        any of them
}

rule Suspicious_Crypto_Ransom {
    meta:
        description = "Detects crypto/ransomware keywords"
        severity = "high"
    strings:
        $r1 = "Your files have been encrypted" ascii nocase
        $r2 = "pay the ransom" ascii nocase
        $r3 = "bitcoin" ascii nocase
        $r4 = "decrypt your files" ascii nocase
        $r5 = ".onion" ascii nocase
        $r6 = "wallet address" ascii nocase
    condition:
        2 of them
}

rule Suspicious_Keylogger_Strings {
    meta:
        description = "Detects keylogger-related strings"
        severity = "high"
    strings:
        $k1 = "GetAsyncKeyState" ascii
        $k2 = "SetWindowsHookEx" ascii
        $k3 = "keylog" ascii nocase
        $k4 = "keystroke" ascii nocase
    condition:
        2 of them
}

rule Suspicious_AntiDebug {
    meta:
        description = "Detects anti-debugging and anti-VM techniques"
        severity = "medium"
    strings:
        $d1 = "IsDebuggerPresent" ascii
        $d2 = "CheckRemoteDebuggerPresent" ascii
        $d3 = "NtQueryInformationProcess" ascii
        $d4 = "OutputDebugString" ascii
        $vm1 = "vmtoolsd" ascii nocase
        $vm2 = "VBoxService" ascii nocase
        $vm3 = "SbieDll" ascii nocase
    condition:
        2 of them
}

rule Suspicious_Process_Injection {
    meta:
        description = "Detects process injection API patterns"
        severity = "critical"
    strings:
        $i1 = "VirtualAllocEx" ascii
        $i2 = "WriteProcessMemory" ascii
        $i3 = "CreateRemoteThread" ascii
        $i4 = "NtUnmapViewOfSection" ascii
    condition:
        2 of them
}
"""

_compiled_rules = None


def _get_rules():
    global _compiled_rules
    if _compiled_rules is None and YARA_AVAILABLE:
        try:
            _compiled_rules = yara.compile(source=BUILTIN_RULES_SOURCE)
        except Exception as exc:
            logger.warning("Failed to compile YARA rules: %s", exc)
    return _compiled_rules


def scan_with_yara(binary_path):
    if not YARA_AVAILABLE:
        return []

    if not os.path.isfile(binary_path):
        return []

    rules = _get_rules()
    if rules is None:
        return []

    try:
        matches = rules.match(binary_path, timeout=30)
    except Exception as exc:
        logger.warning("YARA scan failed: %s", exc)
        return []

    results = []
    for match in matches:
        meta = match.meta if hasattr(match, "meta") else {}
        results.append({
            "rule": match.rule,
            "description": meta.get("description", ""),
            "severity": meta.get("severity", "medium"),
            "tags": list(match.tags) if hasattr(match, "tags") else [],
        })
        logger.info("YARA match: %s — %s", match.rule, meta.get("description", ""))

    return results
