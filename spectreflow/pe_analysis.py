import os
import math
import hashlib
import logging

import pefile

logger = logging.getLogger("spectreflow.pe_analysis")

PACKER_SECTIONS = {".UPX", ".upx", ".aspack", ".themida", ".vmp", ".petite",
                   ".mpress", ".nsp", ".enigma"}

DANGEROUS_APIS = {
    "CreateRemoteThread":    "Code injection into another process",
    "VirtualAllocEx":        "Allocates memory in a remote process",
    "WriteProcessMemory":    "Writes data into another process's memory",
    "NtUnmapViewOfSection":  "Used in process hollowing attacks",
    "SetWindowsHookExA":     "Installs a keyboard / input hook (keylogging)",
    "SetWindowsHookExW":     "Installs a keyboard / input hook (keylogging)",
    "GetAsyncKeyState":      "Reads keyboard state (keylogging)",
    "URLDownloadToFileA":    "Downloads a file from the internet",
    "URLDownloadToFileW":    "Downloads a file from the internet",
    "ShellExecuteA":         "Executes a command or opens a file",
    "ShellExecuteW":         "Executes a command or opens a file",
    "WinExec":               "Executes a command",
    "InternetOpenA":         "Opens an internet connection",
    "InternetOpenW":         "Opens an internet connection",
    "InternetOpenUrlA":      "Opens a URL directly",
    "InternetOpenUrlW":      "Opens a URL directly",
    "HttpSendRequestA":      "Sends an HTTP request",
    "CryptEncrypt":          "Encrypts data (possible ransomware)",
    "CryptDecrypt":          "Decrypts data",
    "RegSetValueExA":        "Modifies Windows registry (persistence)",
    "RegSetValueExW":        "Modifies Windows registry (persistence)",
    "NtSetInformationProcess": "Modifies process information (anti-debug)",
    "IsDebuggerPresent":     "Checks for debugger presence (anti-analysis)",
    "CheckRemoteDebuggerPresent": "Checks for remote debugger (anti-analysis)",
    "AdjustTokenPrivileges": "Elevates process privileges",
    "OpenProcessToken":      "Opens a process token for privilege changes",
    "CreateServiceA":        "Creates a Windows service (persistence)",
    "CreateServiceW":        "Creates a Windows service (persistence)",
}


def _section_entropy(data):
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def _compute_hashes(binary_path):
    with open(binary_path, "rb") as f:
        data = f.read()
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def analyze_pe(binary_path):
    _, ext = os.path.splitext(binary_path)
    if ext.lower() not in (".exe", ".dll", ".scr", ".sys"):
        return None

    try:
        pe = pefile.PE(binary_path)
    except pefile.PEFormatError as e:
        logger.warning("Not a valid PE file: %s", e)
        return None

    findings = []
    suspicious_imports = []
    sections_info = []

    hashes = _compute_hashes(binary_path)
    logger.info("File hashes — MD5: %s  SHA-256: %s", hashes["md5"], hashes["sha256"])

    has_signature = hasattr(pe, "DIRECTORY_ENTRY_SECURITY")
    if not has_signature:
        findings.append({
            "indicator": "No digital signature",
            "severity": "medium",
            "detail": "Legitimate software is almost always code-signed",
        })
        logger.info("PE finding: No digital signature")

    for section in pe.sections:
        name = section.Name.decode(errors="ignore").strip("\x00")
        entropy = _section_entropy(section.get_data())

        if entropy > 7.0:
            verdict = "encrypted / compressed"
        elif entropy > 6.5:
            verdict = "possibly packed"
        elif entropy < 1.0 and section.SizeOfRawData > 0:
            verdict = "mostly empty"
        else:
            verdict = "normal"

        sections_info.append({
            "name": name,
            "entropy": round(entropy, 2),
            "raw_size": section.SizeOfRawData,
            "virtual_size": section.Misc_VirtualSize,
            "verdict": verdict,
        })

        if name in PACKER_SECTIONS:
            findings.append({
                "indicator": f"Packed with {name}",
                "severity": "high",
                "detail": "Binary is obfuscated with a known packer",
            })
            logger.info("PE finding: Packed section '%s'", name)

        if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
            findings.append({
                "indicator": f"Section '{name}' unpacks at runtime",
                "severity": "high",
                "detail": "Raw size is 0 but virtual size is %d — code is hidden" % section.Misc_VirtualSize,
            })
            logger.info("PE finding: Runtime-unpacked section '%s'", name)

        if entropy > 7.0:
            findings.append({
                "indicator": f"High entropy in section '{name}' ({entropy:.2f})",
                "severity": "medium",
                "detail": "Entropy > 7.0 suggests encrypted or compressed content",
            })

    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_section = None
    for section in pe.sections:
        if section.contains_rva(ep):
            ep_section = section.Name.decode(errors="ignore").strip("\x00")
            break

    if ep_section and ep_section != ".text":
        findings.append({
            "indicator": f"Entry point in '{ep_section}' (expected .text)",
            "severity": "high",
            "detail": "Hijacked or unusual execution start location",
        })
        logger.info("PE finding: Entry point in '%s'", ep_section)

    total_imports = 0
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                total_imports += 1
                if imp.name:
                    api_name = imp.name.decode(errors="ignore")
                    if api_name in DANGEROUS_APIS:
                        suspicious_imports.append({
                            "api": api_name,
                            "dll": entry.dll.decode(errors="ignore"),
                            "reason": DANGEROUS_APIS[api_name],
                        })
                        logger.info("Suspicious API: %s — %s",
                                    api_name, DANGEROUS_APIS[api_name])
    except AttributeError:
        findings.append({
            "indicator": "No import table at all",
            "severity": "critical",
            "detail": "Binary has no imports — likely resolves everything at runtime",
        })
        logger.info("PE finding: No import table")

    if total_imports > 0 and total_imports < 5:
        findings.append({
            "indicator": f"Very few imports ({total_imports})",
            "severity": "high",
            "detail": "Likely resolves APIs dynamically to evade detection",
        })
        logger.info("PE finding: Only %d imports", total_imports)

    pe.close()

    return {
        "findings": findings,
        "suspicious_imports": suspicious_imports,
        "sections": sections_info,
        "hashes": hashes,
        "signed": has_signature,
        "total_imports": total_imports,
    }
