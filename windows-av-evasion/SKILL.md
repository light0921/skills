---
name: windows-av-evasion
description: >-
  AV/EDR evasion playbook for Windows. Use when bypassing AMSI, ETW, .NET assembly detection, shellcode execution, process injection, API hooking, and signature-based detection on Windows endpoints.
---

# SKILL: AV/EDR Evasion — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: This is the entry point. Load specific `references/*.md` files only when the corresponding technique is needed. This keeps context lean.

## 0. RELATED ROUTING

Before going deep, consider loading:

- [windows-privilege-escalation](../windows-privilege-escalation/SKILL.md) when privesc tools are blocked by AV
- [windows-lateral-movement](../windows-lateral-movement/SKILL.md) when lateral movement tools trigger EDR
- [active-directory-kerberos-attacks](../active-directory-kerberos-attacks/SKILL.md) when Rubeus/Mimikatz are detected
- [active-directory-acl-abuse](../active-directory-acl-abuse/SKILL.md) for non-binary AD attacks (less AV-sensitive)

### Advanced Reference

Also load [AMSI_BYPASS_TECHNIQUES.md](./AMSI_BYPASS_TECHNIQUES.md) when you need PowerShell/.NET-specific AMSI bypass patterns.

---

## Quick Reference — "I Need To..."

| Scenario | Load This Reference | Key Technique |
|---|---|---|
| PowerShell blocked by AMSI | `references/amsi-bypass.md` | C patch (x64: `B8 57 00 07 80 C3`) or HW breakpoint |
| .NET assembly loads detected | `references/shellcode-execution.md` §Donut | Convert to shellcode → inject |
| ETW logging PowerShell/.NET | `references/etw-bypass.md` | Patch EtwEventWrite (0xC3) or Provider disable |
| EDR hooking ntdll syscalls | `references/ntdll-unhook.md` | Fresh copy from `\KnownDlls\` |
| Need stealth syscall (no unhook) | `references/syscall-proxy.md` | Indirect syscall + call stack spoofing |
| Execute shellcode in process | `references/shellcode-execution.md` §Local | Callback API (EnumWindows) vs CreateThread |
| Inject into remote process | `references/shellcode-execution.md` §Remote | Early Bird APC / Module Stomping |
| Memory scanner detects payload | `references/shellcode-execution.md` §Sleep | Ekko / Foliage sleep obfuscation |
| Static signature detection | §7 below (Signature Evasion) | String encrypt, API hash, metadata strip |
| Binary entropy too high (>7) | `references/static-evasion.md` §1 | Low-entropy data injection (target ≤6) |
| Suspicious import table | `references/static-evasion.md` §2 | 60+ harmless API dilution |
| No version info in binary | `references/static-evasion.md` §3 | Fake Microsoft version resource |
| Cloud sandbox analysis (微步/VT) | `references/sandbox-evasion.md` | Path detection + behavior delay + harmless exit |

---

## 1. AMSI Bypass → `references/amsi-bypass.md`

AMSI inspects PowerShell, .NET, VBScript, JScript, and Office macros at runtime.

**Quick picks:**
- **C patch**: `mov eax, 0x80070057; ret` at AmsiScanBuffer entry — full code in reference
- **Patchless**: Hardware breakpoint (DR0) + VEH handler — zero memory modification
- **PS quick**: `powershell -Version 2` (if .NET 2.0 available, bypasses AMSI entirely)

---

## 2. ETW Bypass → `references/etw-bypass.md`

ETW reports .NET loads, PS script blocks, process creation to EDR/SIEM. **Must pair with AMSI bypass.**

**Quick picks:**
- **Default**: Patch `ntdll!EtwEventWrite` with `0xC3` (single-byte RET)
- **Win11 24H2+**: Also patch `EtwEventWriteFull` + selectively disable Threat-Intelligence Provider via NtTraceControl
- **PS-only**: Reflection disable Script Block Logging

---

## 3. NTDLL Unhooking → `references/ntdll-unhook.md`

EDR hooks ntdll .text section to intercept syscalls. Solution: overwrite with clean copy.

**Quick picks:**
- **Fresh Copy**: Read `\\.\GLOBALROOT\KnownDlls\ntdll.dll` → overwrite in-memory .text (full C code)
- **Verify**: Check `NtAllocateVirtualMemory` entry bytes → `4C 8B D1 B8` = clean

---

## 4. Syscall Proxy → `references/syscall-proxy.md`

Direct/indirect syscalls for bypassing API hooks without unhooking ntdll.

**Quick picks:**
- **L2 AV**: Hell's Gate (dynamic SSN extraction)
- **L3 EDR (CS Falcon/S1)**: Indirect syscall + call stack spoofing
- **Win11 24H2 HVCI**: Unhook ntdll first, then optional syscall proxy

---

## 5. Shellcode & Injection → `references/shellcode-execution.md`

From .NET assembly loading to local/remote shellcode execution.

**Quick picks:**
- **Avoid CreateThread**: Use callback APIs (`EnumWindows`, `CertEnumSystemStore`)
- **Remote injection**: Early Bird APC (low-med detection) or Module Stomping (low)
- **Sleep obfuscation**: Ekko (ROP chain) or Foliage (APC-based) for beacon mode

---

## 6. Payload Encryption

```csharp
// AES (preferred for static evasion)
using Aes aes = Aes.Create();
aes.Key = key; aes.IV = iv;
byte[] encrypted = aes.CreateEncryptor().TransformFinalBlock(sc, 0, sc.Length);

// XOR (simple, fast)
for (int i = 0; i < shellcode.Length; i++) shellcode[i] ^= key[i % key.Length];
```

**Staged loading pattern**: Stage 1 (small, encrypted loader) → Stage 2 (download encrypted payload) → Stage 3 (decrypt in memory → execute).

---

## 7. Signature Evasion

### String Encryption
Avoid plaintext API names, URLs, tool names. Decrypt at runtime.

### API Hashing
Resolve by hash instead of name: `GetProcAddressByHash(module, 0x91AFCA54)` for "VirtualAlloc".

### Metadata Removal
```bash
# .NET: ConfuserEx / .NET Reactor / Obfuscar
# PE: Strip timestamps, rich header, debug info, PDB paths
```

### C2 Framework Evasion

| Framework | Key Evasion Features |
|---|---|
| **Cobalt Strike** | Malleable C2 profiles, HTTP/S traffic shaping, sleep jitter |
| **Sliver** | Multiple protocols (mTLS, WireGuard, DNS), built-in obfuscation |
| **Havoc** | Indirect syscalls, sleep obfuscation, module stomping |
| **Brute Ratel** | Badger agent, syscall evasion, ETW/AMSI bypass built-in |

---

## 8. AV/EDR Evasion Decision Tree

```
Need to execute tool/payload on protected host
│
├── PowerShell-based payload?
│   ├── AMSI blocking? → references/amsi-bypass.md
│   │   ├── .NET 2.0 available? → PS v2 downgrade (no AMSI)
│   │   ├── Memory patch AmsiScanBuffer
│   │   └── Reflection-based bypass
│   ├── Script Block Logging? → references/etw-bypass.md
│   └── Constrained Language Mode? → CLM bypass or switch to C#
│
├── .NET assembly (Rubeus, SharpHound, etc.)?
│   ├── Direct execution blocked?
│   │   ├── In-memory Assembly.Load
│   │   ├── Convert to shellcode with Donut
│   │   └── Use C2 execute-assembly
│   └── Still detected?
│       ├── Obfuscate assembly (ConfuserEx)
│       ├── Modify source + recompile
│       └── Use BOFs (Beacon Object Files) if CS
│
├── Shellcode execution needed?
│   ├── Basic → references/shellcode-execution.md §Local
│   ├── Need injection → references/shellcode-execution.md §Remote
│   │   ├── Low detection → module stomping or phantom DLL
│   │   ├── Medium → early bird APC or NtMapViewOfSection
│   │   └── Quick and dirty → CreateRemoteThread
│   └── Memory scanners → references/shellcode-execution.md §Sleep
│
├── EDR hooking ntdll.dll?
│   ├── Direct syscalls → references/syscall-proxy.md
│   ├── Full unhook → references/ntdll-unhook.md
│   └── Indirect syscalls → references/syscall-proxy.md §Indirect
│
├── Signature detection?
│   ├── Known tool signature → modify + recompile
│   ├── String-based → string encryption / API hashing (§7)
│   ├── PE metadata → strip/modify (§7)
│   └── Behavioral → change execution flow, add junk code
│
└── All local evasion fails?
    ├── Use Living-off-the-Land (LOLBins): certutil, mshta, regsvr32
    ├── Use legitimate admin tools (PsExec, WMI, WinRM)
    └── Switch to fileless / memory-only techniques
```
