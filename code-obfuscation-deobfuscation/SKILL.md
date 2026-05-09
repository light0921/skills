---
name: code-obfuscation-deobfuscation
description: >-
  Code obfuscation & deobfuscation — both attack and defense perspectives. Use for: (1) REVERSE: identifying and defeating obfuscation in protected binaries; (2) OFFENSIVE: implementing compiler-level obfuscation (OLLVM), .NET obfuscation (ConfuserEx), string encryption, IAT hiding, and PE header modification for AV evasion.
---

# SKILL: Code Obfuscation & Deobfuscation — Expert Analysis Playbook

> **AI LOAD INSTRUCTION**: This is the entry point. Load specific `references/*.md` files when deep-diving into a technique. This keeps context lean.

## 0. RELATED ROUTING

- [av-evasion-orchestrator](../av-evasion-orchestrator/SKILL.md) — 免杀决策入口（当混淆用于免杀目的时，orchestrator 会路由到本 skill 的 §11 attack perspective）
- [anti-debugging-techniques](../anti-debugging-techniques/SKILL.md) when the obfuscated binary also has anti-debug layers
- [symbolic-execution-tools](../symbolic-execution-tools/SKILL.md) when using angr/Z3 for automated deobfuscation
- [vm-and-bytecode-reverse](../vm-and-bytecode-reverse/SKILL.md) for deep VM protector bytecode analysis

### Quick identification picks

| Symptom in IDA/Ghidra | Likely Obfuscation | Start With |
|---|---|---|
| Flat CFG, single giant switch | Control flow flattening | `references/control-flow-flattening.md` |
| Only `mov` instructions | movfuscator | `references/movfuscator-vmprotect.md` §1 |
| pushad/pushfd → VM entry | VM protector | `references/movfuscator-vmprotect.md` §2 |
| XOR loop before code execution | SMC / string encryption | `references/self-modifying-code.md` |
| Impossible conditions (opaque predicates) | Junk code insertion | `references/junk-code-opaque.md` |
| All strings unreadable | String encryption | §1 below |
| No imports in IAT | Import hiding | §2 below |

---

## 1. STRING ENCRYPTION (Defensive Analysis)

### 1.1 Common Patterns

| Pattern | Example | Recovery |
|---|---|---|
| XOR loop | `for (i=0; i<len; i++) s[i] ^= key;` | Hook or emulate XOR function |
| Stack strings | `mov [esp+0], 'H'; mov [esp+1], 'e'; ...` | IDA FLIRT / Ghidra script to reassemble |
| RC4 encrypted | Encrypted blob + RC4 key in binary | Extract key, decrypt offline |
| AES encrypted | Encrypted blob + AES key derived at runtime | Hook after decryption |
| Custom encoding | Base64 + XOR + reverse | Trace the decode function, replicate |

### 1.2 Automated String Decryption

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

## 2. IMPORT HIDING (Defensive Analysis)

### 2.1 GetProcAddress + Hash Lookup

```c
FARPROC resolve(DWORD hash) {
    // Walk PEB → LDR → InMemoryOrderModuleList
    // For each DLL, walk export table
    // Hash each export name, compare with target hash
    // Return matching function pointer
}
```

### 2.2 Recovery

1. Identify the hash algorithm (common: CRC32, djb2, ROR13+ADD)
2. Compute hashes for all known API names
3. Build hash → API name lookup table
4. Annotate resolved calls in IDA/Ghidra

### 2.3 Common Hash Algorithms

| Name | Algorithm | Used By |
|---|---|---|
| ROR13 | `hash = (hash >> 13 \| hash << 19) + char` | Metasploit shellcode |
| djb2 | `hash = hash * 33 + char` | Various malware |
| CRC32 | Standard CRC32 of function name | Sophisticated packers |
| FNV-1a | `hash = (hash ^ char) * 0x01000193` | Modern malware |

---

## 3. ANTI-DISASSEMBLY TRICKS

| Trick | Mechanism | Fix |
|---|---|---|
| Overlapping instructions | `jmp $+2; db 0xE8` (fake call prefix) | Manual re-analysis from correct offset |
| Misaligned jumps | Jump into middle of multi-byte instruction | Force IDA to re-analyze at target |
| Conditional jump pair | `jz $+5; jnz $+3` (always jumps) | Convert to unconditional jmp |
| Return address manipulation | `push addr; ret` instead of `jmp addr` | Recognize push+ret as jump |
| Exception-based flow | Trigger exception, real code in handler | Analyze exception handler chain |
| Call + add [esp] | `call $+5; add [esp], N; ret` (computed jump) | Calculate actual target |

**IDA Fixes**: Right-click → Undefine (U) → Right-click → Code (C) at correct offset

---

## 4. DECISION TREE

```
Obfuscated binary — how to approach?
│
├─ Can you run it?
│  ├─ Yes → Dynamic analysis first
│  │  ├─ Set BP on interesting APIs (file, network, crypto)
│  │  ├─ Trace execution to understand real behavior
│  │  └─ Dump decrypted code/strings at runtime
│  └─ No (embedded/firmware/exotic arch) → Static only
│
├─ What does the code look like?
│  ├─ Giant flat switch/dispatcher loop?
│  │  ├─ State variable drives control flow → CFF → references/control-flow-flattening.md
│  │  └─ Bytecode fetch-decode-execute → VM → references/movfuscator-vmprotect.md
│  ├─ Only mov instructions? → references/movfuscator-vmprotect.md §1
│  ├─ XOR/ADD loop → .text section? → references/self-modifying-code.md
│  ├─ Impossible branch conditions? → references/junk-code-opaque.md §2
│  ├─ Disassembly looks wrong? → Anti-disassembly (§3 above)
│  ├─ No readable strings? → String encryption (§1 above)
│  └─ No imports in IAT? → Import hiding (§2 above)
│
└─ What tool to use?
   ├─ Known protector (VMProtect/Themida) → specific deprotection guide
   ├─ Custom obfuscation → combine: IDA scripting + Triton + manual
   ├─ CTF challenge → angr symbolic execution often fastest
   └─ Malware analysis → dynamic (debugger + API monitor) first
```

---

## 5. TOOLBOX

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

## Reference Files — Load On Demand

| Reference | Lines | When to Load |
|---|---|---|
| `references/junk-code-opaque.md` | 47 | Junk code insertion, opaque predicate identification & removal |
| `references/self-modifying-code.md` | 48 | SMC XOR decryption loops, Unicorn emulation unpacking |
| `references/control-flow-flattening.md` | 52 | CFF structure, D-810, angr symbolic deflattening |
| `references/movfuscator-vmprotect.md` | 79 | movfuscator demovfuscation, VMProtect/Themida handler extraction |
| `references/compiler-obfuscation.md` | 241 | **OFFENSIVE**: OLLVM configs, ConfuserEx templates, string/IAT hiding code |
