# Syscall Proxy — Complete Reference

> **Belongs to**: `windows-av-evasion` skill
> **Load when**: Need to bypass EDR API hooks without unhooking ntdll (lower footprint)

## Direct Syscalls (SysWhispers / HellsGate)

EDR hooks `ntdll.dll` functions. Direct syscalls bypass hooks by invoking the kernel directly.

```
Normal: User code → ntdll.dll (HOOKED) → kernel
Direct: User code → syscall instruction → kernel (bypasses hook)
```

## Tool Comparison

| Tool | Method | SSN Retrieval | Footprint |
|---|---|---|---|
| **SysWhispers2/3** | Compile-time stubs | Hardcoded SSN per Windows build | Medium — static SSN pattern detectable |
| **HellsGate** | Runtime SSN resolution | Parse ntdll to find syscall gadget + SSN | Low — dynamic, adapts to build |
| **HalosGate** | Neighboring unhooked syscalls | Find SSN from nearby unhooked functions | Low — resilient to partial hooks |
| **TartarusGate** | Extended HalosGate | More robust fallback chain | Lowest — handles edge cases |

## Syscall Number (SSN) Retrieval Strategy

| Windows Version | Strategy |
|---|---|
| Win10 1909-22H2 | Hell's Gate — SSNs stable within build, dynamic extraction works |
| Win11 21H2-22H2 | HalosGate — some syscalls may be partially hooked, use neighbors |
| Win11 23H2+ | TartarusGate — increased variablity, need multiple fallbacks |
| Win11 24H2+ (HVCI) | Fresh ntdll unhooking preferred over syscall proxy |

## Indirect Syscalls (Call Stack Spoofing)

```
// Direct syscall:    your_code() → syscall → kernel
//                     Stack shows return to your_code — SUSPICIOUS

// Indirect syscall:  your_code() → ntdll.dll!syscall → kernel
//                     Stack shows return to ntdll.dll — LEGITIMATE
```

The `syscall` instruction executes inside `ntdll.dll`'s memory region, and the return address on the stack points to a legitimate `ntdll.dll` address. EDR call stack analysis cannot distinguish this from normal syscall flow.

### Implementation Pattern

```c
// 1. Locate syscall gadget in ntdll.dll
//    Find a "syscall; ret" sequence within ntdll.dll .text section
BYTE syscallGadget[] = { 0x0F, 0x05, 0xC3 }; // syscall; ret

// 2. Set up registers (SSN in eax, params per calling convention)
// 3. Jump to ntdll gadget address (NOT inline syscall in your code)
// 4. Stack frame shows ntdll as caller → call stack spoofing achieved
```

## When to Use What

| Scenario | Best Approach |
|---|---|
| L2 environment (Defender/3rd-party AV) | Direct syscall (Hell's Gate) |
| L3 EDR with call stack analysis (CS Falcon, S1) | Indirect syscall (stack spoofing) |
| Partial ntdll hooking | HalosGate / TartarusGate |
| HVCI enabled (Win11 24H2) | Unhook ntdll first, then syscall proxy is optional |
| Maximum stealth required | Fresh ntdll unhooking (§ntdll-unhook) + indirect syscall |
