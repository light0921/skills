---
name: av-evasion-orchestrator
description: >-
  免杀决策路由系统 — 统一的免杀入口 skill。根据攻击阶段、目标环境防御水平、负载类型等条件，自动分析场景并推荐最优免杀方案，按需路由到 byovd-kernel-evasion、advanced-process-injection、windows-av-evasion、code-obfuscation-deobfuscation、anti-debugging-techniques 等专项 skill。适用于任何需要绕过杀软/EDR 的场景。
---

# 免杀决策路由系统 — 统一入口

> **定位**: 免杀技术的总调度中心。不做重复搬运，只做场景分析 → 方案推荐 → 路由子技能。
>
> **子技能是「怎么做」，本 skill 是「什么时候用什么」。**

---

## 0. 覆盖的免杀技术全景

```
免杀决策路由 (本 skill)
│
├── 用户态免杀
│   ├── [windows-av-evasion] AMSI/ETW bypass、syscall、unhooking、shellcode 执行、签名规避
│   ├── [advanced-process-injection] PoolParty、Threadless、Module Stomping、Sleep Obfuscation
│   └── [code-obfuscation-deobfuscation] 代码混淆、控制流平坦化、字符串加密、IAT 隐藏
│
├── 内核态免杀
│   └── [byovd-kernel-evasion] BYOVD 驱动加载、EDR 内核回调清除、PPL 绕过
│
├── 逆向对抗
│   ├── [anti-debugging-techniques] 反调试检测与绕过（PEB、ptrace、时序、TLS 回调）
│   └── [binary-protection-bypass] ASLR/PIE/NX/RELRO/canary 保护绕过
│
└── 辅助
    ├── [windows-privilege-escalation] 提权（当免杀工具需要高权限）
    └── [sandbox-escape-techniques] 沙箱逃逸（当运行在受限环境）
```

---

## 1. 攻击阶段路由（第一层决策）

根据你当前在杀伤链的位置，快速定位需要哪些免杀技术：

| 阶段 | 典型动作 | 主要威胁 | 推荐加载 |
|---|---|---|---|
| **初始访问** | 钓鱼附件、宏、LNK | Defender SmartScreen、AMSI | `windows-av-evasion`（AMSI bypass + 宏免杀） |
| **执行** | 运行 payload/工具 | AV 静态扫描、行为监控 | `windows-av-evasion` + `advanced-process-injection` |
| **持久化** | 注册表/计划任务/WMI | EDR 行为规则、启动项监控 | `windows-av-evasion`（签名规避 + LOLBin） |
| **防御规避** | 关闭/致盲 AV/EDR | EDR 内核回调、自保护 | `byovd-kernel-evasion` + `windows-av-evasion` |
| **凭证访问** | dump LSASS、Mimikatz | PPL 保护、Credential Guard | `byovd-kernel-evasion`（PPL 绕过）+ `advanced-process-injection` |
| **横向移动** | PsExec、WMI、WinRM | EDR 网络检测、行为关联 | `windows-av-evasion`（syscall + unhooking） |
| **信息收集** | 文件枚举、网络扫描 | 较少（主要是 EDR 行为基线） | `windows-av-evasion`（LOLBin 优先） |
| **数据渗出** | 上传文件、C2 通信 | 网络 DLP、流量分析 | C2 框架内置规避（非本 skill 覆盖） |

---

## 2. 防御水平评估（第二层决策）

在选择具体免杀方案前，先评估目标环境的防御等级：

### 防御等级定义

| 等级 | 特征 | 典型环境 |
|---|---|---|
| **L1 - 基线** | 仅 Windows Defender，默认配置 | 个人 PC、小企业 |
| **L2 - 增强** | Defender + ATP / 第三方 AV（ESET、卡巴） | 中型企业 |
| **L3 - EDR** | CS Falcon / CrowdStrike / SentinelOne / Defender for Endpoint | 大型企业 |
| **L4 - 硬化** | EDR + HVCI/VBS + Credential Guard + ASR 规则 + 应用白名单 | 金融/政府/关键基础设施 |

### 快速评估命令

```powershell
# 1. 检测 AV/EDR 产品
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct

# 2. 检测 HVCI / VBS 状态
Get-ComputerInfo | Select-Object -Property *DeviceGuard*

# 3. 检测 Credential Guard
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags"

# 4. 检测 PPL 保护（LSASS）
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL"

# 5. 检测应用白名单（AppLocker / WDAC）
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
```

---

## 3. 核心决策矩阵（第三层决策 — 选方案）

**使用方式**: 先看「场景」列找到你的情况 → 看推荐的「首选方案」→ 加载对应的子 skill 获取详细实施步骤。

### 3.1 PowerShell / 脚本负载免杀

| 场景 | L1 方案 | L2-L3 方案 | L4 方案 |
|---|---|---|---|
| PS 脚本被 AMSI 拦截 | PS v2 降级 或 内存 patch AmsiScanBuffer | 反射法设置 amsiInitFailed + 混淆触发字符串 | 转 C# / .NET 内存加载 + ETW bypass |
| Script Block Logging | ETW patch EtwEventWrite | 同 L1 + PowerShell 内部字段禁用 | 不落盘脚本，直接内存执行 |
| CLM (受限语言模式) | COM hijack 绕过 CLM | WMI 替代 PS 执行 | 转 C# 内存加载 |

→ 加载 `windows-av-evasion`

### 3.2 .NET 工具免杀（Rubeus / SharpHound / Seatbelt 等）

| 场景 | L1 方案 | L2-L3 方案 | L4 方案 |
|---|---|---|---|
| .NET EXE 被杀 | ConfuserEx 混淆 + 重编译 | Donut 转 shellcode → 进程注入 | 改用 BOF（Beacon Object File）替代 |
| 内存加载被 EDR 检测 | Assembly.Load 内存加载 + ETW bypass | 同 L1 + 签名伪造 + 字符串加密 | 改用 C2 内置 execute-assembly |
| 执行后被行为规则匹配 | 修改源码移除特征字符串 | 同 L1 + API hashing + sleep obfuscation | 改用纯 syscall 方案 |

→ 加载 `windows-av-evasion`（AMSI/ETW/.NET 加载章节）+ `code-obfuscation-deobfuscation`

### 3.3 Shellcode / 进程注入免杀

| 场景 | L1 方案 | L2-L3 方案 | L4 方案 |
|---|---|---|---|
| 简单 payload 执行 | VirtualAlloc + EnumWindows 回调 | Early Bird APC 注入 | Module Stomping + Indirect Syscall |
| 需要注入到远程进程 | CreateRemoteThread（快速但高检测） | Process Hollowing 或 Phantom DLL | PoolParty V7 + Module Stomping |
| EDR 检测到 Private MEM 分配 | Module Stomping（覆写合法 DLL .text 段） | 同 L1 + Sleep Obfuscation | Crystal Palace 链（PoolParty + Stomping + Sleep） |
| EDR Hook ntdll.dll | SysWhispers3 直接 syscall | HellsGate/HalosGate 动态解析 | Fresh ntdll copy（从 KnownDlls 读取） |
| 行为检测（创建新线程） | Threadless Injection（Hook NtClose） | PoolParty（利用线程池回调） | Fiber Execution（无新线程 + 原生调用栈） |

→ 加载 `advanced-process-injection` + `windows-av-evasion`（unhooking/syscall 章节）

### 3.4 内核级免杀 / EDR 致盲

| 场景 | 必备条件 | 推荐方案 |
|---|---|---|
| 需要 dump LSASS（PPL 保护） | 管理员权限 + 非 HVCI | `byovd-kernel-evasion` — RTCore64.sys 清除 PPL 回调 |
| 需要终止 EDR 进程 | 管理员权限 | kprocesshacker.sys 或 EDRSandBlast |
| EDR 在用户态已绕过但内核层拦截 | 管理员权限 + 非 HVCI | BlindEDR 全流程致盲 + 恢复 |
| HVCI 启用（Win11 24H2+） | 管理员权限 | **回退用户态方案**：AMSI+ETW+unhooking+PoolParty |
| Credential Guard 启用 | - | 无法 dump LSASS → 改用 Kerberos ticket / SAM 提取 |

→ 加载 `byovd-kernel-evasion`

### 3.5 静态免杀（Payload 生成阶段）

| 场景 | 方案 |
|---|---|
| 检测到已知工具签名 | 修改源码重编译 + 去除 PDB 路径 + 伪造编译时间戳 |
| 检测到特征字符串（API 名、URL） | 字符串加密 + API hashing 动态解析 |
| 检测到 PE 结构特征 | PE 头修改 + Rich Header 清除 + Section 重命名 |
| 检测到 .NET 元数据 | ConfuserEx / .NET Reactor / Obfuscar 混淆 |

→ 加载 `code-obfuscation-deobfuscation` + `windows-av-evasion`（签名规避章节）

### 3.6 逆向分析对抗

| 场景 | 方案 |
|---|---|
| 沙箱环境（自动分析） | 延迟执行 + 环境检测（CPU/内存/磁盘/用户行为） |
| 调试器附加 | PEB.BeingDebugged 检测 + 反附加入口 |
| 虚拟机检测 | Red Pill 技术（注册表/进程/设备指纹） |
| 静态分析工具（IDA/Ghidra） | 控制流平坦化 + 不透明谓词 + SMC（自修改代码） |

→ 加载 `anti-debugging-techniques` + `code-obfuscation-deobfuscation`

---

## 4. 组合拳方案（多技术串联）

单一技术的免杀能力有限，实战推荐组合链：

### 4.1 轻量级链（L1-L2 环境）

```
Payload 生成
  → 字符串加密 + API hashing（静态免杀）
  → SysWhispers3 间接 syscall（绕过 ntdll Hook）
  → VirtualAlloc + EnumWindows 回调（无 CreateThread）
```

### 4.2 标准链（L3 EDR 环境）

```
Payload 生成
  → Donut 转 shellcode + AES 加密
  → Module Stomping（写入合法 DLL .text 段）
  → PoolParty V7 触发执行（无新线程）
  → ETW + AMSI bypass（阻止遥测上报）
  → Sleep Obfuscation（保护休眠期）
```

### 4.3 重装链（L4 硬化环境 + 需要内核致盲）

```
Phase 1: 用户态存活
  → AMSI bypass + ETW bypass
  → Indirect syscall（绕过 Hook）
  → 不落地执行（内存链）

Phase 2: 内核致盲
  → BYOVD 加载漏洞驱动（选不在 Blocklist 中的驱动）
  → 清除 EDR 进程/线程/镜像回调
  → 清除 ObRegisterCallbacks（反注入保护）

Phase 3: 敏感操作（致盲窗口期）
  → PPL 绕过 → dump LSASS
  → 或执行 Mimikatz
  → 或注入保护进程

Phase 4: 恢复清理
  → 恢复 EDR 回调（降低检测概率）
  → 卸载驱动
  → 清除日志
```

---

## 5. 子技能路由速查

| 你想要做的事 | 加载哪个 skill |
|---|---|
| PowerShell/宏绕过 AMSI | `windows-av-evasion` §1 |
| 绕过 ETW / Script Block Logging | `windows-av-evasion` §2 |
| .NET 工具内存加载 | `windows-av-evasion` §3 |
| shellcode 执行（无注入） | `windows-av-evasion` §4 |
| 进程注入（不被 EDR 发现） | `advanced-process-injection` → 按场景选变体 |
| 绕过 ntdll Hook / syscall | `windows-av-evasion` §6 |
| 静态免杀（签名/字符串/PE 头） | `windows-av-evasion` §8 |
| 代码混淆（反逆向） | `code-obfuscation-deobfuscation` |
| 反调试/反沙箱 | `anti-debugging-techniques` |
| ASLR/NX/canary 绕过 | `binary-protection-bypass` |
| EDR 内核致盲（BYOVD） | `byovd-kernel-evasion` |
| 终止保护的 EDR 进程 | `byovd-kernel-evasion` §3 |
| dump LSASS（PPL 保护） | `byovd-kernel-evasion` + PPLKiller |

---

## 6. 快速决策流程图

```
开始免杀任务
│
├─ 你处于什么阶段？
│   ├─ 生成 payload / 编译工具
│   │   └─ 需要静态免杀
│   │       → §3.5 静态免杀矩阵
│   │       → 加载 code-obfuscation-deobfuscation
│   │
│   ├─ 需要在目标上执行代码
│   │   └─ 看负载类型：
│   │       ├─ PowerShell → §3.1 脚本免杀
│   │       ├─ .NET 工具 → §3.2 .NET 免杀
│   │       └─ Shellcode/EXE → §3.3 注入免杀
│   │
│   ├─ 需要做敏感操作（dump LSASS/注入保护进程/终止 EDR）
│   │   └─ 先判断 HVCI 状态：
│   │       ├─ HVCI 未启用 → §3.4 内核致盲
│   │       └─ HVCI 启用 → 回退 §3.3 用户态方案
│   │
│   └─ 需要持久化或横向移动
│       → 主要用 LOLBin + syscall，负载与上述同理
│
└─ 目标防御等级？
    ├─ L1（Defender）→ 轻量方案：syscall + callback + 基础混淆
    ├─ L2-L3（EDR）→ 标准方案：PoolParty + Stomping + Sleep Obfuscation
    └─ L4（硬化）→ 组合方案：BYOVD + 用户态全链 + 恢复清理
```

---

## 7. 环境前置检查清单

在制定免杀方案前，必须确认以下信息（缺少任何一项都会影响方案选择）：

- [ ] 目标 OS 版本（Win10/Win11/Server 2016/2019/2022？具体 Build？）
- [ ] HVCI / VBS 是否启用？（决定能否走内核路线）
- [ ] Credential Guard 是否启用？（决定能否 dump LSASS）
- [ ] AV/EDR 产品是什么？（Defender / CrowdStrike / SentinelOne / 其他？）
- [ ] 是否有应用白名单？（AppLocker / WDAC？）
- [ ] 当前权限级别？（普通用户 / 管理员 / SYSTEM？）
- [ ] 你的负载是什么类型？（PS 脚本 / .NET 工具 / C/C++ EXE / Shellcode？）
- [ ] 是否需要持久化？（影响落地 vs 不落地的选择）
- [ ] 操作的敏感度？（dump 密码 > 文件读取 > 网络扫描）

---

## 8. 踩坑汇总（来自各子技能的实战反馈）

1. **Win11 24H2 默认 HVCI → BYOVD 直接废掉** → 先 `Get-ComputerInfo` 确认，不要假设能走内核
2. **PoolParty 需要目标进程有活跃线程池** → GUI 进程（explorer/svchost）天然满足，纯服务进程需要验证
3. **Module Stomping 的 DLL 选择要慎重** → 选不常用但足够大的 DLL（如 `AppResolver.dll`），避免覆盖高频函数
4. **EDR 可能检测到驱动加载事件** → BYOVD 前先 patch ETW，否则加载驱动本身就会告警
5. **内核回调清除后 EDR 可能蓝屏** → 只清特定回调不要全清；务必准备恢复机制
6. **部分 EDR 对 Callback API 执行也加了规则** → 2026 年 EnumWindows/CertEnumSystemStore 等回调执行已被 SentinelOne 和 Defender for Endpoint 加入特征库
7. **Sleep Obfuscation 各方法都有指纹** → Ekko (ROP Gadget 特征)、Foliage (Timer Queue API 特征)，需搭配使用

---

## 9. 决策示例

**场景**: L3 环境（CrowdStrike Falcon），Win11 22H2，管理员权限，需要 dump LSASS，HVCI 未启用。

```
1. 阶段判定: 凭证访问 → 需要 dump LSASS
2. 防御评估: L3（CS Falcon）, 非 HVCI → 可以走内核
3. 方案选择:
   ┌─ Phase 1: 用户态存活
   │   → windows-av-evasion §2 (ETW bypass 阻止驱动加载事件上报)
   │   → windows-av-evasion §6 (indirect syscall)
   │
   ├─ Phase 2: BYOVD 致盲
   │   → byovd-kernel-evasion (RTCore64.sys → 清除 Falcon 内核回调)
   │
   ├─ Phase 3: Dump LSASS
   │   → byovd-kernel-evasion §5 (PPLKiller 绕过 PPL)
   │   → Mimikatz sekurlsa::logonpasswords
   │
   └─ Phase 4: 恢复
       → 恢复回调 → 卸载驱动 → 清除事件日志
```

---

_本 skill 不包含具体代码实现，所有实施细节在对应的子 skill 中。_
_路由到子 skill 后，子 skill 会给出完整的分步操作指南。_
