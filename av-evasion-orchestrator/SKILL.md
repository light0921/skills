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

> **注意**: 以下是预设模板，适合快速决策。需要更灵活的组合时，使用 §12「技术叠加器」逐层定制。

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
├─ 你知道目标 EDR 是什么吗？
│   ├─ 是（CrowdStrike / SentinelOne / Defender / 卡巴）
│   │   └─ → §9 EDR 差异化方案矩阵
│   └─ 否
│       └─ → 使用 §2 防御等级评估命令获取信息
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

## 9. EDR 差异化方案矩阵

通用免杀方案在不同 EDR 面前效果差异很大。以下是四大主流 EDR 的检测重点和针对性绕过策略：

### 9.1 EDR 产品速识

```powershell
# 快速识别目标 EDR
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct |
    Select-Object displayName, productState

# 进程特征识别
Get-Process | Where-Object {
    $_.ProcessName -match "MsMpEng|Sense|CSFalcon|SentinelAgent|avp"
} | Select-Object ProcessName, Id

# 服务特征识别
Get-Service | Where-Object {
    $_.Name -match "WinDefend|Sense|CSFalcon|SentinelAgent|AVP"
} | Select-Object Name, Status
```

### 9.2 四大 EDR 差异化方案

| EDR | 检测强项 | 核心弱点 | 针对性绕过方案 |
|---|---|---|---|
| **CrowdStrike Falcon** | 行为序列分析、云端 AI 关联、进程链回溯 | 用户态 Hook 深度有限（仅关键 API）；对间接 syscall + 栈欺骗敏感 | ① Indirect syscall + CallStack Spoofing（伪造 ntdll 返回地址）② 避开 Falcon 重点监控的父子进程关系（不用 Office→cmd→powershell 链）③ 使用 Fiber 执行替代 CreateThread |
| **SentinelOne** | 静态 ML + 行为双引擎、VSS 卷影保护、文件回滚 | 内核回调注册较 CS Falcon 少；对 C#/.NET 的静态特征检测偏重 | ① Donut 转 shellcode 避免 .NET 反射特征② 静态混淆（OLLVM）优先于动态对抗③ 利用 S1 对合法云服务 C2 检测较弱的特点 |
| **Defender for Endpoint** | AMSI/ETW 深度集成、MAPS 云端 ML、ASR 攻击面缩减规则 | 已知绕过方法多；用户态防护为主；社区研究充分 | ① AMSI + ETW 双杀（硬件断点最佳）② WDAC 评估用 LOLBAS Chaining ③ 避开 ASR 规则触发的 Office/Adobe 子进程创建 |
| **卡巴斯基** | System Watcher 行为序列、应用控制、启发式仿真深度大 | 性能开销大 → 仿真超时可绕过；对 Rust/Go 二进制分析耗时 | ① 延长执行延迟（超出卡巴仿真时限 ~60s）② ntdll Unhooking + Indirect Syscall ③ 使用 Rust/Go 编译增大二进制体积，耗尽沙箱时间④ 行为序列中插入合法 API 调用作噪声 |

### 9.3 EDR 指纹识别 → 方案选择流程

```
检测到 EDR 进程/服务
│
├── CsFalconService / CSFalconContainer?
│   └── 方案: 栈欺骗 + Fiber 执行 + 避开敏感进程链
│
├── SentinelAgent / SentinelHelperService?
│   └── 方案: OLLVM 混淆 + Donut 转 shellcode + Cloud C2
│
├── MsMpEng + Sense (MDE)?
│   └── 方案: AMSI/ETW 双杀 + LOLBAS Chaining + 避开 ASR
│
├── avp / avpui (Kaspersky)?
│   └── 方案: Unhook ntdll + 延长延迟 + Rust/Go 编译
│
└── 未知 EDR / 多个共存?
    └── 按 L4 硬化方案: BYOVD 致盲 → 敏感操作 → 恢复
```

---
## 10. Windows 11 24H2/25H2 安全变化对免杀的系统性影响

Win11 24H2 的安全架构升级对免杀的影响远超单点修补，是系统性的。以下按影响程度排序：

### 10.1 五大安全变化及影响矩阵

| 安全特性 | 启用条件 | 对免杀的影响 | 影响等级 | 应对方案 |
|---|---|---|---|---|
| **HVCI 默认强制** | 支持 VBS 的设备默认开启 | 未签名驱动无法加载 → BYOVD 直接报废；内核内存不可写 → 内核致盲失败 | ⚠️ 致命 | 回退用户态全链：AMSI+ETW+Unhook+PoolParty+Sleep Obfuscation |
| **Smart App Control 增强** | Win11 SE / 新装 24H2 | 未签名/低信誉二进制直接拦截 → 连执行机会都没有 | ⚠️ 高 | ① 使用有效代码签名证书（EV 证书首选）② 利用有信誉的 LOLBin 链 ③ 钓鱼绕过（诱导用户手动允许） |
| **ETW Threat Intel Provider** | Win11 24H2 默认 | 记录所有 syscall 调用栈、RWX 内存操作 → 间接 syscall 被记录 | ⚠️ 高 | ① Provider 级选择性禁用（§9.2.1）② 避免 RWX 内存 → 使用 RW→RX 分步修改 ③ 利用合法调用栈（Fiber/线程池） |
| **Kernel Callback 完整性校验** | Win11 24H2+ | 定期校验 PsSetCreateProcessNotifyRoutine 等回调链表 → 篡改触发 BSOD | ⚠️ 高 | 不修改回调链表本身 → 改为修改回调函数指针指向空实现 |
| **Credential Guard 默认** | Win11 24H2（部分 SKU） | LSASS 隔离在 VTL1 → 用户态无法 dump → Mimikatz 直接失效 | ⚠️ 致命 | ① 放弃 dump LSASS → 改用 Kerberos ticket (.kirbi) ② DPAPI 解密 ③ SAM/SECURITY 注册表提取 ④ 网络级凭证捕获（Responder/ntlmrelayx） |

### 10.2 版本适配决策清单

```
目标 OS 版本?
│
├── Win10 / Win11 22H2-23H2
│   └── 用户态 + 内核态方案全可用（前提：HVCI 未手动开启）
│
├── Win11 24H2
│   ├── HVCI 开启 → 内核方案不可用 → 走用户态全链
│   ├── Credential Guard 开启 → dump LSASS 不可用 → 改用 ticket/SAM
│   ├── SAC 开启 → 需签名证书或 LOLBAS 链
│   └── ETW Threat Intel → 需 Provider 级绕过
│
├── Win11 25H2 (预计 2025H2)
│   └── 预计: Intel CET Shadow Stack 硬件强制 + KDP 范围扩大
│       → ROP 链、栈欺骗直接失效
│       → 应对: JOP/COP 替代 ROP、Signal-Oriented Programming
│
└── Windows Server 2025+
    └── VBS/HVCI 默认开启（与 Win11 一致）+ WDAC 策略更严格
```

---
## 11. 附录：C2 框架选型参考

C2 框架直接影响免杀方案的选型和成本。以下为 2026 年主流框架对比：

| 框架 | 语言 | 协议 | 免杀能力 | 生态 | 适合场景 |
|---|---|---|---|---|---|
| **Sliver** | Go | mTLS/HTTP/HTTPS/WireGuard/DNS | ★★★★ 原生 syscall、PPID 欺骗、Malleable Profile | 开源(BishopFox)、活跃社区 | 替代 CS 的首选，Go 编译天然免杀优势 |
| **Havoc** | Python+C | HTTP/HTTPS/SMB | ★★★★ 集成 Shhhloader、多种注入、OLLVM 支持 | 开源、法语团队 | 中大型红队，需要多种注入方式切换 |
| **Mythic** | Python+Go | HTTP/HTTPS/DNS/WebSocket | ★★★☆ 多语言 Agent（Apollo/Athena/Medusa）、自定义 C2 Profile | 开源、最活跃社区 | 需要高度定制的多平台操作 |
| **Nighthawk** | C++ | HTTP/HTTPS | ★★★★★ 内置栈伪造、间接 syscall、ETW 补丁、内存加密 | 商业(MDSec)、$10K+/年 | 高对抗 L4 环境、APT 模拟 |
| **Cobalt Strike** | Java+C | HTTP/HTTPS/DNS/SMB/TCP | ★★★★ UDRL 自定义、Malleable C2、Sleep 加密 | 商业(Fortra)、最大生态 | 传统红队首选，但被特征化严重 |
| **Brute Ratel** | C/C++ | HTTP/HTTPS/DNS/SMB | ★★★★★ Badger Agent、直接 syscall、内存加密、无特征 | 商业、$2.5K+/年 | L3-L4 环境、需要高隐蔽性 |
| **PoshC2** | Python+PS | HTTP/HTTPS | ★★★ AMSI 绕过、进程注入 | 开源 | 仅 PS/.NET 场景，Windows 渗透快攻 |

### 与免杀方案的关联

| C2 选择 | 推荐搭配的免杀链 | 原因 |
|---|---|---|
| Sliver / Havoc / Mythic（开源） | **标准链**: Donut→Stomping→PoolParty→ETW/AMSI | 开源 C2 的 beacon 特征更可能被标记，需更多的执行层绕过 |
| Nighthawk / Brute Ratel（商业） | **轻量链**: syscall + 栈欺骗即可 | 商业 C2 内置免杀更完善，不需重型注入 |
| Cobalt Strike | **标准链 + 签名规避**: 重点防静态特征 + 使用 UDRL | CS beacon 被几乎所有 EDR 特征化，静态免杀是第一步 |

---
## 12. 技术叠加器 — 灵活组合替代固定方案

> §4 的组合拳（轻量/标准/重装链）是预设模板，适合快速决策。当你需要更精细的控制时，使用本节的六层架构逐层叠加。

### 12.1 六层技术架构

```
┌─────────────────────────────────────────────────────┐
│ 第零层: 基础编码规范     — 所有组合必须               │
│   ☑ 函数名模糊化  ☑ 变量名模糊化  ☑ 低熵填充       │
├─────────────────────────────────────────────────────┤
│ 第一层: 执行方式         — 本地5种 / 远程7种          │
│   ○ VirtualAlloc+Thread  ○ Fiber  ○ Callback        │
│   ○ Early Bird APC  ○ Process Hollowing              │
│   ○ Module Stomping  ○ Threadless Injection          │
├─────────────────────────────────────────────────────┤
│ 第二层: 系统调用方式     — 4种                        │
│   ○ 标准API  ○ syscall.SyscallN                      │
│   ○ Hell's Gate  ○ HellsHall (间接syscall+栈欺骗)     │
├─────────────────────────────────────────────────────┤
│ 第三层: 加密+混淆        — 16种组合                    │
│   加密: ○ XOR  ○ AES  ○ ChaCha20                     │
│   混淆: ○ IPv4  ○ UUID  ○ MAC  ○ Base64              │
├─────────────────────────────────────────────────────┤
│ 第四层: 高级规避技术     — 10项（☑=防御等级强制）      │
│   L1: ☑ETW ☑AMSI                                      │
│   L2: ☑ETW ☑AMSI □NTDLL脱钩                            │
│   L3: ☑ETW ☑AMSI ☑NTDLL脱钩 □间接syscall □VEH内存保护  │
│   L4: ☑全开 □睡眠混淆 □PE波动 □堆加密 □沙箱检测        │
├─────────────────────────────────────────────────────┤
│ 第五层: 注入增强         — 远程注入必须                │
│   □ 参数欺骗  □ BlockDLLs  □ PPID欺骗  □ 模块踩踏     │
├─────────────────────────────────────────────────────┤
│ 第六层: Beacon模式       — 长驻必须                    │
│   □ 睡眠混淆(Ekko/Foliage)  □ 堆加密  □ PE波动        │
└─────────────────────────────────────────────────────┘
```

### 12.2 防御等级 → 必备技术映射

| 等级 | 必备技术 | 叠加自由度 |
|---|---|---|
| **L1 基线** (Defender) | 第零层 + ETW + AMSI | 第三层加密可自由选择 16 种组合 |
| **L2 增强** (第三方AV) | L1预设 + NTDLL脱钩 + 沙箱检测 | 第二层 syscall 可选 Hell's Gate |
| **L3 EDR** (CS/S1/MDE) | L2预设 + 间接syscall + VEH内存保护 | 第四层建议全开；第一层避免 CreateRemoteThread |
| **L4 硬化** (EDR+HVCI) | L3预设 + 全部第四层 + 第六层 | 如 HVCI 开启 → BYOVD 不可用，走用户态全链 |

### 12.3 技术组合速查 — 直接复制到方案中

**快速过 Defender (L1)**:
```
☑第零层: 函数名/变量名模糊化
☑第一层: VirtualAlloc + Callback (EnumWindows)
☑第二层: syscall.SyscallN
☑第三层: XOR + IPv4
☑第四层: ETW + AMSI
```

**标准对抗 EDR (L3)**:
```
☑第零层: 全部
☑第一层: Early Bird APC + Module Stomping
☑第二层: HellsHall (间接syscall)
☑第三层: AES + UUID
☑第四层: ETW + AMSI + NTDLL脱钩 + VEH + 沙箱检测
☑第五层: BlockDLLs + 参数欺骗
```

**Beacon 长驻 (L3/L4)**:
```
☑第零层: 全部
☑第一层: Module Stomping
☑第二层: HellsHall
☑第三层: ChaCha20 + IPv6
☑第四层: 全开 (10项)
☑第五层: BlockDLLs + 模块踩踏
☑第六层: 睡眠混淆(Ekko+Foliage) + 堆加密 + PE波动
```

### 12.4 与其他 skill 的联动

| 叠加层 | 加载哪个 skill |
|---|---|
| 第一层 (执行方式) | `advanced-process-injection` §1-3 |
| 第二层 (syscall) | `windows-av-evasion` references/syscall-proxy.md |
| 第三层 (加密混淆) | `windows-av-evasion` §6 + `code-obfuscation-deobfuscation` references/compiler-obfuscation.md |
| 第四层 (高级规避) | `windows-av-evasion` references/amsi-bypass.md, etw-bypass.md, ntdll-unhook.md, sandbox-evasion.md |
| 第五层 (注入增强) | `advanced-process-injection` + `windows-av-evasion` references/shellcode-execution.md |
| 第六层 (Beacon) | `advanced-process-injection` §4 (Sleep Obfuscation) |

---
## 13. 决策示例

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
