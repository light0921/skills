# 免杀技术 Skill 体系

> 面向实战的免杀知识库 — 7 个专项 Skill + 1 个统一决策路由入口，覆盖用户态到内核态的完整免杀技术栈，合计 3152 行实战内容。

## 架构

```
av-evasion-orchestrator (统一决策入口 · 439行)
│
├── 用户态免杀
│   ├── windows-av-evasion (683行)           AMSI/ETW bypass · syscall · unhooking · shellcode · C签名规避
│   ├── advanced-process-injection (296行)    PoolParty · Threadless · Module Stomping · Sleep Obfuscation
│   └── code-obfuscation-deobfuscation (680行) OLLVM/ConfuserEx · 控制流平坦化 · 字符串加密 · IAT隐藏
│
├── 内核态免杀
│   └── byovd-kernel-evasion (342行)          BYOVD驱动 · EDR回调清除 · PPL绕过 · 检测规则(Sysmon/Sigma)
│
└── 逆向对抗
    ├── anti-debugging-techniques (407行)     反调试检测与绕过 (PEB / ptrace / 时序 / TLS)
    └── binary-protection-bypass (295行)      ASLR / PIE / NX / RELRO / canary 绕过
```

## 使用方式

做免杀时，只需加载决策入口：

```
加载 av-evasion-orchestrator
```

它会按 **三层决策架构** 自动分析场景并推荐最优方案：

1. **攻击阶段路由** — 你在杀伤链的哪个环节？
2. **防御水平评估** — L1 (Defender) / L2 (第三方AV) / L3 (EDR) / L4 (硬化)
3. **EDR 差异化分析** — 识别 CrowdStrike Falcon / SentinelOne / Defender / 卡巴斯基，给出针对性绕行策略
4. **方案推荐 + 路由子 Skill** — 给出具体技术选型，按需加载对应专项 Skill

## Skill 清单

| Skill | 定位 | 核心能力 |
|---|---|---|
| `av-evasion-orchestrator` | 免杀决策路由 | 三层决策架构、四大 EDR 差异化矩阵、Win11 24H2 适配、6 大场景矩阵 + 3 套组合拳、**C2 框架选型附录 (7 框架对比)** |
| `windows-av-evasion` | Windows AV/EDR 规避 | **完整 C 语言 AMSI patch**、**ETW Provider 级深度绕过 (NtTraceControl)**、Fresh ntdll copy、.NET 内存加载、syscall 代理、签名规避、shellcode 执行 |
| `advanced-process-injection` | 高级进程注入 | PoolParty 8 变体、Threadless Injection、Module Stomping、Crystal Palace 组合链、Sleep Obfuscation |
| `byovd-kernel-evasion` | BYOVD 内核致盲 | 漏洞驱动加载、EDR 内核回调清除、PPL 绕过、7 驱动选型表、**Sysmon/Sigma 检测规则** |
| `code-obfuscation-deobfuscation` | 代码混淆对抗 | **OLLVM 编译配置 (4 Pass+实战配方)**、**ConfuserEx 模板**、字符串加密+IAT 隐藏完整代码、控制流平坦化、SMC、VM 保护器 |
| `anti-debugging-techniques` | 反调试对抗 | PEB 检测、ptrace、时序检测、TLS 回调、VEH 技巧 |
| `binary-protection-bypass` | 二进制保护绕过 | ASLR/PIE/NX/RELRO/canary/FORTIFY 绕过 |

## v1.1 更新 (2026-05-07)

基于第三方评测反馈，对 4 个核心 Skill 大幅增强（+908 行代码/规则/模板）：

- **windows-av-evasion** (+382行) — 完整 C 语言 AMSI patch / ETW Provider 级深度绕过 / Fresh ntdll copy
- **av-evasion-orchestrator** (+119行) — 四大 EDR 差异化矩阵 / Win11 24H2 五大影响 / C2 框架选型附录
- **code-obfuscation-deobfuscation** (+288行) — OLLVM 编译配置 / ConfuserEx 模板 / 字符串加密+IAT 隐藏
- **byovd-kernel-evasion** (+119行) — Sysmon XML + Sigma YAML 规则 / 四大 EDR 告警配置

## 目录结构

```
skills/
├── av-evasion-orchestrator/
│   └── SKILL.md                 # 统一决策路由 (含EDR矩阵+C2附录)
├── windows-av-evasion/
│   ├── SKILL.md                 # AV/EDR 规避主文档 (含C代码)
│   └── AMSI_BYPASS_TECHNIQUES.md
├── advanced-process-injection/
│   └── SKILL.md                 # 进程注入技术
├── byovd-kernel-evasion/
│   └── SKILL.md                 # BYOVD 内核致盲 (含检测规则)
├── code-obfuscation-deobfuscation/
│   └── SKILL.md                 # 代码混淆 (含OLLVM/ConfuserEx)
├── anti-debugging-techniques/
│   ├── SKILL.md                 # 反调试
│   └── ANTI_DEBUG_MATRIX.md
├── binary-protection-bypass/
│   ├── SKILL.md                 # 保护绕过
│   └── PROTECTION_BYPASS_MATRIX.md
└── README.md
```

## 平台兼容

这些 Skill 设计用于 WorkBuddy / CodeBuddy Code 的 Skill 系统，存放于 `~/.workbuddy/skills/` 目录。也可以作为独立知识库直接阅读 `SKILL.md` 文件获取完整技术内容。

---

_维护者: @light0921 · 最后更新: 2026-05-07 · v1.1_
