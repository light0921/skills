# 免杀技术 Skill 体系

> 面向实战的免杀知识库 — 7 个专项 Skill + 1 个统一决策路由入口，覆盖用户态到内核态的完整免杀技术栈。

## 架构

```
av-evasion-orchestrator (统一决策入口)
│
├── 用户态免杀
│   ├── windows-av-evasion          AMSI/ETW bypass · syscall · unhooking · shellcode · 签名规避
│   ├── advanced-process-injection  PoolParty · Threadless · Module Stomping · Sleep Obfuscation
│   └── code-obfuscation-deobfuscation  控制流平坦化 · 字符串加密 · IAT 隐藏 · 反逆向
│
├── 内核态免杀
│   └── byovd-kernel-evasion        BYOVD 驱动加载 · EDR 内核回调清除 · PPL 绕过
│
└── 逆向对抗
    ├── anti-debugging-techniques   反调试检测与绕过 (PEB / ptrace / 时序 / TLS)
    └── binary-protection-bypass    ASLR / PIE / NX / RELRO / canary 绕过
```

## 使用方式

做免杀时，只需加载决策入口：

```
加载 av-evasion-orchestrator
```

它会按 **三层决策架构** 自动分析场景并推荐最优方案：

1. **攻击阶段路由** — 你在杀伤链的哪个环节？
2. **防御水平评估** — L1 (Defender) / L2 (第三方AV) / L3 (EDR) / L4 (硬化)
3. **方案推荐 + 路由子 Skill** — 给出具体技术选型，按需加载对应专项 Skill

## Skill 清单

| Skill | 定位 | 核心能力 |
|---|---|---|
| `av-evasion-orchestrator` | 免杀决策路由 | 场景分析 -> 方案推荐 -> 路由子技能，6 大场景矩阵 + 3 套组合拳 |
| `windows-av-evasion` | Windows AV/EDR 规避 | AMSI bypass、ETW bypass、.NET 内存加载、syscall/unhooking、签名规避、shellcode 执行 |
| `advanced-process-injection` | 高级进程注入 | PoolParty 8 变体、Threadless Injection、Module Stomping、Crystal Palace 组合链、Sleep Obfuscation |
| `byovd-kernel-evasion` | BYOVD 内核致盲 | 漏洞驱动加载、EDR 内核回调清除、PPL 绕过、7 驱动选型表 |
| `code-obfuscation-deobfuscation` | 代码混淆对抗 | 控制流平坦化、不透明谓词、SMC、VM 保护器、字符串加密 |
| `anti-debugging-techniques` | 反调试对抗 | PEB 检测、ptrace、时序检测、TLS 回调、VEH 技巧 |
| `binary-protection-bypass` | 二进制保护绕过 | ASLR/PIE/NX/RELRO/canary/FORTIFY 绕过 |

## 目录结构

```
skills/
├── av-evasion-orchestrator/
│   └── SKILL.md                 # 统一决策路由（入口）
├── windows-av-evasion/
│   ├── SKILL.md                 # AV/EDR 规避主文档
│   └── AMSI_BYPASS_TECHNIQUES.md
├── advanced-process-injection/
│   └── SKILL.md                 # 进程注入技术
├── byovd-kernel-evasion/
│   └── SKILL.md                 # BYOVD 内核致盲
├── code-obfuscation-deobfuscation/
│   └── SKILL.md                 # 代码混淆
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

_维护者: @light0921 · 最后更新: 2026-05-07_
