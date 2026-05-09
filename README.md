# 免杀技术 Skill 体系

> 面向实战的免杀知识库 — 7 个专项 Skill + 1 个统一决策路由入口，覆盖用户态到内核态的完整免杀技术栈。

## v2.0 更新 (2026-05-09)

**结构重构**: 借鉴 bypassav-skills 的 `SKILL.md + references/` 模式，将两个最大的 skill 文件拆分：

| Skill | v1.1 | v2.0 | 变化 |
|---|---|---|---|
| windows-av-evasion | 683行单文件 | 183行入口 + 7个references/ | 683→804行（含新增静态规避+沙箱对抗） |
| code-obfuscation | 680行单文件 | 166行入口 + 5个references/ | 680→654行（攻防分离） |
| orchestrator | 439行 | 530行 | +91行（新增六层技术叠加器） |

**新增模块**（从 bypassav-skills 借鉴）:
- `references/static-evasion.md` — 熵值控制、导入表稀释、版本信息伪装、函数名混淆
- `references/sandbox-evasion.md` — 沙箱路径检测、行为延迟、QVM 对抗、无害活动模拟

**新增决策模式**: orchestrator §12「技术叠加器」— 六层架构支持灵活按需组合，替代纯固定方案

## 架构

```
av-evasion-orchestrator (统一决策入口 · 530行)
│
├── 用户态免杀
│   ├── windows-av-evasion (183行入口 + 7个references)
│   │   └── references/  amsi-bypass | etw-bypass | ntdll-unhook | syscall-proxy
│   │                    shellcode-execution | static-evasion | sandbox-evasion
│   ├── advanced-process-injection (296行)
│   │   PoolParty · Threadless · Module Stomping · Sleep Obfuscation
│   └── code-obfuscation-deobfuscation (166行入口 + 5个references)
│       └── references/  junk-code | smc | cff | movfuscator-vmprotect | compiler-obfuscation
│
├── 内核态免杀
│   └── byovd-kernel-evasion (342行)
│       BYOVD驱动 · EDR回调清除 · PPL绕过 · Sysmon/Sigma检测规则
│
└── 逆向对抗
    ├── anti-debugging-techniques (407行)
    └── binary-protection-bypass (295行)
```

## 使用方式

做免杀时，只需加载决策入口：

```
加载 av-evasion-orchestrator
```

### 三层决策 + 技术叠加器

1. **攻击阶段路由** — 你在杀伤链的哪个环节？
2. **防御水平评估** — L1 (Defender) / L2 (第三方AV) / L3 (EDR) / L4 (硬化)
3. **EDR 差异化分析** — CrowdStrike / SentinelOne / Defender / 卡巴斯基
4. **方案推荐** — 预设组合拳（轻量/标准/重装）或 §12 技术叠加器灵活定制
5. **路由子 Skill** — 按需加载对应专项 Skill

## Skill 清单

| Skill | 定位 | 核心能力 |
|---|---|---|
| `av-evasion-orchestrator` | 免杀决策路由 | 三层决策、EDR差异化矩阵、Win11 24H2适配、C2框架附录、**六层技术叠加器** |
| `windows-av-evasion` | Windows AV/EDR规避 | C语言AMSI patch、ETW Provider级绕过、Fresh ntdll copy、**熵值控制、沙箱对抗** |
| `advanced-process-injection` | 高级进程注入 | PoolParty 8变体、Threadless Injection、Module Stomping、Sleep Obfuscation |
| `byovd-kernel-evasion` | BYOVD内核致盲 | 驱动加载、EDR回调清除、PPL绕过、7驱动选型表、Sysmon/Sigma检测规则 |
| `code-obfuscation-deobfuscation` | 代码混淆（攻+防） | OLLVM编译配置、ConfuserEx模板、字符串加密、IAT隐藏、CFF/VMP逆向分析 |
| `anti-debugging-techniques` | 反调试对抗 | PEB/ptrace/时序/TLS回调/VEH检测与绕过 |
| `binary-protection-bypass` | 二进制保护绕过 | ASLR/PIE/NX/RELRO/canary/CET/MTE绕过 |

## 目录结构

```
skills/
├── av-evasion-orchestrator/SKILL.md
├── windows-av-evasion/
│   ├── SKILL.md
│   ├── AMSI_BYPASS_TECHNIQUES.md
│   └── references/          # 7个技术参考文件
├── advanced-process-injection/SKILL.md
├── byovd-kernel-evasion/SKILL.md
├── code-obfuscation-deobfuscation/
│   ├── SKILL.md
│   └── references/          # 5个技术参考文件
├── anti-debugging-techniques/
│   ├── SKILL.md
│   └── ANTI_DEBUG_MATRIX.md
├── binary-protection-bypass/
│   ├── SKILL.md
│   └── PROTECTION_BYPASS_MATRIX.md
└── README.md
```

## v1.1 更新 (2026-05-07)

第三方评测驱动的增强（+908行）：

- **windows-av-evasion** (+382行) — C语言AMSI patch / ETW Provider绕过 / Fresh ntdll copy
- **av-evasion-orchestrator** (+119行) — 四大EDR差异化矩阵 / Win11 24H2影响 / C2框架附录
- **code-obfuscation-deobfuscation** (+288行) — OLLVM编译配置 / ConfuserEx模板 / 字符串加密+IAT隐藏
- **byovd-kernel-evasion** (+119行) — Sysmon XML + Sigma YAML规则 / EDR告警配置

---

_维护者: @light0921 · 最后更新: 2026-05-09 · v2.0_
