# MRID6 EC 电池养护模式（60%–80% 原生阈值）

> 给 **机械革命 蛟龙16 Pro / MRID6-23**（Insyde BIOS、ITE IT5570 EC、BM5235 电池）开启
> **EC 原生**的充电上限：插电只充到 80%，掉到 60% 才回充。一次配置，**无需常驻程序**。

[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey)](#)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](#)
[![EC](https://img.shields.io/badge/EC-ITE%20IT5570%200.38-informational)](#)
[![Risk](https://img.shields.io/badge/risk-high-red)](#-先读这个)

---

## ⚠️ 先读这个

这个项目会**直接读写你笔记本的嵌入式控制器（EC）**。做错了有可能让电池、充电器行为异常，
严重时需要断电或拆电池恢复。**请务必先读完 [`SAFETY.md`](SAFETY.md)。**

三条底线，任何情况下都不违反：

1. **永远不碰 `10/0C`** —— 那是主动放电 / LEARN，不是停充。
2. **SOC ≥ 80% 时不要启用 `10/0D`** —— 会触发固件的主动放电初始化分支（插着电却用电池掉电）。
3. **不要为了加载驱动去关闭 HVCI / 内存完整性 / 易受攻击驱动阻止列表**。被拦就停。

本项目**不分发** WinRing0 驱动二进制（见 [`SAFETY.md`](SAFETY.md#-为什么仓库里没有驱动文件)）。

---

## 它解决什么问题

机械革命的官方控制中心**没有**充电阈值功能，Windows / ACPI 也没有暴露这个接口。
但该机型的 EC 固件里**已经带了一套原生的充电阈值状态机**，只是没有对外入口。

本项目的做法是：通过 `0x10/0x0D` 这条已存在的固件邮箱命令，把 **80/60** 两个阈值写进 EC，
之后**由 EC 自己维护滞回**：

```
SOC < 60%   → 允许充电
SOC 到 80%  → 停止充电，保持（插电但不充不放）
60%–80%     → 维持当前状态
```

配置完成后**不需要任何常驻进程**，也不需要每次开机重跑。

### 实测效果

| | 启用前 | 启用后 |
|---|---|---|
| 插电过夜 | 一路充到 100% 并长期满电顶着 | 停在 ~80%（实测 76%–83% 区间） |
| 充电状态 | `charging=true`，`ChargeRate≈28–30 W` | `charging=false`，`ChargeRate=0` |
| 放电状态 | — | `discharging=false`，`DischargeRate=0`（电脑吃适配器） |
| 需要常驻程序 | — | **不需要** |

---

## 已验证的环境

| 项目 | 值 |
|---|---|
| 机型 | MECHREVO `Jiaolong Series MRID6` / 蛟龙16 Pro |
| 主板 | `MRId6-23` |
| BIOS | Insyde `MRID6_23_R_V38`（2024-07-31） |
| EC | ITE **IT5570**，固件 **0.38**（`0x8411 = 0x26`） |
| 电池 | BM5235 管理，`AEC616864` |
| OS | Windows 11 |

> 其他机型 / 其他 EC 版本**不要照搬**。本项目的寄存器地图是逐字节对比加实机验证得出的。

### 已验证到什么程度

| 项目 | 状态 |
|---|---|
| 只读寄存器地图（20 个地址） | ✅ 实机验证，多轮一致 |
| `10/0E` 停充 | ✅ 实机验证（EC 0.38） |
| `10/0F` 恢复 | ✅ 实机验证（逐字节还原） |
| `10/0D` 80/60 启用 | ✅ 实机验证，多次成功 |
| 配置后驱动卸载、无残留 | ✅ 每次均核实 |
| **跨 Windows 重启** | ✅ 保持（实测过一次） |
| **跨硬断电 / 长按电源键** | ❌ **会丢失**，需重新配置 |
| 睡眠 / 休眠 | ⚠️ 未系统验证 |
| 完整 60→80→60 循环 | ⚠️ 未跑完整循环 |
| 拔插 AC 后是否重入放电分支 | ⚠️ 静态分析认为会，未实机确认 |

---

## 工作原理（简述）

```
Windows 程序
   │  DeviceIoControl（我们自己的最小 transport）
   ▼
WinRing0 内核驱动  →  端口 0x62 / 0x66
   ▼
ITE IT5570 EC  →  扩展命令 0x92(读) / 0x93(写)  →  EC XRAM
   ▼
0x8150..0x8154 邮箱  →  固件原生阈值状态机
```

### 关键寄存器

| XRAM | 含义 |
|---|---|
| `0x8150` | 邮箱主命令：`0`=空闲，`0x10`=电池组命令 |
| `0x8151` | 子命令：`0x0D` 原生阈值 / `0x0E` 停充 / `0x0F` 恢复 |
| `0x8152` | 结果：`0x55` 表示处理函数返回（**不等于**子命令生效） |
| `0x8153` | 原生阈值上限（80 → `0x50`） |
| `0x8154` | 原生阈值下限（60 → `0x3C`） |
| `0x83C0` | 模式：`0x00` 正常 / `0x02` 停充 / `0x48` 原生阈值 |
| `0x83A0` | 原生子状态：`1` 初始化 / `2` 停充保持 / `3` 允许充电 |
| `0x83A1/0x83A2` | 阈值的副本（80/60） |
| `0x8370` | 调度状态：`0x32` 原生保持 / `0x31` 停充 / `0x04` 正常 |
| `0x837C/0x837D` | 固件"请求充电电流"缓冲（**不是实测电流**） |
| `0x8460` | 电源标志：bit0 AC、bit1 电池在位、bit2 充电、bit3 放电 |
| `0x847C` | EC 自己的 SOC 百分比 |

细节见 [`docs/01-hardware-and-registers.md`](docs/01-hardware-and-registers.md)。

---

## 快速开始

### 0. 准备

- Windows 10/11，**管理员权限**
- Python **3.10+**
- 能接受"临时加载一个内核驱动"（详见 SAFETY）

### 1. 部署驱动到受保护目录

```powershell
# 先取得驱动文件并校验（本项目不附带二进制）
python fetch_driver.py

# 部署 + 锁定 ACL（需要管理员）
powershell -ExecutionPolicy Bypass -Command "& .\windows\Install-EcGuard.ps1"
powershell -ExecutionPolicy Bypass -Command "& .\windows\ECGuard-Deploy.ps1"
```

> 驱动会被放到 `C:\ProgramData\ECGuard\driver`，ACL 设为
> `Authenticated Users = 读取执行`、`Administrators/SYSTEM = 完全控制`，
> 防止普通用户替换内核驱动。
>
> **注意**：`WinRing0x64.dll` 有个坑——它用 `GetModuleFileName(NULL, ...)` 找 `.sys`，
> 也就是**宿主 EXE 所在目录**，不是 DLL 目录。所以 `ECGuardBridge.exe`、`.dll`、`.sys`
> 必须放在**同一个目录**。`ECGuard-Deploy.ps1` 已经处理好了。

### 2. 只读巡检（**不要跳过**）

```powershell
. .\windows\ECGuard-Kernel.ps1   # 或在管理员 PowerShell 里：
.\windows\ECGuard-Kernel.ps1 -Action inspect
```

它会检查：EC 版本、平台是否 MRID6、邮箱是否空闲、模式是否已知、
EC 与 Windows 的 AC/SOC 是否一致、寄存器是否稳定。**任一项不过就不写。**

### 3. 启用 80/60

**先确认 SOC 在 60%–79%**（不要 ≥80%），然后：

```powershell
.\windows\ECGuard-Kernel.ps1 -Action enable
```

只写 4 个字节，严格按序：

```
0x8153 ← 0x50    上限 80
0x8154 ← 0x3C    下限 60
0x8151 ← 0x0D    原生阈值子命令
0x8150 ← 0x10    触发（必须最后）
```

### 4. 验证

```powershell
python tools\care_state_check.py
```

期望看到：

```
83C0 = 0x48   83A0 = 0x02   8370 = 0x32   83A1/83A2 = 80/60
charging=false   discharging=false   ChargeRate=0   DischargeRate=0
```

### 5. 想撤销

```powershell
.\windows\ECGuard-Kernel.ps1 -Action disable    # 提交 0x8151=0x0F, 0x8150=0x10
```

或直接**长按电源键硬断电**（不推荐，但这确实会清掉，因为 EC 会复位）。

---

## 命令参考

| 命令 | 作用 | 写 EC？ |
|---|---|---|
| `ECGuard-Kernel.ps1 -Action inspect` | 只读巡检 + 前置门 | ❌ |
| `ECGuard-Kernel.ps1 -Action verify` | 只读多轮采样 | ❌ |
| `ECGuard-Kernel.ps1 -Action enable` | 启用 80/60 | ✅ 4 字节 |
| `ECGuard-Kernel.ps1 -Action disable` | 恢复原厂策略 | ✅ 2 字节 |
| `ECGuard-Kernel.ps1 -Action guard` | 查看 guard / 审计账本 | ❌ |
| `python selftest.py` | 75 项硬件无关安全自检 | ❌ |

### 单独的验证工具

| 工具 | 用途 |
|---|---|
| `tools/care_state_check.py` | 快速看养护状态（只读，3 次采样） |
| `tools/telemetry_only.py` | 只看 Windows 侧电量/电源（**不需要管理员、不需要驱动**） |
| `tools/readonly_probe.py` | 首次 transport 打通验证（只读） |
| `tools/stop_resume_probe.py` | `10/0E` → `10/0F` 停充/恢复验证（**会写 EC**） |
| `tools/restore_probe.py` | 单独恢复（**会写 EC**） |
| `tools/soc_drop_investigate.py` | 排查电量异常变化 |

---

## 安全设计

这个项目的核心不是"能写 EC"，而是**在写之前、写之中、写之后都不失控**。

- **写入白名单**：只允许 6 个 `(地址, 值)` 组合，`0x0C` 永久拒绝，内部寄存器（`0x83C0`/`0x83A0`/`0x837C`…）**不可写**
- **分阶段授权**：每个工具只能用自己的写入子集（`PROFILE_0E_0F` / `PROFILE_0D`）
- **端口白名单**：只有 `0x62` / `0x66`，且只实现"读字节/写字节"两个能力
- **Poison 落盘**：任何超时/异常 → 写盘标记 → 后续写入一律拒绝，直到人工只读复核后显式清除
- **崩溃日志**：事务意图在**写第一个字节之前**落盘；进程被杀也会留下"在途"标记
- **不重试**：超时不 retry、不 flush、不补发恢复命令
- **不常驻**：不注册服务（除单次操作期间的 demand-start）、无计划任务、无开机自启
- **用完即卸**：`DeinitializeOls()` 在 `finally` 里，操作结束驱动即卸载

`python selftest.py` 覆盖 75 项，包括"`0x0C` 在所有 profile 下都被拒绝"、
"`0x8153=0x51`（81%）被拒绝"、"失败后不会补发触发"等。

---

## 已知限制 / 坑

1. **80% 不是精确 80%。** EC 判停用的是它自己的 SOC（`0x847C`），这个值会漂。
   实测会停在 **76%–83%** 之间。**它不是充到 100%**，只是精度有限。

2. **Windows 显示的百分比和 EC 的不是同一个数。** Windows 用容量寄存器算，
   EC 用自己的 `0x847C`。两者差 1–7 个点属正常，不要慌张。

3. **"电量掉了"可能是假象。** 停充静置后电量计会重算，数字可能上下跳。
   判断是否真放电要看 `0x8460` 标志位 + `DischargeRate` + **电压是否恒定**。

4. **硬断电会丢失配置。** 长按电源键 / 拔电清灰 → EC 复位 → 阈值没了，需要重新启用。
   正常重启**不会**丢。

5. **`0x8152 = 0x55` 不等于成功。** 它只表示处理函数返回了。
   必须联查 `0x83C0`、`0x83A0`、`0x83A1/0x83A2`。

6. **EC 状态机是异步的。** 邮箱立刻返回，但 `0x8370` / `0x837C` 要等下一个周期才更新。
   **不要用即时快照判失败**（这是本项目踩过的坑），要轮询等沉降。

更多见 [`docs/05-troubleshooting.md`](docs/05-troubleshooting.md)。

---

## 目录结构

```
.
├── README.md                  本文件
├── SAFETY.md                  ⚠️ 必读：风险、禁令、法律与安全
├── LICENSE                    MIT
├── selftest.py                75 项硬件无关自检
├── fetch_driver.py            取驱动并双重哈希校验（不附带二进制）
├── ecguard/                   Python 包
│   ├── profile.py             EC 0.38 profile、寄存器地图、写入白名单
│   ├── guard.py               Poison / 崩溃日志 / 审计账本
│   ├── transport.py           桥接客户端、互斥、指数退避
│   ├── winring0_dev.py        DeviceIoControl 直连内核驱动（不用 DLL）
│   ├── ec_write.py            受限写路径（0x0E/0x0F/0x0D）
│   ├── probe.py               只读门 + 启用前置门
│   └── cli.py                 inspect / verify / enable / disable
├── tools/                     独立探测工具
├── windows/                   PowerShell 包装 + C# 桥接源码
└── docs/                      硬件、固件、transport、验证历史、排障
```

---

## 参考

- 上游 EC 逆向与首次验证：[`Zcodeoooo/JiaoLong16Pro-Battery-threshold`](https://github.com/Zcodeoooo/JiaoLong16Pro-Battery-threshold)
- 同族 EC 寄存器地图：[`kzyha/jiaolong16-linux`](https://github.com/kzyha/jiaolong16-linux)
- OpenLibSys / WinRing0 源码与 IOCTL 定义：[`GermanAizek/WinRing0`](https://github.com/GermanAizek/WinRing0)

---

## License

代码以 **MIT** 发布，见 [`LICENSE`](LICENSE)。

**不含**任何厂商固件、厂商驱动或第三方二进制。
WinRing0 驱动需自行获取，其版权与许可归原作者（OpenLibSys.org / hiyohiyo）。

使用风险自负。本项目作者不对任何硬件损坏、数据丢失或保修失效负责。
