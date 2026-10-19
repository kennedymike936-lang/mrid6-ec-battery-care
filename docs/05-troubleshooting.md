# 05 · 排障 / 踩坑记录

> 每一条都是实际踩到过的。按症状查。

---

## A. 驱动与 transport

### A1. `WinRing0 DLL status=3`，`InitializeOls() -> 0`

**不是**签名问题，**不是**安全策略，**不是**驱动没装。

WinRing0 DLL 用 `GetModuleFileName(NULL, ...)` 找 `.sys` —— 那是**宿主 EXE 的目录**，
不是 DLL 的目录。找不到就返回 `OLS_DLL_DRIVER_NOT_FOUND (3)`。

**修**：把 `bridge.exe`、`WinRing0x64.dll`、`WinRing0x64.sys` 放**同一个目录**。

**没用的做法**：把 `.sys` 丢进 `System32\drivers` —— DLL 根本不看那里。

### A2. `GetDllStatus` 返回值含义

| 值 | 含义 |
|---|---|
| `0` | 正常 |
| `1` | 平台不支持 |
| `2` | 驱动未加载 |
| `3` | **驱动文件未找到**（看 A1） |
| `4` | 驱动已卸载 |
| `5` | 网络驱动器上不加载 |
| `10–14` | `ManageDriver` 的 SCM 错误 |

### A3. 调用 `GetDllVersion()` 直接崩（access violation）

那份 DLL 的 ABI 与常见声明不一致。**别调它**。
需要驱动版本就用 IOCTL `IOCTL_OLS_GET_DRIVER_VERSION`（`0x9C402000`）走 `DeviceIoControl`。

本仓库的直接 `DeviceIoControl` 研究工具可绕开 DLL；但主流程 `ECGuard-Kernel.ps1` 使用 C# 桥接，仍会调用 DLL 的 `InitializeOls()`。两条 transport 路径不要混为一谈。

### A4. `DeviceIoControl` 返回失败，错误 87（参数错误）

IOCTL 值算错了。最常见的错：**漏了 access 位**。

```
错：0x9C4020CC   (assume FILE_ANY_ACCESS)
对：0x9C4060CC   READ_IO_PORT_BYTE  (FILE_READ_ACCESS << 14)
对：0x9C40A0D8   WRITE_IO_PORT_BYTE (FILE_WRITE_ACCESS << 14)
```

### A5. `CreateFile("\\.\WinRing0_1_2_0")` 失败，错误 161

错误 161 = `ERROR_BAD_PATHNAME` / 设备不存在 → **驱动没加载**。
先确认 `sc query <name>` 是 `RUNNING`。

### A6. `sc start` 失败

**如果这是签名/阻止列表拒绝，就停。** 不要为此关闭 HVCI、内存完整性、
易受攻击驱动阻止列表、DSE 或 Secure Boot。见 [`SAFETY.md`](../SAFETY.md#-为了加载驱动而关闭安全机制)。

---

## B. EC 判读

### B1. `0x8152 = 0x55` 但功能没生效

`0x55` 只表示**邮箱处理函数返回了**，不表示子命令真的执行成功。
未知子命令也可能返回 `0x55`。

**必须联查**：`0x83C0`（模式）、`0x8370`（调度）、`0x83A0`（原生子状态）、
`0x83A1/0x83A2`（阈值副本）、`0x837C/0x837D`（请求电流）。

### B2. 写完立刻检查，"没生效"，判定失败 —— **假阴性**

EC 状态机是**异步**的：

| 寄存器 | 更新时机 |
|---|---|
| `0x83C0` / `0x8152` | 立即 |
| `0x8370` | 下一个周期 |
| `0x837C/0x837D` | 更晚 |
| 充电器实际动作 | 更晚（SMBus） |

**不要用即时快照判失败。** 用"硬判据立即 + 沉降轮询"：

```python
# 硬判据：立即可信
if mode != 0x02 or mailbox_result != 0x55: 失败

# 沉降判据：轮询最多 12 秒
while not settled and now < deadline:
    settled = requested_current_zero and not charging and not discharging
```

本项目在 `0x0E` 和 `0x0D` 上都**因为没等沉降而误判失败过**。

### B3. EC 说 79%，Windows 说 76% —— 谁对？

**两个都对，它们是不同的数字。**

| 数字 | 来源 |
|---|---|
| `0x847C` | EC 自己的 SOC |
| Windows 百分比 | 用容量寄存器（`0x8464/0x8468/0x846E`）算的 |

差 1–7 个点属正常。**不要试图让它们相等。**

### B4. "电量在掉，是不是在放电？" —— 怎么判断

**看这三个，不要看百分比**：

| 证据 | 放电 | 静置（正常养护） |
|---|---|---|
| `0x8460` bit3 | 1 | 0 |
| `DischargeRate` | > 0 | 0 |
| **电压** | **下降** | **恒定** |
| `RemainingCapacity` | 持续下降 | 冻结 |

实测静置样例（51 秒 / 6 次）：

```
EC charging=false  discharging=false
ChargeRate=0  DischargeRate=0
Voltage = 15400 ×6      ← 恒定 → 没有电流
RemainingCapacity = 39140 ×6  ← 冻结
```

**如果百分比变了但上面四项没变，那是电量计重算，不是放电。**

### B5. 养护模式停在哪？

**实测 76%–83%**，不是精确 80%。

EC 用自己会漂的 SOC 判断，精度受电量计限制。
重点是：**不会充到 100%**，且停下来之后**真的不充不放**。

---

## C. Guard / 状态文件

### C1. `Refusing to write: a previous EC transaction did not complete cleanly`

Poison 生效了。说明之前有事务超时/异常。

**处理**：
1. 跑只读巡检，确认 `0x8150` 空闲、`0x83C0` 是已知模式
2. 确认无误后显式清除：

```powershell
python -m ecguard.cli inspect --clear-guard-after-inspection
```

### C2. `Refusing to write: a transaction is marked in-flight`

有**陈旧的崩溃日志**（进程被杀死时留下的）。

早期版本 `clear_poison()` 只清 `poisoned` 不清 journal，会导致**永久堵死**。
现在 `--clear-guard-after-inspection` 会**同时丢弃陈旧 journal**，并把丢弃记录
归档到 `state.json` 的 `transaction_history`。

### C3. 状态文件在哪

```
C:\ProgramData\ECGuard\state\state.json    ← poison / journal / 清除历史
C:\ProgramData\ECGuard\state\ledger.jsonl  ← 审计账本（每次写入）
```

查看：`ECGuard-Kernel.ps1 -Action guard`

---

## D. 配置丢失

### D1. 过了一夜/重启后阈值没了

| 场景 | 保留？ |
|---|---|
| 正常 Windows 重启 | ✅ 会保留 |
| **长按电源键 / 拔电 / 硬断电** | ❌ **丢失** |
| 清灰、拆机 | ❌ 丢失（会断电） |

硬断电会触发 **EC 硬件复位**，阈值被清空，充电回原厂行为。

**修**：等 SOC 落到 60–79%，重新跑 `-Action enable`。

### D2. 启用后电量还是涨到 83%

正常。见 B5。只要 `0x83C0=0x48` 且充电已停，就没有失控。

### D3. SOC ≥ 80% 想启用，被拒绝

**这是保护，不是 bug。** SOC ≥ 80% 会命中固件的主动放电初始化分支。

**修**：拔电正常用到 60–79%，再插电启用。**不要绕过这个检查。**

---

## E. 环境 / 工具链

### E1. `python` 找不到 / 版本太老

需要 **Python 3.10+**。

```powershell
$env:ECGUARD_PYTHON = 'C:\Path\To\python.exe'
```

`windows/Resolve-Python.ps1` 会依次找：`ECGUARD_PYTHON` → PATH → `py -3` → 常见安装目录。

### E2. `ModuleNotFoundError: No module named 'ecguard'`

需要把**仓库根目录**放进 `PYTHONPATH`：

```powershell
$env:PYTHONPATH = (Get-Location).Path
```

`windows/*.ps1` 已经设好。

### E3. `Start-Process -Verb RunAs` 配 `-File` 立刻退出码 1

实测 `-ArgumentList '-File',<path>` 会**静默失败**（无输出）。
改用 `-Command "& '<path>'"`：

```powershell
Start-Process powershell -Verb RunAs -Wait -ArgumentList `
  '-NoProfile','-ExecutionPolicy','Bypass','-Command',"& 'C:\path\to\script.ps1'"
```

### E4. PowerShell 输出中文乱码

提权进程无法被调用方重定向流，且 `sc.exe` 用 OEM 代码页输出。

- 脚本内部用 `Start-Transcript` 自己记日志
- 读文件时 **`Get-Content` 默认按 ANSI 解码** → UTF-8 中文会显示成乱码。
  这是**显示问题**，文件没坏。用 `Get-Content -Encoding UTF8` 或直接用编辑器看。

### E5. 二进制里搜地址/设备名搜不到

**地址**不是以 ASCII `"8150"` 存的，是 `MOV DPTR,#0x8150` 的立即数 `90 81 50`。

**设备/驱动名**是 **UTF-16LE** 存的，用 ASCII 搜会全部落空：

```python
# 正确
needle = "WinRing0_1_2_0".encode("utf-16-le")
dll.find(needle)      # -> 命中
dll.find(b"WinRing0_1_2_0")   # -> -1
```

### E6. `sc.exe` 输出解码时 UnicodeDecodeError

`sc.exe` 按 OEM 代码页输出。用：

```python
proc.run(["sc.exe", ...], capture_output=True)      # 不要 text=True
out.decode("utf-8", errors="replace")
```

---

## F. 已知的非问题（看到别慌）

| 现象 | 说明 |
|---|---|
| EC SOC 与 Windows % 差几个点 | 两个不同来源，正常 |
| 停充后百分比小幅回落 | 电量计重算 |
| `0x8394` = `0x44` / `0x8395` = `0x04` | 原生模式下的正常辅助状态 |
| `83A0` 从 `0` 变 `2` | 初始化 → 停充保持 |
| Windows `Charging` 标志滞后 | 电池类驱动上报延迟，可滞后数分钟 |
| `ChargeRate` 显示非 0 但 EC 已停充 | 同上，上报滞后 |
