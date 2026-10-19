# 新手操作指南：从下载到撤销

[返回主页](../README.md) · [English guide](06-getting-started.en.md) · [安全说明](../SAFETY.md)

这份指南面向不会编程、不使用 AI 的用户。按顺序操作，每次只执行一个步骤；看到错误就停在当前步骤。
**教程降低操作门槛，不代表硬件风险降低，也不保证每台机器都能完成设置。**

## 1. 先判断自己的机器是否适合

本仓库记录的本项目实机环境是：

| 项目 | 记录值 |
|---|---|
| 机型 | 机械革命 蛟龙16 Pro / Jiaolong Series MRID6 |
| 主板 | MRId6-23 |
| BIOS | MRID6_23_R_V38，2024-07-31 |
| EC | ITE IT5570，0.38 |
| 电池 | BM5235 管理，AEC616864 |
| 系统 | Windows 11 |

按 `Win + R`，输入 `msinfo32`，回车，在“系统摘要”查看系统型号、主板产品和 BIOS 版本。
这里不一定显示 EC 版本；后续只读巡检会读取它。**不知道自己的 EC 版本时，不要猜测或尝试写入。**

代码也包含来自上游的 EC 0.40 profile；这不表示本项目在所有 0.40 机器上都做过实测。
Windows 10 是项目目标平台，但这里记录的本项目实机系统是 Windows 11。
机型、主板或固件不符时，不要跟着本指南运行 EC 命令，先看 [其他机型参考](07-other-mechrevo-models.md)。

开始前读完 [SAFETY.md](../SAFETY.md)。特别记住：

- 启用时 **EC 电量必须为 60%–79%**，并插好 AC 电源；Windows 百分比不能代替 EC 电量。
- 不关闭内存完整性、驱动阻止列表、Defender、签名检查或 Secure Boot 来加载驱动。
- 超时、poisoned、写入结果不明时不反复运行 `enable`，不删除 guard 文件。
- 不刷 BIOS，不改寄存器或白名单，不运行 `tools/` 下的写入探测脚本。

## 2. 下载并解压项目

1. 打开 [GitHub 仓库](https://github.com/kennedymike936-lang/mrid6-ec-battery-care)。
2. 点击绿色 **Code → Download ZIP**，或用 [源码 ZIP 链接](https://github.com/kennedymike936-lang/mrid6-ec-battery-care/archive/refs/heads/main.zip)。
3. 在资源管理器右键 ZIP，选择“全部解压”。**不要在压缩包窗口里运行文件。**
4. 找到同时包含 `README.md`、`fetch_driver.py`、`ecguard`、`windows` 的那一层文件夹。
5. 为方便跟随下面的命令，把这一层文件夹放到 C 盘并命名为 `ECGuardSource`。最终应能看到 `C:\ECGuardSource\README.md`，而不是多套了一层文件夹。

不需要安装 Git、GitHub Desktop 或注册 GitHub 账号。
如果选择其他位置，后面的 `C:\ECGuardSource` 必须改成你的实际路径。

## 3. 准备 Python

已有可用的 **64 位 Python 3.10 或更新版本**可以直接使用。
没有的话，到 [Python 官方 Windows 下载页](https://www.python.org/downloads/windows/) 安装正式版运行时；使用 Python install manager 时，按它的安装提示完成运行时配置。
如果使用带有 **Add python.exe to PATH** 选项的传统安装器，勾选该选项。
安装后关闭旧终端，再重新打开。

本项目使用 Python 标准库，正常使用不需要 `pip install`，也不需要 Node.js、AI 或 Visual Studio。
C# 桥接由部署脚本调用系统中的 .NET Framework C# 编译器生成；缺少编译器时见后面的排障。

## 4. 打开管理员 Windows PowerShell

1. 打开开始菜单，搜索 **Windows PowerShell**。
2. 右键选择“以管理员身份运行”，在 UAC 窗口确认。
3. 应看到带“管理员”字样的终端窗口。不要在 Python 的 `>>>` 窗口或 CMD 中粘贴下面的 PowerShell 命令。
4. 一次复制一个代码框，按回车执行；不要复制代码框边框或 `PS C:\...>` 这样的提示符。

进入项目目录：

```powershell
Set-Location -LiteralPath 'C:\ECGuardSource'
```

确认位置正确：

```powershell
Get-Item .\README.md, .\fetch_driver.py, .\windows\ECGuard-Kernel.ps1
```

应列出这三个文件。若报“找不到路径”，回到第 2 步检查解压层级。

确认 Python 可运行：

```powershell
python --version
```

应显示 Python 3.10 或更新版本。如果命令找不到或打开商店，先解决 Python 安装问题。
如果 `python` 不可用、但 `py -3 --version` 可用，下一条里的 `python` 可以换成 `py -3`。

固定后续使用的解释器：

```powershell
$env:ECGUARD_PYTHON = (python -c "import sys; print(sys.executable)").Trim()
```

查看版本和位数：

```powershell
& $env:ECGUARD_PYTHON -c "import sys, struct; print(sys.version); print('bits:', struct.calcsize('P') * 8)"
```

需要 Python 3.10+ 和 `bits: 64`。本窗口中的环境变量会传给后续脚本；新开窗口需要重新进入目录并设置解释器。

## 5. 下载驱动并部署

**这一步需要联网。** 仓库不附带驱动。脚本从上游 GitHub 仓库下载两个文件，而非从厂商官方网站下载；具体来源和固定哈希在 `fetch_driver.py` 中。
哈希匹配只说明文件与预期一致，**不代表 WinRing0 没有漏洞或一定能被 Windows 允许加载**。

下载并校验：

```powershell
& $env:ECGUARD_PYTHON .\fetch_driver.py
```

两个文件的 `sha256`、`git blob` 都应显示 `MATCH`，最后显示 `driver files verified`。
若出现 `MISMATCH`、`DRIVER VERIFICATION FAILED`、404 或网络异常，停在这里；不要改哈希或换来路不明的文件。

部署驱动和受保护的状态目录：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\Install-EcGuard.ps1
```

成功后会显示 `Driver deployed` 和目录信息。只有这一步成功才继续：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\ECGuard-Deploy.ps1
```

应显示桥接编译/部署结果，三个必需文件均为 `OK`：

```text
C:\ProgramData\ECGuard\driver\ECGuardBridge.exe
C:\ProgramData\ECGuard\driver\WinRing0x64.dll
C:\ProgramData\ECGuard\driver\WinRing0x64.sys
```

此时只是部署文件，尚未启用养护。不要单独双击桥接程序。
这里的 `-ExecutionPolicy Bypass` 仅针对该次 PowerShell 子进程的脚本执行策略，不修改系统长期策略；它不绕过驱动签名、HVCI 或驱动阻止列表。
如果组织策略禁止脚本执行，联系管理员，不要继续尝试绕过。

## 6. 插电并做只读巡检

先保存工作，关闭其他硬件监测/调参工具和可能访问 EC 的厂商控制中心，避免并发访问。
不要在系统更新、睡眠恢复或电源状态切换时操作。连接适配器，保持电源连接稳定。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\ECGuard-Kernel.ps1 -Action inspect
```

此命令不修改 EC 配置，但会临时加载驱动、访问 EC；“只读”不等于没有驱动风险。
输出是逐行 JSON。找到：

```json
{"event":"readonly_gate","pass":true,"poisoned":false}
```

这是关键字段示意，真实行还有时间、版本、电量和模式。
必须是 `pass: true`、`poisoned: false`，各项致命检查均通过，且最后 `exit code: 0`。
如果不符，不进行下一步。巡检通过只表示代码中的检查通过，不保证硬件完全兼容。

查看 `soc`（EC 电量）和 `windows` 行中的 Windows 电量。启用要求 EC 电量 60–79，二者差值不超过 5 个百分点。
Windows 显示 75% 不代表 EC 一定低于 80%。

- 电量太高：本次命令结束后拔电正常使用，等降到目标范围再插电、重新巡检；不要在命令执行中拔插电源。
- 电量太低：先正常充到范围内，再巡检。
- 已有 `mode: 72`：说明 EC 已处于原生养护模式，跳到第 8 步查看，不再启用一次。
- 常规首次设置应为 `mode: 0`；`mode: 2` 是停充模式，虽然代码允许启用，但不应在不清楚其来由时继续。

## 7. 启用固定 60%–80% 养护

**这是写入 EC 的步骤。** 确认巡检通过、电量符合、已插电，并已知道第 9 步如何恢复。
阈值固定为低 60、高 80，本指南不提供自定义阈值。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\ECGuard-Kernel.ps1 -Action enable
```

等命令自然结束，不中途关窗口、休眠或拔插电源。
正常输出包含 `verification`，其中 `mailbox_result_ok`、`mode_is_native`、`native_copies_match` 均为 `true`，`bytes_written` 为 4，退出码为 0。
接着做下一步只读观察。**不要因为暂时还在充电而再运行一次 enable。**

任何失败、`abort`、`poisoned` 或非零退出码：停止写入，按第 10 步处理。

## 8. 确认是否生效

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\ECGuard-Kernel.ps1 -Action verify
```

默认采样 5 次，间隔 10 秒，采样间等待合计约 40 秒，另有读取耗时。
**此命令退出码 0 仅说明读取结束；不会自动判断养护成功。** 在 `verify_sample` 的 `ec` 对象中看这些字段：

| 字段 | 含义 / 期望 |
|---|---|
| `mode: 72` | 十六进制 `0x48`，原生养护模式 |
| `native_high: 80`、`native_low: 60` | 阈值副本正确 |
| `mailbox_command: 0` | 邮箱空闲 |
| `native_substate: 3` | 允许充电，刚启用后仍充电可能正常 |
| `native_substate: 2` | 停充保持 |
| `state: 50` | 十六进制 `0x32`，停充保持时的典型调度状态 |
| `charging: false`、`discharging: false` | EC 表示不充不放，停充保持时应观察到 |

`raw` 对象里的字符串按十六进制显示，例如 `"83C0":"48"`；普通数值字段按十进制显示。
`mailbox_result: 85` 是 `0x55`，只表示处理函数返回，不能单独证明成功。

若电量尚未到上限，原生模式继续充电不代表失败；到上限附近后才应进入保持。
仓库历史记录中的 Windows 停充读数约为 76%–83%，不是精确 80% 的承诺。
用 `cim.batteries` 中的 `PowerOnline`、`Charging`、`Discharging`、`ChargeRate` 和 `DischargeRate` 交叉观察；Windows 上报可能滞后。
若 `cim.available: false`、没有电池数据或读数是未知值，不能把缺失数据当作 0，更不能断言“不放电”。

也可只读取 Windows 遥测，不加载 EC 驱动：

```powershell
& $env:ECGUARD_PYTHON .\tools\telemetry_only.py
```

此命令不含 EC 模式，不能单独证明阈值已设置。
生效后可关闭终端，不需要常驻程序或设置开机任务。保留源码，便于以后撤销和排查。
正常重启曾验证保留一次；硬断电会丢配置。睡眠/休眠、完整循环、AC 拔插仍有未验证项，见主页。

## 9. 撤销，恢复原厂充电策略

重新打开管理员 PowerShell 时，先按第 4 步进入目录并固定 Python。运行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\ECGuard-Kernel.ps1 -Action disable
```

这会写入恢复命令，也可能因 guard 阻止而拒绝。完成后再运行第 8 步的 `verify`，确认 `ec.mode` 回到 `0`。
`disable` 的退出码 0 不能代替这个状态检查。恢复后允许按原厂策略充到 100%。
**删除源码、驱动文件或卸载 Python 都不会撤销 EC 中已有的配置。** 先恢复再考虑清理文件；排障期间保留 `C:\ProgramData\ECGuard\state` 中的记录。
普通重启不等于 EC 复位，不能作为可靠的撤销方式。

## 10. 常见问题

| 看到的提示 / 现象 | 怎么处理 |
|---|---|
| 找不到 `python` / 打开商店 | 完成 Python 安装，重新开终端；能用 `py -3` 时按第 4 步替换一次解释器发现命令 |
| `This wrapper must run elevated` / `must run elevated` | 用“以管理员身份运行”的 Windows PowerShell |
| 找不到 `.ps1` / `fetch_driver.py` | 检查是否进入含 README 的仓库根目录，而非 ZIP 或外层目录 |
| 下载失败、404、哈希不匹配 | 停在下载步骤；网络问题解决前不部署，不改校验值 |
| `bridge not built` / `csc failed` | 部署需要 `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`；通过 Windows 官方维护方式修复/启用 .NET Framework，保存错误信息，勿下载陌生 EXE 替代 |
| `status=3` / 缺少驱动文件 | 核对第 5 步三个文件是否同在受保护目录，部署是否完整；不要手动复制到 System32 |
| Windows 安全中心阻止、签名错误、`status=2` | 停止使用；不关闭系统保护。`status=2` 不足以独自确定原因 |
| `bridge exited unexpectedly` / `bridge did not become ready` | 保存完整错误；可能有多种原因，不凭这一句认定安全策略有问题，不改保护设置 |
| `platform_is_mrid6` / `ec_version_accepted` 失败 | 不兼容或证据不足，停止；不修改 profile 或机型检查 |
| `soc_consistent` 失败 | 差值超过 5 个百分点或读数缺失；不提高容差来强行通过 |
| `soc_gate` / `soc_in_target_band` 失败 | 本次命令结束后按第 6 步正常充放电至范围内，不用 LEARN 主动放电 |
| `registers_stable` / `mailbox_idle` 失败 | 停止，不反复尝试写入；保存输出以便分析并发/状态问题 |
| 退出码 2 | 前置检查失败或未满足条件；看具体 `check` / `abort` |
| 退出码 3 | 提交后的即时验证未满足条件；不要重试写入，先只读查看状态 |
| 退出码 4 / `poisoned` / 超时 | 状态不确定，停止写入，保留日志，只读复核 |
| 退出码 5 / 6 | transport 错误 / 拒绝操作；根据具体错误停止并排查，不当作可忽略提示 |
| 百分比稍微下降 | 不能只据百分比认定放电；结合 EC 标志、CIM 功率和多次电压/容量读数 |
| 插电持续真实放电、充电异常 | 若无超时/不确定事务且 guard 允许，可执行一次 `disable`；若被拒绝或无效，不绕过，保存工作、停止实验并按安全说明处理 |
| 风扇/电源明显异常、系统失去响应 | 以硬件安全为先；按厂商的关机/EC 复位指引处理。强制关机有丢数据风险，不能把拔掉适配器等同于内置电池也已断电；不熟悉拆机时联系售后 |

### Guard 被锁住怎么办？

先查看记录（不写 EC）：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\ECGuard-Kernel.ps1 -Action guard
```

再运行第 6 步 `inspect`。**只有全部只读检查通过，且人工确认当前状态合理、异常原因已经排除，才考虑下面的显式清除。**
不理解输出就停在这里，在 Issues 求助；不必借助 AI，更不应靠猜测清锁。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\ECGuard-Kernel.ps1 -Action inspect -ClearGuardAfterInspection
```

这不写 EC 配置，但会修改磁盘 guard 状态。应看到 `guard_cleared`；没有这条不能当作清除成功。
清除不会恢复原厂模式，也不代表应当重新启用。完整事务历史仍可能需要人工分析。
不要删除 `state.json`、编辑其内容或换状态目录逃过保护。

## 11. 不会判断时如何求助

打开 [仓库 Issues](https://github.com/kennedymike936-lang/mrid6-ec-battery-care/issues)，新建问题，附上：

- 机型、主板产品、BIOS 版本，Windows 和 Python 版本。
- 执行到第几步、完整命令、错误文字和退出码。
- 若已成功读取，提供 `readonly_gate` / `verify_sample` 的相关输出。
- 写入是否开始、是否出现超时/poisoned，以及目前插电/充电行为。

发布前遮盖用户名、机器名、电池序列号、`InstanceName`、本地个人路径等信息。
不要上传驱动、固件、原始 dump 或未经检查的整个日志目录。
没有人必须回复，也不要把问题回复当作官方兼容认证。

## 官方操作参考

- [GitHub：下载仓库文件](https://docs.github.com/en/repositories/working-with-files/using-files/downloading-files-from-github)
- [Python：Windows 安装与使用](https://docs.python.org/3/using/windows.html)
- [Microsoft：PowerShell 执行策略与进程作用域](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
