# 其他机械革命机型：可参考的方法与适用边界

[中文主页](../README.md) · [English README](../README.en.md) · [English below](#english)

## 可以参考，不等于直接兼容

本项目可以给其他机械革命机型的充电阈值研究提供参考。价值主要在于：确认固件是否已有原生策略、建立命令与状态之间的证据链，以及把不确定状态下的写入挡住。

**目前不能据此宣称“机械革命全系支持”。** 品牌、外观、产品名相同，不代表主板、EC 芯片、固件版本、电池管理和端口协议相同。
即便同样使用 ITE EC，也不能推定 `0x8150` 邮箱或 `10/0D` 命令含义一致。
当前本项目实机记录集中在 MRID6-23 / IT5570 / EC 0.38；代码包含的上游 0.40 依据与本项目本地实测应分别看待。

| 可以借鉴 | 不能直接复制 |
|---|---|
| 优先寻找厂商已有的充电阈值入口或固件原生策略 | MRID6 的寄存器地址、命令字、参数顺序 |
| 将固件分析与精确硬件/版本对应起来 | 仅凭同品牌、同 EC 厂商或相似型号就启用 |
| EC 状态与 Windows 电池遥测交叉判断 | 用单个结果字节或 Windows 百分比认定成功 |
| 先只读、后写入；限制允许的写入组合 | 关闭机型/版本/SOC 检查以适配新机器 |
| 事务前记录意图、异常后拒绝继续写入 | 超时后自动重试或“补一条恢复命令” |
| 等待异步状态变化并记录失败与未验证项 | 照抄 60/80 阈值就认定主动放电风险已排除 |

## 普通用户可以先做什么

这些步骤不需要下载或运行 EC 工具：

1. 检查该机型的官方控制中心、BIOS 设置和说明书是否已经提供电池养护/充电上限功能；有官方入口时优先使用。
2. 在 `msinfo32` 记录精确系统型号、主板产品和 BIOS 版本；不知道 EC 版本可以写“未知”，不必为了补全信息运行低层探测。
3. 记录 Windows 版本、期望的充电上限、是否有官方功能以及目前的充电行为。
4. 在 [Issues](https://github.com/kennedymike936-lang/mrid6-ec-battery-care/issues) 提出兼容性研究请求。不要因为名称相似就先运行本项目的巡检或写入工具。

可复制这个模板；不要填写序列号或机器唯一标识：

```text
请求研究其他机械革命机型（不是已支持声明）
机型：
主板产品：
BIOS 版本：
EC 版本：未知 / 已知来源
Windows 版本：
官方充电阈值功能：有 / 无 / 不确定
希望实现的行为：
是否运行过 EC 工具：没有 / 如运行过，请说明工具和结果
```

Issues 不保证有人能适配。没有经过对应硬件/固件分析与验证前，不能给出可运行的写入命令。

## 对新机型开展研究时需要补足的证据

这是一份研究范围说明，**不是让用户现在对未知硬件执行探测或写入的操作步骤**。

- 确定对应主板、EC 和固件版本，区分文件静态分析、上游实测、本项目本地实测。
- 从该硬件的合法可用资料中确认访问协议、命令语义和状态机，不能从本项目地址直接外推。
- 重新确定允许读取/写入的范围、阈值前提、失败状态及恢复途径。
- 保留现有保护思路，但为新硬件建立独立、明确的 profile；不能简单添加型号字符串放行。
- 说明验证覆盖：启用、上限停充、低位回充、撤销、重启、睡眠、AC 切换、驱动清理；没有测过的明确写“未验证”。

在这些证据齐备之前，“能参考”始终只表示思路和设计可借鉴。

## English

### A reference for other MECHREVO models, not universal support

Other MECHREVO laptops can use this project as a reference for researching native charge thresholds. Its reusable contributions include establishing firmware evidence, correlating controller state with battery telemetry, restricting writes, journaling intent, and stopping when the state is uncertain.

**This is not an all-model MECHREVO utility.** The same brand, product name, appearance, or EC vendor does not establish compatible boards, firmware, batteries, protocols, register maps, or mailbox semantics. An ITE EC alone does not establish that `0x8150` or `10/0D` means the same thing.

Local project hardware records concern MRID6-23 / IT5570 / EC 0.38. The profile's upstream evidence for 0.40 is a separate evidence source, not local testing of all configurations.

| Reusable research ideas | Hardware-specific assumptions that must not be copied |
|---|---|
| Look for an official threshold feature or native firmware policy first | MRID6 addresses, subcommands, parameters, or transaction order |
| Tie each conclusion to exact hardware and firmware | Compatibility inferred from brand/model resemblance |
| Correlate EC state and Windows battery telemetry | Success inferred from one return byte or displayed percentage |
| Restrict access and inspect before writing | Removing platform/version/SOC gates to force support |
| Journal transactions and stop on uncertainty | Automatic retries or recovery writes after a timeout |
| Document asynchronous settling and untested cases | Assuming 60/80 eliminates a different firmware's discharge risk |

### What ordinary users can do first

No EC tool is needed for these steps:

1. Check the exact model's official control center, BIOS settings, and manual for an existing battery-care feature. Prefer an official supported interface where available.
2. Use `msinfo32` to record the system model, baseboard product, and BIOS version. Leave EC version as unknown if it is not available through ordinary information sources.
3. Record Windows version, desired charging behavior, any official feature, and current behavior.
4. Open a [compatibility research issue](https://github.com/kennedymike936-lang/mrid6-ec-battery-care/issues). Do not run this project's low-level inspection or write tools first just because the laptop name looks similar.

```text
Research request for another MECHREVO model (not a support claim)
Model:
Baseboard product:
BIOS version:
EC version: unknown / known source
Windows version:
Official charging-threshold feature: yes / no / unsure
Desired behavior:
Any previous EC tool use: none / describe tool and outcome
```

Do not include serial numbers or unique machine identifiers. An issue does not guarantee that someone can add support.

### Evidence needed for a new hardware profile

This describes research requirements, **not a procedure to probe or write an unknown laptop now**:

- Establish the exact board, EC, and firmware; distinguish static analysis, upstream observations, and local hardware tests.
- Determine protocol, command semantics, and state machine from legitimately available material for that hardware.
- Define allowed accesses, threshold preconditions, failure handling, and recovery independently.
- Create a separate documented profile after establishing evidence; adding a model-name string or removing a gate is not sufficient.
- Record coverage for enable, upper stop, lower resume, restore, restart, sleep, AC transitions, and cleanup. Mark anything untested explicitly.

Until that evidence exists, “reference” means the method and design can inform research, not that these commands are ready to run.
