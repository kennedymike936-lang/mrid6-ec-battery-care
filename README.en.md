# MRID6 EC battery care: native 60%–80% thresholds

[中文](README.md) | **English**

**New here? Start with the [step-by-step beginner guide](docs/06-getting-started.en.md).**
It covers downloading, Python, administrator PowerShell, installation, interpreting results, restoring factory behavior, and troubleshooting. Programming and AI tools are not required.

Enable the embedded controller's native charging policy on the recorded **MECHREVO Jiaolong 16 Pro / MRID6-23** configuration: stop charging near 80% and allow charging again below 60%. The EC maintains the policy without a background application.

## Read this first

**High risk: this project reads and writes your laptop's embedded controller (EC), using a kernel driver.** Incorrect or interrupted operations may cause abnormal battery, charger, fan, or power behavior. Recovery may require an EC reset. Read [SAFETY.en.md](SAFETY.en.md) before any hardware operation.

Three rules:

1. Never use `10/0C`. It invokes LEARN / active discharge, not charge inhibition.
2. Never enable `10/0D` with EC SOC at or above 80%. This tool requires **60%–79%** to avoid the firmware's active-discharge initialization path.
3. Never disable Memory Integrity / HVCI, the vulnerable driver blocklist, driver signature enforcement, Defender, or Secure Boot to load the driver. If Windows blocks it, stop.

WinRing0 is a known vulnerable driver. Its binaries are deliberately absent from this repository. File hashes identify expected files; they do not make the driver safe or establish Windows compatibility.

## What it does

The recorded machine's vendor control center and Windows ACPI interface do not expose charging thresholds. The firmware nevertheless has a native threshold state machine. This project sends its existing `0x10/0x0D` mailbox command with upper/lower parameters **80/60**.

```text
EC SOC below 60%  -> allow charging
EC SOC reaches 80% -> stop charging
Between thresholds -> keep the current charging state
```

The policy uses the EC's SOC, which can differ from the percentage Windows displays. Historical observations put the Windows stop level around **76%–83%**; this is not a precision guarantee.

| Observation in the recorded environment | Before | After settling in hold mode |
|---|---|---|
| Plugged in | Charges toward 100% | Stops near the upper threshold |
| Charging telemetry | Approximately 28–30 W | Charging false, charge rate 0 |
| Discharging telemetry | — | Discharging false, discharge rate 0 |
| Background application | — | Not required |

These are historical project observations, not new testing or a promise for every laptop.

## Recorded hardware and validation limits

| Item | Recorded local environment |
|---|---|
| Model | MECHREVO Jiaolong Series MRID6 / Jiaolong 16 Pro |
| Board | MRId6-23 |
| BIOS | Insyde MRID6_23_R_V38, 2024-07-31 |
| EC | ITE IT5570, firmware 0.38 (`0x8411 = 0x26`) |
| Battery | AEC616864, managed by BM5235 |
| OS | Windows 11 |

The profile also accepts EC 0.40 based on upstream evidence. That is not a claim that this project locally tested every 0.40 configuration. Windows 10 is a target platform; the recorded local OS is Windows 11.

| Item | Status in the supplied project history |
|---|---|
| Audited read-only register map | Checked on hardware across multiple sweeps |
| `10/0E` stop and `10/0F` restore | Checked on EC 0.38 |
| `10/0D` native 80/60 enable | Multiple successful observations |
| Driver cleanup after operations | Checked in recorded sessions |
| Normal Windows restart | Retained in one recorded test |
| Hard power loss / EC reset | Configuration lost |
| Sleep / hibernation | Not systematically validated |
| Complete 60→80→60 cycle | Not fully validated |
| AC unplug/replug discharge-path behavior | Static-analysis concern; not confirmed on hardware |

The supplied package reports **75/75 hardware-independent self-test checks passed**. This documentation update did not rerun them or perform hardware tests. Full historical evidence is in [validation history](docs/04-validation-history.md), currently in Chinese.

### Other MECHREVO laptops

**Other MECHREVO models can use this work as a research reference. They are not automatically supported.** Even machines with the same brand, series, or model name may have different boards, ECs, firmware, and batteries.

Reusable ideas include looking for native firmware policies, correlating controller state with Windows telemetry, restricting writes, and stopping on uncertain outcomes. Register addresses, commands, port protocols, and driver assumptions are hardware-specific.

Read [the cross-model research notes](docs/07-other-mechrevo-models.md#english). Do not remove platform checks or expand the whitelist to force another machine through the tool. If you cannot analyze firmware, collect ordinary system information and ask in Issues without first running EC tools.

## Quick start

For experienced command-line users. First-time users should follow the [complete guide](docs/06-getting-started.en.md) and confirm each step before continuing.

Requirements: the matching hardware/firmware, Windows x64, administrator access, 64-bit Python 3.10+, Internet access for the driver download, and the .NET Framework compiler used by the deployment script. No third-party Python packages are required.

Open **Windows PowerShell as administrator** and change to the extracted repository root. Run commands individually; do not paste the entire workflow at once.

Find the interpreter and fetch the expected driver files:

```powershell
$env:ECGUARD_PYTHON = (python -c "import sys; print(sys.executable)").Trim()
& $env:ECGUARD_PYTHON .\fetch_driver.py
```

If `python` is unavailable but `py -3` works, use `py -3` instead of `python` in the interpreter-discovery line. Both hashes for both files must report `MATCH`, ending with `driver files verified`.

Deploy the driver files and protected state directory:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\Install-EcGuard.ps1
```

Only after success, compile and deploy the bridge:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\ECGuard-Deploy.ps1
```

The executable, DLL, and SYS must all be in `C:\ProgramData\ECGuard\driver`. The deployment scripts arrange this. The DLL resolves the SYS relative to its host executable.

With stable AC power connected, inspect without changing EC configuration:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\ECGuard-Kernel.ps1 -Action inspect
```

Require `readonly_gate` with `pass: true`, `poisoned: false`, no failed fatal checks, and exit code 0. Inspection still loads a driver; it is not risk-free.

Only if inspection passes, EC SOC is **60–79**, the guard is clear, and the current mode is understood, enable **once**:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\ECGuard-Kernel.ps1 -Action enable
```

If native mode is already active, inspect it instead of enabling again. On a timeout, uncertain write, or nonzero exit, stop; do not retry writes.

Observe the result with five read-only samples:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\ECGuard-Kernel.ps1 -Action verify
```

**`verify` exit code 0 means sampling finished, not that battery care passed an automatic acceptance test.** Look for `ec.mode: 72` (`0x48`), `native_high: 80`, `native_low: 60`, and an idle mailbox. In settled hold mode, `native_substate: 2`, `state: 50` (`0x32`), and EC charging/discharging false are typical. Charging may continue normally before the upper threshold is reached.

Corroborate with CIM battery telemetry if available. Missing/unknown readings are not zero. See the guide for decimal/hex interpretation and stop conditions.

To restore factory policy:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\ECGuard-Kernel.ps1 -Action disable
```

Then use `verify` to confirm `ec.mode: 0`. The guard can block restoration too; do not bypass it. Deleting files or uninstalling Python does not undo the EC configuration. A normal Windows restart is not an EC reset.

`-ExecutionPolicy Bypass` above applies to each PowerShell child process only. It does not disable kernel protections or override organization policy.

## Commands

All actions below use `ECGuard-Kernel.ps1 -Action <action>` through the full PowerShell command above.

| Action | Purpose | Changes EC configuration? |
|---|---|---|
| `inspect` | Read-only precondition checks | No |
| `verify` | Read-only repeated samples; operator interprets them | No |
| `enable` | Submit fixed 80/60 native policy once | Yes, four bytes |
| `disable` | Restore factory policy | Yes, unless already normal |
| `guard` | Display guard state and recent ledger entries | No EC I/O; wrapper still requires deployed files |

`tools/telemetry_only.py` reads Windows telemetry without an EC driver. The other tools are research/diagnostic utilities, some of which write EC configuration. Beginners should use the documented wrapper workflow, not run every script in `tools/`.

## How it works

```text
Python CLI -> C# bridge -> WinRing0 DLL/kernel driver
  -> I/O ports 0x62 / 0x66 -> IT5570 EC XRAM
  -> mailbox 0x8150..0x8154 -> native firmware state machine
```

The repository also includes a direct `DeviceIoControl` transport for separate research tools. The primary `ECGuard-Kernel.ps1` workflow uses the C# bridge and DLL.

| Address | Meaning |
|---|---|
| `0x8150` | Main mailbox command; zero means idle |
| `0x8151` | Subcommand: `0x0D` native, `0x0E` stop, `0x0F` restore |
| `0x8152` | `0x55` means handler returned, not proof of effect |
| `0x8153/0x8154` | Upper/lower parameters, 80/60 |
| `0x83C0` | Mode: normal `0x00`, stop `0x02`, native `0x48` |
| `0x83A0` | Native substate: initialization, hold, or charge |
| `0x83A1/0x83A2` | Threshold copies |
| `0x8370` | Scheduler state |
| `0x837C/0x837D` | Requested-current buffer, not measured current |
| `0x8460` | AC/battery/charging/discharging flags |
| `0x847C` | EC SOC, distinct from Windows percentage |

Do not write internal state registers. The enable transaction stages high, low, subcommand, then the trigger last. The code restricts allowed address/value pairs and records transaction intent on disk before writing. Timeouts or uncertainty block subsequent writes through a persistent guard; there is no automatic retry or recovery write.

The global mutex coordinates participating ECGuard sessions. It does not coordinate Windows ACPI or unrelated vendor software. Cleanup is attempted when a session ends; forced termination and system failures require checking for leftovers.

## Documentation

- [Beginner guide](docs/06-getting-started.en.md)
- [Safety and recovery](SAFETY.en.md)
- [Other MECHREVO models: research boundaries](docs/07-other-mechrevo-models.md#english)
- [Hardware and register map](docs/01-hardware-and-registers.md) — Chinese
- [Firmware analysis](docs/02-firmware-analysis.md) — Chinese
- [Transport design](docs/03-transport-design.md) — Chinese
- [Validation history](docs/04-validation-history.md) — Chinese
- [Detailed troubleshooting](docs/05-troubleshooting.md) — Chinese

## References and license

- [Upstream MRID6 battery-threshold research](https://github.com/Zcodeoooo/JiaoLong16Pro-Battery-threshold)
- [Related Jiaolong Linux research](https://github.com/kzyha/jiaolong16-linux)
- [WinRing0 source reference](https://github.com/GermanAizek/WinRing0)

Project code is published under the [MIT license and NOTICE](LICENSE). No vendor firmware, driver binaries, or third-party binaries are included. WinRing0 has its own copyright/license, separate from this project's MIT license. Use at your own risk.
