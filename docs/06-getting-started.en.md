# Beginner guide: download, set up, check, and restore

[English README](../README.en.md) · [中文指南](06-getting-started.zh-CN.md) · [Safety](../SAFETY.en.md)

This guide is for people who do not program and do not use AI. Follow the steps in order, one command at a time. Stop at any error rather than continuing with the next step.
**Detailed instructions do not reduce the hardware risk or guarantee that setup will work on every machine.**

## 1. Check whether this is applicable to your laptop

The project's recorded local hardware is:

| Item | Recorded value |
|---|---|
| Model | MECHREVO Jiaolong 16 Pro / Jiaolong Series MRID6 |
| Board | MRId6-23 |
| BIOS | MRID6_23_R_V38, 2024-07-31 |
| EC | ITE IT5570, firmware 0.38 |
| Battery | AEC616864, managed by BM5235 |
| OS | Windows 11 |

Press `Win + R`, enter `msinfo32`, and press Enter. In System Summary, look for System Model, BaseBoard Product, and BIOS Version/Date. EC version may not be shown there; the later inspection reads it. Do not guess an EC version or attempt writes while it is unknown.

The code also accepts a 0.40 profile based on upstream evidence. That is not local testing of every 0.40 machine. Windows 10 is a target platform, while the recorded local OS is Windows 11.
If the model, board, or firmware differs, do not run this guide's EC commands. Read [the other-model reference](07-other-mechrevo-models.md#english) first.

Read [SAFETY.en.md](../SAFETY.en.md) in full. In particular:

- Enable only with **EC SOC 60–79%** and stable AC power connected. Windows percentage is not a substitute for EC SOC.
- Do not disable driver blocking, Memory Integrity, Defender, signature enforcement, or Secure Boot.
- Do not rerun `enable` after a timeout, poison lock, or uncertain result; do not delete guard state.
- Do not flash firmware, edit addresses/whitelists, or run the write-probe scripts in `tools/`.

## 2. Download and extract the project

1. Open [the GitHub repository](https://github.com/kennedymike936-lang/mrid6-ec-battery-care).
2. Select the green **Code → Download ZIP**, or use the [source ZIP link](https://github.com/kennedymike936-lang/mrid6-ec-battery-care/archive/refs/heads/main.zip).
3. In File Explorer, right-click the ZIP and choose **Extract All**. Do not run files from inside the ZIP window.
4. Find the extracted folder that directly contains `README.md`, `fetch_driver.py`, `ecguard`, and `windows`.
5. To match the commands below, place that folder at `C:\ECGuardSource`. You should have `C:\ECGuardSource\README.md`, without another project folder nested between them.

You do not need Git, GitHub Desktop, or a GitHub account to download and use the source. If you choose a different location, replace `C:\ECGuardSource` in the directory command with the actual path.

## 3. Prepare Python

Use an existing **64-bit Python 3.10 or newer** installation if available. Otherwise, install a stable runtime from [Python's official Windows downloads](https://www.python.org/downloads/windows/). If using Python install manager, complete its runtime setup prompts. With a traditional installer that offers **Add python.exe to PATH**, select that option.

Close old terminal windows after installation, then open a new one.
The project uses the Python standard library; normal use does not need `pip install`, Node.js, AI, or Visual Studio. Deployment builds the C# bridge using the system .NET Framework C# compiler; see troubleshooting if it is absent.

## 4. Open Windows PowerShell as administrator

1. Open Start and search for **Windows PowerShell**.
2. Right-click it, choose **Run as administrator**, and accept the UAC prompt.
3. Check that the window title indicates administrator access. These commands belong in PowerShell, not CMD or Python's `>>>` prompt.
4. Copy one code block at a time and press Enter. Do not include code-block borders or a `PS C:\...>` prompt.

Enter the extracted project folder:

```powershell
Set-Location -LiteralPath 'C:\ECGuardSource'
```

Check that you selected the right folder:

```powershell
Get-Item .\README.md, .\fetch_driver.py, .\windows\ECGuard-Kernel.ps1
```

All three files should be listed. If not, check the extraction/folder level in step 2.

Check Python:

```powershell
python --version
```

It must print Python 3.10 or newer. If it opens the Store or is not found, finish/fix Python installation first. If `python` does not work but `py -3 --version` does, replace `python` with `py -3` in the next command.

Pin the interpreter for subsequent commands in this window:

```powershell
$env:ECGUARD_PYTHON = (python -c "import sys; print(sys.executable)").Trim()
```

Check its version and bitness:

```powershell
& $env:ECGUARD_PYTHON -c "import sys, struct; print(sys.version); print('bits:', struct.calcsize('P') * 8)"
```

Require Python 3.10+ and `bits: 64`. The environment variable is inherited by the scripts launched below. In a new terminal, enter the folder and set the interpreter again.

## 5. Download and deploy the driver files

Internet access is required for the download. The repository contains no driver binaries. The fetch script downloads two files from the upstream project's GitHub repository, **not the laptop manufacturer's official site**. The URL and pinned hashes are in `fetch_driver.py`.
Matching hashes identify expected bytes; they do not remove WinRing0's vulnerabilities or guarantee Windows will allow the driver.

Download and check the files:

```powershell
& $env:ECGUARD_PYTHON .\fetch_driver.py
```

Both `sha256` and `git blob` checks must show `MATCH` for both files, followed by `driver files verified`.
On `MISMATCH`, `DRIVER VERIFICATION FAILED`, HTTP 404, or a network exception, stop here. Do not alter the hashes or substitute files from an unknown source.

Deploy the files and protected state directory:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\Install-EcGuard.ps1
```

Success includes `Driver deployed` and directory information. Only after that succeeds, run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\ECGuard-Deploy.ps1
```

Expect bridge build/deployment output and `OK` for all three required files:

```text
C:\ProgramData\ECGuard\driver\ECGuardBridge.exe
C:\ProgramData\ECGuard\driver\WinRing0x64.dll
C:\ProgramData\ECGuard\driver\WinRing0x64.sys
```

This deploys files; it has not enabled battery care. Do not double-click the bridge executable.
`-ExecutionPolicy Bypass` above affects the launched PowerShell process only. It does not change the system's persistent script policy or bypass driver signature/HVCI/blocklist checks. If organization policy disallows scripts, contact the administrator instead of trying to override it.

## 6. Connect AC and inspect without configuration writes

Save your work. Close other EC monitoring/tuning applications and vendor control-center applications that may access the controller. Do not operate during an OS update, resume-from-sleep transition, or power transition. Connect the adapter and keep power stable.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\ECGuard-Kernel.ps1 -Action inspect
```

This does not modify EC configuration, but still temporarily loads a kernel driver and accesses the EC. Read-only does not mean risk-free.

Output is one JSON object per line. Look for these fields:

```json
{"event":"readonly_gate","pass":true,"poisoned":false}
```

This is a field illustration, not the complete real line; the real output also includes time, version, SOC, and mode.
Require `pass: true`, `poisoned: false`, no failed fatal checks, and final `exit code: 0`. Otherwise, do not proceed. Passing these software checks is not a complete hardware compatibility certification.

Read the EC `soc` and the Windows SOC in the `windows` event. Enabling requires EC SOC **60–79**, with the two readings within 5 percentage points. Windows showing 75% does not prove the EC reading is below 80%.

- Too high: after this command has ended, unplug and use the laptop normally until it reaches the band, reconnect AC, then inspect again. Do not unplug during an active command.
- Too low: charge normally into the band, then inspect.
- `mode: 72`: native mode is already active. Skip enabling and observe it in step 8.
- A normal first setup should start at `mode: 0`. `mode: 2` is stop mode; although the code permits enabling from it, do not proceed if you do not understand why it is active.

## 7. Enable the fixed 60%–80% policy

**This step writes EC configuration.** Confirm inspection passed, SOC is in range, AC is connected, and you understand the restoration procedure in step 9. The supported thresholds are fixed at low 60/high 80; this guide does not customize them.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\ECGuard-Kernel.ps1 -Action enable
```

Let it finish naturally. Do not close the window, sleep the system, or change power connections during execution.
Normal output includes a `verification` event with `mailbox_result_ok`, `mode_is_native`, and `native_copies_match` all `true`, `bytes_written: 4`, and exit code 0. Continue to read-only observation below.
**Do not run enable again merely because charging has not stopped yet.**

On any failure, `abort`, `poisoned`, or nonzero exit code, stop writes and use step 10.

## 8. Check whether the policy took effect

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\ECGuard-Kernel.ps1 -Action verify
```

The default is five samples, ten seconds apart: about 40 seconds of waiting plus read time.
**Exit code 0 only means sampling finished; this command does not automatically certify battery-care success.** Read the `ec` object in each `verify_sample`:

| Field | Interpretation |
|---|---|
| `mode: 72` | Hex `0x48`: native battery-care mode |
| `native_high: 80`, `native_low: 60` | Correct threshold copies |
| `mailbox_command: 0` | Mailbox idle |
| `native_substate: 3` | Charging allowed; may be normal before reaching the upper threshold |
| `native_substate: 2` | Charge-inhibited hold state |
| `state: 50` | Hex `0x32`: typical scheduler state during native hold |
| `charging: false`, `discharging: false` | EC indicates neither charging nor discharging, expected during settled hold |

Ordinary numeric fields are decimal. Strings in `raw` are hexadecimal, for example `"83C0":"48"`. `mailbox_result: 85` is hex `0x55`: handler returned, not proof of success by itself.

If the upper threshold has not been reached, continued normal charging in native mode can be expected. Historical Windows stop readings were around 76%–83%, not an exact 80% promise.
Cross-check `PowerOnline`, `Charging`, `Discharging`, `ChargeRate`, and `DischargeRate` in `cim.batteries`. Windows telemetry can lag. If `cim.available` is false, the battery list is empty, or a value is unknown, do not treat it as zero or claim it proves no discharge.

For Windows-only telemetry without loading an EC driver:

```powershell
& $env:ECGUARD_PYTHON .\tools\telemetry_only.py
```

This does not show EC mode and cannot independently prove the thresholds were installed.
Once configured, you can close the terminal; no resident application or startup task is needed. Keep the source for restoration and troubleshooting.
Normal restart retention was recorded once; hard power loss clears the configuration. Sleep/hibernation, complete cycles, and AC transitions still have validation gaps described in the README.

## 9. Restore factory charging behavior

If using a new administrator PowerShell window, first repeat step 4's folder and interpreter setup. Then run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\ECGuard-Kernel.ps1 -Action disable
```

This submits a restore write, and the guard can refuse it. Afterwards, run step 8's `verify` command and confirm `ec.mode: 0`. A disable exit code of 0 is not a replacement for that state check. Factory policy can allow charging back to 100%.

**Deleting the source/driver files or uninstalling Python does not undo an EC configuration.** Restore first before considering file cleanup. Preserve records in `C:\ProgramData\ECGuard\state` while investigating any problem.
A normal Windows restart is not an EC reset and is not a reliable undo procedure.

## 10. Troubleshooting

| Message / symptom | Action |
|---|---|
| Python not found / Store opens | Finish Python installation, reopen the terminal; if `py -3` works, use it for interpreter discovery in step 4 |
| `This wrapper must run elevated` / `must run elevated` | Open Windows PowerShell using Run as administrator |
| Missing script / `fetch_driver.py` | Check that you are in the extracted repository root, not the ZIP or parent folder |
| Download error, 404, hash mismatch | Stop at download; do not deploy, change hashes, or substitute unknown files |
| `bridge not built` / `csc failed` | Deployment expects `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`; use official Windows servicing to restore/enable .NET Framework, retain the error, and do not download an unknown EXE |
| `status=3` / missing driver files | Check the three-file layout and deployment in step 5; do not copy files into System32 |
| Security block, signature error, `status=2` | Stop; keep Windows protections enabled. Status 2 alone does not establish the cause |
| `bridge exited unexpectedly` / `bridge did not become ready` | Preserve the error. Multiple causes are possible; do not assume a security-policy fault or disable protections |
| `platform_is_mrid6` / `ec_version_accepted` fails | Unsupported or insufficient evidence; stop, do not edit profile checks |
| `soc_consistent` fails | Missing readings or more than 5 percentage points apart; do not raise tolerance |
| `soc_gate` / `soc_in_target_band` fails | After the command ends, charge/use normally into the band as in step 6; do not use active-discharge LEARN |
| `registers_stable` / `mailbox_idle` fails | Stop writes; preserve output to investigate state/concurrent access |
| Exit 2 | Preconditions failed; read the specific check/abort event |
| Exit 3 | Immediate post-submission criteria were not met; do not repeat writes, inspect read-only |
| Exit 4 / poisoned / timeout | Uncertain state: stop writes, retain records, inspect read-only if safe |
| Exit 5 / 6 | Transport error / refusal; act on the specific message rather than ignoring it |
| Percentage falls slightly | Check EC flags, CIM rates, and repeated voltage/capacity readings; percentage alone does not establish discharge |
| Persistent real discharge on AC / abnormal charging | If no uncertain transaction exists and the guard permits, run disable once. If refused or ineffective, do not bypass; save work and follow safety recovery guidance |
| Severe power/fan abnormality or unresponsive system | Prioritize hardware safety; follow the manufacturer's shutdown/EC-reset instructions. Forced shutdown risks data loss. Removing AC alone does not disconnect an internal battery; seek service if unsure |

### A locked guard

Display records without EC I/O:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\ECGuard-Kernel.ps1 -Action guard
```

Then use step 6's `inspect`. **Only consider the explicit clear below after all read-only checks pass and a human understands the live state and has resolved the cause.** If you cannot interpret it, stop and ask in Issues; no AI is required, and guessing is not appropriate.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\ECGuard-Kernel.ps1 -Action inspect -ClearGuardAfterInspection
```

This changes disk guard state, not EC configuration. Look for `guard_cleared`; without that event, do not assume clearing succeeded. Clearing neither restores factory policy nor implies that enable should be run again. Transaction history may still need analysis.
Never delete/edit `state.json` or switch state directories to escape a lock.

## 11. How to ask for help

Open an issue in [the repository](https://github.com/kennedymike936-lang/mrid6-ec-battery-care/issues) with:

- Exact model, board product, BIOS version, Windows version, and Python version.
- Step number, complete command, error text, and exit code.
- Relevant `readonly_gate` / `verify_sample` output, if successfully read.
- Whether writes began, any timeout/poison lock, and current AC/charging behavior.

Redact usernames, computer names, battery serial numbers, `InstanceName`, personal paths, and similar identifiers before posting. Do not upload drivers, firmware, raw dumps, or an unreviewed full log directory. Responses are not guaranteed and do not constitute official hardware certification.

## Official references

- [GitHub: downloading repository files](https://docs.github.com/en/repositories/working-with-files/using-files/downloading-files-from-github)
- [Python: installation and use on Windows](https://docs.python.org/3/using/windows.html)
- [Microsoft: PowerShell execution policies and process scope](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
