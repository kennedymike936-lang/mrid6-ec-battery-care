# Safety: read before using ECGuard

[中文](SAFETY.md) · [English README](README.en.md) · [Beginner guide](docs/06-getting-started.en.md)

**This project performs low-level EC access through a known vulnerable kernel driver. It can affect charging and power behavior. A successful past test does not guarantee safe operation on your machine.**

## 1. Scope and risks

The primary workflow uses a C# bridge, WinRing0 DLL/kernel driver, and EC I/O ports `0x62/0x66`. Separate research tools include a direct `DeviceIoControl` path. Writes target a firmware mailbox in EC RAM; this project is not a BIOS/EC flashing utility.

| Risk | Why it matters |
|---|---|
| Interrupted EC transaction | Windows ACPI and other software may access the same ports. ECGuard's mutex does not serialize those other clients. |
| Incorrect hardware assumptions | Commands and addresses can have different meanings on another board or firmware. |
| Active-discharge initialization | Enabling the native command at high SOC can cause battery discharge while connected to AC. |
| Vulnerable driver | WinRing0 exposes privileged hardware access and may be blocked by Windows security protections. |
| Interrupted cleanup | A crash, forced process termination, or OS failure can prevent normal cleanup. |

Consequences may include abnormal battery/charger/fan behavior, system crashes, data loss, or hardware damage. Recovery may require an EC reset and, in some cases, professional service. Do not assume disconnecting the AC adapter also disconnects the internal battery.

## 2. Actions that must not be taken

- **Never send `10/0C`.** It is LEARN / active discharge, not stop-charge.
- **Never enable `10/0D` at EC SOC ≥80%.** The supported enable band is **60–79%**, with AC connected. EC SOC is not the Windows displayed percentage.
- Never write unknown addresses or internal state registers such as `0x83C0`, `0x83A0`, or `0x837C`.
- Never remove platform, firmware, SOC, stability, or whitelist checks to force compatibility.
- Never mix this procedure with BIOS/EC/SPI flashing.
- Never disable Memory Integrity/HVCI, the vulnerable driver blocklist, signature enforcement, Defender, Secure Boot, or Code Integrity to load the driver. If blocked, stop.
- Never retry an interrupted or uncertain write, add automatic recovery writes, or repeatedly run `enable` to see whether it works.
- Never delete/edit the guard state, change the state directory, or clear a lock without understanding why it was set.

The allowed write pairs are the fixed upper/lower parameters 80/60, mailbox subcommands `0x0D/0x0E/0x0F`, and the `0x10` main trigger. They are not permission to issue arbitrary combinations manually.

## 3. Driver files and trust

This repository does not distribute `WinRing0x64.dll` or `WinRing0x64.sys`. `fetch_driver.py` downloads the expected files from the upstream project's GitHub repository and checks SHA256 plus Git blob SHA1. This is **not** a download from the laptop manufacturer's official site.

Expected SHA256 values:

```text
WinRing0x64.dll  a746fd5728e7485f741cc330a279674bc8590b1b8007d8614046c49f58698485
WinRing0x64.sys  11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5
```

The installer checks hashes before/after deployment. The bridge checks them before `InitializeOls()`. A matching hash means expected bytes, not absence of vulnerabilities. Never change expected values to accept an unexpected download.

WinRing0 belongs to OpenLibSys.org / hiyohiyo and has a separate license. This project's MIT license does not replace third-party licensing terms. If you do not accept using this driver, do not use the hardware workflow.

## 4. Deployment and cleanup

The deployment scripts place the bridge, DLL, and SYS together in `C:\ProgramData\ECGuard\driver` and restrict write access to administrators/SYSTEM. They also create a protected state directory. A standard user should not be able to replace those files.

During an EC operation, the driver is loaded on demand. The normal bridge path calls `DeinitializeOls()` during cleanup, and the wrapper checks matching driver-service names afterwards. Separate direct-transport tools have their own service cleanup. This is not a background battery management service, scheduled task, or startup application.

**Cleanup is not guaranteed after forced termination or system failure.** Treat any leftover-service warning as something to investigate before another hardware operation. Do not manually start or create extra driver services to work around a failure.

The documented `-ExecutionPolicy Bypass` switch affects only the launched PowerShell process's script policy. It does not turn off Windows kernel protections or override organization policy.

## 5. Before enabling

- [ ] Exact model/board/firmware context is understood; recorded evidence is applicable.
- [ ] All read-only checks pass, including version, platform, mailbox idle, known mode, and register stability.
- [ ] EC SOC is **60–79%**, with Windows/EC SOC difference no more than 5 percentage points.
- [ ] AC is connected and both EC and Windows agree; battery is present.
- [ ] For the normal first-use procedure, current mode is normal (`0`). If native mode (`72` / `0x48`) is already active, inspect instead of enabling again.
- [ ] Guard is not poisoned and there is no unresolved transaction.
- [ ] Other EC monitoring/tuning applications are closed; no update, sleep transition, or power transition is occurring.
- [ ] Work is saved and the operator knows the restore procedure.
- [ ] The operator accepts the driver and hardware risks.

Automated gates check specific conditions; they do not certify complete compatibility or eliminate race conditions.

## 6. Interpret results conservatively

`0x8152 = 0x55` only means the handler returned. Confirm mode, threshold copies, mailbox state, and subsequent EC/Windows telemetry. Some firmware state changes settle asynchronously. Do not repeat the write because an immediate snapshot looks incomplete.

`verify` outputs samples and may exit 0 even when the samples do not show the desired policy. Interpret them using the beginner guide. Charging before the upper threshold is reached can be normal. Missing/unknown telemetry is not a zero-current measurement.

Percentage drift alone is not proof of discharge; compare EC discharge flags, CIM rates, and repeated voltage/capacity observations. Do not infer zero current from stable voltage alone. Unexpected persistent discharge on AC needs attention.

## 7. Failure and recovery

| Situation | Action |
|---|---|
| A precondition check fails | Do not write. Investigate the reported condition. |
| Timeout, poisoned guard, or uncertain transaction | Stop writes. Preserve output/state and inspect read-only if safe. Do not retry or force a restore write. |
| Policy is active but unwanted, with a clean guard | Run `disable` once, then confirm `ec.mode: 0` with read-only samples. |
| Unexpected real discharge on AC | If no uncertain transaction exists and the guard permits, attempt `disable` once. If refused or ineffective, stop experimenting and follow the hardware recovery procedure. |
| Severe power/fan/battery abnormality or unresponsive system | Prioritize hardware safety. Follow the manufacturer's shutdown/EC-reset instructions; seek service if unsure. Forced shutdown risks data loss. Do not improvise internal battery disconnection. |
| Blue screen / restart | Do not assume the EC reset. Inspect before deciding what to do next. |

A normal Windows restart was observed to retain this configuration. A genuine EC reset/hard power loss was observed to clear it. Neither unplugging AC alone nor an ordinary restart is a reliable substitute for a documented EC-reset procedure.

After a guard lock, only consider explicit clearing after the read-only inspection passes and a human has understood the live state and resolved the cause. The documented `inspect -ClearGuardAfterInspection` changes disk guard state, not EC configuration. It is not an automatic repair or an instruction to rerun enable.

Deleting source files, driver files, or Python does not restore factory charging behavior. Preserve state and ledger records during investigation.

## 8. Cross-model use and responsibility

Other MECHREVO laptops may benefit from the [research method](docs/07-other-mechrevo-models.md#english). Brand similarity is not compatibility evidence. Do not run these write commands on a different machine or weaken the gates. Modifying EC behavior may affect warranty; use only hardware you own and are authorized to modify.

Sleep/hibernation, a complete charge/discharge cycle, and AC transition behavior have unresolved validation limits. No universal or production-readiness claim is made.

Use at your own risk; see [LICENSE](LICENSE). If you find yourself trying to bypass a safety check, stop there.
