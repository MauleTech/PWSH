# Windows 11 Decrapifier / Debloat

Two new commands for Windows 11 workforce builds. Both are additive: `Invoke-Win10Decrap` and
`Scripts\Win-10-DeCrapifier\Windows10Decrapifier.txt` are untouched and still work exactly as
before.

Background and evidence for every change: `Scripts\Win-10-DeCrapifier\WINDOWS11-REVIEW.md`.

## Quick reference

| Command | What it is |
|---|---|
| `Invoke-Win11Decrap` | Our fork of the Decrapifier, patched for Windows 11 and managed endpoints. Apps + settings. |
| `Invoke-Win11Debloat` | Wrapper around Andrew Taylor's `RemoveBloat.ps1`. Apps + OEM Win32 crapware. No settings. |
| `Invoke-Win10Decrap` | Unchanged original. Windows 10 only. |

Both new commands need an elevated session.

## Recommended test-build sequence

```powershell
irm ps.mauletech.com | iex

# 1. Baseline: capture what is on the box before anything runs
Get-AppxPackage -AllUsers | Select-Object Name, SignatureKind, NonRemovable |
    Sort-Object Name | Export-Csv C:\before-apps.csv -NoTypeInformation

# 2. OEM and consumer app removal (Taylor's script, with our keep-list)
Invoke-Win11Debloat

# 3. Privacy, telemetry and Windows 11 AI settings (ours)
Invoke-Win11Decrap -SettingsOnly

# 4. Reboot, then compare
Get-AppxPackage -AllUsers | Select-Object Name | Sort-Object Name |
    Export-Csv C:\after-apps.csv -NoTypeInformation
```

`Invoke-Win11Decrap` on its own (no `-SettingsOnly`) does apps and settings together and skips the
OEM Win32 crapware entirely. Use that if you would rather not introduce the third-party script yet.

## What to verify on the test build

`Invoke-Win11Decrap` is **verbose by default** and now checks itself. Look for these in the
output before you go anywhere near the manual commands:

1. **Environment banner** at the top. Confirms the OS gate saw a Windows 11 build, and lists
   exactly which switches were in effect.
2. **Package triage.** A count of what was skipped and why:

   ```
       142 packages installed
        61 skipped: inbox system components (SignatureKind System)
        24 skipped: frameworks (VCLibs, .NET Native, WinUI)
         3 skipped: flagged NonRemovable by Windows
        31 protected by the keep-list
        23 targeted for removal
   ```

   The "SignatureKind System" line is the F4 fix proving itself. If it reads **0**, the script
   says so loudly: the structural guard did not work on that build and only the name list is
   protecting system components. Stop and check the removal list before continuing.
   Every protected package is then listed by name, so you can eyeball that Teams, Get Help,
   PowerShell and the Intel graphics panel are on the keep side.
3. **Every registry value it writes**, as `path\name = value`.
4. **Post-run verification.** The script re-reads the settings that matter and prints PASS/FAIL
   per item, including two values read back out of the **default profile hive**, which is the
   only way to confirm new users will inherit the settings without creating an account. The
   summary ends with `Verification : N passed, N failed`.

Anything other than `0 failed` needs looking at before the build ships.

Pass `-Quiet` to drop back to summary-only output once a build process is trusted.

The manual cross-checks below still hold if you want to confirm independently after the reboot.

| Check | Expected | Command |
|---|---|---|
| DiagTrack still running | `Running` / `Automatic` | `Get-Service DiagTrack \| Select-Object Status, StartType` |
| Telemetry at Required | `1` | `Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' AllowTelemetry` |
| Teams survived | package present | `Get-AppxPackage MSTeams` |
| Get Help survived | package present | `Get-AppxPackage Microsoft.GetHelp` |
| Intel graphics panel survived | package present | `Get-AppxPackage AppUp.IntelArcSoftware` |
| Widgets board disabled | `1` | `Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' DisableWidgetsBoard` |
| Widgets actually gone | no widgets button on the taskbar after reboot | look at the taskbar |
| Recall off | `1` | `Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' DisableAIDataAnalysis` |
| File extensions visible | `0` | `Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' HideFileExt` |
| No Start menu errors | transcript has no `Import-StartLayout` | `Select-String -Path C:\Windows11DCtranscript.txt -Pattern 'StartLayout'` |
| No access-denied noise | `Registry values failed : 0` | tail of `C:\Windows11DCtranscript.txt` |

Then log in as a brand new user and confirm the default-profile settings took (file extensions
visible, no suggested content in Start, no "Finish setting up your device" prompt).

## Reading the transcript

`Invoke-Win11Decrap` writes to `C:\Windows11DCtranscript.txt` (the Windows 10 script's
`WindowsDCtranscript.txt` is left alone so both can coexist).

The output is deliberately different from the old script:

* `[REMOVED]` means the package is verified gone. `[KEPT]` means Windows refused the removal.
  The Windows 10 script printed a removal line before every attempt and never checked, which made
  its transcript look far more destructive than the run actually was.
* Registry writes are counted rather than echoed. Only failures are named, inline and again in the
  summary. The old script emitted "The operation completed successfully." roughly 100 times per run
  and buried two real failures in the middle of it.

* Scheduled tasks and services report the state they actually ended in, and distinguish
  `[DISABLED]` (we changed it) from `[ALREADY]` (it was fine) and `[ABSENT]` (not on this build).
  A `[FAILED]` line means the item is still enabled after the attempt.

`Invoke-Win11Debloat` uses upstream's own log at `C:\ProgramData\Debloat\Debloat.log`.

## Switch mapping from the Windows 10 script

Three switches were hardcoded on in the old script, immediately below its `param()` block, so they
could not be turned off and the header documentation described the opposite of what happened. The
defaults here are the same as the old script's real behaviour; the names now say what turning them
on does.

| Windows 10 script | Windows 11 fork | Default |
|---|---|---|
| `$AppAccess = $true` (hardcoded) | `-RestrictAppAccess` | off, same as before. Turning it on breaks Teams camera and mic. |
| `$Tablet = $true` (hardcoded) | `-RestrictLocation` | off, same as before |
| `$OneDrive = $true` (hardcoded) | `-DisableOneDrive` | off, same as before |
| `$ClearStart = $true` (hardcoded) | removed | `Import-StartLayout` is deprecated on Windows 11 and failed on every run |
| n/a | `-LeaveAI` | off, so Recall / Click to Do / Copilot / Paint AI get disabled |
| n/a | `-DisableTelemetryService` | off. Only for genuinely unmanaged machines. |
| n/a | `-Quiet` | off, i.e. verbose output IS the default |

`-LeaveTasks`, `-LeaveServices`, `-Xbox`, `-Cortana`, `-AllApps`, `-NoLog`, `-AppsOnly` and
`-SettingsOnly` behave as they did.

## A note on widgets, hover, and what 25H2 blocks

**Two of the widgets registry values cannot be written at all on Windows 11 25H2 (build 26200),
even by an elevated administrator.** Confirmed on our own hardware:

| Value | 23H2 / 24H2 | 25H2 |
|---|---|---|
| `Dsh\AllowNewsAndInterests` | writes | **Access is denied** |
| `Explorer\Advanced\TaskbarDa` | writes | **Access is denied** |
| `Dsh\DisableWidgetsBoard` | writes | writes |
| `Dsh\DisableWidgetsOnLockScreen` | writes | writes |

This is not a permissions problem and taking ownership does not help. Registry ACLs are per key,
not per value, and `DisableWidgetsBoard` writes successfully to the *same key* in the *same pass*
where `AllowNewsAndInterests` is refused. The shell enforces these two above the ACL layer. It is
not a `reg.exe` quirk either: winutil
[issue 2886](https://github.com/ChrisTitusTech/winutil/issues/2886) shows `Set-ItemProperty` on
`TaskbarDa` raising `UnauthorizedAccessException`, so the .NET API is blocked the same way.

The script still sets both, because they work on 23H2 and 24H2 and most of the fleet is not on
25H2 yet. They are marked as superseded, so on a 25H2 machine they report as `[BLOCKED]` with the
reason rather than as failures, and the summary counts them separately:

```
  Values Windows blocked    : 3 (superseded, not a fault)
  Registry values failed    : 0
```

**`DisableWidgetsBoard` is the control that matters now.** Microsoft documents it as "you won't be
able to invoke the Widgets board and its entry point will no longer appear on the taskbar", and it
writes cleanly on every build we have tried. Confirm on the test machine after a reboot that the
taskbar widget is actually gone; that is the real check, not the registry read-back.

### On "Open on hover" specifically

There is **no machine-wide policy for the "Open Widgets board on hover" toggle**, and no working
per-user registry value for it either. Microsoft does not ship one: the `NewsAndInterests` CSP
contains exactly three settings (`AllowNewsAndInterests`, `DisableWidgetsBoard`,
`DisableWidgetsOnLockScreen`) and none of them is hover.

Two keys that guides commonly suggest do **not** do what people think:

* `HKCU\...\CurrentVersion\Feeds\ShellFeedsTaskbarOpenOnHover` is the Windows **10** News and
  Interests key. It has no effect on Windows 11.
* `HKCU\...\CurrentVersion\Feeds\DSB\OpenOnHover` is **search** on hover, not widgets. The
  script sets it anyway, because opening search on hover is the same class of annoyance, but it
  is a different feature.

The script handles hover by removing the thing you would hover over, at three levels:

| Setting | Scope | Effect |
|---|---|---|
| `Dsh\AllowNewsAndInterests` = 0 | machine | Turns off the whole widgets feature "including content on the taskbar". Released policy, Pro supported. |
| `Dsh\DisableWidgetsBoard` = 1 | machine | "Its entry point will no longer appear on the taskbar." Same ADMX. Microsoft still marks this preview, so it may be a no-op on some builds; an unrecognised policy value is ignored, so it costs nothing and starts working when the build catches up. |
| `Explorer\Advanced\TaskbarDa` = 0 | per user + default profile | Hides the widgets button. Belt and braces if a build ignores the policies above. |

`Dsh\DisableWidgetsOnLockScreen` = 1 is set too, for lock screen widgets.

Worth knowing: Microsoft is changing this default upstream anyway. Insider Beta build 26220.8680
(June 2026) lists "Disabling **Open on hover** by default" and taskbar badging off by default as
shipping changes to make Widgets "quiet by default".

## Notes on Invoke-Win11Debloat

* The upstream script is Authenticode signed by `Open Source Developer Andrew Taylor` through the
  Certum CA. The wrapper verifies that before running it and aborts otherwise. There is no pinned
  SHA256 because upstream ships changes frequently and a pinned hash would fail constantly.
* `-AllowStartMenuReset` is off by default. With it on, upstream downloads a `start2.bin` from its
  own GitHub repository into the default user profile, which is an unsigned third-party binary in a
  user's shell state.
* `-TasksToRemove` is empty by default. Upstream *deletes* the tasks it is given, which is harder
  to reverse than disabling them; `Invoke-Win11Decrap` disables the CEIP tasks instead.
* The OEM Win32 removal (HP, Dell, Lenovo, McAfee) is aggressive. Validate per vendor on a test
  build before fleet use, particularly on Dell where management tooling shares naming with the
  crapware. One case is already handled: upstream removes **Dell Command | Update**, which
  `Update-DellPackages` installs and drives through `dcu-cli`, so all four of its names are in
  the keep-list. Upstream already protects Dell Display Manager, Dell Pair, Dell Peripheral
  Manager, Dell Optimizer Core and the SupportAssist remediation plugins. SupportAssist itself is
  removed, which matches what we do elsewhere.
* Use `-AdditionalKeep` with EXACT package or program names. Upstream matches exactly, not as
  substrings, so `Microsoft.WindowsCamera` works and `camera` does not. This is the opposite of
  `$GoodApps` in our own script, which is substring matched.

## Known gaps

* Not yet run on real hardware. Logic was exercised against stubbed Appx, service, scheduled task
  and `reg.exe` calls; the `SignatureKind` / `IsFramework` / `NonRemovable` filter in particular
  needs confirming on a live Windows 11 build. The package triage output is designed to make that
  confirmation a glance rather than an investigation.
* The verification pass checks the current user and the default profile. It does not check other
  existing user profiles, which the script does not write to either.
* Windows 11 Start layout is not configured at all. If we want one, it belongs in Intune or a
  staged `LayoutModification.json`, not in this script.
