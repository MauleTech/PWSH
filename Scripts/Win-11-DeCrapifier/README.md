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

After the reboot, confirm these. They are the findings the fork exists to fix.

| Check | Expected | Command |
|---|---|---|
| DiagTrack still running | `Running` / `Automatic` | `Get-Service DiagTrack \| Select-Object Status, StartType` |
| Telemetry at Required | `1` | `Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' AllowTelemetry` |
| Teams survived | package present | `Get-AppxPackage MSTeams` |
| Get Help survived | package present | `Get-AppxPackage Microsoft.GetHelp` |
| Intel graphics panel survived | package present | `Get-AppxPackage AppUp.IntelArcSoftware` |
| Widgets policy applied | `0` | `Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' AllowNewsAndInterests` |
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

`-LeaveTasks`, `-LeaveServices`, `-Xbox`, `-Cortana`, `-AllApps`, `-NoLog`, `-AppsOnly` and
`-SettingsOnly` behave as they did.

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
  crapware.
* Use `-AdditionalKeep` with EXACT package or program names. Upstream matches exactly, not as
  substrings, so `Microsoft.WindowsCamera` works and `camera` does not. This is the opposite of
  `$GoodApps` in our own script, which is substring matched.

## Known gaps

* Not yet run on real hardware. Logic was exercised against stubbed Appx, service, scheduled task
  and `reg.exe` calls; the `SignatureKind` / `IsFramework` / `NonRemovable` filter in particular
  needs confirming on a live Windows 11 build.
* Windows 11 Start layout is not configured at all. If we want one, it belongs in Intune or a
  staged `LayoutModification.json`, not in this script.
