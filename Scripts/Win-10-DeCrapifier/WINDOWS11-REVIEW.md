# Windows 10 Decrapifier: Windows 11 Workforce Review

Review of `Windows10Decrapifier.txt` (CSAND, Jan 2022) as invoked by `Invoke-Win10Decrap`
in `Functions/PS-Invoke.psm1`, against a transcript from a run on a new Windows 11 machine.

Scope: devices destined to become managed workforce endpoints (Microsoft 365, Intune
and/or Action1, Defender).

**Verdict:** patch it, do not replace it yet. The app selection is still broadly right.
Four targeted edits fix most of the risk. The deny-by-default design should be inverted
over time, and on Enterprise/Education SKUs app removal should move into policy.

---

## 0. How to read the transcript

The log overstates what happened. Every `Removing app package:` line is a `Write-Host`
printed *before* the attempt, and every removal runs with `-ErrorAction SilentlyContinue`
with no verification afterwards. The 46 package names are removal *attempts*.

Several certainly failed. Andrew Taylor's enterprise debloat script keeps an explicit
`$NonRemovable` array of "apps that were getting attempted and the system would reject
the uninstall", and it contains many of the same entries this run tried: the four GUID
packages, `Microsoft.Windows.PeopleExperienceHost`,
`Microsoft.Windows.PinningConfirmationDialog`, `Microsoft.Windows.NarratorQuickStart`,
`Microsoft.XboxGameCallableUI`, `Windows.CBSPreview`, `MicrosoftWindows.UndockedDevKit`.

What the log does prove, because these produced real output:

- 21 provisioned packages were genuinely removed.
- `Import-StartLayout` threw a terminating error. The Start menu section did nothing.
- Two `ERROR: Access is denied.` lines, one per registry pass, at the same position.

There is no OS version gate anywhere in the script. The transcript says "Decrapifying
Windows 10" and the closing message references the Windows 10 execution policy default.

---

## 1. Findings

### F1 (Critical) - Disables the telemetry service the RMM/EDR stack depends on

    Line 176: Get-Service Diagtrack,WMPNetworkSvc | stop-service -passthru | set-service -startuptype disabled
    Line 418: Reg Add "HKLM\...\Windows\DataCollection" /V "AllowTelemetry" /D 0 /F

- Intune Endpoint Analytics lists it as a hard prerequisite: "The Connected User
  Experiences and Telemetry service (DiagTrack) must be enabled and running."
- Windows Update for Business reports require diagnostic data at Required (1) minimum
  and instruct that all default OOBE services remain running.
- Defender for Endpoint logs Event 62 when DiagTrack fails to start ("Non-Microsoft
  Defender for Endpoint telemetry isn't sent from this machine") and Event 17 on
  onboarding, whose documented remedy is "ensure the diagnostic data service is enabled."

Andrew Taylor's script has both of these commented out, noting "This is needed for
Intune reporting to work."

**Fix:** drop `Diagtrack` from the service line (keep `WMPNetworkSvc`); change
`AllowTelemetry` from 0 to 1. If a client genuinely has no cloud management, gate the
old behavior behind a new `-DisableTelemetryService` switch instead of defaulting to it.

### F2 (Critical) - Start menu section is dead code and fails every run

`Import-StartLayout` is deprecated on Windows 11 and per Microsoft's own cmdlet docs
"has no effect on either Start or Taskbar layout". Windows 11 uses
`LayoutModification.json` and a binary `start2.bin`.

Because `$ClearStart = $true` is hardcoded after the param block, this runs every time
and always throws. Net effect: a red wall of text in every transcript, and one of the
script's four advertised jobs has never happened on a Windows 11 machine.

**Fix:** delete or version-gate `ClearStartMenu`. For a controlled Windows 11 Start
layout, stage a `LayoutModification.json` into
`C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\` or drive it from Intune.
Windows 11 only accepts an OEM-format JSON there, not one exported from a live machine.

### F3 (High) - Removes apps a Microsoft 365 workforce user needs

| Package removed | What it is | Impact |
|---|---|---|
| `MSTeams` | New Teams client | Teams gone. Microsoft's commercial policy default marks it do-not-remove. |
| `Microsoft.OutlookForWindows` | New Outlook | Microsoft's commercial default also keeps it. |
| `Microsoft.MicrosoftOfficeHub` | Renamed to Microsoft 365 Copilot app (Jan 2025); the Office launcher | Taylor's script stopped removing this in Aug 2026 for exactly this reason. |
| `Microsoft.GetHelp` | Hosts Windows 11's built-in troubleshooters | Removing it breaks them for our own techs. |
| `Microsoft.PowerShell` | PowerShell 7 (Store/MSIX build) | Uninstalls PS7 if Store-installed. PS 5.1 in System32 unaffected. |
| `AppUp.IntelArcSoftware` | Intel Graphics Software, successor to Graphics Command Center | On Core Ultra this IS the graphics control panel. The deprecated `AppUp.IntelGraphicsExperience` is on the keep-list; the current one is not. |
| `AppUp.IntelManagementandSecurityStatus` | Intel vPro / AMT status | Matters on any vPro fleet. |
| `MicrosoftWindows.CrossDevice` | Cross-device / Phone Link backend | Inconsistent: `Microsoft.YourPhone` is kept, its backend is not. |

**Fix:** extend `$GoodApps`. See section 2.

### F4 (High) - Deny-by-default sweeps in new Windows components blind

`RemoveApps` removes everything not matching `$SafeApps` or `$GoodApps`. Any package
Microsoft ships that nobody thought to whitelist becomes a removal target automatically.
The log shows this with packages that did not exist when the script was written:

    MicrosoftWindows.54792954.Filons      MicrosoftWindows.61869720.Voiess
    MicrosoftWindows.58680125.Speion      MicrosoftWindows.61869721.Livtop
    MicrosoftWindows.58681517.Voiess      MicrosoftWindows.61869722.Speion
    MicrosoftWindows.58681560.Livtop      MicrosoftWindows.61869836.InpApp
    MicrosoftWindows.58683691.InpApp      Microsoft.AIFabric.CBS.1.6
    Microsoft.Windows.AugLoop.CBS         MdOdrMcpFilterPackage

These are Windows 11 inbox system apps under `C:\Windows\SystemApps\SxS\`, shipped as
part of the Feature Experience Pack. A public mapping of each codename to its feature
could not be confirmed, so no guess is offered here. The point holds regardless: these
are signed OS shell components, not consumer bloatware, and nothing decided to remove
them except the absence of a whitelist entry.

**Fix:** filter on package properties instead of growing the keep-list. See section 2.

### F5 (Medium) - The two "Access is denied" errors are an obsolete Windows 10 key

Counting the registry writes that actually execute under the hardcoded switch settings
gives exactly 48 per pass. The log shows 33 successes, the error, then 14 more, in both
passes. That puts the failure at operation 34:

    Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /T REG_DWORD /V "ShellFeedsTaskbarViewMode" /D 2 /F

This is the Windows 10 "News and Interests" taskbar key. Windows 11 replaced that
feature with Widgets; the key is obsolete and ACL-protected.

**Fix:** replace with the documented Windows 11 policy:
`HKLM\SOFTWARE\Policies\Microsoft\Dsh` -> `AllowNewsAndInterests` = 0 (DWORD).
Device scope, applies to Pro, covers the whole Widgets experience.

### F6 (Medium) - Hardcoded overrides contradict the documented switches

Immediately below `param()`, four switches are forced on regardless of caller input:

    $OneDrive   = $true    # OneDrive left fully functional
    $ClearStart = $true    # empty Start menu (F2: always fails on Win11)
    $Tablet     = $true    # location and sensors left enabled
    $AppAccess  = $true    # ALL Settings > Privacy restrictions skipped

`$AppAccess = $true` means the entire camera / microphone / contacts / calendar /
documents privacy block never runs. That is probably correct for Teams users, but it
should be a stated decision, and the header docs still describe the opposite behavior.

**Fix:** move these to defaults in the `param()` block (`[switch]$OneDrive = $true`) so
they are visible and overridable, and correct the header comments.

### F7 (Medium) - App removal only affects the current user

`Get-AppxPackage -AllUsers` enumerates every profile, but `Remove-AppxPackage` is called
without `-AllUsers`, so it only unregisters for the account running the script. On a
fresh build from a staging account this rarely bites (provisioned removal covers future
profiles). On an in-use machine, existing profiles keep everything.

**Fix:** `Remove-AppxPackage -Package $RemovedApp.PackageFullName -AllUsers -ErrorAction SilentlyContinue`.
Also add `#Requires -RunAsAdministrator`; the script needs elevation but never checks.

### F8 (Low) - Dead settings and repo hygiene

- Cortana block (8 writes): Cortana retired 2023. No-ops.
- My People (`PeopleBand`, `ShoulderTap`): feature does not exist in Windows 11.
- Meet Now (`HideSCAMeetNow`): removed from Windows 11.
- Legacy Edge and Internet Explorer Do Not Track keys: both browsers retired.
- Delivery Optimization is written under `...\CurrentVersion\DeliveryOptimization\Config`,
  not the supported policy path `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization`.
- `Invoke-Win10Decrap` fetches from `/PWSH/master/`; the repo only has `main`. GitHub's
  legacy-name redirect still serves it (confirmed HTTP 200) but this is fragile.
- No integrity check on the fetch. `Invoke-Win10Decrap` does a bare
  `Invoke-WebRequest | Invoke-Expression` while this repo already has
  `Invoke-ValidatedDownload` and `DownloadManifest.json` for exactly this pattern; the
  Decrapifier is not in the manifest. Separately, because it is a `.txt`,
  `Sign-Scripts.ps1` deliberately skips it, so it is unsigned by design.

---

## 2. The $GoodApps list

Two reference points for what a business PC should keep: Microsoft's own curated default
in the `RemoveDefaultMicrosoftStorePackages` policy, and the whitelist in Andrew Taylor's
Intune debloat script. They agree closely and both keep more than the current list.

### Recommended additions

Definite:

    MSTeams
    Microsoft.CompanyPortal
    Microsoft.GetHelp
    Microsoft.PowerShell
    AppUp.IntelArcSoftware
    AppUp.IntelManagementandSecurityStatus
    MicrosoftCorporationII.MicrosoftRemoteDesktop
    MicrosoftCorporationII.Windows365
    Microsoft.RemoteDesktop
    AD2F1837                      (HP publisher prefix)
    E046963F                      (Lenovo publisher prefix)
    RealtekSemiconductorCorp
    SynapticsIncorporated
    DolbyLaboratories
    NVIDIACorp
    AdvancedMicroDevicesInc
    ELANMicroelectronics

Policy calls, decide as a team:

    Microsoft.OutlookForWindows                   (new Outlook)
    Microsoft.MicrosoftOfficeHub                  (Office launcher / M365 Copilot app)
    MicrosoftWindows.CrossDevice                  (keep, or drop Microsoft.YourPhone too)
    Microsoft.ZuneMusic                           (Media Player)
    Microsoft.ApplicationCompatibilityEnhancements

Tokens are substring-matched case-insensitively through `-notmatch`. Keep them specific;
avoid short tokens like `HP` that would match unrelated names. Currently only `Dell` and
`WavesAudio` cover OEM/driver companions.

### Drop-in replacement (also removes the duplicate "store" token)

    $GoodApps = "AppUp.IntelOptaneMemoryandStorageManagement|AppUp.IntelGraphicsExperience|AppUp.IntelArcSoftware|AppUp.IntelManagementandSecurityStatus|Windows.PrintDialog|NotepadPlusPlus|MicrosoftWindows.Client|MicrosoftCorporationII.QuickAssist|Microsoft.Winget.Source|Microsoft.WindowsAppRuntime|Microsoft.Windows.PrintQueueActionCenter|Microsoft.Win32WebViewHost|Microsoft.Todos|Microsoft.CredDialogHost|Microsoft.CompanyPortal|Microsoft.PowerShell|Microsoft.GetHelp|Microsoft.ApplicationCompatibilityEnhancements|MSTeams|Microsoft.OutlookForWindows|Microsoft.MicrosoftOfficeHub|MicrosoftCorporationII.MicrosoftRemoteDesktop|MicrosoftCorporationII.Windows365|Microsoft.RemoteDesktop|MicrosoftWindows.CrossDevice|Microsoft.ZuneMusic|Dell|AD2F1837|E046963F|RealtekSemiconductorCorp|SynapticsIncorporated|DolbyLaboratories|NVIDIACorp|AdvancedMicroDevicesInc|ELANMicroelectronics|WindowsTerminal|WavesAudio|store|calculator|camera|sticky|windows.photos|soundrecorder|mspaint|microsoft.paint|windowsnotepad|screensketch|Microsoft.HEIFImageExtension|Microsoft.WindowsNotepad|Microsoft.HEVCVideoExtension|Microsoft.VP9VideoExtensions|Microsoft.WebMediaExtensions|Microsoft.WebpImageExtension|Extension|Microsoft.YourPhone|Microsoft.MicrosoftEdge|Alarms"

### Better: stop targeting system packages at all (F4 fix)

This makes the whole `SystemApps\SxS` block, the AI Fabric packages and the shell
components untouchable without naming any of them, and keeps working as Microsoft ships
new ones.

    $RemoveApps = Get-AppxPackage -AllUsers | Where-Object {
            # Inbox shell components are SignatureKind 'System'; Store apps are 'Store'
            $_.SignatureKind -ne 'System' -and
            -not $_.IsFramework -and
            -not $_.NonRemovable -and
            $_.Name -notmatch $SafeApps
    }

    ForEach ($RemovedApp in $RemoveApps) {
            Write-Host "Removing app package: $($RemovedApp.Name)"
            Remove-AppxPackage -Package $RemovedApp.PackageFullName -AllUsers -ErrorAction SilentlyContinue
    }

Validate on a test build before rollout. This was reasoned from the package model, not
executed against a Windows host.

---

## 3. Windows 11 controls this script does not set

Backing column separates documented Microsoft policy from community registry tweaks,
which matters when a client asks us to justify a change. All apply to Windows 11 Pro.

| Control | Key and value | Backing |
|---|---|---|
| Turn off Widgets / news feed (replaces F5) | `HKLM\SOFTWARE\Policies\Microsoft\Dsh` -> `AllowNewsAndInterests` = 0 | Documented CSP/ADMX, Pro supported |
| Stop Recall saving snapshots | `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI` -> `DisableAIDataAnalysis` = 1 | Documented, Pro, 24H2 + KB5055627 |
| Remove Recall component | same key -> `AllowRecallEnablement` = 0 | Documented. Recall is already off by default on commercially managed devices |
| Disable Click to Do | same key -> `DisableClickToDo` = 1 | Documented CSP/ADMX |
| Disable Paint generative AI | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint` -> `DisableImageCreator` / `DisableCocreator` / `DisableGenerativeFill` = 1 | Documented CSP/ADMX, Pro |
| Turn off Windows Copilot | `HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot` -> `TurnOffWindowsCopilot` = 1 | Documented but DEPRECATED; Microsoft states it does not cover the current Copilot app. Remove the app instead |
| Show file extensions (security control) | `HKCU\...\Explorer\Advanced` -> `HideFileExt` = 0 | Community tweak |
| Explorer opens to This PC | `HKCU\...\Explorer\Advanced` -> `LaunchTo` = 1 | Community tweak |
| Suppress "Finish setting up your device" | `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement` -> `ScoobeSystemSettingEnabled` = 0 | Community tweak |
| Hide consumer Chat taskbar icon | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat` -> `ChatIcon` = 3 | ADMX-backed |

---

## 4. Options

Not mutually exclusive. B and C are the destination; A makes this week's builds safe.

**A. Patch what we have (do this now).** Fix F1, delete the Start menu function (F2),
extend `$GoodApps` (F3), swap the Feeds key for the Dsh policy (F5), add the section 3
controls. Roughly half a day plus a test build. Nothing about the delivery path changes
and every tech already knows the command.

**B. Adopt a maintained script (evaluate next quarter).** Andrew Taylor's
`RemoveBloat.ps1` is the closest match to how we work: built for MSPs, deployed through
Intune or an RMM, allow-list-by-default, still updated (July 2026 changelog entries),
and it already makes the correct Intune and Defender calls that F1 gets wrong. Raphire's
`Win11Debloat` is more polished with a proper CLI (`-Silent`, `-Sysprep`, per-user
targeting) but is aimed at enthusiasts rather than fleets. Cost: loses the vendor-app
handling we have tuned, and adds a third-party dependency to the build path.

**C. Move app removal into policy (where the SKU allows).** Windows 11 24H2 added
`RemoveDefaultMicrosoftStorePackages`, a supported GPO/Intune policy that removes inbox
apps and stops them coming back at the next user provisioning. Configurable from the
Settings catalog, works during Autopilot before the user reaches the desktop.
**Catch: Enterprise, Education and IoT Enterprise only. It does NOT apply to Windows 11
Pro**, which is most of a typical MSP fleet. Removals are one-way; reprovision to undo.

---

## 5. Recommendation

Patch it (A) now, plan toward a split model. Order of work:

1. **F1.** Stop disabling DiagTrack, raise `AllowTelemetry` to 1. This is quietly
   costing monitoring fidelity on every machine built so far.
2. **F2.** Delete `ClearStartMenu`. Never worked on Windows 11; it is why transcripts
   look broken.
3. **F3.** Extend `$GoodApps`. Decide the four policy calls as a team.
4. **F4.** Add the `SignatureKind` filter. This is what stops the next Windows release
   surprising us.
5. Add the section 3 controls, then the F5-F8 cleanups.

Longer term the honest split is: **policy for what policy can do** (Option C on
Enterprise/Education, plus the documented AI and Widgets policies on everything
including Pro, ideally delivered by Intune or Action1 so they reapply), and **the script
for what policy cannot**, which is OEM crapware, vendor bundles and the Pro-SKU gap.
That is a smaller, better-scoped script that stops being a fork of a 2022 Windows 10
tool.

One item to decide explicitly rather than inherit: the script currently strips
accessibility-adjacent packages (Narrator Quick Start, and whichever SxS components back
Voice Access and Live Captions) purely because they were not on a 2022 keep-list. If any
client has an accessibility obligation, that should be a deliberate exclusion, not a
side effect.

---

## Sources

1. Endpoint analytics prerequisites (DiagTrack must be enabled and running):
   https://learn.microsoft.com/intune/endpoint-analytics/#prerequisites
2. Windows Update for Business reports prerequisites (Required diagnostic data minimum):
   https://learn.microsoft.com/windows/deployment/update/wufb-reports-prerequisites#diagnostic-data-requirements
   and required services:
   https://learn.microsoft.com/windows/deployment/update/wufb-reports-configuration-manual#required-endpoints
3. Defender for Endpoint event and error codes (Events 17 and 62):
   https://learn.microsoft.com/defender-endpoint/event-error-codes
4. Import-StartLayout (deprecated on Windows 11):
   https://learn.microsoft.com/en-us/powershell/module/startlayout/import-startlayout
   Customize the Start layout for managed devices:
   https://learn.microsoft.com/en-us/windows/configuration/start/layout
5. Policy-based in-box app removal:
   https://learn.microsoft.com/windows/configuration/policy-based-inbox-app-removal/policy-based-inbox-app-removal
   RemoveDefaultMicrosoftStorePackages CSP (Enterprise/Education only):
   https://learn.microsoft.com/windows/client-management/mdm/policy-csp-applicationmanagement#removedefaultmicrosoftstorepackages
6. Policy CSP WindowsAI (Recall, Click to Do, Paint AI):
   https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai
   Manage Recall: https://learn.microsoft.com/windows/client-management/manage-recall
7. Policy CSP NewsAndInterests (AllowNewsAndInterests):
   https://learn.microsoft.com/windows/client-management/mdm/policy-csp-newsandinterests
8. andrew-s-taylor/public RemoveBloat.ps1:
   https://github.com/andrew-s-taylor/public/blob/main/De-Bloat/RemoveBloat.ps1
9. Raphire/Win11Debloat: https://github.com/Raphire/Win11Debloat
10. Microsoft 365 app transition to the Microsoft 365 Copilot app (Office Hub rename):
    https://support.microsoft.com/en-us/microsoft-365-copilot/the-microsoft-365-app-transition-to-the-microsoft-365-copilot-app
11. Intel Graphics Software FAQ (successor to Graphics Command Center):
    https://www.intel.com/content/www/us/en/support/articles/000100501/graphics.html
12. Removing Get Help breaks Windows 11 troubleshooting:
    https://github.com/undergroundwires/privacy.sexy/issues/280
