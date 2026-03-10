# Plan: Clean up Drive Space Script Improvements

## Script Analysis

**Intent:** This script is a comprehensive Windows disk cleanup utility designed for IT/MSP use. It runs remotely (via `Invoke-RestMethod | Invoke-Expression`), captures before/after disk metrics, and performs a wide range of cleanup operations including:

- Temp file cleanup (system + per-user)
- Browser cache/data removal (Chrome, Firefox, Edge, IE)
- Windows Update cache purging
- WinSxS component cleanup (DISM)
- Stale user profile removal (>731 days)
- Duplicate driver removal
- Orphaned MSI/MSP installer cleanup
- Recycle Bin emptying
- Event log clearing
- Restore point removal (non-Server only)
- Windows Disk Cleanup Manager (cleanmgr.exe)
- Downloads deduplication
- Hibernation file removal
- WMI repository cleanup
- Crash dump removal
- Old Windows upgrade remnants ($WINDOWS.~BT, Windows.old, etc.)

---

## Recommendation 1: Additional Safe Cleanup Targets

### A. NTFS Compression on Low-Access System Directories

The following directories are rarely read and compress very well with NTFS compression, with minimal/no performance impact:

1. **`C:\Windows\Installer`** — Contains cached MSI files for installed programs. These are only accessed during repair/uninstall operations. Compression typically yields 40-60% savings. This folder can grow to many GB.
   ```powershell
   compact /C /S:"$Env:SystemRoot\Installer" /I /Q
   ```

2. **`C:\Windows\Logs`** — Log files compress extremely well (80%+) and are rarely read.
   ```powershell
   compact /C /S:"$Env:SystemRoot\Logs" /I /Q
   ```

3. **`C:\Windows\WinSxS\Backup`** — Backup copies of system files; only accessed during repair.
   ```powershell
   compact /C /S:"$Env:SystemRoot\WinSxS\Backup" /I /Q
   ```

4. **`C:\Windows\INF`** — Driver information files, heavily text-based, compress well.
   ```powershell
   compact /C /S:"$Env:SystemRoot\INF" /I /Q
   ```

5. **`C:\Windows\Help`** — Help files, rarely accessed.
   ```powershell
   compact /C /S:"$Env:SystemRoot\Help" /I /Q
   ```

6. **`C:\Windows\Fonts`** (with caution) — Font files are loaded at boot but cached in memory; compression has minimal ongoing impact. However, this is lower priority due to marginal savings.

**Note:** Do NOT compress `C:\Windows\System32`, `C:\Windows\SysWOW64`, or `C:\Windows\WinSxS` root — these are hot paths and compression would degrade performance.

### B. Additional Cleanup Paths Not Currently Covered

7. **Windows Delivery Optimization Cache** — Can be very large (multiple GB). Files are used for P2P Windows Update sharing.
   ```powershell
   Delete-DeliveryOptimizationCache -Force
   # Or manually: "$Env:SystemRoot\SoftwareDistribution\DeliveryOptimization"
   ```

8. **Windows Font Cache** — Rebuilt automatically on next boot.
   ```powershell
   # "$Env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\FontCache\*.dat"
   ```

9. **Thumbnail Cache** — Per-user thumbnail databases that regenerate automatically.
   ```powershell
   # "$LocalAppData\Microsoft\Windows\Explorer\thumbcache_*.db"
   ```

10. **Windows Error Reporting (local dumps)** — CrashDump files from application crashes.
    ```powershell
    # "$LocalAppData\CrashDumps"
    # "$RootAppData\CrashDumps"
    ```

11. **Teams Classic cache** (if still present on legacy machines):
    ```powershell
    # "$LocalAppData\Microsoft\Teams\Cache"
    # "$LocalAppData\Microsoft\Teams\blob_storage"
    # "$LocalAppData\Microsoft\Teams\databases"
    # "$LocalAppData\Microsoft\Teams\GPUCache"
    # "$LocalAppData\Microsoft\Teams\IndexedDB"
    # "$LocalAppData\Microsoft\Teams\Local Storage"
    # "$LocalAppData\Microsoft\Teams\tmp"
    ```

12. **New Teams (ms-teams) cache**:
    ```powershell
    # "$LocalAppData\Packages\MSTeams_*\LocalCache"
    ```

13. **Windows Search Index** — Can be rebuilt; sometimes grows very large.
    ```powershell
    # Stop WSearch service, delete "$Env:ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb", restart WSearch
    ```
    **Caution:** This requires the search index to fully rebuild, which takes time and CPU. Best suited for emergency space recovery.

14. **Outlook AutoComplete (NK2/dat streams)** and **OST recreation note** — The script already handles stale OSTs. Consider also cleaning Outlook temp attachment folders:
    ```powershell
    # "$LocalAppData\Microsoft\Windows\INetCache\Content.Outlook\*"
    ```

15. **`.tmp` files on the system drive root** — Scattered temp files from various installers:
    ```powershell
    # "$Env:SystemDrive\*.tmp"
    ```

16. **NVIDIA / AMD GPU shader caches**:
    ```powershell
    # "$LocalAppData\NVIDIA\DXCache"
    # "$LocalAppData\NVIDIA\GLCache"
    # "$LocalAppData\AMD\DxCache"
    # "$LocalAppData\AMD\GLCache"
    ```

---

## Recommendation 2: Reorder Operations by Impact (Biggest First)

The current script interleaves operations without prioritizing by expected space recovery. Below is the recommended execution order, grouped by typical impact (largest to smallest):

### Phase 1: Pre-requisites (keep as-is)
1. Record pre-cleanup disk state
2. Regenerate .NET Native Images
3. Stop Windows Update service
4. Disable hibernation (`powercfg -h off`) — **This alone can free 2-8+ GB** (40% of RAM). Move this to the very top of cleanup actions since it's instant and high-impact.

### Phase 2: Highest Impact Deletions (typically multi-GB each)
5. **Delete `Windows.old`** (~10-30 GB when present)
6. **Delete `$WINDOWS.~BT`, `$WINDOWS.~WS`, `$GetCurrent`, `$WinREAgent`** (upgrade remnants, can be 5-20 GB)
7. **WinSxS cleanup via DISM** (`/StartComponentCleanup /ResetBase`) — often 1-5+ GB
8. **`StartComponentCleanup` scheduled task**
9. **`DISM /Online /Set-ReservedStorageState /State:Disabled`** — frees ~7 GB of reserved storage
10. **Remove stale user profiles** (can be many GB per profile)
11. **Empty Recycle Bin** (highly variable, often multi-GB)
12. **Delete `MEMORY.dmp`** (can be full RAM size, e.g. 16 GB)
13. **Delete `C:\MSOCache`** (Office installation cache, 1-3 GB)
14. **Clean Windows Update downloads** (`SoftwareDistribution\Download`) — often 1-5 GB
15. **NEW: Delivery Optimization Cache cleanup** — often 1-5 GB

### Phase 3: Medium Impact (hundreds of MB to a few GB)
16. **Temp folder cleanup** (`C:\Windows\Temp`, user temp, `C:\Temp`)
17. **Browser caches** (Chrome, Edge, Firefox, IE — combined can be 1-5 GB across users)
18. **`cleanmgr.exe`** runs (`/verylowdisk` and `/sagerun`) — catches misc items
19. **Orphaned MSI/MSP installer files** — often hundreds of MB to several GB
20. **Stale Outlook OST/BAK files** (can be 1-10 GB each)
21. **NEW: Outlook temp attachments** (`Content.Outlook`)
22. **Remove Restore Points / Shadow Copies** (variable, often 1-10 GB)
23. **Downloads deduplication**
24. **NEW: Teams cache cleanup**

### Phase 4: Lower Impact (tens to hundreds of MB)
25. **Crash dumps** (`*.dmp`, `LiveKernelReports`, `minidump`)
26. **Log file cleanup** (CBS, DISM, WindowsUpdate, WER, various)
27. **Duplicate driver removal**
28. **WMI repository salvage**
29. **IE temp data via rundll32**
30. **Event log clearing**
31. **Prefetch cleanup**
32. **Java/Flash/Adobe caches**
33. **RDP cache files**
34. **WinSxS ManifestCache**
35. **`C:\Intel`**, **`C:\PerfLogs`**, **`C:\swsetup`**, **`C:\swtools`**
36. **`.chk` files from chkdsk**
37. **NEW: GPU shader caches**
38. **NEW: Thumbnail caches**
39. **NEW: Font cache files**

### Phase 5: NTFS Compression (runs last, non-destructive, reclaims space in-place)
40. **NEW: Compress `C:\Windows\Installer`**
41. **NEW: Compress `C:\Windows\Logs`**
42. **NEW: Compress `C:\Windows\WinSxS\Backup`**
43. **NEW: Compress `C:\Windows\INF`**
44. **NEW: Compress `C:\Windows\Help`**

### Phase 6: Post-cleanup (keep as-is)
45. Restart Windows Update service
46. Record post-cleanup disk state and report results

---

## Recommendation 3: Structural Improvements

### A. Consolidate the three path lists by impact
Currently the script has `$FoldersToClean` (age-based deletion), `$PathsToDelete` (full deletion), and `$FoldersToDeDuplicate`. Reorder items within each list so the highest-impact paths come first. This way, if the script is interrupted or times out, the most impactful cleanup has already run.

### B. Move inline commands into the ordered flow
Several high-impact operations (like DISM cleanup, `powercfg -h off`, and `Remove-StaleProfiles`) currently run as inline commands between the list processing blocks. These should be explicitly sequenced into the ordered execution flow so the biggest wins happen first.

### C. Add a compression function
Create a new function (e.g., `Enable-NTFSCompression`) that wraps `compact /C /S:<path> /I /Q` with error handling and logging, then call it for each target directory in Phase 5.

### D. Consider a Delivery Optimization cleanup function
Wrap `Delete-DeliveryOptimizationCache` with a fallback to manual path deletion for older Windows versions that don't have the cmdlet.

---

## Summary of Changes

| Category | Items | Expected Impact |
|----------|-------|-----------------|
| New cleanup targets | 10 new paths/operations | Moderate to High |
| NTFS compression targets | 5 directories | Moderate (non-destructive) |
| Reordering by impact | All existing + new items | Script is more effective if interrupted early |
| Structural improvements | 4 changes | Better maintainability |
