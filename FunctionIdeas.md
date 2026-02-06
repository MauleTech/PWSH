# Future Function Ideas

Based on a review of all 150+ existing functions across 26 modules, the following 10 concepts address gaps in the current library. Each builds on existing patterns and tools already in use.

---

### 1. `Get-LocalAdminAudit`
Scan one or more machines and report all members of the local Administrators group. Flag non-standard accounts (anything beyond the built-in Administrator and the expected domain admin group). Output a CSV for security compliance audits where local admin sprawl is a common finding.

### 2. `Export-UserOffboardingPackage`
Single orchestration function for employee offboarding. Chains existing capabilities: converts mailbox to shared (`Convert-ToSharedMailbox`), exports OneDrive (`Export-UsersOneDrive`), disables the AD account, strips group memberships, and generates a summary report. One command with a `-Username` parameter replaces a multi-step manual checklist.

### 3. `Test-PrinterConnectivity`
Accepts a printer IP/hostname (or queries AD print server queues) and tests ICMP ping, SNMP status, port 9100 (RAW), and port 631 (IPP). Returns toner level, page count, and error state where SNMP is available. Targets printer issues — one of the highest-volume IT support ticket categories.

### 4. `Sync-SharedMailboxPermissions`
Audits current Full Access / Send-As / Send-on-Behalf permissions on a shared mailbox and compares against a CSV or AD group as the source of truth. Reports permission drift and optionally reconciles. Fills the ongoing permission management gap between `Get-UserMailboxAccess` and `Convert-ToSharedMailbox`.

### 5. `Get-EndpointComplianceReport`
Queries a target machine and returns a single compliance scorecard: BitLocker status, OS patch level (days since last update), antivirus definition age, firewall state, Secure Boot status, and TPM version. Outputs pass/fail per check. Consolidates information currently gathered individually across `Get-BitLockerKey`, `Enable-DellSecureBoot`, and `Update-Windows`.

### 6. `Install-NewMachineBaseline`
A deployment pipeline that chains existing install functions (`Install-Choco`, `Install-WinGet`, `Install-O365`, `Install-ScreenConnect`, `Install-Action1`, `Install-UmbrellaDns`, `Install-AppDefaults`) driven by a site-specific JSON/CSV configuration file. Accepts a `-SiteProfile` parameter (e.g., `"ClientA-Desktop"`) that defines which apps and settings to apply per client.

### 7. `Watch-ServiceHealth`
Lightweight polling monitor for critical services (DNS, DHCP, Print Spooler, backup agents, etc.) on one or more servers at a configurable interval. Sends desktop toast notification or Teams/Slack webhook when a service stops. Bridges the gap between existing `Get-*` status functions and a full RMM solution.

### 8. `Repair-UserProfile`
Detects and fixes common Windows user profile corruption: recreates the NTUSER.DAT registry hive link, resets the profile path in `HKLM\...\ProfileList`, and optionally migrates data from a `.bak` profile to a fresh one. Targets the "user gets a temp profile / can't log in" scenario using existing capabilities from `Get-UserProfileSpace` and `Remove-PathForcefully`.

### 9. `Compare-GroupPolicyBaseline`
Exports the applied GPO resultant set (RSoP) from a target machine and diffs it against a known-good baseline export. Highlights missing policies, changed settings, and inheritance conflicts. Addresses the "this machine isn't behaving like the others" escalation that currently requires manual `gpresult` comparison.

### 10. `Send-BulkWakeAndPatch`
Combines `Send-WakeOnLan` with `Update-Windows` (and optionally `Update-Everything`) for after-hours maintenance windows. Accepts a CSV or AD OU of machines, sends WOL packets, waits for online status, runs updates in parallel via PSRemoting, and produces a completion report. Turns two existing standalone functions into a single maintenance-window workflow.
