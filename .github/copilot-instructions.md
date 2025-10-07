# Copilot Instructions for MauleTech/PWSH

## Overview
This repository is a collection of PowerShell functions and scripts for IT automation and maintenance, primarily used by Maule Techs. The codebase is organized by function type and scenario, with modular `.psm1` files in `Functions/` and scenario-driven scripts in `Scripts/` and `OneOffs/`.

## Loading Functions
- **Primary workflow:** Functions are loaded into a PowerShell session using either:
  - `irm rb.gy/0kyfn2 | iex`
  - `IEX(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/LoadFunctions.txt')`
- The loader script sets up environment variables, enables TLS, and ensures dependencies (e.g., Git Portable) are available.

## Directory Structure
- `Functions/`: Core function modules, each named by verb (e.g., `PS-Install.psm1`, `PS-Get.psm1`).
- `Scripts/`: Scenario-based scripts (e.g., Office 365 migration, maintenance checks).
- `OneOffs/`: Ad-hoc scripts for specific tasks.
- `LoadFunctions.txt`: Main loader script for all functions.

## Function Naming & Usage
- Functions follow a `[Verb]-[Noun]` pattern (e.g., `Install-WinGet`, `Get-DiskUsage`).
- To list available functions: see README or run `Get-Command -Module PS-* | Select Name`.
- For help on any function: `Help <function-name> -Detailed`.

## Office 365 Migration Tools
- Found in `Scripts/365-migration/`.
- Pre-migration scripts require repeated authentication with a Global Admin account.
- Data gathering is performed via PowerShell remoting and API calls.

## Conventions & Patterns
- All automation is PowerShell-centric; scripts assume Windows environment.
- Environment variables (e.g., `$ITFolder`) are set globally for path management.
- External dependencies (e.g., Git Portable) are checked and installed by loader.
- Functions are grouped by action (Add, Backup, Connect, etc.) for discoverability.

## Integration Points
- Some functions interact with external services (Office 365, Sophos, Unifi, etc.).
- Credentials and sensitive data are prompted interactively; no secrets are stored in code.

## Examples
- To install WinGet: `Install-WinGet`
- To get disk usage: `Get-DiskUsage`
- To start server maintenance: `Start-ServerMaintenance`

## Troubleshooting
- If SSL/TLS errors occur, ensure PowerShell supports TLS 1.2+.
- If functions do not load, verify internet connectivity and permissions.

---
_If you discover undocumented conventions or workflows, update this file to help future AI agents._
