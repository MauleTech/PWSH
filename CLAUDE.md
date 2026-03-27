# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

Portable PowerShell toolbox for IT automation and maintenance (Maule Techs). Designed to be called from any internet-connected Windows machine:
- `irm ps.mauletech.com | iex` (primary)
- `irm https://raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/LoadFunctions.txt | iex` (fallback if DNS doesn't resolve)

This runs `LoadFunctions.txt` which bootstraps Git, clones the repo, and dynamically imports all `.psm1` modules.

## Architecture

- **Functions/** -- 30 verb-based modules (`PS-Install.psm1`, `PS-Get.psm1`, etc.) containing ~158 functions. No `.psd1` manifests; modules are loaded dynamically by `LoadFunctions.txt` via `Import-Module`.
- **Scripts/** -- Scenario-specific scripts (O365 migration, maintenance checks, server reboots).
- **OneOffs/** -- Ad-hoc utility scripts.
- **LoadFunctions.txt** -- Master loader: sets execution policy, configures TLS 1.2+, installs/finds MinGit, clones repo, imports all modules.
- **Sign-Scripts.ps1** -- Authenticode signing via Azure Key Vault.
- **DownloadManifest.json** -- Hash verification for trusted external downloads.

## CI/CD

- **code-signing.yml** -- Auto-signs `.ps1` and `.psm1` files on push to main (commits with `[skip ci]`).
- **claude-code-review.yml** -- Automated code review on PRs.
- **claude.yml** -- Responds to `@claude` mentions on issues/PRs.

There is no test framework (no Pester). All commits must be code reviewed for quality. Code signing and PR review are the quality gates.

## Conventions

- Functions follow `Verb-Noun` naming (e.g., `Install-WinGet`, `Get-DiskUsage`).
- All functions must have comment-based help: `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`.
- Use `[CmdletBinding()]` and typed parameters (`[string]`, `[switch]`, etc.).
- User feedback via `Write-Host -ForegroundColor` (Green=success, Red=error, Yellow=warning, Cyan=info). Pipeline output via `Write-Output`.
- **Security is a top priority.** Validate inputs, avoid command injection, and handle credentials safely.
- Credentials are prompted interactively -- never hardcoded.
- **ASCII only in .ps1/.psm1/.psd1 files.** No em-dashes or non-ASCII characters. PowerShell 5.1 reads UTF-8-without-BOM as Windows-1252, causing parse errors from multi-byte characters.
- New functions go in the existing module matching their verb (e.g., a `Get-*` function goes in `PS-Get.psm1`).

## Encryption Pattern (PS-Protect/PS-Unprotect)

Config file encryption uses AES-256-CBC with PBKDF2-SHA256 (600K iterations) and HMAC-SHA256 (Encrypt-then-MAC). Crypto objects must be disposed in `finally` blocks with explicit array clearing of key material.
