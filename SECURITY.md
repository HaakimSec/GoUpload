# Security Policy

## Scope

This policy covers security vulnerabilities in **GoUpload itself** — the CLI tool, its worker/oracle/template engine, the optional ML server, and this repository's build/release process.

It does **not** cover vulnerabilities you discover in a *target* system while using GoUpload to test it — those are between you and the system's owner, and should be reported through that organization's own responsible disclosure process (or, if applicable, a bug bounty program).

## Supported Versions

GoUpload is developed on a rolling `main` branch with tagged releases. Security fixes are made against the latest tagged release; older tags are not separately patched.

| Version | Supported |
| ------- | --------- |
| Latest tagged release (see [Releases](https://github.com/HaakimSec/GoUpload/releases)) | ✅ |
| Older tags | ❌ |

## Reporting a Vulnerability

If you discover a security vulnerability in GoUpload itself — for example, a way a malicious scan target could exploit the scanner, unsafe handling of template files, or a flaw in the self-update mechanism — please report it privately rather than opening a public issue.

**Preferred: GitHub Private Vulnerability Reporting**
Use the "Report a vulnerability" button under this repository's [Security tab](https://github.com/HaakimSec/GoUpload/security/advisories/new). This creates a private advisory visible only to maintainers, with its own communication thread.

**Alternative: Email**
haakimsec@gmail.com

Please do not open a public GitHub issue or discussion for security vulnerabilities in the tool — this gives us a chance to release a fix before the issue is public.

### What to include

- A description of the vulnerability and its potential impact
- Steps to reproduce (a minimal example is ideal)
- The GoUpload version/commit you tested against
- Whether you've identified a fix or mitigation

### What to expect

- Acknowledgment of your report within  7 business days
- An initial assessment of severity and validity within 14 days
- Credit in the release notes / a published security advisory, if you'd like it, once a fix ships
- Coordinated disclosure — we'll work with you on timing before any public advisory or CVE is published

## Out of Scope

- Findings produced *by* GoUpload when scanning a target you don't own or lack authorization to test
- Vulnerabilities in third-party dependencies — please report those upstream, though we'll appreciate a heads-up so we can update our pinned version
- Social engineering, physical security, or denial-of-service attacks requiring unrealistic resource levels

## Recognition

Reporters of valid, previously-unknown vulnerabilities will be credited in the fix's release notes and any published security advisory, unless you prefer to remain anonymous.
