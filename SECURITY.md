# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

Only the latest minor release of each supported major version receives security patches. We recommend always running the most recent version.

## Reporting a Vulnerability

If you discover a security vulnerability in PortSentinel, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Please use GitHub Security Advisories to report vulnerabilities: https://github.com/Thebul500/portsentinel/security/advisories

Include:

- A description of the vulnerability
- Steps to reproduce the issue
- The affected version(s)
- Any potential impact assessment

### What to Expect

- **Acknowledgment** within 48 hours of your report
- **Status update** within 7 days with an initial assessment
- **Resolution target** of 30 days for confirmed vulnerabilities

If the vulnerability is accepted, we will:

1. Develop and test a fix in a private branch
2. Assign a CVE identifier if applicable
3. Release a patched version
4. Credit you in the release notes (unless you prefer anonymity)

If the vulnerability is declined, we will provide a detailed explanation of why it does not qualify.

## Scope

The following are in scope for security reports:

- Remote code execution via crafted scan targets or inputs
- SQL injection in the SQLite history database
- Command injection through CLI arguments
- Unauthorized file system access via export paths
- Denial of service through resource exhaustion during scanning

## Security Best Practices

When running PortSentinel:

- Run with the minimum required privileges
- Restrict daemon mode access to trusted users
- Store the SQLite database in a directory with appropriate file permissions
- Validate all target specifications before scanning production networks
