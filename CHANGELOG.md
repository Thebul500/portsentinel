# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-25

### Added

- TCP port scanner with configurable timeout and batched concurrency
- Scan individual ports, port lists, or port ranges (1-65535)
- 26 common ports scanned by default (FTP, SSH, HTTP, HTTPS, databases, etc.)
- Service fingerprinting via banner grabbing with protocol-specific probes
- Banner pattern matching for SSH, FTP, SMTP, HTTP, POP3, IMAP, MySQL, Redis, VNC, MongoDB, PostgreSQL
- Confidence-level service identification (high/medium/low/none)
- Change detection engine comparing consecutive scans for a host
- Detection of newly opened ports, closed ports, and service changes
- Human-readable change summary reports
- Alert system with severity levels (info, warning, critical)
- High-risk port classification (FTP, Telnet, MSRPC, NetBIOS, SMB, MSSQL, RDP, VNC)
- SQLite scan history database with WAL mode for concurrent reads
- Indexed tables for fast host and timestamp lookups
- Scan history browsing with configurable limits
- JSON and CSV export formats
- File export with automatic directory creation
- CLI with `scan` and `history` commands via Commander.js
- Port specification via `--ports`, `--range`, or default common ports
- `--fingerprint` flag for service identification during scans
- `--json` and `--csv` output flags
- `--output` flag to write results to a file
- `--db` flag for persistent scan storage and change detection
- Docker support with multi-stage build and non-root container
- Docker Compose configuration for quick deployment
- GitHub Actions CI pipeline with lint, test, and coverage
- ESLint configuration for code quality
- NYC/Istanbul test coverage configuration
- Unit tests for all modules (scanner, fingerprinter, detector, database, exporter, alerts)
- Integration tests against real network targets
- MIT license

[1.0.0]: https://github.com/portsentinel/portsentinel/releases/tag/v1.0.0
