# PortSentinel

[![CI](https://github.com/your-org/portsentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/portsentinel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org/)

Real-time port scanner and service fingerprinter with change detection. Monitors network hosts, detects new open ports, identifies running services, and alerts on changes. Stores scan history in SQLite with JSON/CSV export.

## Quick Start

```bash
git clone https://github.com/your-org/portsentinel.git
cd portsentinel
npm install

# Scan a host with default ports
node bin/portsentinel.js scan 192.168.1.1

# Scan ports 1-1024 with service fingerprinting
node bin/portsentinel.js scan 192.168.1.1 -r 1-1024 -f

# Save results to database, detect changes on next run
node bin/portsentinel.js scan 192.168.1.1 -r 1-1024 -d scans.db
```

Or with Docker:

```bash
docker compose build
docker compose run --rm portsentinel scan 192.168.1.1 -r 1-1024 -f
```

## Features

- **TCP port scanning** — scan individual ports, port lists, or ranges with configurable timeouts and concurrency
- **Service fingerprinting** — banner grabbing and pattern matching to identify services (SSH, HTTP, MySQL, Redis, etc.)
- **Change detection** — compare scans to find newly opened/closed ports and service changes
- **Severity-based alerts** — automatic risk assessment with critical/warning/info levels for high-risk ports (FTP, Telnet, SMB, RDP, VNC)
- **SQLite history** — persistent scan storage with WAL mode for fast concurrent reads
- **JSON/CSV export** — export results to file or stdout
- **Docker support** — multi-stage Alpine build with docker-compose

## Installation

### From source

```bash
git clone https://github.com/your-org/portsentinel.git
cd portsentinel
npm install
```

### Global CLI install

```bash
npm install -g .
portsentinel --help
```

### Docker

```bash
docker compose build
```

**Requirements:** Node.js 18+ (tested on 18, 20, 22)

## Usage

### Scan a host (default common ports)

```bash
portsentinel scan 192.168.1.1
```

### Scan a port range

```bash
portsentinel scan 10.0.0.1 -r 1-1024
```

### Scan specific ports

```bash
portsentinel scan example.com -p 22,80,443,3306,8080
```

### Fingerprint services on open ports

```bash
portsentinel scan 10.0.0.1 -r 1-1024 -f
```

### Set connection timeout

```bash
portsentinel scan 10.0.0.1 -t 5000
```

### Export results

```bash
# JSON to stdout
portsentinel scan 10.0.0.1 --json

# CSV to stdout
portsentinel scan 10.0.0.1 --csv

# Write to file
portsentinel scan 10.0.0.1 -o results.json
portsentinel scan 10.0.0.1 -o results.csv --csv
```

### Store results in SQLite and detect changes

```bash
# First scan — saves to database
portsentinel scan 10.0.0.1 -r 1-1024 -d scans.db

# Second scan — compares with previous, alerts on changes
portsentinel scan 10.0.0.1 -r 1-1024 -d scans.db
```

### View scan history

```bash
portsentinel history 10.0.0.1 -d scans.db
portsentinel history 10.0.0.1 -d scans.db -n 20
```

### Docker

```bash
# Scan localhost ports 1-1024 (default)
docker compose up

# Custom scan
docker compose run --rm portsentinel scan 192.168.1.1 -r 1-1024 -f -d /data/scans.db
```

## CLI Reference

### `portsentinel scan <host>`

| Option | Description | Default |
|---|---|---|
| `-p, --ports <ports>` | Comma-separated port list | Common ports (26 ports) |
| `-r, --range <range>` | Port range, e.g. `1-1024` | — |
| `-t, --timeout <ms>` | Connection timeout in ms | `2000` |
| `-f, --fingerprint` | Fingerprint open ports | Off |
| `-d, --db <path>` | SQLite database path | — |
| `--json` | Output as JSON | — |
| `--csv` | Output as CSV | — |
| `-o, --output <file>` | Write output to file | — |

### `portsentinel history <host>`

| Option | Description | Default |
|---|---|---|
| `-d, --db <path>` | SQLite database path | `portsentinel.db` |
| `-n, --limit <n>` | Number of records | `10` |

## Configuration

### Default Ports

When no ports are specified, PortSentinel scans these 26 commonly targeted ports:

```
21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80 (HTTP),
110 (POP3), 111 (RPCBind), 135 (MSRPC), 139 (NetBIOS), 143 (IMAP),
443 (HTTPS), 445 (SMB), 993 (IMAPS), 995 (POP3S), 1433 (MSSQL),
1521 (Oracle), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL),
5900 (VNC), 6379 (Redis), 8080 (HTTP Proxy), 8443 (HTTPS Alt),
9090 (Web Admin), 27017 (MongoDB)
```

### High-Risk Ports

These ports trigger `CRITICAL` severity alerts when newly opened:

```
21 (FTP), 23 (Telnet), 135 (MSRPC), 139 (NetBIOS),
445 (SMB), 1433 (MSSQL), 3389 (RDP), 5900 (VNC)
```

### Scan Concurrency

Ports are scanned in batches of 100 concurrent connections by default. This can be configured programmatically via the `concurrency` option.

### Service Fingerprinting

The fingerprinter identifies services using a two-tier approach:

1. **Banner matching** (high confidence) — connects to open ports, sends protocol-specific probes (HTTP `HEAD`, Redis `PING`), and matches responses against known patterns
2. **Port-based lookup** (low confidence) — falls back to well-known port assignments when no banner is received

Recognized services: SSH, FTP, SMTP, HTTP, POP3, IMAP, MySQL, PostgreSQL, Redis, MongoDB, VNC, RDP, SMB, MSSQL, Oracle, and more.

### Alert Severity Levels

| Severity | Trigger |
|---|---|
| `CRITICAL` | High-risk port newly opened (FTP, Telnet, RDP, SMB, VNC, etc.) |
| `WARNING` | Any new port opened or service changed |
| `INFO` | Ports closed or no significant changes |

## Architecture

```
portsentinel/
├── bin/
│   └── portsentinel.js    # CLI entry point (Commander.js)
├── src/
│   ├── index.js           # Module exports
│   ├── scanner.js         # TCP port scanning (net.Socket)
│   ├── fingerprinter.js   # Banner grabbing & service identification
│   ├── detector.js        # Change detection between scans
│   ├── database.js        # SQLite storage (better-sqlite3, WAL mode)
│   ├── exporter.js        # JSON/CSV export
│   └── alerts.js          # Severity calculation & alert formatting
├── test/                  # Mocha + Chai + Sinon test suite
├── Dockerfile             # Multi-stage Alpine build
├── docker-compose.yml     # Docker Compose with host networking
└── .github/workflows/
    └── ci.yml             # CI: lint, test, coverage, security audit
```

### Pipeline

```
Host/Ports (CLI input)
        │
        ▼
   ┌─────────┐      ┌───────────────┐
   │ Scanner  │─────▶│ Fingerprinter │
   │ (TCP)    │      │ (banners)     │
   └─────────┘      └───────────────┘
        │                   │
        ▼                   ▼
   ┌──────────┐      ┌──────────┐
   │ Database │      │ Exporter │
   │ (SQLite) │      │ (JSON/   │
   └──────────┘      │  CSV)    │
        │            └──────────┘
        ▼
   ┌──────────┐      ┌────────┐
   │ Detector │─────▶│ Alerts │
   │ (diff)   │      │ (severity)│
   └──────────┘      └────────┘
```

### Module Overview

**scanner** — Core TCP scanning using `net.Socket`. Supports single port, port list, and range scanning with configurable timeout and batch concurrency. Returns structured results with port state and latency.

**fingerprinter** — Connects to open ports, sends protocol-specific probes (HTTP HEAD, Redis PING), and matches response banners against known patterns. Returns service name, banner, and confidence level (high/medium/low/none).

**detector** — Compares two scan results to identify newly opened ports, newly closed ports, and service changes. Produces a structured change report with a `hasChanges` flag.

**alerts** — Takes change reports and calculates severity based on which ports changed. High-risk ports (FTP, Telnet, RDP, SMB, VNC) trigger critical alerts. Formats alerts for console output.

**database** — SQLite persistence via `better-sqlite3` with WAL journaling. Stores full scan data as JSON with a normalized `scan_ports` table for querying. Supports history retrieval, host listing, and cleanup.

**exporter** — Converts scan results to JSON (pretty-printed) or CSV format. Writes to files with automatic directory creation.

### Programmatic API

```javascript
const { scanner, fingerprinter, detector, ScanDatabase, exporter, alerts } = require('portsentinel');

// Scan ports
const result = await scanner.scanHost('10.0.0.1', [22, 80, 443]);

// Fingerprint open ports
const fp = await fingerprinter.fingerprintScan(result);

// Store in database
const db = new ScanDatabase('./scans.db');
db.saveScan(result);

// Detect changes
const previous = db.getLatestScan('10.0.0.1');
const changes = detector.detectChanges(previous, result);

// Generate alerts
if (changes.hasChanges) {
  const alert = alerts.createAlert(changes);
  console.log(alerts.formatAlert(alert));
}

// Export
exporter.exportScan(result, 'output.json', 'json');

db.close();
```

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Lint
npm run lint
```

## License

MIT
