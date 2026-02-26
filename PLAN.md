# PortSentinel — Project Plan

## Architecture

### System Design

PortSentinel is a modular, pipeline-based network monitoring tool. Each stage of the pipeline operates independently and can be used standalone as a library or composed through the CLI.

```
Input (CLI / API)
  |
  v
+------------------+     +---------------------+
|    Scanner        | --> |   Fingerprinter      |
| (TCP connect)     |     | (banner grab +       |
|                   |     |  pattern matching)    |
+------------------+     +---------------------+
         |                         |
         v                         v
+--------------------------------------------------+
|              Change Detector                      |
|  (diff current scan against previous from DB)     |
+--------------------------------------------------+
         |                         |
         v                         v
+------------------+     +---------------------+
|    Alert Engine   |     |    Database (SQLite) |
| (severity-based   |     | (scan history,       |
|  risk assessment) |     |  WAL mode)           |
+------------------+     +---------------------+
         |
         v
+------------------+
|    Exporter       |
| (JSON / CSV /     |
|  console output)  |
+------------------+
```

### Components

| Component | File | Responsibility |
|-----------|------|----------------|
| **Scanner** | `src/scanner.js` | TCP connect scanning with concurrency control. Pure `net.Socket` — no raw packets, no root required. Scans single ports, lists, or ranges with configurable timeout and parallelism (default: 100 concurrent). |
| **Fingerprinter** | `src/fingerprinter.js` | Service identification via banner grabbing and protocol-specific probes (HTTP HEAD, Redis PING). Matches against 15+ service patterns (SSH, FTP, SMTP, HTTP, MySQL, PostgreSQL, MongoDB, Redis, VNC, etc.) with confidence scoring (high/medium/low/none). |
| **Detector** | `src/detector.js` | Compares two scan snapshots to identify new open ports, newly closed ports, and service version changes. Produces a structured diff with `hasChanges` flag. |
| **Alert Engine** | `src/alerts.js` | Risk-based severity classification. High-risk ports (FTP/21, Telnet/23, SMB/445, RDP/3389, VNC/5900) trigger CRITICAL alerts. Other new ports produce WARNING. Info-only for closed ports or no changes. |
| **Database** | `src/database.js` | SQLite via `better-sqlite3` with WAL mode. Two tables: `scans` (full JSON blob + metadata) and `scan_ports` (normalized port rows for querying). Supports history retrieval, host listing, and cleanup. |
| **Exporter** | `src/exporter.js` | Output formatting to JSON (pretty-printed) or CSV with proper escaping. Supports file export with automatic directory creation. |
| **CLI** | `bin/portsentinel.js` | Commander.js interface with two commands: `scan` (full pipeline) and `history` (query past scans). Wires all components together. |

### Data Flow

1. **Scan phase**: Scanner opens TCP connections to target ports, records open/closed state and latency.
2. **Fingerprint phase** (optional): For each open port, Fingerprinter connects, sends a protocol probe, reads the banner, and matches it against known service patterns.
3. **Detection phase** (requires database): Database retrieves the most recent scan for the host. Detector diffs the current and previous scans.
4. **Alert phase**: Alert Engine evaluates the diff, assigns severity based on which ports changed and their risk level.
5. **Output phase**: Results are formatted and sent to stdout (JSON/CSV/table) or written to file. Alerts go to stderr.

### Design Principles

- **No root required**: TCP connect scan works as unprivileged user, unlike SYN scans.
- **Minimal dependencies**: 2 production deps (`better-sqlite3`, `commander`). Everything else is Node.js stdlib.
- **Dual-use**: Every module works as a standalone library import or through the CLI.
- **Stateful monitoring**: SQLite history enables change detection without external infrastructure.
- **Pipeline composition**: Each component takes structured input and produces structured output — they compose cleanly.

---

## Technology

### Language: Node.js (JavaScript)

**Why Node.js:**
- Native async I/O is ideal for concurrent network operations (scanning hundreds of ports simultaneously).
- `net.Socket` provides TCP connect scanning without native binaries or root privileges.
- npm ecosystem for distribution — users install with `npm install -g portsentinel`.
- Runs on Linux, macOS, and Windows without platform-specific builds (except the SQLite native addon).
- Target audience (developers, DevOps) already has Node.js installed.

### Core Libraries

| Library | Version | Purpose | Why This One |
|---------|---------|---------|--------------|
| **better-sqlite3** | ^11.0.0 | Persistent scan history | Synchronous API avoids callback complexity for database ops. WAL mode gives concurrent read performance. 10-100x faster than `sqlite3` (async wrapper). Single-file database — zero infrastructure. |
| **commander** | ^12.0.0 | CLI argument parsing | De facto standard for Node.js CLIs. Declarative option definitions, automatic help generation, subcommand support. |

### Dev Dependencies

| Library | Purpose |
|---------|---------|
| **mocha** | Test runner — mature, well-supported, good async handling |
| **chai** | BDD assertions (`expect(...).to.equal(...)`) |
| **sinon** | Stubs/mocks for isolating I/O in tests |
| **nyc** | Istanbul-based code coverage reporting |
| **eslint** | Static analysis and style enforcement |

### Why Not Alternatives

- **Why not Nmap bindings?** Adds a heavy native dependency, requires Nmap installed, often needs root. PortSentinel targets lightweight monitoring, not full security auditing.
- **Why not raw sockets (SYN scan)?** Requires root/CAP_NET_RAW. TCP connect is sufficient for port monitoring and change detection use cases.
- **Why SQLite over PostgreSQL/Redis?** Zero infrastructure. A single `.db` file travels with the project. WAL mode handles the read-heavy workload (history queries during scans).
- **Why not TypeScript?** Keeps the project simple. No build step. Source files run directly. For a focused tool with 7 modules and 111 tests, the type safety tradeoff isn't worth the complexity.

---

## Milestones

### Phase 1: Core Engine (COMPLETE)

**Deliverables:**
- [x] TCP port scanner with concurrency control (`src/scanner.js`)
- [x] Service fingerprinting with banner grabbing (`src/fingerprinter.js`)
- [x] Change detection between scan snapshots (`src/detector.js`)
- [x] Severity-based alert engine (`src/alerts.js`)
- [x] SQLite persistence with WAL mode (`src/database.js`)
- [x] JSON/CSV export (`src/exporter.js`)
- [x] CLI with `scan` and `history` commands (`bin/portsentinel.js`)
- [x] Unit tests for all modules (111 tests passing)
- [x] ESLint configuration and clean lint

### Phase 2: Production Packaging (COMPLETE)

**Deliverables:**
- [x] `package.json` with proper metadata, bin entry, scripts
- [x] Multi-stage Dockerfile (Alpine, minimal image)
- [x] `docker-compose.yml` with host networking and persistent volume
- [x] GitHub Actions CI (test matrix: Node 18/20/22, lint, coverage, security audit)
- [x] `.gitignore`, `.dockerignore` for clean builds
- [x] MIT License
- [x] README with installation, usage examples, and API docs
- [x] Competitive analysis (`ANALYSIS.md`)

### Phase 3: Quality & Documentation (CURRENT)

**Deliverables:**
- [x] Project plan (`PLAN.md` — this document)
- [ ] Integration tests — end-to-end CLI test covering scan + fingerprint + database + change detection pipeline
- [ ] Performance benchmarks (`BENCHMARKS.md`) — scan throughput at various concurrency levels, database write/read latency
- [ ] `SECURITY.md` — vulnerability reporting policy, security considerations for network scanning tools
- [ ] `CONTRIBUTING.md` — development setup, coding standards, PR process, test requirements
- [ ] `CHANGELOG.md` — version history following Keep a Changelog format
- [ ] CI badge in README
- [ ] `docs/` directory with use-case guides (homelab monitoring, CI security checks, library usage)
- [ ] SBOM generation (`sbom.json`) via `npm sbom`
- [ ] Validation report (`VALIDATION.md`) — real-world testing against known hosts

### Phase 4: Feature Expansion (PLANNED)

**Deliverables:**
- [ ] **Daemon mode**: Background process with configurable scan intervals, automatic change detection and alerting
- [ ] **Webhook alerts**: POST scan results and alerts to configurable HTTP endpoints (Slack, Discord, custom)
- [ ] **UDP scanning**: Basic UDP port checks for DNS (53), SNMP (161), NTP (123)
- [ ] **Scan profiles**: Predefined port lists (quick/web/database/full) selectable via `--profile`
- [ ] **Host discovery**: CIDR range input with concurrent host scanning (`portsentinel scan 10.0.0.0/24`)
- [ ] **Rate limiting**: Configurable packets-per-second to avoid triggering IDS/firewall rules

### Phase 5: Ecosystem (FUTURE)

**Deliverables:**
- [ ] **npm publish**: Package on npmjs.com for `npm install -g portsentinel`
- [ ] **Docker Hub image**: Pre-built multi-arch images
- [ ] **Prometheus metrics endpoint**: Expose scan results as metrics for Grafana dashboards
- [ ] **Configuration file**: YAML/JSON config for persistent settings (default ports, timeout, database path, alert destinations)
- [ ] **Plugin system**: Custom service fingerprint patterns loadable from external files
