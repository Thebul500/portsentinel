# Deployment Guide

## Requirements

- Node.js 18+ (tested on 18, 20, 22)
- npm 9+
- Linux, macOS, or Windows (WSL recommended for Windows)

## Install from Source

```bash
git clone https://github.com/your-org/portsentinel.git
cd portsentinel
npm install
```

Run directly:

```bash
node bin/portsentinel.js scan 127.0.0.1
```

Or install globally:

```bash
npm install -g .
portsentinel scan 127.0.0.1
```

## Docker Deployment

### Build

```bash
docker compose build
```

The Dockerfile uses a multi-stage Alpine build:
1. **Builder stage** — installs `python3`, `make`, `g++` for compiling native dependencies (`better-sqlite3`)
2. **Production stage** — copies only compiled `node_modules`, source, and binary into a minimal `node:20-alpine` image

### Run a One-Off Scan

```bash
docker compose run --rm portsentinel scan 10.0.0.1 -r 1-1024 -f -d /data/scans.db
```

### Persistent Monitoring

The default `docker-compose.yml` scans `127.0.0.1` ports 1-1024 with SQLite storage:

```bash
docker compose up
```

Configuration:
- **Network mode**: `host` — required for accurate port scanning (container shares the host network stack)
- **Volume**: `portsentinel-data` mounted at `/data` — persists the SQLite database across container restarts
- **Entry point**: `node bin/portsentinel.js`

### Custom Docker Compose Override

Create a `docker-compose.override.yml` for your environment:

```yaml
services:
  portsentinel:
    command: ["scan", "10.0.0.1", "-r", "1-65535", "-f", "-d", "/data/scans.db"]
```

## Cron-Based Monitoring

For automated periodic scanning without Docker:

```bash
# /etc/cron.d/portsentinel
*/30 * * * * root /usr/local/bin/portsentinel scan 10.0.0.1 -p 22,80,443 -f -d /var/lib/portsentinel/scans.db 2>> /var/log/portsentinel.log
```

Alerts are written to stderr, so `2>>` captures them to a log file. Normal scan output goes to stdout.

## Database Location

By default, the `history` command reads from `portsentinel.db` in the current directory. For production, use an explicit path:

```bash
portsentinel scan 10.0.0.1 -d /var/lib/portsentinel/scans.db
portsentinel history 10.0.0.1 -d /var/lib/portsentinel/scans.db
```

The SQLite database uses WAL journaling mode for safe concurrent reads. No additional database server is required.
