# PortSentinel Use Cases

## 1. Continuous Server Monitoring

Track open ports on production servers over time. Run periodic scans with SQLite storage to detect unauthorized changes automatically.

```bash
# Initial baseline scan of a web server
portsentinel scan webserver.example.com -p 22,80,443 -f -d /var/lib/portsentinel/scans.db

# Subsequent scans compare against the baseline and alert on changes
portsentinel scan webserver.example.com -p 22,80,443 -f -d /var/lib/portsentinel/scans.db
```

Set this up as a cron job for automated monitoring:

```cron
# Scan every 30 minutes, alerts print to stderr (capture with logging)
*/30 * * * * portsentinel scan webserver.example.com -p 22,80,443 -f -d /var/lib/portsentinel/scans.db 2>> /var/log/portsentinel-alerts.log
```

When a new port opens (e.g., someone starts a debug service on port 9090), PortSentinel prints a severity-rated alert:

```
[WARNING] Port change alert for webserver.example.com
Time: 2026-02-25T14:30:00.000Z
  New open ports detected: 9090
```

If a high-risk port opens (FTP, Telnet, RDP, SMB, VNC, MSSQL), the alert escalates to `CRITICAL`.

## 2. Network Audit and Compliance

Scan a subnet gateway or key hosts and export structured results for compliance reporting.

```bash
# Full port range scan with fingerprinting, export to JSON
portsentinel scan 10.0.2.1 -r 1-1024 -f -o audit-firewall.json

# Export as CSV for spreadsheet analysis
portsentinel scan 10.0.2.1 -r 1-1024 -f -o audit-firewall.csv --csv
```

The JSON output includes host, timestamp, port states, latency, and identified services — ready for ingestion by SIEM tools or compliance dashboards.

## 3. Pre-Deployment Verification

Before deploying a new service, verify that only expected ports are open. After deployment, confirm the new service is reachable and correctly identified.

```bash
# Before deploy — baseline
portsentinel scan staging.example.com -r 1-65535 -d deploys.db --json > pre-deploy.json

# Deploy your service...

# After deploy — detect what changed
portsentinel scan staging.example.com -r 1-65535 -d deploys.db -f
```

The change detection output tells you exactly which ports opened/closed and whether services changed, confirming your deployment worked as expected.

## 4. Incident Response Triage

When investigating a potential breach, quickly enumerate open ports and identify running services on a suspect host.

```bash
# Fast scan of common ports with service fingerprinting
portsentinel scan 10.0.5.42 -f --json | jq '.ports[] | select(.state == "open")'
```

PortSentinel identifies services via banner grabbing — SSH versions, HTTP servers, database engines — giving responders immediate visibility into what's exposed.

## 5. Home Lab / Small Network Inventory

Monitor a home network or small office for unexpected services. Store history to track what's running over time.

```bash
# Scan the router
portsentinel scan 10.0.2.1 -r 1-1024 -f -d homelab.db

# Scan a NAS
portsentinel scan 10.0.2.50 -p 22,80,443,445,9090 -f -d homelab.db

# Review history
portsentinel history 10.0.2.1 -d homelab.db
portsentinel history 10.0.2.50 -d homelab.db
```

## 6. Docker-Based Scheduled Scanning

Run PortSentinel in a container for isolated, repeatable scans without installing Node.js on the host.

```bash
# Build the image
docker compose build

# One-off scan
docker compose run --rm portsentinel scan 192.168.1.1 -r 1-1024 -f -d /data/scans.db

# Persistent monitoring with docker compose
docker compose up
```

The Docker setup uses host networking for accurate scanning and a named volume (`portsentinel-data`) to persist the SQLite database across runs.

## 7. Programmatic Integration

Embed PortSentinel in a Node.js application for custom monitoring pipelines.

```javascript
const { scanner, fingerprinter, detector, ScanDatabase, alerts } = require('portsentinel');

async function monitor(host, ports) {
  const db = new ScanDatabase('./monitor.db');
  const previous = db.getLatestScan(host);
  const result = await scanner.scanHost(host, ports);
  const fp = await fingerprinter.fingerprintScan(result);
  result.services = fp.services;
  db.saveScan(result);

  if (previous) {
    const changes = detector.detectChanges(previous, result);
    if (changes.hasChanges) {
      const alert = alerts.createAlert(changes);
      // Send to Slack, PagerDuty, email, etc.
      notify(alerts.formatAlert(alert));
    }
  }

  db.close();
  return result;
}
```
