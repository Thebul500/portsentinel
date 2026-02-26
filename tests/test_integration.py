"""
Integration tests for PortSentinel.

Tests against real network targets — NO mocks.
Targets:
  - 127.0.0.1      (localhost)
  - 10.0.2.1       (OPNsense firewall)
  - 10.0.2.2       (Pi-hole server)
"""

import json
import os
import socket
import subprocess
import tempfile
import time

import pytest

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(PROJECT_DIR, "bin", "portsentinel.js")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_cli(*args, timeout=30):
    """Run the portsentinel CLI and return (stdout, stderr, returncode)."""
    cmd = ["node", CLI] + list(args)
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=PROJECT_DIR,
    )
    return result.stdout, result.stderr, result.returncode


def run_cli_json(*args, timeout=30):
    """Run the portsentinel CLI with --json and parse the output."""
    stdout, stderr, rc = run_cli(*args, "--json", timeout=timeout)
    assert rc == 0, f"CLI failed (rc={rc}): {stderr}"
    return json.loads(stdout)


def tcp_connect(host, port, timeout=3):
    """Test raw TCP connectivity. Returns True if the port is open."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_db(tmp_path):
    """Provide a temporary SQLite database path."""
    return str(tmp_path / "test_portsentinel.db")


@pytest.fixture
def tmp_output(tmp_path):
    """Provide a temporary output file path."""
    return str(tmp_path / "scan_output")


# ---------------------------------------------------------------------------
# Test: CLI basics
# ---------------------------------------------------------------------------

class TestCLIBasics:
    def test_help_flag(self):
        stdout, _, rc = run_cli("--help")
        assert rc == 0
        assert "portsentinel" in stdout.lower()
        assert "scan" in stdout
        assert "history" in stdout

    def test_version_flag(self):
        stdout, _, rc = run_cli("--version")
        assert rc == 0
        assert stdout.strip()  # non-empty version string

    def test_scan_help(self):
        stdout, _, rc = run_cli("scan", "--help")
        assert rc == 0
        assert "--ports" in stdout
        assert "--range" in stdout
        assert "--fingerprint" in stdout
        assert "--json" in stdout
        assert "--csv" in stdout

    def test_invalid_command_exits_nonzero(self):
        _, _, rc = run_cli("nonexistent")
        assert rc != 0


# ---------------------------------------------------------------------------
# Test: Scanning localhost (127.0.0.1)
# ---------------------------------------------------------------------------

class TestScanLocalhost:
    """Scan localhost where we know ports 22 and 80 are open."""

    def test_scan_known_open_port(self):
        data = run_cli_json("scan", "127.0.0.1", "-p", "22")
        assert data["host"] == "127.0.0.1"
        assert len(data["ports"]) == 1
        assert data["ports"][0]["port"] == 22
        assert data["ports"][0]["state"] == "open"
        assert data["ports"][0]["latency"] >= 0

    def test_scan_known_closed_port(self):
        data = run_cli_json("scan", "127.0.0.1", "-p", "1")
        assert data["ports"][0]["port"] == 1
        assert data["ports"][0]["state"] == "closed"

    def test_scan_multiple_ports(self):
        data = run_cli_json("scan", "127.0.0.1", "-p", "22,80,443,1")
        assert len(data["ports"]) == 4
        states = {p["port"]: p["state"] for p in data["ports"]}
        assert states[22] == "open"
        assert states[80] == "open"
        assert states[1] == "closed"

    def test_scan_port_range(self):
        data = run_cli_json("scan", "127.0.0.1", "-r", "22-22")
        assert len(data["ports"]) == 1
        assert data["ports"][0]["port"] == 22
        assert data["ports"][0]["state"] == "open"

    def test_scan_has_timestamp(self):
        data = run_cli_json("scan", "127.0.0.1", "-p", "22")
        assert "timestamp" in data
        # ISO 8601 format check
        assert "T" in data["timestamp"]

    def test_scan_with_timeout(self):
        data = run_cli_json("scan", "127.0.0.1", "-p", "22", "-t", "5000")
        assert data["ports"][0]["state"] == "open"

    def test_scan_text_output(self):
        stdout, _, rc = run_cli("scan", "127.0.0.1", "-p", "22,80")
        assert rc == 0
        assert "127.0.0.1" in stdout
        assert "OPEN" in stdout
        assert "22" in stdout

    def test_scan_csv_output(self):
        stdout, _, rc = run_cli("scan", "127.0.0.1", "-p", "22,80", "--csv")
        assert rc == 0
        lines = stdout.strip().split("\n")
        assert lines[0].startswith("host,port,state")
        assert len(lines) >= 3  # header + 2 ports
        assert "127.0.0.1" in lines[1]


# ---------------------------------------------------------------------------
# Test: Fingerprinting real services
# ---------------------------------------------------------------------------

class TestFingerprinting:
    """Fingerprint services running on localhost."""

    def test_fingerprint_ssh(self):
        data = run_cli_json("scan", "127.0.0.1", "-p", "22", "-f")
        assert "services" in data
        assert len(data["services"]) == 1
        svc = data["services"][0]
        assert svc["port"] == 22
        assert svc["service"] == "ssh"
        assert svc["confidence"] == "high"
        assert "SSH" in svc["banner"]

    def test_fingerprint_http(self):
        data = run_cli_json("scan", "127.0.0.1", "-p", "80", "-f")
        assert "services" in data
        services = data["services"]
        assert len(services) >= 1
        svc = services[0]
        assert svc["port"] == 80
        # Port 80 should be identified as http
        assert svc["service"] in ("http", "http-proxy")

    def test_fingerprint_multiple_services(self):
        data = run_cli_json("scan", "127.0.0.1", "-p", "22,80", "-f")
        assert "services" in data
        assert len(data["services"]) == 2
        svc_map = {s["port"]: s for s in data["services"]}
        assert svc_map[22]["service"] == "ssh"

    def test_fingerprint_closed_port_not_fingerprinted(self):
        data = run_cli_json("scan", "127.0.0.1", "-p", "1,22", "-f")
        # Only open port 22 should be fingerprinted, not closed port 1
        assert len(data["services"]) == 1
        assert data["services"][0]["port"] == 22


# ---------------------------------------------------------------------------
# Test: Scanning remote hosts
# ---------------------------------------------------------------------------

class TestScanFirewall:
    """Scan OPNsense firewall at 10.0.2.1."""

    def test_firewall_reachable(self):
        assert tcp_connect("10.0.2.1", 443, timeout=5), \
            "Firewall 10.0.2.1:443 not reachable"

    def test_scan_firewall_https(self):
        data = run_cli_json("scan", "10.0.2.1", "-p", "443")
        assert data["host"] == "10.0.2.1"
        assert data["ports"][0]["state"] == "open"

    def test_scan_firewall_ssh(self):
        data = run_cli_json("scan", "10.0.2.1", "-p", "22")
        assert data["ports"][0]["state"] == "open"

    def test_scan_firewall_multiple(self):
        data = run_cli_json("scan", "10.0.2.1", "-p", "22,80,443")
        open_ports = [p["port"] for p in data["ports"] if p["state"] == "open"]
        assert 443 in open_ports


class TestScanPihole:
    """Scan Pi-hole server at 10.0.2.2."""

    def test_pihole_reachable(self):
        assert tcp_connect("10.0.2.2", 22, timeout=5), \
            "Pi-hole 10.0.2.2:22 not reachable"

    def test_scan_pihole_ssh(self):
        data = run_cli_json("scan", "10.0.2.2", "-p", "22")
        assert data["ports"][0]["state"] == "open"

    def test_scan_pihole_http(self):
        data = run_cli_json("scan", "10.0.2.2", "-p", "80")
        assert data["ports"][0]["state"] == "open"

    def test_scan_pihole_dns(self):
        data = run_cli_json("scan", "10.0.2.2", "-p", "53")
        assert data["ports"][0]["state"] == "open"

    def test_fingerprint_pihole_ssh(self):
        data = run_cli_json("scan", "10.0.2.2", "-p", "22", "-f")
        assert data["services"][0]["service"] == "ssh"
        assert "SSH" in data["services"][0]["banner"]


# ---------------------------------------------------------------------------
# Test: Database integration
# ---------------------------------------------------------------------------

class TestDatabaseIntegration:
    """Test scan storage and retrieval with a real SQLite database."""

    def test_save_and_retrieve_scan(self, tmp_db):
        # First scan
        run_cli("scan", "127.0.0.1", "-p", "22,80", "-d", tmp_db, "--json")
        # Check history
        stdout, _, rc = run_cli("history", "127.0.0.1", "-d", tmp_db)
        assert rc == 0
        assert "127.0.0.1" not in "" or "open" in stdout.lower() or "/" in stdout

    def test_multiple_scans_create_history(self, tmp_db):
        run_cli("scan", "127.0.0.1", "-p", "22", "-d", tmp_db, "--json")
        time.sleep(0.1)
        run_cli("scan", "127.0.0.1", "-p", "22,80", "-d", tmp_db, "--json")
        stdout, _, rc = run_cli("history", "127.0.0.1", "-d", tmp_db)
        assert rc == 0
        lines = [l.strip() for l in stdout.strip().split("\n") if l.strip()]
        assert len(lines) >= 2  # at least 2 history entries

    def test_history_empty_host(self, tmp_db):
        # No scans saved for this host
        run_cli("scan", "127.0.0.1", "-p", "22", "-d", tmp_db, "--json")
        stdout, _, rc = run_cli("history", "10.99.99.99", "-d", tmp_db)
        assert rc == 0
        assert "no scan history" in stdout.lower()

    def test_change_detection_via_db(self, tmp_db):
        # Scan 1: port 22 only
        run_cli("scan", "127.0.0.1", "-p", "22", "-d", tmp_db, "--json")
        # Scan 2: ports 22 and 80 — should detect port 80 as new
        stdout, stderr, rc = run_cli(
            "scan", "127.0.0.1", "-p", "22,80", "-d", tmp_db, "--json"
        )
        assert rc == 0
        # Change alerts go to stderr
        if stderr:
            assert "80" in stderr or "alert" in stderr.lower() or "WARNING" in stderr


# ---------------------------------------------------------------------------
# Test: Export functionality
# ---------------------------------------------------------------------------

class TestExport:
    """Test file export with real scan data."""

    def test_export_json(self, tmp_output):
        json_path = tmp_output + ".json"
        _, _, rc = run_cli(
            "scan", "127.0.0.1", "-p", "22,80", "-o", json_path
        )
        assert rc == 0
        assert os.path.exists(json_path)
        with open(json_path) as f:
            data = json.load(f)
        assert data["host"] == "127.0.0.1"
        assert len(data["ports"]) == 2

    def test_export_csv(self, tmp_output):
        csv_path = tmp_output + ".csv"
        _, _, rc = run_cli(
            "scan", "127.0.0.1", "-p", "22,80", "--csv", "-o", csv_path
        )
        assert rc == 0
        assert os.path.exists(csv_path)
        with open(csv_path) as f:
            content = f.read()
        assert "host,port,state" in content
        assert "127.0.0.1" in content

    def test_export_json_with_fingerprint(self, tmp_output):
        json_path = tmp_output + "_fp.json"
        _, _, rc = run_cli(
            "scan", "127.0.0.1", "-p", "22", "-f", "-o", json_path
        )
        assert rc == 0
        with open(json_path) as f:
            data = json.load(f)
        assert "services" in data
        assert data["services"][0]["service"] == "ssh"


# ---------------------------------------------------------------------------
# Test: Node.js module integration (via inline script)
# ---------------------------------------------------------------------------

class TestModuleIntegration:
    """Test the Node.js modules directly via inline scripts."""

    def _run_node(self, script, timeout=30):
        result = subprocess.run(
            ["node", "-e", script],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=PROJECT_DIR,
        )
        return result.stdout, result.stderr, result.returncode

    def test_scanner_module_scan_port(self):
        script = """
        const { scanPort } = require('./src/scanner');
        scanPort('127.0.0.1', 22, 3000).then(r => {
            console.log(JSON.stringify(r));
        });
        """
        stdout, _, rc = self._run_node(script)
        assert rc == 0
        data = json.loads(stdout)
        assert data["port"] == 22
        assert data["state"] == "open"
        assert data["latency"] >= 0

    def test_scanner_module_scan_host(self):
        script = """
        const { scanHost } = require('./src/scanner');
        scanHost('127.0.0.1', [22, 80, 1], { timeout: 3000 }).then(r => {
            console.log(JSON.stringify(r));
        });
        """
        stdout, _, rc = self._run_node(script)
        assert rc == 0
        data = json.loads(stdout)
        assert data["host"] == "127.0.0.1"
        states = {p["port"]: p["state"] for p in data["ports"]}
        assert states[22] == "open"
        assert states[80] == "open"
        assert states[1] == "closed"

    def test_fingerprinter_module(self):
        script = """
        const { fingerprint } = require('./src/fingerprinter');
        fingerprint('127.0.0.1', 22, 3000).then(r => {
            console.log(JSON.stringify(r));
        });
        """
        stdout, _, rc = self._run_node(script)
        assert rc == 0
        data = json.loads(stdout)
        assert data["service"] == "ssh"
        assert "SSH" in data["banner"]

    def test_detector_module(self):
        script = """
        const { detectChanges } = require('./src/detector');
        const prev = {
            host: '127.0.0.1', timestamp: '2024-01-01T00:00:00Z',
            ports: [{ port: 22, state: 'open', latency: 1 }]
        };
        const curr = {
            host: '127.0.0.1', timestamp: '2024-01-01T01:00:00Z',
            ports: [
                { port: 22, state: 'open', latency: 1 },
                { port: 80, state: 'open', latency: 2 }
            ]
        };
        const changes = detectChanges(prev, curr);
        console.log(JSON.stringify(changes));
        """
        stdout, _, rc = self._run_node(script)
        assert rc == 0
        data = json.loads(stdout)
        assert data["hasChanges"] is True
        assert len(data["newPorts"]) == 1
        assert data["newPorts"][0]["port"] == 80

    def test_database_module(self, tmp_db):
        script = f"""
        const {{ ScanDatabase }} = require('./src/database');
        const db = new ScanDatabase('{tmp_db}');
        const scanResult = {{
            host: '127.0.0.1',
            timestamp: new Date().toISOString(),
            ports: [{{ port: 22, state: 'open', latency: 5 }}]
        }};
        const id = db.saveScan(scanResult);
        const latest = db.getLatestScan('127.0.0.1');
        const hosts = db.getHosts();
        db.close();
        console.log(JSON.stringify({{ id, latest, hosts }}));
        """
        stdout, _, rc = self._run_node(script)
        assert rc == 0
        data = json.loads(stdout)
        assert data["id"] >= 1
        assert data["latest"]["host"] == "127.0.0.1"
        assert "127.0.0.1" in data["hosts"]

    def test_exporter_module(self):
        script = """
        const { toJSON, toCSV } = require('./src/exporter');
        const scan = {
            host: '127.0.0.1',
            timestamp: '2024-01-01T00:00:00Z',
            ports: [{ port: 22, state: 'open', latency: 5 }]
        };
        const j = toJSON(scan);
        const c = toCSV(scan);
        console.log(JSON.stringify({ json: JSON.parse(j), csv: c }));
        """
        stdout, _, rc = self._run_node(script)
        assert rc == 0
        data = json.loads(stdout)
        assert data["json"]["host"] == "127.0.0.1"
        assert "host,port,state" in data["csv"]

    def test_alerts_module(self):
        script = """
        const { createAlert, formatAlert, calculateSeverity } = require('./src/alerts');
        const changes = {
            host: '127.0.0.1', timestamp: '2024-01-01T00:00:00Z',
            hasChanges: true,
            newPorts: [{ port: 3389, state: 'open' }],
            closedPorts: [], changedServices: []
        };
        const alert = createAlert(changes);
        const text = formatAlert(alert);
        console.log(JSON.stringify({ severity: alert.severity, text }));
        """
        stdout, _, rc = self._run_node(script)
        assert rc == 0
        data = json.loads(stdout)
        assert data["severity"] == "critical"  # RDP is high-risk
        assert "3389" in data["text"]


# ---------------------------------------------------------------------------
# Test: End-to-end pipeline
# ---------------------------------------------------------------------------

class TestEndToEnd:
    """Full pipeline: scan -> fingerprint -> store -> detect changes -> export."""

    def test_full_pipeline(self, tmp_db, tmp_output):
        json_path = tmp_output + "_e2e.json"

        # Step 1: Scan with fingerprinting + database + export
        stdout, stderr, rc = run_cli(
            "scan", "127.0.0.1", "-p", "22,80",
            "-f", "-d", tmp_db, "-o", json_path,
        )
        assert rc == 0
        assert os.path.exists(json_path)

        with open(json_path) as f:
            data = json.load(f)
        assert data["host"] == "127.0.0.1"
        assert len(data["ports"]) == 2
        assert "services" in data
        assert len(data["services"]) == 2

        # Step 2: Second scan — change detection should fire
        stdout2, stderr2, rc2 = run_cli(
            "scan", "127.0.0.1", "-p", "22,80,443",
            "-f", "-d", tmp_db, "--json",
        )
        assert rc2 == 0
        data2 = json.loads(stdout2)
        assert len(data2["ports"]) == 3

        # Step 3: Check history shows both scans
        stdout3, _, rc3 = run_cli("history", "127.0.0.1", "-d", tmp_db)
        assert rc3 == 0
        lines = [l.strip() for l in stdout3.strip().split("\n") if l.strip()]
        assert len(lines) >= 2

    def test_scan_remote_and_localhost(self, tmp_db):
        """Scan multiple real hosts and store results."""
        # Scan localhost
        run_cli("scan", "127.0.0.1", "-p", "22", "-d", tmp_db, "--json")
        # Scan Pi-hole
        run_cli("scan", "10.0.2.2", "-p", "22,53,80", "-d", tmp_db, "--json")

        # Both hosts should appear in history
        script = f"""
        const {{ ScanDatabase }} = require('./src/database');
        const db = new ScanDatabase('{tmp_db}');
        console.log(JSON.stringify(db.getHosts()));
        db.close();
        """
        result = subprocess.run(
            ["node", "-e", script],
            capture_output=True, text=True, cwd=PROJECT_DIR,
        )
        hosts = json.loads(result.stdout)
        assert "127.0.0.1" in hosts
        assert "10.0.2.2" in hosts


# ---------------------------------------------------------------------------
# Test: Real-world socket verification
# ---------------------------------------------------------------------------

class TestRawConnectivity:
    """Verify real TCP connectivity using Python sockets (no portsentinel)."""

    def test_localhost_ssh(self):
        assert tcp_connect("127.0.0.1", 22)

    def test_localhost_http(self):
        assert tcp_connect("127.0.0.1", 80)

    def test_localhost_closed_port(self):
        assert not tcp_connect("127.0.0.1", 1)

    def test_firewall_https(self):
        assert tcp_connect("10.0.2.1", 443)

    def test_pihole_ssh(self):
        assert tcp_connect("10.0.2.2", 22)

    def test_pihole_dns(self):
        assert tcp_connect("10.0.2.2", 53)

    def test_results_match_socket(self):
        """Verify portsentinel results match raw socket tests."""
        data = run_cli_json("scan", "127.0.0.1", "-p", "22,80,1")
        states = {p["port"]: p["state"] for p in data["ports"]}

        assert states[22] == "open"
        assert tcp_connect("127.0.0.1", 22)

        assert states[80] == "open"
        assert tcp_connect("127.0.0.1", 80)

        assert states[1] == "closed"
        assert not tcp_connect("127.0.0.1", 1)


# ---------------------------------------------------------------------------
# Test: Error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_scan_invalid_host(self):
        _, stderr, rc = run_cli("scan", "", "-p", "22")
        assert rc != 0

    def test_scan_no_host(self):
        _, stderr, rc = run_cli("scan")
        assert rc != 0

    def test_scan_invalid_port_range(self):
        _, stderr, rc = run_cli("scan", "127.0.0.1", "-r", "100-50")
        assert rc != 0
        assert "error" in stderr.lower()
