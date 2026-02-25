'use strict';

const path = require('path');

let Database;
try {
  Database = require('better-sqlite3');
} catch {
  Database = null;
}

const DEFAULT_DB_PATH = path.join(process.cwd(), 'portsentinel.db');

class ScanDatabase {
  constructor(dbPath = DEFAULT_DB_PATH) {
    if (!Database) {
      throw new Error('better-sqlite3 is not installed');
    }
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this._init();
  }

  _init() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        port_count INTEGER NOT NULL,
        open_count INTEGER NOT NULL,
        data TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS scan_ports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        port INTEGER NOT NULL,
        state TEXT NOT NULL,
        service TEXT,
        banner TEXT,
        latency REAL,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
      );

      CREATE INDEX IF NOT EXISTS idx_scans_host ON scans(host);
      CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
      CREATE INDEX IF NOT EXISTS idx_scan_ports_scan_id ON scan_ports(scan_id);
    `);
  }

  saveScan(scanResult) {
    if (!scanResult || !scanResult.host || !Array.isArray(scanResult.ports)) {
      throw new Error('Invalid scan result');
    }

    const openPorts = scanResult.ports.filter((p) => p.state === 'open');

    const insertScan = this.db.prepare(`
      INSERT INTO scans (host, timestamp, port_count, open_count, data)
      VALUES (?, ?, ?, ?, ?)
    `);

    const insertPort = this.db.prepare(`
      INSERT INTO scan_ports (scan_id, port, state, service, banner, latency)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    const transaction = this.db.transaction(() => {
      const result = insertScan.run(
        scanResult.host,
        scanResult.timestamp || new Date().toISOString(),
        scanResult.ports.length,
        openPorts.length,
        JSON.stringify(scanResult)
      );

      const scanId = result.lastInsertRowid;

      for (const p of scanResult.ports) {
        insertPort.run(
          scanId,
          p.port,
          p.state,
          p.service || null,
          p.banner || null,
          p.latency || null
        );
      }

      return scanId;
    });

    return transaction();
  }

  getLatestScan(host) {
    if (typeof host !== 'string' || host.trim().length === 0) {
      throw new Error('Host must be a non-empty string');
    }

    const row = this.db.prepare(`
      SELECT * FROM scans WHERE host = ? ORDER BY timestamp DESC LIMIT 1
    `).get(host);

    if (!row) return null;

    return JSON.parse(row.data);
  }

  getHistory(host, limit = 10) {
    if (typeof host !== 'string' || host.trim().length === 0) {
      throw new Error('Host must be a non-empty string');
    }

    const rows = this.db.prepare(`
      SELECT * FROM scans WHERE host = ? ORDER BY timestamp DESC LIMIT ?
    `).all(host, limit);

    return rows.map((row) => ({
      id: row.id,
      host: row.host,
      timestamp: row.timestamp,
      portCount: row.port_count,
      openCount: row.open_count,
    }));
  }

  getScanById(id) {
    const row = this.db.prepare('SELECT * FROM scans WHERE id = ?').get(id);
    if (!row) return null;
    return JSON.parse(row.data);
  }

  getHosts() {
    const rows = this.db.prepare(
      'SELECT DISTINCT host FROM scans ORDER BY host'
    ).all();
    return rows.map((r) => r.host);
  }

  deleteScansByHost(host) {
    if (typeof host !== 'string' || host.trim().length === 0) {
      throw new Error('Host must be a non-empty string');
    }

    const scanIds = this.db.prepare(
      'SELECT id FROM scans WHERE host = ?'
    ).all(host).map((r) => r.id);

    if (scanIds.length === 0) return 0;

    const transaction = this.db.transaction(() => {
      for (const id of scanIds) {
        this.db.prepare('DELETE FROM scan_ports WHERE scan_id = ?').run(id);
      }
      const result = this.db.prepare('DELETE FROM scans WHERE host = ?').run(host);
      return result.changes;
    });

    return transaction();
  }

  close() {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }
}

module.exports = { ScanDatabase };
