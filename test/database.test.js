'use strict';

const { expect } = require('chai');
const path = require('path');
const fs = require('fs');
const { ScanDatabase } = require('../src/database');

describe('Database', () => {
  const testDbPath = path.join(__dirname, 'test-portsentinel.db');
  let db;

  const sampleScan = {
    host: '10.0.0.1',
    timestamp: '2026-01-01T12:00:00.000Z',
    ports: [
      { port: 22, state: 'open', latency: 5 },
      { port: 80, state: 'open', latency: 3, service: 'http', banner: 'Apache' },
      { port: 443, state: 'closed', latency: null },
    ],
  };

  beforeEach(() => {
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
    // Also clean up WAL files
    for (const suffix of ['-wal', '-shm']) {
      const walPath = testDbPath + suffix;
      if (fs.existsSync(walPath)) {
        fs.unlinkSync(walPath);
      }
    }
    db = new ScanDatabase(testDbPath);
  });

  afterEach(() => {
    if (db) {
      db.close();
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
    for (const suffix of ['-wal', '-shm']) {
      const walPath = testDbPath + suffix;
      if (fs.existsSync(walPath)) {
        fs.unlinkSync(walPath);
      }
    }
  });

  describe('saveScan()', () => {
    it('should save a scan result and return an id', () => {
      const id = db.saveScan(sampleScan);
      expect(id).to.be.a('number');
      expect(id).to.be.greaterThan(0);
    });

    it('should save multiple scans', () => {
      const id1 = db.saveScan(sampleScan);
      const id2 = db.saveScan({ ...sampleScan, timestamp: '2026-01-02T12:00:00.000Z' });
      expect(id2).to.be.greaterThan(id1);
    });

    it('should throw on invalid scan result', () => {
      expect(() => db.saveScan(null)).to.throw('Invalid scan result');
      expect(() => db.saveScan({})).to.throw('Invalid scan result');
      expect(() => db.saveScan({ host: 'x' })).to.throw('Invalid scan result');
    });
  });

  describe('getLatestScan()', () => {
    it('should retrieve the latest scan for a host', () => {
      db.saveScan(sampleScan);
      const later = { ...sampleScan, timestamp: '2026-01-02T12:00:00.000Z' };
      db.saveScan(later);

      const result = db.getLatestScan('10.0.0.1');
      expect(result).to.not.be.null;
      expect(result.timestamp).to.equal('2026-01-02T12:00:00.000Z');
    });

    it('should return null for unknown host', () => {
      const result = db.getLatestScan('192.168.99.99');
      expect(result).to.be.null;
    });

    it('should throw on invalid host', () => {
      expect(() => db.getLatestScan('')).to.throw('Host must be a non-empty string');
    });
  });

  describe('getHistory()', () => {
    it('should return scan history ordered by most recent first', () => {
      db.saveScan({ ...sampleScan, timestamp: '2026-01-01T00:00:00.000Z' });
      db.saveScan({ ...sampleScan, timestamp: '2026-01-02T00:00:00.000Z' });
      db.saveScan({ ...sampleScan, timestamp: '2026-01-03T00:00:00.000Z' });

      const history = db.getHistory('10.0.0.1');
      expect(history).to.have.length(3);
      expect(history[0].timestamp).to.equal('2026-01-03T00:00:00.000Z');
    });

    it('should respect limit parameter', () => {
      for (let i = 1; i <= 5; i++) {
        db.saveScan({ ...sampleScan, timestamp: `2026-01-0${i}T00:00:00.000Z` });
      }

      const history = db.getHistory('10.0.0.1', 2);
      expect(history).to.have.length(2);
    });

    it('should return empty array for unknown host', () => {
      const history = db.getHistory('192.168.99.99');
      expect(history).to.deep.equal([]);
    });

    it('should include metadata in history entries', () => {
      db.saveScan(sampleScan);
      const history = db.getHistory('10.0.0.1');
      expect(history[0]).to.have.property('id');
      expect(history[0]).to.have.property('host', '10.0.0.1');
      expect(history[0]).to.have.property('portCount', 3);
      expect(history[0]).to.have.property('openCount', 2);
    });
  });

  describe('getScanById()', () => {
    it('should retrieve a scan by id', () => {
      const id = db.saveScan(sampleScan);
      const result = db.getScanById(id);
      expect(result).to.not.be.null;
      expect(result.host).to.equal('10.0.0.1');
    });

    it('should return null for unknown id', () => {
      const result = db.getScanById(999);
      expect(result).to.be.null;
    });
  });

  describe('getHosts()', () => {
    it('should return list of scanned hosts', () => {
      db.saveScan(sampleScan);
      db.saveScan({ ...sampleScan, host: '10.0.0.2' });
      db.saveScan({ ...sampleScan, host: '10.0.0.1' }); // duplicate

      const hosts = db.getHosts();
      expect(hosts).to.deep.equal(['10.0.0.1', '10.0.0.2']);
    });

    it('should return empty array when no scans', () => {
      expect(db.getHosts()).to.deep.equal([]);
    });
  });

  describe('deleteScansByHost()', () => {
    it('should delete all scans for a host', () => {
      db.saveScan(sampleScan);
      db.saveScan({ ...sampleScan, timestamp: '2026-01-02T00:00:00.000Z' });
      db.saveScan({ ...sampleScan, host: '10.0.0.2' });

      const deleted = db.deleteScansByHost('10.0.0.1');
      expect(deleted).to.equal(2);

      expect(db.getLatestScan('10.0.0.1')).to.be.null;
      expect(db.getLatestScan('10.0.0.2')).to.not.be.null;
    });

    it('should return 0 for unknown host', () => {
      const deleted = db.deleteScansByHost('192.168.99.99');
      expect(deleted).to.equal(0);
    });

    it('should throw on invalid host', () => {
      expect(() => db.deleteScansByHost('')).to.throw('Host must be a non-empty string');
    });
  });

  describe('close()', () => {
    it('should close the database connection', () => {
      db.close();
      db = null; // Prevent afterEach from double-closing
    });
  });
});
