'use strict';

const { expect } = require('chai');
const fs = require('fs');
const path = require('path');
const { toJSON, toCSV, writeToFile, exportScan } = require('../src/exporter');

describe('Exporter', () => {
  const sampleScan = {
    host: '10.0.0.1',
    timestamp: '2026-01-01T12:00:00.000Z',
    ports: [
      { port: 22, state: 'open', service: 'ssh', banner: null, latency: 5 },
      { port: 80, state: 'open', service: 'http', banner: 'Apache/2.4', latency: 3 },
      { port: 443, state: 'closed', latency: null },
    ],
  };

  const testDir = path.join(__dirname, 'tmp-export');

  afterEach(() => {
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true });
    }
  });

  describe('toJSON()', () => {
    it('should export scan result as pretty JSON', () => {
      const json = toJSON(sampleScan);
      const parsed = JSON.parse(json);
      expect(parsed.host).to.equal('10.0.0.1');
      expect(parsed.ports).to.have.length(3);
      expect(json).to.include('\n'); // pretty printed
    });

    it('should export compact JSON when pretty=false', () => {
      const json = toJSON(sampleScan, false);
      expect(json).to.not.include('\n');
      const parsed = JSON.parse(json);
      expect(parsed.host).to.equal('10.0.0.1');
    });

    it('should throw on null input', () => {
      expect(() => toJSON(null)).to.throw('Scan result is required');
    });
  });

  describe('toCSV()', () => {
    it('should export scan result as CSV', () => {
      const csv = toCSV(sampleScan);
      const lines = csv.split('\n');

      expect(lines[0]).to.equal('host,port,state,service,banner,latency,timestamp');
      expect(lines).to.have.length(4); // header + 3 ports
      expect(lines[1]).to.include('10.0.0.1,22,open,ssh');
      expect(lines[2]).to.include('80,open,http');
    });

    it('should handle banners with quotes', () => {
      const scan = {
        host: '10.0.0.1',
        timestamp: '2026-01-01T00:00:00.000Z',
        ports: [{ port: 80, state: 'open', banner: 'Server "test"' }],
      };
      const csv = toCSV(scan);
      expect(csv).to.include('"Server ""test"""');
    });

    it('should handle ports without optional fields', () => {
      const scan = {
        host: '10.0.0.1',
        timestamp: '2026-01-01T00:00:00.000Z',
        ports: [{ port: 80, state: 'closed' }],
      };
      const csv = toCSV(scan);
      const lines = csv.split('\n');
      expect(lines).to.have.length(2);
    });

    it('should throw on invalid input', () => {
      expect(() => toCSV(null)).to.throw('Invalid scan result');
      expect(() => toCSV({})).to.throw('Invalid scan result');
    });
  });

  describe('writeToFile()', () => {
    it('should write content to a file', () => {
      const filePath = path.join(testDir, 'test.json');
      writeToFile('{"test": true}', filePath);
      expect(fs.existsSync(filePath)).to.be.true;
      expect(fs.readFileSync(filePath, 'utf8')).to.equal('{"test": true}');
    });

    it('should create directories if needed', () => {
      const filePath = path.join(testDir, 'deep', 'nested', 'test.json');
      writeToFile('hello', filePath);
      expect(fs.existsSync(filePath)).to.be.true;
    });

    it('should throw on empty content', () => {
      expect(() => writeToFile('', 'test.json')).to.throw('Content must be a non-empty string');
    });

    it('should throw on invalid file path', () => {
      expect(() => writeToFile('data', '')).to.throw('File path must be a non-empty string');
    });
  });

  describe('exportScan()', () => {
    it('should export as JSON file', () => {
      const filePath = path.join(testDir, 'scan.json');
      exportScan(sampleScan, filePath, 'json');
      const content = fs.readFileSync(filePath, 'utf8');
      const parsed = JSON.parse(content);
      expect(parsed.host).to.equal('10.0.0.1');
    });

    it('should export as CSV file', () => {
      const filePath = path.join(testDir, 'scan.csv');
      exportScan(sampleScan, filePath, 'csv');
      const content = fs.readFileSync(filePath, 'utf8');
      expect(content).to.include('host,port,state');
    });

    it('should default to JSON format', () => {
      const filePath = path.join(testDir, 'scan.json');
      exportScan(sampleScan, filePath);
      const content = fs.readFileSync(filePath, 'utf8');
      expect(() => JSON.parse(content)).to.not.throw();
    });

    it('should throw on unsupported format', () => {
      expect(() => exportScan(sampleScan, 'test.xml', 'xml')).to.throw("Unsupported format: xml. Use 'json' or 'csv'.");
    });
  });
});
