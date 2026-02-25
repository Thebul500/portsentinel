'use strict';

const { expect } = require('chai');
const { detectChanges, detectServiceChanges, summarizeChanges } = require('../src/detector');

describe('Detector', () => {
  const baseScan = (ports, services) => ({
    host: '10.0.0.1',
    timestamp: '2026-01-01T00:00:00.000Z',
    ports,
    services: services || [],
  });

  describe('detectChanges()', () => {
    it('should detect newly opened ports', () => {
      const prev = baseScan([
        { port: 22, state: 'open' },
        { port: 80, state: 'open' },
      ]);
      const curr = baseScan([
        { port: 22, state: 'open' },
        { port: 80, state: 'open' },
        { port: 443, state: 'open' },
      ]);
      curr.timestamp = '2026-01-02T00:00:00.000Z';

      const changes = detectChanges(prev, curr);
      expect(changes.newPorts).to.have.length(1);
      expect(changes.newPorts[0].port).to.equal(443);
      expect(changes.closedPorts).to.have.length(0);
      expect(changes.hasChanges).to.be.true;
    });

    it('should detect closed ports', () => {
      const prev = baseScan([
        { port: 22, state: 'open' },
        { port: 80, state: 'open' },
      ]);
      const curr = baseScan([
        { port: 22, state: 'open' },
        { port: 80, state: 'closed' },
      ]);
      curr.timestamp = '2026-01-02T00:00:00.000Z';

      const changes = detectChanges(prev, curr);
      expect(changes.closedPorts).to.have.length(1);
      expect(changes.closedPorts[0].port).to.equal(80);
      expect(changes.hasChanges).to.be.true;
    });

    it('should detect no changes', () => {
      const prev = baseScan([
        { port: 22, state: 'open' },
        { port: 80, state: 'closed' },
      ]);
      const curr = baseScan([
        { port: 22, state: 'open' },
        { port: 80, state: 'closed' },
      ]);
      curr.timestamp = '2026-01-02T00:00:00.000Z';

      const changes = detectChanges(prev, curr);
      expect(changes.newPorts).to.have.length(0);
      expect(changes.closedPorts).to.have.length(0);
      expect(changes.hasChanges).to.be.false;
    });

    it('should track unchanged ports', () => {
      const prev = baseScan([
        { port: 22, state: 'open' },
        { port: 80, state: 'open' },
      ]);
      const curr = baseScan([
        { port: 22, state: 'open' },
        { port: 80, state: 'open' },
      ]);

      const changes = detectChanges(prev, curr);
      expect(changes.unchanged).to.have.length(2);
    });

    it('should detect service changes', () => {
      const prev = baseScan(
        [{ port: 80, state: 'open' }],
        [{ port: 80, service: 'http', banner: 'Apache' }]
      );
      const curr = baseScan(
        [{ port: 80, state: 'open' }],
        [{ port: 80, service: 'https', banner: 'Nginx' }]
      );

      const changes = detectChanges(prev, curr);
      expect(changes.changedServices).to.have.length(1);
      expect(changes.changedServices[0].previousService).to.equal('http');
      expect(changes.changedServices[0].currentService).to.equal('https');
      expect(changes.hasChanges).to.be.true;
    });

    it('should return host and timestamps', () => {
      const prev = baseScan([]);
      const curr = baseScan([]);
      curr.timestamp = '2026-01-02T00:00:00.000Z';

      const changes = detectChanges(prev, curr);
      expect(changes.host).to.equal('10.0.0.1');
      expect(changes.timestamp).to.equal('2026-01-02T00:00:00.000Z');
      expect(changes.previousTimestamp).to.equal('2026-01-01T00:00:00.000Z');
    });

    it('should throw if scans are missing', () => {
      expect(() => detectChanges(null, baseScan([]))).to.throw('Both previous and current scans are required');
      expect(() => detectChanges(baseScan([]), null)).to.throw('Both previous and current scans are required');
    });

    it('should throw if ports array is missing', () => {
      expect(() => detectChanges({ host: 'x' }, baseScan([]))).to.throw('Scan results must contain a ports array');
    });
  });

  describe('detectServiceChanges()', () => {
    it('should return empty array for non-array inputs', () => {
      expect(detectServiceChanges(null, null)).to.deep.equal([]);
      expect(detectServiceChanges(undefined, [])).to.deep.equal([]);
    });

    it('should detect service name changes', () => {
      const prev = [{ port: 80, service: 'http', banner: 'old' }];
      const curr = [{ port: 80, service: 'nginx', banner: 'new' }];
      const changes = detectServiceChanges(prev, curr);
      expect(changes).to.have.length(1);
      expect(changes[0].port).to.equal(80);
    });

    it('should not flag unchanged services', () => {
      const prev = [{ port: 80, service: 'http', banner: 'Apache' }];
      const curr = [{ port: 80, service: 'http', banner: 'Apache v2' }];
      const changes = detectServiceChanges(prev, curr);
      expect(changes).to.have.length(0);
    });
  });

  describe('summarizeChanges()', () => {
    it('should summarize no changes', () => {
      const changes = {
        host: '10.0.0.1',
        timestamp: '2026-01-01T00:00:00.000Z',
        hasChanges: false,
        newPorts: [],
        closedPorts: [],
        changedServices: [],
      };

      const summary = summarizeChanges(changes);
      expect(summary).to.include('10.0.0.1');
      expect(summary).to.include('No changes detected');
    });

    it('should summarize new ports', () => {
      const changes = {
        host: '10.0.0.1',
        timestamp: '2026-01-01T00:00:00.000Z',
        hasChanges: true,
        newPorts: [{ port: 443, state: 'open' }],
        closedPorts: [],
        changedServices: [],
      };

      const summary = summarizeChanges(changes);
      expect(summary).to.include('New open ports');
      expect(summary).to.include('443');
    });

    it('should summarize closed ports', () => {
      const changes = {
        host: '10.0.0.1',
        timestamp: '2026-01-01T00:00:00.000Z',
        hasChanges: true,
        newPorts: [],
        closedPorts: [{ port: 80, state: 'open' }],
        changedServices: [],
      };

      const summary = summarizeChanges(changes);
      expect(summary).to.include('closed ports');
      expect(summary).to.include('80');
    });

    it('should summarize service changes', () => {
      const changes = {
        host: '10.0.0.1',
        timestamp: '2026-01-01T00:00:00.000Z',
        hasChanges: true,
        newPorts: [],
        closedPorts: [],
        changedServices: [
          { port: 80, previousService: 'http', currentService: 'nginx' },
        ],
      };

      const summary = summarizeChanges(changes);
      expect(summary).to.include('Service changes');
      expect(summary).to.include('http -> nginx');
    });

    it('should throw on missing changes', () => {
      expect(() => summarizeChanges(null)).to.throw('Changes object is required');
    });
  });
});
