'use strict';

const { expect } = require('chai');
const {
  createAlert,
  calculateSeverity,
  formatAlert,
  createAlerts,
  SEVERITY,
  HIGH_RISK_PORTS,
} = require('../src/alerts');

describe('Alerts', () => {
  describe('calculateSeverity()', () => {
    it('should return info when no changes', () => {
      expect(calculateSeverity({ hasChanges: false })).to.equal(SEVERITY.INFO);
    });

    it('should return critical for high-risk new ports', () => {
      const changes = {
        hasChanges: true,
        newPorts: [{ port: 23 }], // telnet
        changedServices: [],
      };
      expect(calculateSeverity(changes)).to.equal(SEVERITY.CRITICAL);
    });

    it('should return critical for RDP', () => {
      const changes = {
        hasChanges: true,
        newPorts: [{ port: 3389 }],
        changedServices: [],
      };
      expect(calculateSeverity(changes)).to.equal(SEVERITY.CRITICAL);
    });

    it('should return warning for non-high-risk new ports', () => {
      const changes = {
        hasChanges: true,
        newPorts: [{ port: 8080 }],
        changedServices: [],
      };
      expect(calculateSeverity(changes)).to.equal(SEVERITY.WARNING);
    });

    it('should return warning for service changes', () => {
      const changes = {
        hasChanges: true,
        newPorts: [],
        changedServices: [{ port: 80 }],
      };
      expect(calculateSeverity(changes)).to.equal(SEVERITY.WARNING);
    });

    it('should return info for only closed ports', () => {
      const changes = {
        hasChanges: true,
        newPorts: [],
        closedPorts: [{ port: 80 }],
        changedServices: [],
      };
      expect(calculateSeverity(changes)).to.equal(SEVERITY.INFO);
    });

    it('should return info for null input', () => {
      expect(calculateSeverity(null)).to.equal(SEVERITY.INFO);
    });
  });

  describe('createAlert()', () => {
    it('should create an alert from changes with new ports', () => {
      const changes = {
        host: '10.0.0.1',
        timestamp: '2026-01-01T00:00:00.000Z',
        hasChanges: true,
        newPorts: [{ port: 22 }, { port: 80 }],
        closedPorts: [],
        changedServices: [],
      };

      const alert = createAlert(changes);
      expect(alert.host).to.equal('10.0.0.1');
      expect(alert.severity).to.equal(SEVERITY.WARNING);
      expect(alert.messages).to.have.length(1);
      expect(alert.messages[0]).to.include('22, 80');
    });

    it('should create an alert with closed ports', () => {
      const changes = {
        host: '10.0.0.1',
        timestamp: '2026-01-01T00:00:00.000Z',
        hasChanges: true,
        newPorts: [],
        closedPorts: [{ port: 443 }],
        changedServices: [],
      };

      const alert = createAlert(changes);
      expect(alert.messages).to.have.length(1);
      expect(alert.messages[0]).to.include('443');
    });

    it('should create an alert with service changes', () => {
      const changes = {
        host: '10.0.0.1',
        timestamp: '2026-01-01T00:00:00.000Z',
        hasChanges: true,
        newPorts: [],
        closedPorts: [],
        changedServices: [{ port: 80, previousService: 'http', currentService: 'nginx' }],
      };

      const alert = createAlert(changes);
      expect(alert.messages).to.have.length(1);
      expect(alert.messages[0]).to.include('http -> nginx');
    });

    it('should include all change types in messages', () => {
      const changes = {
        host: '10.0.0.1',
        timestamp: '2026-01-01T00:00:00.000Z',
        hasChanges: true,
        newPorts: [{ port: 443 }],
        closedPorts: [{ port: 21 }],
        changedServices: [{ port: 80, previousService: 'apache', currentService: 'nginx' }],
      };

      const alert = createAlert(changes);
      expect(alert.messages).to.have.length(3);
    });

    it('should throw on null changes', () => {
      expect(() => createAlert(null)).to.throw('Changes object is required');
    });
  });

  describe('formatAlert()', () => {
    it('should format alert as readable text', () => {
      const alert = {
        host: '10.0.0.1',
        timestamp: '2026-01-01T00:00:00.000Z',
        severity: SEVERITY.WARNING,
        messages: ['New open ports detected: 80, 443'],
      };

      const text = formatAlert(alert);
      expect(text).to.include('[WARNING]');
      expect(text).to.include('10.0.0.1');
      expect(text).to.include('New open ports detected');
    });

    it('should format critical alerts', () => {
      const alert = {
        host: '10.0.0.1',
        timestamp: '2026-01-01T00:00:00.000Z',
        severity: SEVERITY.CRITICAL,
        messages: ['New open ports detected: 3389'],
      };

      const text = formatAlert(alert);
      expect(text).to.include('[CRITICAL]');
    });

    it('should throw on null alert', () => {
      expect(() => formatAlert(null)).to.throw('Alert object is required');
    });
  });

  describe('createAlerts()', () => {
    it('should create alerts from multiple change reports', () => {
      const changesList = [
        {
          host: '10.0.0.1',
          timestamp: '2026-01-01T00:00:00.000Z',
          hasChanges: true,
          newPorts: [{ port: 80 }],
          closedPorts: [],
          changedServices: [],
        },
        {
          host: '10.0.0.2',
          timestamp: '2026-01-01T00:00:00.000Z',
          hasChanges: false,
          newPorts: [],
          closedPorts: [],
          changedServices: [],
        },
      ];

      const alertsList = createAlerts(changesList);
      expect(alertsList).to.have.length(1); // only one has changes
      expect(alertsList[0].host).to.equal('10.0.0.1');
    });

    it('should return empty array when no changes', () => {
      const changesList = [
        { hasChanges: false },
        { hasChanges: false },
      ];
      expect(createAlerts(changesList)).to.have.length(0);
    });

    it('should throw on non-array input', () => {
      expect(() => createAlerts('invalid')).to.throw('Changes list must be an array');
    });
  });

  describe('constants', () => {
    it('should export SEVERITY levels', () => {
      expect(SEVERITY.INFO).to.equal('info');
      expect(SEVERITY.WARNING).to.equal('warning');
      expect(SEVERITY.CRITICAL).to.equal('critical');
    });

    it('should export HIGH_RISK_PORTS', () => {
      expect(HIGH_RISK_PORTS).to.be.an.instanceOf(Set);
      expect(HIGH_RISK_PORTS.has(23)).to.be.true;  // telnet
      expect(HIGH_RISK_PORTS.has(3389)).to.be.true; // RDP
      expect(HIGH_RISK_PORTS.has(445)).to.be.true;  // SMB
    });
  });
});
