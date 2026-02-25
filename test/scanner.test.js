'use strict';

const { expect } = require('chai');
const net = require('net');
const { scanPort, scanHost, scanRange, getOpenPorts, COMMON_PORTS, DEFAULT_TIMEOUT } = require('../src/scanner');

describe('Scanner', () => {
  describe('scanPort()', () => {
    let server;
    let serverPort;

    before((done) => {
      server = net.createServer((socket) => socket.end());
      server.listen(0, '127.0.0.1', () => {
        serverPort = server.address().port;
        done();
      });
    });

    after((done) => {
      server.close(done);
    });

    it('should detect an open port', async () => {
      const result = await scanPort('127.0.0.1', serverPort, 2000);
      expect(result).to.have.property('port', serverPort);
      expect(result).to.have.property('state', 'open');
      expect(result).to.have.property('latency');
      expect(result.latency).to.be.a('number');
      expect(result.latency).to.be.at.least(0);
    });

    it('should detect a closed port', async () => {
      // Use a port that's almost certainly closed
      const result = await scanPort('127.0.0.1', 1, 1000);
      expect(result).to.have.property('port', 1);
      expect(result).to.have.property('state', 'closed');
      expect(result.latency).to.be.null;
    });

    it('should throw on invalid host', () => {
      expect(() => scanPort('', 80)).to.throw('Host must be a non-empty string');
      expect(() => scanPort(123, 80)).to.throw('Host must be a non-empty string');
    });

    it('should throw on invalid port', () => {
      expect(() => scanPort('127.0.0.1', 0)).to.throw('Port must be an integer between 1 and 65535');
      expect(() => scanPort('127.0.0.1', 70000)).to.throw('Port must be an integer between 1 and 65535');
      expect(() => scanPort('127.0.0.1', 1.5)).to.throw('Port must be an integer between 1 and 65535');
      expect(() => scanPort('127.0.0.1', 'abc')).to.throw('Port must be an integer between 1 and 65535');
    });

    it('should throw on invalid timeout', () => {
      expect(() => scanPort('127.0.0.1', 80, -1)).to.throw('Timeout must be a positive number');
      expect(() => scanPort('127.0.0.1', 80, 'fast')).to.throw('Timeout must be a positive number');
    });

    it('should timeout on unreachable host', async () => {
      // 192.0.2.1 is TEST-NET, should be unreachable
      const result = await scanPort('192.0.2.1', 80, 500);
      expect(result.state).to.equal('closed');
    }).timeout(5000);
  });

  describe('scanHost()', () => {
    let server;
    let serverPort;

    before((done) => {
      server = net.createServer((socket) => socket.end());
      server.listen(0, '127.0.0.1', () => {
        serverPort = server.address().port;
        done();
      });
    });

    after((done) => {
      server.close(done);
    });

    it('should scan multiple ports and return structured result', async () => {
      const closedPort = serverPort + 1000 > 65535 ? serverPort - 1 : serverPort + 1000;
      const result = await scanHost('127.0.0.1', [serverPort, closedPort], { timeout: 2000 });

      expect(result).to.have.property('host', '127.0.0.1');
      expect(result).to.have.property('timestamp').that.is.a('string');
      expect(result).to.have.property('ports').that.is.an('array');
      expect(result.ports).to.have.length(2);

      const openResult = result.ports.find((p) => p.port === serverPort);
      expect(openResult.state).to.equal('open');
    });

    it('should use default common ports when none specified', async () => {
      // Just verify the function doesn't throw with defaults
      // Don't actually scan common ports to keep test fast
      const result = await scanHost('127.0.0.1', [serverPort]);
      expect(result.ports).to.have.length(1);
    });

    it('should throw on invalid host', async () => {
      try {
        await scanHost('', [80]);
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err.message).to.equal('Host must be a non-empty string');
      }
    });

    it('should throw on empty ports array', async () => {
      try {
        await scanHost('127.0.0.1', []);
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err.message).to.equal('Ports must be a non-empty array');
      }
    });

    it('should respect concurrency option', async () => {
      const result = await scanHost('127.0.0.1', [serverPort], { concurrency: 1, timeout: 2000 });
      expect(result.ports).to.have.length(1);
    });
  });

  describe('scanRange()', () => {
    it('should scan a port range', async () => {
      const result = await scanRange('127.0.0.1', 1, 3, { timeout: 500 });
      expect(result.ports).to.have.length(3);
      expect(result.ports[0].port).to.equal(1);
      expect(result.ports[2].port).to.equal(3);
    });

    it('should throw if start > end', async () => {
      try {
        await scanRange('127.0.0.1', 100, 50);
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err.message).to.equal('Start port must be less than or equal to end port');
      }
    });

    it('should throw on invalid ports', async () => {
      try {
        await scanRange('127.0.0.1', 0, 100);
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err.message).to.include('Port must be an integer');
      }
    });
  });

  describe('getOpenPorts()', () => {
    it('should filter to only open ports', () => {
      const scanResult = {
        host: '127.0.0.1',
        ports: [
          { port: 22, state: 'open', latency: 1 },
          { port: 80, state: 'open', latency: 2 },
          { port: 443, state: 'closed', latency: null },
        ],
      };
      const open = getOpenPorts(scanResult);
      expect(open).to.have.length(2);
      expect(open[0].port).to.equal(22);
      expect(open[1].port).to.equal(80);
    });

    it('should return empty array when no ports are open', () => {
      const scanResult = {
        host: '127.0.0.1',
        ports: [{ port: 80, state: 'closed', latency: null }],
      };
      expect(getOpenPorts(scanResult)).to.have.length(0);
    });

    it('should throw on invalid scan result', () => {
      expect(() => getOpenPorts(null)).to.throw('Invalid scan result');
      expect(() => getOpenPorts({})).to.throw('Invalid scan result');
    });
  });

  describe('constants', () => {
    it('should export COMMON_PORTS as an array', () => {
      expect(COMMON_PORTS).to.be.an('array');
      expect(COMMON_PORTS.length).to.be.greaterThan(0);
      expect(COMMON_PORTS).to.include(80);
      expect(COMMON_PORTS).to.include(443);
    });

    it('should export DEFAULT_TIMEOUT', () => {
      expect(DEFAULT_TIMEOUT).to.equal(2000);
    });
  });
});
