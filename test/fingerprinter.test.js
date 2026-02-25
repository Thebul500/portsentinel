'use strict';

const { expect } = require('chai');
const net = require('net');
const {
  grabBanner,
  identifyService,
  fingerprint,
  fingerprintScan,
  SERVICE_SIGNATURES,
  BANNER_PATTERNS,
} = require('../src/fingerprinter');

describe('Fingerprinter', () => {
  describe('identifyService()', () => {
    it('should identify SSH from banner', () => {
      const result = identifyService(22, 'SSH-2.0-OpenSSH_8.9');
      expect(result.service).to.equal('ssh');
      expect(result.confidence).to.equal('high');
      expect(result.banner).to.equal('SSH-2.0-OpenSSH_8.9');
    });

    it('should identify FTP from banner', () => {
      const result = identifyService(21, '220 Welcome to FTP server');
      expect(result.service).to.equal('ftp');
      expect(result.confidence).to.equal('high');
    });

    it('should identify SMTP from banner', () => {
      const result = identifyService(25, '220 mail.example.com SMTP Postfix');
      expect(result.service).to.equal('smtp');
      expect(result.confidence).to.equal('high');
    });

    it('should identify HTTP from banner', () => {
      const result = identifyService(80, 'HTTP/1.1 200 OK\r\nServer: nginx');
      expect(result.service).to.equal('http');
      expect(result.confidence).to.equal('high');
    });

    it('should identify Redis from banner', () => {
      const result = identifyService(6379, '+PONG');
      expect(result.service).to.equal('redis');
      expect(result.confidence).to.equal('high');
    });

    it('should identify POP3 from banner', () => {
      const result = identifyService(110, '+OK POP3 server ready');
      expect(result.service).to.equal('pop3');
      expect(result.confidence).to.equal('high');
    });

    it('should identify IMAP from banner', () => {
      const result = identifyService(143, '* OK IMAP4rev1 Server ready');
      expect(result.service).to.equal('imap');
      expect(result.confidence).to.equal('high');
    });

    it('should identify VNC from banner', () => {
      const result = identifyService(5900, 'RFB 003.008');
      expect(result.service).to.equal('vnc');
      expect(result.confidence).to.equal('high');
    });

    it('should fall back to port-based identification with banner', () => {
      const result = identifyService(3306, 'some unknown banner');
      expect(result.service).to.equal('mysql');
      expect(result.confidence).to.equal('medium');
    });

    it('should fall back to port-based identification without banner', () => {
      const result = identifyService(443);
      expect(result.service).to.equal('https');
      expect(result.confidence).to.equal('low');
    });

    it('should return unknown for unrecognized port', () => {
      const result = identifyService(12345);
      expect(result.service).to.equal('unknown');
      expect(result.confidence).to.equal('none');
    });

    it('should return unknown for unrecognized port with banner', () => {
      const result = identifyService(12345, 'some random banner');
      expect(result.service).to.equal('unknown');
      expect(result.confidence).to.equal('none');
      expect(result.banner).to.equal('some random banner');
    });

    it('should truncate long banners to 256 chars', () => {
      const longBanner = 'A'.repeat(500);
      const result = identifyService(12345, longBanner);
      expect(result.banner).to.have.length(256);
    });

    it('should throw on invalid port', () => {
      expect(() => identifyService(0)).to.throw('Port must be an integer between 1 and 65535');
      expect(() => identifyService(70000)).to.throw('Port must be an integer between 1 and 65535');
    });
  });

  describe('grabBanner()', () => {
    let server;
    let serverPort;

    before((done) => {
      server = net.createServer((socket) => {
        socket.write('SSH-2.0-TestServer\r\n');
        socket.end();
      });
      server.listen(0, '127.0.0.1', () => {
        serverPort = server.address().port;
        done();
      });
    });

    after((done) => {
      server.close(done);
    });

    it('should grab a banner from an open port', async () => {
      const banner = await grabBanner('127.0.0.1', serverPort, 2000);
      expect(banner).to.include('SSH-2.0-TestServer');
    });

    it('should return null for closed port', async () => {
      const banner = await grabBanner('127.0.0.1', 1, 1000);
      expect(banner).to.be.null;
    });

    it('should throw on invalid host', () => {
      expect(() => grabBanner('', 80)).to.throw('Host must be a non-empty string');
    });

    it('should throw on invalid port', () => {
      expect(() => grabBanner('127.0.0.1', 0)).to.throw('Port must be an integer between 1 and 65535');
    });
  });

  describe('fingerprint()', () => {
    let server;
    let serverPort;

    before((done) => {
      server = net.createServer((socket) => {
        socket.write('SSH-2.0-OpenSSH_9.0\r\n');
        socket.end();
      });
      server.listen(0, '127.0.0.1', () => {
        serverPort = server.address().port;
        done();
      });
    });

    after((done) => {
      server.close(done);
    });

    it('should fingerprint an open port', async () => {
      const result = await fingerprint('127.0.0.1', serverPort, 2000);
      expect(result).to.have.property('port', serverPort);
      expect(result).to.have.property('service');
      expect(result).to.have.property('confidence');
    });
  });

  describe('fingerprintScan()', () => {
    let server;
    let serverPort;

    before((done) => {
      server = net.createServer((socket) => {
        socket.write('SSH-2.0-Test\r\n');
        socket.end();
      });
      server.listen(0, '127.0.0.1', () => {
        serverPort = server.address().port;
        done();
      });
    });

    after((done) => {
      server.close(done);
    });

    it('should fingerprint all open ports from scan result', async () => {
      const scanResult = {
        host: '127.0.0.1',
        timestamp: new Date().toISOString(),
        ports: [
          { port: serverPort, state: 'open', latency: 1 },
          { port: 1, state: 'closed', latency: null },
        ],
      };

      const result = await fingerprintScan(scanResult, 2000);
      expect(result).to.have.property('host', '127.0.0.1');
      expect(result).to.have.property('services').that.is.an('array');
      expect(result.services).to.have.length(1);
      expect(result.services[0].port).to.equal(serverPort);
    });

    it('should throw on invalid scan result', async () => {
      try {
        await fingerprintScan(null);
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err.message).to.equal('Invalid scan result');
      }
    });
  });

  describe('constants', () => {
    it('should export SERVICE_SIGNATURES', () => {
      expect(SERVICE_SIGNATURES).to.be.an('object');
      expect(SERVICE_SIGNATURES[80]).to.have.property('name', 'http');
    });

    it('should export BANNER_PATTERNS', () => {
      expect(BANNER_PATTERNS).to.be.an('array');
      expect(BANNER_PATTERNS.length).to.be.greaterThan(0);
    });
  });
});
