'use strict';

const net = require('net');

const DEFAULT_TIMEOUT = 3000;

/**
 * Known service signatures mapped by common port numbers.
 */
const SERVICE_SIGNATURES = {
  21: { name: 'ftp', probe: null },
  22: { name: 'ssh', probe: null },
  23: { name: 'telnet', probe: null },
  25: { name: 'smtp', probe: null },
  53: { name: 'dns', probe: null },
  80: { name: 'http', probe: 'HEAD / HTTP/1.0\r\n\r\n' },
  110: { name: 'pop3', probe: null },
  111: { name: 'rpcbind', probe: null },
  135: { name: 'msrpc', probe: null },
  139: { name: 'netbios', probe: null },
  143: { name: 'imap', probe: null },
  443: { name: 'https', probe: null },
  445: { name: 'smb', probe: null },
  993: { name: 'imaps', probe: null },
  995: { name: 'pop3s', probe: null },
  1433: { name: 'mssql', probe: null },
  1521: { name: 'oracle', probe: null },
  3306: { name: 'mysql', probe: null },
  3389: { name: 'rdp', probe: null },
  5432: { name: 'postgresql', probe: null },
  5900: { name: 'vnc', probe: null },
  6379: { name: 'redis', probe: 'PING\r\n' },
  8080: { name: 'http-proxy', probe: 'HEAD / HTTP/1.0\r\n\r\n' },
  8443: { name: 'https-alt', probe: null },
  9090: { name: 'web-admin', probe: null },
  27017: { name: 'mongodb', probe: null },
};

/**
 * Banner patterns to identify services from response data.
 */
const BANNER_PATTERNS = [
  { pattern: /^SSH-/i, service: 'ssh' },
  { pattern: /^220.*FTP/i, service: 'ftp' },
  { pattern: /^220.*SMTP/i, service: 'smtp' },
  { pattern: /^220.*mail/i, service: 'smtp' },
  { pattern: /HTTP\/\d\.\d/i, service: 'http' },
  { pattern: /^\+OK.*POP3/i, service: 'pop3' },
  { pattern: /^\* OK.*IMAP/i, service: 'imap' },
  { pattern: /^mysql/i, service: 'mysql' },
  { pattern: /^\+PONG/i, service: 'redis' },
  { pattern: /^RFB \d/i, service: 'vnc' },
  { pattern: /MongoDB/i, service: 'mongodb' },
  { pattern: /PostgreSQL/i, service: 'postgresql' },
];

/**
 * Grab a banner from a host:port by connecting and reading initial response.
 */
function grabBanner(host, port, timeout = DEFAULT_TIMEOUT) {
  if (typeof host !== 'string' || host.trim().length === 0) {
    throw new Error('Host must be a non-empty string');
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('Port must be an integer between 1 and 65535');
  }

  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner = '';

    socket.setTimeout(timeout);

    socket.on('connect', () => {
      const sig = SERVICE_SIGNATURES[port];
      if (sig && sig.probe) {
        socket.write(sig.probe);
      }
    });

    socket.on('data', (data) => {
      banner += data.toString('utf8');
      socket.destroy();
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve(banner || null);
    });

    socket.on('error', () => {
      socket.destroy();
      resolve(null);
    });

    socket.on('close', () => {
      resolve(banner || null);
    });

    socket.connect(port, host);
  });
}

/**
 * Identify a service based on port number and optional banner string.
 */
function identifyService(port, banner = null) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('Port must be an integer between 1 and 65535');
  }

  // Try banner matching first
  if (banner && typeof banner === 'string') {
    for (const { pattern, service } of BANNER_PATTERNS) {
      if (pattern.test(banner)) {
        return {
          port,
          service,
          banner: banner.trim().substring(0, 256),
          confidence: 'high',
        };
      }
    }
  }

  // Fall back to port-based identification
  const sig = SERVICE_SIGNATURES[port];
  if (sig) {
    return {
      port,
      service: sig.name,
      banner: banner ? banner.trim().substring(0, 256) : null,
      confidence: banner ? 'medium' : 'low',
    };
  }

  return {
    port,
    service: 'unknown',
    banner: banner ? banner.trim().substring(0, 256) : null,
    confidence: 'none',
  };
}

/**
 * Fingerprint a host:port — grab banner and identify service.
 */
async function fingerprint(host, port, timeout = DEFAULT_TIMEOUT) {
  const banner = await grabBanner(host, port, timeout);
  return identifyService(port, banner);
}

/**
 * Fingerprint all open ports from a scan result.
 */
async function fingerprintScan(scanResult, timeout = DEFAULT_TIMEOUT) {
  if (!scanResult || !Array.isArray(scanResult.ports)) {
    throw new Error('Invalid scan result');
  }

  const openPorts = scanResult.ports.filter((p) => p.state === 'open');
  const results = await Promise.all(
    openPorts.map((p) => fingerprint(scanResult.host, p.port, timeout))
  );

  return {
    host: scanResult.host,
    timestamp: scanResult.timestamp,
    services: results,
  };
}

module.exports = {
  grabBanner,
  identifyService,
  fingerprint,
  fingerprintScan,
  SERVICE_SIGNATURES,
  BANNER_PATTERNS,
};
