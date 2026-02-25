'use strict';

const net = require('net');

const DEFAULT_TIMEOUT = 2000;
const COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
  1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090, 27017
];

/**
 * Check if a single TCP port is open on a host.
 * Returns { port, state: 'open'|'closed', latency } or throws on invalid input.
 */
function scanPort(host, port, timeout = DEFAULT_TIMEOUT) {
  validateHost(host);
  validatePort(port);

  if (typeof timeout !== 'number' || timeout <= 0) {
    throw new Error('Timeout must be a positive number');
  }

  return new Promise((resolve) => {
    const start = Date.now();
    const socket = new net.Socket();

    socket.setTimeout(timeout);

    socket.on('connect', () => {
      const latency = Date.now() - start;
      socket.destroy();
      resolve({ port, state: 'open', latency });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ port, state: 'closed', latency: null });
    });

    socket.on('error', () => {
      socket.destroy();
      resolve({ port, state: 'closed', latency: null });
    });

    socket.connect(port, host);
  });
}

/**
 * Scan multiple ports on a host.
 * Returns { host, timestamp, ports: [...] }
 */
async function scanHost(host, ports = COMMON_PORTS, options = {}) {
  validateHost(host);

  if (!Array.isArray(ports) || ports.length === 0) {
    throw new Error('Ports must be a non-empty array');
  }

  const timeout = options.timeout || DEFAULT_TIMEOUT;
  const concurrency = options.concurrency || 100;

  const results = [];
  for (let i = 0; i < ports.length; i += concurrency) {
    const batch = ports.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map((port) => scanPort(host, port, timeout))
    );
    results.push(...batchResults);
  }

  return {
    host,
    timestamp: new Date().toISOString(),
    ports: results,
  };
}

/**
 * Scan a range of ports on a host.
 */
async function scanRange(host, startPort, endPort, options = {}) {
  validateHost(host);
  validatePort(startPort);
  validatePort(endPort);

  if (startPort > endPort) {
    throw new Error('Start port must be less than or equal to end port');
  }

  const ports = [];
  for (let p = startPort; p <= endPort; p++) {
    ports.push(p);
  }

  return scanHost(host, ports, options);
}

/**
 * Filter scan results to only open ports.
 */
function getOpenPorts(scanResult) {
  if (!scanResult || !Array.isArray(scanResult.ports)) {
    throw new Error('Invalid scan result');
  }
  return scanResult.ports.filter((p) => p.state === 'open');
}

function validateHost(host) {
  if (typeof host !== 'string' || host.trim().length === 0) {
    throw new Error('Host must be a non-empty string');
  }
}

function validatePort(port) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('Port must be an integer between 1 and 65535');
  }
}

module.exports = {
  scanPort,
  scanHost,
  scanRange,
  getOpenPorts,
  COMMON_PORTS,
  DEFAULT_TIMEOUT,
};
