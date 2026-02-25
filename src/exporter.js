'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Export scan results to JSON format.
 */
function toJSON(scanResult, pretty = true) {
  if (!scanResult) {
    throw new Error('Scan result is required');
  }
  return pretty
    ? JSON.stringify(scanResult, null, 2)
    : JSON.stringify(scanResult);
}

/**
 * Export scan results to CSV format.
 */
function toCSV(scanResult) {
  if (!scanResult || !Array.isArray(scanResult.ports)) {
    throw new Error('Invalid scan result');
  }

  const header = 'host,port,state,service,banner,latency,timestamp';
  const rows = scanResult.ports.map((p) => {
    const service = p.service || '';
    const banner = p.banner ? `"${p.banner.replace(/"/g, '""')}"` : '';
    const latency = p.latency != null ? p.latency : '';
    return `${scanResult.host},${p.port},${p.state},${service},${banner},${latency},${scanResult.timestamp}`;
  });

  return [header, ...rows].join('\n');
}

/**
 * Write export to a file.
 */
function writeToFile(content, filePath) {
  if (typeof content !== 'string' || content.length === 0) {
    throw new Error('Content must be a non-empty string');
  }
  if (typeof filePath !== 'string' || filePath.trim().length === 0) {
    throw new Error('File path must be a non-empty string');
  }

  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(filePath, content, 'utf8');
  return filePath;
}

/**
 * Export scan results to a file in the given format.
 */
function exportScan(scanResult, filePath, format = 'json') {
  const fmt = format.toLowerCase();
  let content;

  if (fmt === 'json') {
    content = toJSON(scanResult);
  } else if (fmt === 'csv') {
    content = toCSV(scanResult);
  } else {
    throw new Error(`Unsupported format: ${format}. Use 'json' or 'csv'.`);
  }

  return writeToFile(content, filePath);
}

module.exports = {
  toJSON,
  toCSV,
  writeToFile,
  exportScan,
};
