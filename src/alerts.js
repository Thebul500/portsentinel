'use strict';

const SEVERITY = {
  INFO: 'info',
  WARNING: 'warning',
  CRITICAL: 'critical',
};

/**
 * Ports that are commonly flagged as high-risk.
 */
const HIGH_RISK_PORTS = new Set([
  21,    // FTP
  23,    // Telnet
  135,   // MSRPC
  139,   // NetBIOS
  445,   // SMB
  1433,  // MSSQL
  3389,  // RDP
  5900,  // VNC
]);

/**
 * Create an alert from detected changes.
 */
function createAlert(changes) {
  if (!changes) {
    throw new Error('Changes object is required');
  }

  const severity = calculateSeverity(changes);
  const messages = [];

  if (changes.newPorts && changes.newPorts.length > 0) {
    const portList = changes.newPorts.map((p) => p.port).join(', ');
    messages.push(`New open ports detected: ${portList}`);
  }

  if (changes.closedPorts && changes.closedPorts.length > 0) {
    const portList = changes.closedPorts.map((p) => p.port).join(', ');
    messages.push(`Ports closed: ${portList}`);
  }

  if (changes.changedServices && changes.changedServices.length > 0) {
    for (const s of changes.changedServices) {
      messages.push(`Service changed on port ${s.port}: ${s.previousService} -> ${s.currentService}`);
    }
  }

  return {
    host: changes.host,
    timestamp: changes.timestamp,
    severity,
    messages,
    changes,
  };
}

/**
 * Calculate alert severity based on the nature of changes.
 */
function calculateSeverity(changes) {
  if (!changes || !changes.hasChanges) {
    return SEVERITY.INFO;
  }

  // Critical if high-risk ports were newly opened
  if (changes.newPorts) {
    for (const p of changes.newPorts) {
      if (HIGH_RISK_PORTS.has(p.port)) {
        return SEVERITY.CRITICAL;
      }
    }
  }

  // Warning if services changed or any new ports opened
  if (
    (changes.changedServices && changes.changedServices.length > 0) ||
    (changes.newPorts && changes.newPorts.length > 0)
  ) {
    return SEVERITY.WARNING;
  }

  return SEVERITY.INFO;
}

/**
 * Format an alert for console display.
 */
function formatAlert(alert) {
  if (!alert) {
    throw new Error('Alert object is required');
  }

  const lines = [];
  const severityLabel = `[${alert.severity.toUpperCase()}]`;

  lines.push(`${severityLabel} Port change alert for ${alert.host}`);
  lines.push(`Time: ${alert.timestamp}`);

  for (const msg of alert.messages) {
    lines.push(`  ${msg}`);
  }

  return lines.join('\n');
}

/**
 * Create a list of alerts from multiple change reports.
 */
function createAlerts(changesList) {
  if (!Array.isArray(changesList)) {
    throw new Error('Changes list must be an array');
  }

  return changesList
    .filter((c) => c.hasChanges)
    .map((c) => createAlert(c));
}

module.exports = {
  createAlert,
  calculateSeverity,
  formatAlert,
  createAlerts,
  SEVERITY,
  HIGH_RISK_PORTS,
};
