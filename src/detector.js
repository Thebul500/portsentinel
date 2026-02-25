'use strict';

/**
 * Compare two scan results and detect changes.
 * Returns { newPorts, closedPorts, changedServices, unchanged }
 */
function detectChanges(previousScan, currentScan) {
  if (!previousScan || !currentScan) {
    throw new Error('Both previous and current scans are required');
  }

  if (!Array.isArray(previousScan.ports) || !Array.isArray(currentScan.ports)) {
    throw new Error('Scan results must contain a ports array');
  }

  const prevOpen = new Map();
  const currOpen = new Map();

  for (const p of previousScan.ports) {
    if (p.state === 'open') {
      prevOpen.set(p.port, p);
    }
  }

  for (const p of currentScan.ports) {
    if (p.state === 'open') {
      currOpen.set(p.port, p);
    }
  }

  const newPorts = [];
  const closedPorts = [];
  const unchanged = [];

  // Find newly opened ports
  for (const [port, info] of currOpen) {
    if (!prevOpen.has(port)) {
      newPorts.push(info);
    } else {
      unchanged.push(info);
    }
  }

  // Find newly closed ports
  for (const [port, info] of prevOpen) {
    if (!currOpen.has(port)) {
      closedPorts.push(info);
    }
  }

  // Detect service changes if services info is available
  const changedServices = detectServiceChanges(
    previousScan.services,
    currentScan.services
  );

  return {
    host: currentScan.host,
    timestamp: currentScan.timestamp,
    previousTimestamp: previousScan.timestamp,
    newPorts,
    closedPorts,
    changedServices,
    unchanged,
    hasChanges: newPorts.length > 0 || closedPorts.length > 0 || changedServices.length > 0,
  };
}

/**
 * Compare service fingerprints between scans.
 */
function detectServiceChanges(previousServices, currentServices) {
  if (!Array.isArray(previousServices) || !Array.isArray(currentServices)) {
    return [];
  }

  const prevMap = new Map();
  for (const s of previousServices) {
    prevMap.set(s.port, s);
  }

  const changes = [];
  for (const curr of currentServices) {
    const prev = prevMap.get(curr.port);
    if (prev && prev.service !== curr.service) {
      changes.push({
        port: curr.port,
        previousService: prev.service,
        currentService: curr.service,
        previousBanner: prev.banner,
        currentBanner: curr.banner,
      });
    }
  }

  return changes;
}

/**
 * Generate a human-readable summary of changes.
 */
function summarizeChanges(changes) {
  if (!changes) {
    throw new Error('Changes object is required');
  }

  const lines = [];
  lines.push(`Change report for ${changes.host}`);
  lines.push(`Scanned: ${changes.timestamp}`);

  if (!changes.hasChanges) {
    lines.push('No changes detected.');
    return lines.join('\n');
  }

  if (changes.newPorts.length > 0) {
    lines.push(`\nNew open ports (${changes.newPorts.length}):`);
    for (const p of changes.newPorts) {
      lines.push(`  + ${p.port}/tcp OPEN`);
    }
  }

  if (changes.closedPorts.length > 0) {
    lines.push(`\nNewly closed ports (${changes.closedPorts.length}):`);
    for (const p of changes.closedPorts) {
      lines.push(`  - ${p.port}/tcp CLOSED`);
    }
  }

  if (changes.changedServices.length > 0) {
    lines.push(`\nService changes (${changes.changedServices.length}):`);
    for (const s of changes.changedServices) {
      lines.push(`  ~ ${s.port}/tcp: ${s.previousService} -> ${s.currentService}`);
    }
  }

  return lines.join('\n');
}

module.exports = {
  detectChanges,
  detectServiceChanges,
  summarizeChanges,
};
