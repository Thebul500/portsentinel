#!/usr/bin/env node
'use strict';

const { Command } = require('commander');
const { scanner, fingerprinter, detector, ScanDatabase, exporter, alerts } = require('../src');
const pkg = require('../package.json');

const program = new Command();

program
  .name('portsentinel')
  .description(pkg.description)
  .version(pkg.version);

program
  .command('scan <host>')
  .description('Scan ports on a host')
  .option('-p, --ports <ports>', 'Comma-separated list of ports')
  .option('-r, --range <range>', 'Port range (e.g., 1-1024)')
  .option('-t, --timeout <ms>', 'Connection timeout in ms', '2000')
  .option('--json', 'Output as JSON')
  .option('--csv', 'Output as CSV')
  .option('-o, --output <file>', 'Write output to file')
  .option('-f, --fingerprint', 'Fingerprint open ports')
  .option('-d, --db <path>', 'SQLite database path')
  .option('-c, --concurrency <n>', 'Max concurrent connections', '100')
  .option('--top-ports <n>', 'Scan top N most common ports')
  .action(async (host, opts) => {
    try {
      const timeout = parseInt(opts.timeout, 10);
      if (isNaN(timeout) || timeout <= 0) {
        console.error('Error: timeout must be a positive number');
        process.exit(1);
      }

      const concurrency = parseInt(opts.concurrency, 10);
      if (isNaN(concurrency) || concurrency <= 0 || concurrency > 10000) {
        console.error('Error: concurrency must be between 1 and 10000');
        process.exit(1);
      }

      let result;

      if (opts.range) {
        const parts = opts.range.split('-');
        if (parts.length !== 2) {
          console.error('Error: range must be in format START-END (e.g., 1-1024)');
          process.exit(1);
        }
        const [start, end] = parts.map(Number);
        if (isNaN(start) || isNaN(end) || !Number.isInteger(start) || !Number.isInteger(end)) {
          console.error('Error: range must contain valid integers (e.g., 1-1024)');
          process.exit(1);
        }
        result = await scanner.scanRange(host, start, end, { timeout, concurrency });
      } else if (opts.ports) {
        const ports = opts.ports.split(',').map((s) => {
          const n = Number(s.trim());
          if (isNaN(n) || !Number.isInteger(n) || n < 1 || n > 65535) {
            console.error(`Error: invalid port "${s.trim()}" — must be an integer between 1 and 65535`);
            process.exit(1);
          }
          return n;
        });
        result = await scanner.scanHost(host, ports, { timeout, concurrency });
      } else if (opts.topPorts) {
        const n = parseInt(opts.topPorts, 10);
        if (isNaN(n) || n < 1) {
          console.error('Error: --top-ports must be a positive integer');
          process.exit(1);
        }
        const ports = scanner.COMMON_PORTS.slice(0, Math.min(n, scanner.COMMON_PORTS.length));
        result = await scanner.scanHost(host, ports, { timeout, concurrency });
      } else {
        result = await scanner.scanHost(host, undefined, { timeout, concurrency });
      }

      if (opts.fingerprint) {
        const fp = await fingerprinter.fingerprintScan(result, timeout);
        result.services = fp.services;
      }

      if (opts.db) {
        const db = new ScanDatabase(opts.db);
        const prev = db.getLatestScan(host);
        db.saveScan(result);

        if (prev) {
          const changes = detector.detectChanges(prev, result);
          if (changes.hasChanges) {
            const alert = alerts.createAlert(changes);
            console.error(alerts.formatAlert(alert));
          }
        }
        db.close();
      }

      if (opts.output) {
        const format = opts.csv ? 'csv' : 'json';
        exporter.exportScan(result, opts.output, format);
        console.log(`Results written to ${opts.output}`);
      } else if (opts.json) {
        console.log(exporter.toJSON(result));
      } else if (opts.csv) {
        console.log(exporter.toCSV(result));
      } else {
        printResults(result);
      }
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

program
  .command('history <host>')
  .description('Show scan history for a host')
  .option('-d, --db <path>', 'SQLite database path', 'portsentinel.db')
  .option('-n, --limit <n>', 'Number of records', '10')
  .action((host, opts) => {
    try {
      const db = new ScanDatabase(opts.db);
      const history = db.getHistory(host, parseInt(opts.limit, 10));
      if (history.length === 0) {
        console.log(`No scan history for ${host}`);
      } else {
        for (const entry of history) {
          console.log(`  ${entry.timestamp} — ${entry.openCount}/${entry.portCount} ports open`);
        }
      }
      db.close();
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

function printResults(result) {
  const open = scanner.getOpenPorts(result);
  const closed = result.ports.length - open.length;
  const elapsed = open.reduce((max, p) => Math.max(max, p.latency || 0), 0);

  console.log('');
  console.log(`PortSentinel scan report for ${result.host}`);
  console.log(`Scan started at: ${result.timestamp}`);
  console.log(`${result.ports.length} ports scanned — ${open.length} open, ${closed} closed`);
  console.log('');

  if (open.length === 0) {
    console.log('  No open ports detected.');
    console.log('');
    return;
  }

  // Table header
  const portW = 10;
  const stateW = 8;
  const serviceW = 16;
  const latencyW = 10;
  const bannerW = 40;

  console.log(
    '  ' +
    'PORT'.padEnd(portW) +
    'STATE'.padEnd(stateW) +
    'SERVICE'.padEnd(serviceW) +
    'LATENCY'.padEnd(latencyW) +
    'BANNER'
  );
  console.log('  ' + '-'.repeat(portW + stateW + serviceW + latencyW + bannerW));

  for (const p of open) {
    const port = `${p.port}/tcp`.padEnd(portW);
    const state = 'open'.padEnd(stateW);
    const service = (p.service || '').padEnd(serviceW);
    const latency = (p.latency !== null && p.latency !== undefined ? `${p.latency}ms` : '').padEnd(latencyW);
    const banner = p.banner ? p.banner.replace(/[\r\n]+/g, ' ').substring(0, bannerW) : '';
    console.log(`  ${port}${state}${service}${latency}${banner}`);
  }

  console.log('');
}

program.parse();
