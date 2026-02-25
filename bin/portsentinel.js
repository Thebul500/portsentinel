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
  .action(async (host, opts) => {
    try {
      const timeout = parseInt(opts.timeout, 10);
      let result;

      if (opts.range) {
        const [start, end] = opts.range.split('-').map(Number);
        result = await scanner.scanRange(host, start, end, { timeout });
      } else if (opts.ports) {
        const ports = opts.ports.split(',').map(Number);
        result = await scanner.scanHost(host, ports, { timeout });
      } else {
        result = await scanner.scanHost(host, undefined, { timeout });
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
  console.log(`\nScan results for ${result.host} (${result.timestamp})`);
  console.log(`${open.length} open ports found:\n`);

  if (open.length === 0) {
    console.log('  No open ports detected.');
    return;
  }

  for (const p of open) {
    const service = p.service ? ` (${p.service})` : '';
    const latency = p.latency != null ? ` [${p.latency}ms]` : '';
    console.log(`  ${p.port}/tcp  OPEN${service}${latency}`);
  }
}

program.parse();
