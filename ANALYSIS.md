# Competitive Analysis

## Existing Tools

### 1. Nmap + Ndiff

**The gold standard.** [Nmap](https://nmap.org/) is the most widely used network scanner in existence, maintained since 1997 with decades of protocol support, OS fingerprinting, and the NSE scripting engine. Its companion tool [Ndiff](https://nmap.org/ndiff/) compares two XML scan outputs to detect changes in host/port state.

**Strengths:**
- Unmatched protocol coverage — thousands of service signatures, OS fingerprinting, vulnerability scripts
- Battle-tested in enterprise environments, pen-testing, and compliance audits
- Ndiff provides XML-based change detection between any two scan files
- Massive community, extensive documentation, plugin ecosystem
- Supports UDP, SYN, ACK, FIN, and many other scan types beyond TCP connect

**Weaknesses:**
- Change detection requires manual scripting — Ndiff compares files but doesn't persist history, schedule scans, or generate alerts on its own
- No built-in database for scan history; you have to roll your own cron + Ndiff + email/webhook pipeline
- Heavy dependency (C/C++ binary, Lua scripting engine, pcap) — not embeddable in Node.js applications
- Requires root/sudo for most useful scan types (SYN scan, OS detection)
- Output formats (XML, grepable) are powerful but verbose; no native JSON/CSV export without xsltproc or third-party tools

### 2. Masscan

[Masscan](https://github.com/robertdavidgraham/masscan) is the fastest port scanner in existence, capable of scanning the entire IPv4 internet in under 6 minutes using a custom asynchronous TCP/IP stack.

**Strengths:**
- Unparalleled speed — millions of packets per second, designed for internet-scale scanning
- Built-in banner grabbing for basic service identification
- Minimal dependencies, single C binary
- Can output to JSON, XML, or binary formats

**Weaknesses:**
- No change detection whatsoever — strictly a point-in-time scanner
- No persistent storage, no scan history, no alerting
- Banner grabbing is rudimentary compared to Nmap's version detection
- Requires raw socket access (root/sudo)
- No daemon mode or scheduling — one-shot execution only
- Not designed for small-scale, repeated monitoring of specific hosts

### 3. RustScan

[RustScan](https://github.com/bee-san/RustScan) is a modern port scanner written in Rust that acts as a fast front-end to Nmap, scanning all 65,535 ports in seconds and piping results into Nmap for deeper analysis.

**Strengths:**
- Extremely fast initial port discovery (3 seconds for full 65k scan)
- Adaptive learning adjusts scan speed based on network conditions
- Seamlessly pipes open ports to Nmap for service detection
- Scripting engine for custom workflows
- Active open-source community

**Weaknesses:**
- Not a standalone tool — depends on Nmap for actual service fingerprinting
- No built-in change detection, history, or alerting
- No persistent storage or database integration
- Primarily a speed optimizer for Nmap, not a monitoring solution
- Rust binary — cannot be imported as a library in other language ecosystems

### 4. Existing Node.js Packages (portscanner, node-port-scanner)

The npm ecosystem has several port scanning packages like [portscanner](https://www.npmjs.com/package/portscanner) and [node-port-scanner](https://www.npmjs.com/package/node-port-scanner).

**Strengths:**
- Native Node.js, easy to `npm install` and embed
- Simple API for checking port open/closed status

**Weaknesses:**
- Minimal functionality — basic TCP connect check, no service fingerprinting
- No change detection, no alerting, no history
- No CLI tool, library-only
- Largely unmaintained (infrequent updates, sparse documentation)
- No structured output formats (JSON/CSV export)

## Gap

The existing landscape has a clear split:

**Power tools (Nmap, Masscan, RustScan)** excel at one-time scanning but treat change detection as an afterthought. Building a monitoring pipeline around them requires gluing together cron jobs, shell scripts, Ndiff, custom parsers, and alerting systems. This works, but it's fragile, non-portable, and has no built-in history.

**Hosted/enterprise solutions (HostedScan, ManageEngine OpUtils)** offer continuous monitoring with alerts, but they're SaaS platforms or heavyweight enterprise software — not something you can `npm install` into a project or run in a Docker container on your home network.

**Node.js packages** cover basic port checking but stop there. None combine scanning + fingerprinting + change detection + persistence + alerting in a single, dependency-light package.

The gap is a **self-contained, lightweight monitoring tool** that combines port scanning, service fingerprinting, change detection with historical context, and severity-based alerting — all in a single CLI or embeddable library, without requiring root access, Nmap installations, or SaaS subscriptions.

## Differentiator

PortSentinel is not trying to compete with Nmap on protocol depth or Masscan on raw speed. Those tools are mature, battle-tested, and do what they do extremely well. Trying to out-scan Nmap would be foolish.

Instead, PortSentinel targets a different use case: **ongoing port monitoring with built-in change awareness**.

What makes it different:

1. **Change detection is a first-class feature, not a bolt-on.** Every scan can automatically compare against the previous scan for the same host, stored in SQLite. You don't need shell scripts, cron, or Ndiff. Run the same command twice and it tells you what changed.

2. **Severity-based alerting out of the box.** When a high-risk port (Telnet, RDP, SMB, VNC) appears open that wasn't before, PortSentinel flags it as CRITICAL. This is opinionated security logic baked in, not something you have to script yourself.

3. **SQLite history with zero configuration.** Pass `-d scans.db` and you have a persistent, queryable scan history with WAL mode for concurrent access. No external database server, no setup, no migrations.

4. **Pure Node.js, no native scanning dependencies.** Uses `net.Socket` for TCP connect scanning — no pcap, no raw sockets, no root/sudo required. This makes it trivially deployable in containers, CI pipelines, or restricted environments where you can't install system packages.

5. **Embeddable as a library.** Unlike CLI-only tools, PortSentinel exports a clean programmatic API. You can `require('portsentinel')` and integrate scanning, fingerprinting, change detection, and alerting into any Node.js application — a monitoring dashboard, a CI security check, a network inventory tool.

6. **Minimal dependency footprint.** Two production dependencies (`better-sqlite3`, `commander`). Compare this to pulling in Nmap, Lua, pcap, and NSE scripts.

### Honest Assessment

PortSentinel will never match Nmap's 30+ years of service signature development, its NSE scripting ecosystem, or its SYN/UDP/ACK scan capabilities. It won't approach Masscan's speed for internet-scale scanning. It's not trying to.

It's for the developer or homelab operator who wants to run `portsentinel scan 10.0.0.0/24 -d history.db` on a schedule and get notified when something changes — without stitching together five different tools or paying for a SaaS platform. It's the difference between a Swiss Army knife and a dedicated smoke detector: one does everything, the other does one thing well and runs quietly in the background.
