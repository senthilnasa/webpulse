# WebPulse — Web Testing & Diagnostics Platform

[![CI/CD Tests](https://github.com/senthilnasa/webpulse/actions/workflows/test.yml/badge.svg)](https://github.com/senthilnasa/webpulse/actions/workflows/test.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go)](go.mod)

**WebPulse** is a production-quality, open-source web testing and diagnostics platform with a modern Web UI and CLI (`webpulse`) for authorized HTTP/HTTPS endpoint probes, public egress IP detection, SSRF protection, WAF allowlisting verification, and bulk URL automation.

---

> [!IMPORTANT]
> **Authorization & Non-Evasion Policy**
> Only test systems that you own or have explicit written authorization to test. WebPulse adheres strictly to non-evasion security guidelines and identifies itself transparently with `User-Agent: WebPulse-Engine/1.0`. It does **not** attempt to defeat, evade, or bypass WAF/firewall security controls.

---

## Key Platform Features

* 🚀 **Dual Interface**: Modern React SPA Web UI and standalone Go CLI (`webpulse`).
* 🔒 **SSRF & Scope Protection**: Pre-dial DNS resolution verifying all IP addresses against loopback, RFC 1918, RFC 4193, and cloud metadata (`169.254.169.254`), neutralizing DNS rebinding attacks.
* 🌐 **Egress & WAF Allowlisting**: Identifies public outbound IPv4/IPv6 used by background worker probes with explicit WAF allowlisting documentation.
* 📊 **Multi-Layer Diagnostics**: Measures DNS lookup, TCP handshake, TLS negotiation, and HTTP TTFB latencies separately.
* ⚡ **Real-Time Job Telemetry**: Real-time progress bar and log stream powered by Server-Sent Events (SSE).
* 📁 **Bulk Import & Export**: Import URLs from TXT, CSV, or JSON. Export results to JSON, CSV, or ZIP bundles.
* 🩺 **`webpulse doctor`**: CLI command to diagnose network, DNS, TLS, and public egress IP connectivity.

---

## Quickstart Guide

### 1. Run with Docker Compose
```bash
git clone https://github.com/senthilnasa/webpulse.git
cd webpulse
docker compose up -d
```
Open **http://localhost:8080** in your browser.

### 2. Local Go CLI Execution
```bash
# Perform a single URL probe
go run main.go scan https://example.com

# Perform bulk URL scan from input file
go run main.go scan urls.json --profile standard --workers 10

# Perform dry-run validation (validate SSRF and scope without dialing)
go run main.go scan urls.json --dry-run

# Run diagnostic check on local engine environment
go run main.go doctor
```

---

## Repository Architecture

```text
/
├── cmd/
│   ├── webpulse/          # Go CLI executable entrypoint
│   └── server/            # Web Server & REST API entrypoint
├── pkg/
│   ├── api/               # REST API endpoints & SSE stream router
│   ├── db/                # Persistent JSON/SQLite storage layer
│   ├── doctor/            # Environment connectivity diagnostic engine
│   ├── egress/            # Public egress IP detection module
│   ├── engine/            # Diagnostic worker pool & probe coordinator
│   ├── export/            # CSV, JSON, and ZIP report generators
│   ├── plugins/           # Diagnostic plugins (HTTP, TLS, Headers, DNS)
│   ├── scope/             # Target domain scope validator
│   └── ssrf/              # SSRF IP validator & DNS rebinding safe dialer
├── frontend/
│   └── dist/              # Embedded React Single Page Application (SPA) UI
├── docs/                  # Detailed documentation guides
│   ├── SSRF_PROTECTION.md
│   ├── WAF_ALLOWLISTING.md
│   ├── API_SPECIFICATION.md
│   └── CLI_GUIDE.md
├── docker/
│   └── Dockerfile         # Multi-stage Docker container build
├── docker-compose.yml     # One-command container setup
├── main.go                # Root Go CLI entrypoint
└── LICENSE                # Apache 2.0 License
```

---

## Documentation Links

* 🛡️ [SSRF Protection & Security Architecture](docs/SSRF_PROTECTION.md)
* 🌐 [WAF Allowlisting & Egress IP Guide](docs/WAF_ALLOWLISTING.md)
* 📡 [REST API v1 Specification](docs/API_SPECIFICATION.md)
* 💻 [CLI User & Developer Guide](docs/CLI_GUIDE.md)

---

## License

WebPulse is distributed under the terms of the [Apache 2.0 License](LICENSE).
