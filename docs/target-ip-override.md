# Target IP Override & Host Mapping Guide

## Overview

The **Target IP Override / Host Mapping** feature allows authorized users to probe a target hostname against a specific server IP (such as a local, staging, QA, or pre-production migration server) while preserving the original hostname for:
- **HTTP Host Header** (`Host: example.com`)
- **TLS SNI (Server Name Indication)** (`SNI: example.com`)
- **TLS Certificate Validation** (Validates certificate against `example.com`)

---

## 1. Practical Example: Pre-Cutover Staging & Migration Testing

Suppose `example.com` resolves in public DNS to production server `104.20.23.154`.

Before updating public DNS, you want to test a newly provisioned migration server at IP `198.51.100.50`:

```text
Target Hostname:      example.com
Production DNS IP:    104.20.23.154
Override Destination: 198.51.100.50
```

### What WebPulse Does Under the Hood:
1. **TCP Socket**: Connects directly to `198.51.100.50:443`.
2. **TLS ClientHello**: Sends `SNI = example.com`.
3. **TLS Certificate Check**: Validates server certificate presented by `198.51.100.50` against domain `example.com`.
4. **HTTP Header**: Sends `Host: example.com`.
5. **DNS & Routing Telemetry**: Reports both `Normal DNS IP (104.20.23.154)` and `Actual Connection IP (198.51.100.50)` separately.

---

## 2. CLI Usage

### Direct `--resolve` Flag
```bash
webpulse scan https://example.com --resolve example.com:198.51.100.50
```

Multiple resolutions:
```bash
webpulse scan urls.txt \
  --resolve example.com:198.51.100.50 \
  --resolve api.example.com:10.20.30.40
```

### Hosts File Mapping (`--hosts-file`)
Supports standard `/etc/hosts` format, CSV (`hostname,ip`), or JSON:

```bash
webpulse scan urls.txt --hosts-file ./hosts.test
```

Example `./hosts.test` file:
```text
# Staging Server Mappings
198.51.100.50 example.com
10.20.30.40   api.example.com
```

### Dry Run Pre-Check
```bash
webpulse scan https://example.com --resolve example.com:198.51.100.50 --dry-run
```

---

## 3. REST API Usage

### `POST /api/v1/jobs` Payload
```json
{
  "urls": ["https://example.com"],
  "profile": "standard",
  "host_resolutions": {
    "example.com": "198.51.100.50"
  }
}
```

Or pass raw hosts file text:
```json
{
  "urls": ["https://example.com"],
  "hosts_file_content": "198.51.100.50 example.com\n10.20.30.40 api.example.com"
}
```

---

## 4. Canonical Result Schema Routing Output

```json
{
  "url": "https://example.com",
  "status": "completed",
  "target": {
    "hostname": "example.com",
    "resolved_ip": "198.51.100.50"
  },
  "routing": {
    "hostname": "example.com",
    "dns_ip": "104.20.23.154",
    "override_ip": "198.51.100.50",
    "actual_connection_ip": "198.51.100.50",
    "host_header": "example.com",
    "tls_sni": "example.com",
    "is_override_active": true
  }
}
```

---

## 5. Security & SSRF Policy

> [!IMPORTANT]
> - Target IP overrides do **not** bypass default SSRF protections.
> - Overrides mapping to private subnets (RFC 1918, loopback) require enabling explicit private/staging target policy (`--allow-private-targets`).
