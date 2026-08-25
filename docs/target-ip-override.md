# Target IP Override & Host Mapping Guide

## Overview

The **Target IP Override / Host Mapping** feature allows authorized users to probe a target hostname against a specific server IP (such as a local, staging, QA, or pre-production migration server) while preserving the original hostname for:
- **HTTP Host Header** (`Host: krea.edu.in`)
- **TLS SNI (Server Name Indication)** (`SNI: krea.edu.in`)
- **TLS Certificate Validation** (Validates certificate against `krea.edu.in`)

---

## 1. Practical Example: Pre-Cutover Staging & Migration Testing

Suppose `krea.edu.in` resolves in public DNS to production server `104.20.23.154`.

Before updating public DNS, you want to test a newly provisioned migration server at IP `172.232.121.131`:

```text
Target Hostname:      krea.edu.in
Production DNS IP:    104.20.23.154
Override Destination: 172.232.121.131
```

### What WebPulse Does Under the Hood:
1. **TCP Socket**: Connects directly to `172.232.121.131:443`.
2. **TLS ClientHello**: Sends `SNI = krea.edu.in`.
3. **TLS Certificate Check**: Validates server certificate presented by `172.232.121.131` against domain `krea.edu.in`.
4. **HTTP Header**: Sends `Host: krea.edu.in`.
5. **DNS & Routing Telemetry**: Reports both `Normal DNS IP (104.20.23.154)` and `Actual Connection IP (172.232.121.131)` separately.

---

## 2. CLI Usage

### Direct `--resolve` Flag
```bash
webpulse scan https://krea.edu.in --resolve krea.edu.in:172.232.121.131
```

Multiple resolutions:
```bash
webpulse scan urls.txt \
  --resolve krea.edu.in:172.232.121.131 \
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
172.232.121.131 krea.edu.in
10.20.30.40     api.example.com
```

### Dry Run Pre-Check
```bash
webpulse scan https://krea.edu.in --resolve krea.edu.in:172.232.121.131 --dry-run
```

---

## 3. REST API Usage

### `POST /api/v1/jobs` Payload
```json
{
  "urls": ["https://krea.edu.in"],
  "profile": "standard",
  "host_resolutions": {
    "krea.edu.in": "172.232.121.131"
  }
}
```

Or pass raw hosts file text:
```json
{
  "urls": ["https://krea.edu.in"],
  "hosts_file_content": "172.232.121.131 krea.edu.in\n10.20.30.40 api.example.com"
}
```

---

## 4. Canonical Result Schema Routing Output

```json
{
  "url": "https://krea.edu.in",
  "status": "completed",
  "target": {
    "hostname": "krea.edu.in",
    "resolved_ip": "172.232.121.131"
  },
  "routing": {
    "hostname": "krea.edu.in",
    "dns_ip": "104.20.23.154",
    "override_ip": "172.232.121.131",
    "actual_connection_ip": "172.232.121.131",
    "host_header": "krea.edu.in",
    "tls_sni": "krea.edu.in",
    "is_override_active": true
  }
}
```

---

## 5. Security & SSRF Policy

> [!IMPORTANT]
> - Target IP overrides do **not** bypass default SSRF protections.
> - Overrides mapping to private subnets (RFC 1918, loopback) require enabling explicit private/staging target policy (`--allow-private-targets`).
