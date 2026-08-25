# Server-Side Request Forgery (SSRF) Protection & Defense Architecture

## Overview
WebPulse enables users to submit single or bulk URLs for authorized HTTP/HTTPS diagnostic testing. Because user-supplied URLs can point to internal infrastructure, **Server-Side Request Forgery (SSRF)** defenses are baked into the core networking engine.

WebPulse enforces **multi-layered, pre-dial IP verification and DNS rebinding protections** to guarantee that the application can never be coerced into probing internal networks or cloud metadata APIs.

---

## 1. Protected Ranges & Restricted IP Prefixes

Before dialing any network socket, WebPulse parses the resolved IP address against all restricted IPv4 and IPv6 ranges:

| Target Category | Subnet Range / Address | Description |
| :--- | :--- | :--- |
| **Loopback** | `127.0.0.0/8`, `::1/128` | Localhost loopback addresses |
| **RFC 1918 Private IPv4** | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | Internal private subnets |
| **Link-Local & Cloud Metadata** | `169.254.0.0/16`, `fe80::/10` | AWS/GCP/Azure IMDS metadata endpoints |
| **Shared Address Space (CGNAT)** | `100.64.0.0/10` | Carrier-grade NAT addresses |
| **IPv6 Unique Local (ULA)** | `fc00::/7` | Internal IPv6 addresses |
| **Multicast & Broadcast** | `224.0.0.0/4`, `255.255.255.255/32` | Non-unicast destinations |
| **Documentation & TEST-NET** | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | Reserved benchmark subnets |

---

## 2. Safe Dialer & DNS Rebinding Mitigation

Standard HTTP clients resolve hostnames dynamically at dial time, creating a vulnerability window known as **DNS Rebinding** (where a domain initially resolves to a public IP during validation, but returns `127.0.0.1` when the socket connection is created).

### WebPulse Safe Dialer Mechanism (`pkg/ssrf/dialer.go`)
1. **Pre-Resolution**: The domain is resolved using Go's `net.Resolver`.
2. **Strict IP Validation**: Every resolved IP address is verified against `IsIPRestricted()`. If *any* resolved address falls within a restricted subnet, the entire request is immediately aborted before socket creation.
3. **IPv4-Mapped IPv6 Unmapping**: IPv4-in-IPv6 addresses (e.g. `::ffff:127.0.0.1`) are normalized to standard IPv4 prior to evaluation.
4. **Direct IP Connection**: The socket dials the *validated IP address directly* while setting the HTTP `Host` header to the target domain, completely neutralizing DNS rebinding attacks.

---

## 3. HTTP Redirect Re-Validation

When following HTTP redirects (e.g. 301/302/307), WebPulse intercepts the `Location` header URL in `CheckRedirect`:
- Validates the scheme (`http` / `https` only).
- Runs `ValidateDestination()` on the target redirect hostname.
- Rejects any redirect attempt pointing to loopback, private IP, or cloud metadata endpoints.

---

## 4. Target Scope Authorization Guard

In addition to SSRF protection, WebPulse supports project-level **Allowed Scope Policy**:
- Wildcard glob patterns (`*.example.com`, `example.org`).
- URLs outside the configured policy match state `blocked` with reason: `Target Scope Violation`.

---

## Authorization Reminder
> [!IMPORTANT]
> WebPulse is designed for **authorized URL testing** on infrastructure you own or have explicit permission to test.
