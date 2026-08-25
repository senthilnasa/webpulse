# WAF Allowlisting & Egress IP Verification Guide

## Architecture Overview

When WebPulse performs HTTP/HTTPS probes against web endpoints, network traffic travels through the testing engine's outbound NAT/Proxy onto the public Internet:

```text
[WebPulse Testing Engine] ───> [Outbound Router / NAT Gateway]
                                          │
                                          ▼ (Observed Public Egress IP)
                                    [Internet]
                                          │
                                          ▼
                               [Target WAF / Firewall]
                                          │
                                          ▼
                                [Target Web Application]
```

To ensure reliable diagnostic results without synthetic WAF rate-limiting or challenge delays, target Web Application Firewalls (e.g. Cloudflare, AWS WAF, Akamai, Imperva) should be configured to **allowlist the application's outbound egress IP**.

---

## 1. How to Identify the Egress IP

WebPulse includes an integrated **Egress IP Resolver** module (`pkg/egress`):

### Via Web UI
1. Navigate to the **Egress & WAF** page (`/egress`) in the Web UI.
2. Locate the **Public IPv4 Address** box.

### Via CLI
Run `webpulse doctor` or `webpulse version`:
```bash
webpulse doctor
```
Output:
```text
WebTest Doctor
────────────────────────────────────────
Public IPv4          ✓  203.0.113.195
DNS Resolution       ✓  Resolved example.com
Outbound HTTP        ✓  Status 200 OK
Outbound HTTPS / TLS ✓  Status 200 OK
────────────────────────────────────────
Egress IP:           203.0.113.195
Ready for testing:   YES
```

---

## 2. Step-by-Step WAF Allowlisting Instructions

### Cloudflare WAF
1. Log in to the Cloudflare Dashboard and select your domain.
2. Go to **Security** > **WAF** > **Tools** (IP Access Rules).
3. Add a new rule:
   - **Value**: `<Your Egress IP>` (e.g. `203.0.113.195`)
   - **Action**: `Allow`
   - **Zone**: `This website` or `All websites`
   - **Note**: `WebPulse Authorized Testing`

### AWS WAF (v2)
1. Navigate to AWS WAF Console > **IP sets**.
2. Create or select an IP set matching your region.
3. Add IP address `<Your Egress IP>/32`.
4. In your Web ACL, add an `ALLOW` rule matching traffic from the IP set.

---

## 3. Important WAF Policy & Non-Evasion Guarantee

> [!IMPORTANT]
> WebPulse adheres strictly to **non-evasion guidelines**:
> - Uses canonical User-Agent header: `WebPulse-Engine/1.0`.
> - Does **not** perform traffic obfuscation or WAF evasion tactics.
> - Intended solely for authorized testing of systems owned or authorized by the user.
