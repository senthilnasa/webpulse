# WebPulse CLI User & Developer Guide

## Installation

### From Go Source
```bash
go build -o webpulse ./cmd/webpulse
mv webpulse /usr/local/bin/
```

### Docker
```bash
docker compose up -d
docker exec -it webpulse webpulse doctor
```

---

## Commands & Usage

### 1. Single URL Scan
```bash
webpulse scan https://example.com
```

### 2. Bulk Scan from Input File
Supports `.txt`, `.csv`, or `.json` files:
```bash
webpulse scan urls.txt --profile standard --workers 10
```

### 3. Machine-Readable JSON / CSV Export
```bash
webpulse scan urls.json --format json --output results.json
webpulse scan urls.csv --format csv --output report.csv
```

### 4. Dry-Run Validation
Validate SSRF and target scope rules without dialing targets:
```bash
webpulse scan urls.txt --dry-run
```

### 5. CI/CD Fail-On-Error Pipeline Integration
Exits with code `1` if any URL target fails or is blocked:
```bash
webpulse scan urls.txt --fail-on-error
```

### 6. Environment Connectivity Doctor
```bash
webpulse doctor
```

---

## Exit Codes
* `0`: Success (All probes completed / dry-run passed)
* `1`: Test failures or blocked targets detected (with `--fail-on-error`)
* `2`: Configuration or input error
* `3`: Fatal internal error
