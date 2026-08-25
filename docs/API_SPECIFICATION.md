# WebPulse REST API v1 Specification

## Overview
WebPulse provides a full REST API for job execution, target validation, real-time SSE progress streaming, historical job retrieval, and CSV/JSON/ZIP reporting.

Base URL: `http://localhost:8080/api/v1`

---

## Endpoints

### 1. System & Health
* `GET /api/v1/health`: Liveness & readiness check.
* `GET /api/v1/doctor`: Connectivity & environment doctor report.
* `GET /api/v1/egress`: Public outbound egress IP information.

### 2. Diagnostic Jobs
* `POST /api/v1/jobs`: Create and launch a new URL testing job.
  * **Payload**:
    ```json
    {
      "project_id": "default",
      "urls": ["https://example.com", "https://api.example.com"],
      "profile": "standard",
      "workers": 10,
      "allowed_scopes": ["*.example.com"]
    }
    ```
* `GET /api/v1/jobs`: List historical testing jobs.
* `GET /api/v1/jobs/:id`: Fetch job metadata and statistics.
* `POST /api/v1/jobs/:id/cancel`: Cancel an active job.
* `GET /api/v1/jobs/:id/results`: Get target result objects.

### 3. Real-time Progress (SSE)
* `GET /api/v1/jobs/:id/stream`: Server-Sent Events (SSE) progress stream emitting live `%` completed and target result events.

### 4. Exports
* `GET /api/v1/jobs/:id/export.json`: Export canonical JSON report.
* `GET /api/v1/jobs/:id/export.csv`: Export CSV report.
* `GET /api/v1/jobs/:id/export.zip`: Export ZIP bundle containing `results.json`, `results.csv`, and `metadata.json`.

### 5. Target Pre-Check
* `POST /api/v1/targets/validate`: Dry-run validation of URL syntax, SSRF safety, and scope policy.
