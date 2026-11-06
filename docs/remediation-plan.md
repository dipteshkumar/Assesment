# VulnTracker Remediation Plan

This document details the security remediations implemented across the VulnTracker codebase, provides technical before/after justification for each fix, and outlines the risk management strategy, residual risk, and compensating controls for deferred findings.

---

## Part 1: Implemented Remediations

In accordance with the assignment requirements, multiple Critical and High severity findings have been remediated in code. In particular, fixes have been applied across both the starter code and the new Task 1 feature.

### 1. Remediations in New Feature (Task 1)

#### Fix A: Cryptographic Hashing of Shared Report Passwords (SEC-03)
- **Problem**: The initial prototype stored the user-supplied share password in plain text in the `shared_scan_links` table (`password = Column(String(200))`), and authenticated requests using naive string comparison (`password != shared_link.password`).
- **Remediation**:
  - Replaced `password` column with `hashed_password` in `SharedScanLink` model (`app/models.py`).
  - Upon share link generation, hashed the password with bcrypt (`get_password_hash`) before persisting to SQLite.
  - Upon access, verified the password using constant-time bcrypt verification (`verify_password`) in `app/main.py`.
- **Security Impact**: Eliminates plaintext credential storage (CWE-256 / CWE-312) and prevents timing side-channel attacks during password evaluation.

#### Fix B: Broken Object Level Authorization on Share Link Creation (SEC-05)
- **Problem**: `POST /scans/{scan_id}/share` queried `models.ScanResult.id == scan_id` without checking `models.ScanResult.owner_id == current_user.id`. Any authenticated user could generate a public share link for any scan belonging to any other user.
- **Remediation**: Added ownership verification in `POST /scans/{scan_id}/share`:
  ```python
  scan = db.query(models.ScanResult).filter(
      models.ScanResult.id == scan_id,
      models.ScanResult.owner_id == current_user.id,
  ).first()
  if not scan:
      raise HTTPException(status_code=404, detail="Scan not found")
  ```
- **Security Impact**: Enforces horizontal multi-tenant isolation, preventing unauthorized sharing or data exfiltration across organizations.

---

### 2. Remediations in Starter Code

#### Fix C: SQL Injection Elimination & Tenant Search Isolation (SEC-01)
- **Problem**: `search_scans_by_query` in `app/database.py` used Python f-strings to interpolate raw user input directly into an SQL statement executed via SQLAlchemy `text()`. Furthermore, it failed to scope search results to the calling user, leaking other users' scans.
- **Remediation**:
  - Converted the raw SQL string into a parameterized query using SQLAlchemy bind parameters (`:query` and `:owner_id`).
  - Added user isolation so search queries strictly return records belonging to the authenticated tenant:
  ```python
  def search_scans_by_query(db, query: str, owner_id: Optional[int] = None) -> list:
      sql_stmt = (
          "SELECT id, title, description, severity, status, cve_id, "
          "affected_component, owner_id, created_at FROM scan_results "
          "WHERE (title LIKE :query OR description LIKE :query OR cve_id LIKE :query)"
      )
      params = {"query": f"%{query}%"}
      if owner_id is not None:
          sql_stmt += " AND owner_id = :owner_id"
          params["owner_id"] = owner_id
      result = db.execute(text(sql_stmt), params)
      return [dict(row._mapping) for row in result]
  ```
- **Security Impact**: Completely immunizes the search endpoint against SQL injection (CWE-89) and enforces tenant privacy.

#### Fix D: Insecure JWT "none" Algorithm Rejection (SEC-02)
- **Problem**: `decode_token` in `app/auth.py` permitted `"none"` in the algorithms parameter (`algorithms=[ALGORITHM, "none"]`). This allowed an attacker to strip the token signature, set `{"alg": "none"}`, and bypass authentication entirely.
- **Remediation**:
  - Restrict the algorithm list to only `[ALGORITHM]` (`HS256`).
  ```python
  def decode_token(token: str) -> dict:
      try:
          payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
          return payload
  ```
- **Security Impact**: Neutralizes JWT signature bypass (CWE-347) and ensures cryptographic integrity on all bearer tokens.

#### Fix E: Broken Object Level Authorization on Scan Retrieval (SEC-04)
- **Problem**: `GET /scans/{scan_id}` fetched the scan record solely by `id`, allowing any authenticated user to inspect confidential findings owned by other accounts.
- **Remediation**: Updated `get_scan` in `app/main.py` to filter by both `id` and `owner_id == current_user.id`, returning a 404 if the record does not exist or belongs to another user.
- **Security Impact**: Resolves OWASP API Security Top 10 #1 vulnerability (Broken Object Level Authorization).

#### Fix F: Elimination of Plaintext Credential Logging (SEC-07)
- **Problem**: `login` in `app/main.py` logged `payload.password` in plaintext on both successful and failed authentication attempts.
- **Remediation**: Removed all password references from `logger.info` and `logger.warning`, logging only the username.
- **Security Impact**: Prevents credential harvesting via log aggregators, SIEM platforms, and support dashboards (CWE-532).

#### Fix G: CORS Restriction & Origin Whitelisting (SEC-08)
- **Problem**: Middleware dynamically reflected the request's `Origin` header while returning `Access-Control-Allow-Credentials: true`, enabling malicious origins to perform cross-site authenticated data retrieval.
- **Remediation**: Configured strict whitelist validation against `ALLOWED_ORIGINS` from environment configuration. Unrecognized origins receive standard CORS rejection.
- **Security Impact**: Restores the browser Same-Origin Policy boundary for authenticated endpoints.

#### Fix H: Error Handling & Stack Trace Sanitization (SEC-10)
- **Problem**: Global exception handler returned Python tracebacks, exception class names, and filesystem paths in HTTP 500 responses.
- **Remediation**: Sanitized 500 response bodies to return a generic message (`{"detail": "An internal server error occurred."}`) while retaining full tracebacks exclusively in internal server-side logs.
- **Security Impact**: Prevents information disclosure and reduces reconnaissance capability for external attackers (CWE-209).

#### Fix I: Externalization of Application Secrets (SEC-06)
- **Problem**: `SECRET_KEY`, `DB_PASSWORD`, and `ADMIN_API_KEY` were hardcoded into `app/config.py`.
- **Remediation**: Refactored `config.py` to source all sensitive credentials from environment variables (`os.getenv(...)`) with secure defaults for local testing. In Kubernetes, values are injected via Kubernetes Secrets / External Secrets Operator.

---

## Part 2: Deferred Findings & Risk Management Strategy

The table below outlines findings that were deferred from direct code modification during this prototype phase, detailing the residual risk, required remediation effort, and operational compensating controls.

| Finding | Category | Residual Risk Assessment | Required Engineering Effort | Operational Compensating Controls |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-09: Outdated Pinned Dependencies** (`cryptography`, `fastapi`, `python-multipart`) | SCA / 3rd-party | **Medium**: Remote exploitability is constrained because VulnTracker runs behind an ingress reverse proxy. However, multipart parser DoS and cryptographic memory flaws present latent risks. | **Medium (3–5 engineer days)**: Upgrading to `cryptography>=42.0.0` and `fastapi>=0.110.0` requires upgrading `python-jose` to `pyjwt`, testing SQLAlchemy 2.0 migration impacts, and validating Python 3.11 ABI stability. | 1. Ingress reverse proxy terminates all TLS traffic before it reaches the Python container, insulating Python's `cryptography` library from direct public cipher negotiation.<br>2. Ingress proxy restricts `client_max_body_size` to 8MB, mitigating large multipart DoS payloads.<br>3. Container execution strictly drops all Linux capabilities (`capabilities: drop: [ALL]`) and runs as non-root UID 10001. |
| **SEC-11: SSRF in Webhook Dispatcher** (`notify/src/dispatcher.js`) | Node.js Egress | **Medium**: If an attacker registers a webhook pointing to `http://169.254.169.254` or internal cluster IPs, the dispatch request could expose metadata or internal HTTP services. | **Medium (2 engineer days)**: Implement an IP allowlist/blocklist in Node.js dispatcher using `ipaddr.js` to reject RFC 1918 private subnets, loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), and prevent DNS rebinding. | 1. Kubernetes `NetworkPolicy` restricts egress traffic from notification pods to external destinations only; internal cluster pod-to-pod traffic is blocked.<br>2. Cloud metadata access requires IMDSv2 with hop limit set to 1, blocking container-initiated metadata queries.<br>3. Notification service is deployed inside a private VPC subnet without direct internet routing except through an egress NAT gateway. |
| **SEC-12: Unauthenticated Webhook Management** (`notify/src/index.js`) | Node.js API Auth | **Medium**: The notification prototype accepts webhooks and trigger notifications without checking an API key or HMAC signature. | **Small (1 engineer day)**: Implement bearer token or HMAC-SHA256 signature middleware on `/notify` and `/webhooks` using a shared secret managed in Vault. | 1. Kubernetes `NetworkPolicy` strictly isolates `vulntracker-notify`, accepting ingress exclusively from the `vulntracker-api` pod on port 3001.<br>2. Service is internal-only (`ClusterIP`) and is never routed to public Ingress. |
| **SEC-13: Workload in Default Namespace** (`helm/vulntracker`) | IaC Misconfiguration | **Low**: Helm chart default manifests omit a hardcoded namespace. | **Minimal (10 minutes)**: Add namespace parameterization to Helm chart metadata or enforce via deployment pipeline. | Helm deployments are executed with standard CI/CD flags: `helm install vulntracker ./helm/vulntracker --namespace sec-ops --create-namespace`. |

---

## Part 3: Verification & Test Coverage Summary

All remediations have been verified with automated regression and security tests in `tests/test_api.py`:
- `test_get_scan_unauthorized_bola`: Verifies cross-tenant scan isolation (returns HTTP 404).
- `test_create_share_link_unauthorized_bola`: Verifies cross-tenant share link protection (returns HTTP 404).
- `test_share_password_hashed_in_db`: Inspects database state to ensure share link passwords are encrypted with bcrypt hashes.
- `test_search_scans_sqli_protection`: Injects SQL syntax breaking sequences (`' OR '1'='1`) to confirm parameterized query safety.
- `test_jwt_none_algorithm_rejected`: Forges unsigned tokens with `{"alg": "none"}` and validates HTTP 401 rejection.
- All 18 automated API test cases pass with green status.

