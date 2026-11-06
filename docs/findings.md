# VulnTracker Security Assessment Findings

## Executive Overview & Application Context

**VulnTracker** is an enterprise vulnerability management repository and tracking system. Security operations teams, developers, and compliance auditors use it to catalog discovered security vulnerabilities, track remediations, and share findings with internal teams and external auditors.

In the context of this application, the assets being protected are **vulnerability intelligence data, exploit mitigation notes, system architecture details, and administrative credentials**. A compromise of VulnTracker represents an existential security catastrophe: an attacker gaining unauthorized read access obtains a verified roadmap of unpatched weaknesses and zero-days across the organization's entire attack surface. An attacker gaining write access can alter vulnerability severities, mark active exploits as resolved, or delete records to blind the security operations team.

---

## Prioritised Findings Matrix

The table below synthesises results across Static Application Security Testing (SAST), Software Composition Analysis (SCA), Container Image Scanning, Infrastructure-as-Code (IaC) linting, and thorough manual code review.

| ID | Vulnerability Finding | Detected By | Evaluated Severity | Target Location | Business & Operational Impact |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | SQL Injection in Scan Search Query (`search_scans_by_query`) | SAST (Bandit B608) / Manual | **CRITICAL** | Starter Code (`app/database.py`) | Allows authenticated attackers to bypass tenant isolation, dump entire database contents (including all users' password hashes and all confidential scan records), or alter/drop database tables. |
| **SEC-02** | JWT Algorithm Confusion / Insecure "none" Algorithm Allowed | Manual Code Review | **CRITICAL** | Starter Code (`app/auth.py`) | Allows attackers to forge arbitrary authentication tokens with `{"alg": "none"}` and claim administrative user identities without possessing the server's private secret key. |
| **SEC-03** | Plaintext Share Password Storage in Database | Manual Review / SAST | **CRITICAL** | New Feature (`app/models.py`, `app/main.py`) | If the database or an unauthorized dump is accessed, all shared report passwords are immediately exposed in plaintext without cryptographic hashing. |
| **SEC-04** | Broken Object Level Authorization (BOLA/IDOR) on Scan Retrieval | Manual Code Review | **HIGH** | Starter Code (`app/main.py`) | Any authenticated user can view any other user's vulnerability scan reports by incrementing `scan_id` on `GET /scans/{scan_id}`, completely bypassing multi-tenant isolation. |
| **SEC-05** | Broken Object Level Authorization (BOLA/IDOR) on Share Link Creation | Manual Code Review | **HIGH** | New Feature (`app/main.py`) | Any authenticated user can generate a public share link for any scan record in the system—even scans owned by other tenants—exposing confidential reports to unauthorized parties. |
| **SEC-06** | Hardcoded Encryption Secrets, DB Passwords, & Internal API Keys | SAST (Bandit B105) | **HIGH** | Starter Code (`app/config.py`) | Hardcoded production secrets (`SECRET_KEY`, `DB_PASSWORD`, `ADMIN_API_KEY`) committed to git history allows anyone with repository access to sign valid tokens or access data stores. |
| **SEC-07** | Plaintext Credentials Written to Application Logs | SAST (Bandit B105) / Manual | **HIGH** | Starter Code (`app/main.py`) | User passwords entered during login attempts are recorded verbatim in application logs (`logger.info`, `logger.warning`), exposing credentials to log aggregation pipelines and SIEM operators. |
| **SEC-08** | Insecure Dynamic CORS Reflection with Credentials Enabled | Manual Code Review | **HIGH** | Starter Code (`app/main.py`) | Custom CORS middleware reflects whatever `Origin` header the client sends while setting `Access-Control-Allow-Credentials: true`. Malicious websites can make cross-origin authenticated requests and read scan data. |
| **SEC-09** | Outdated Dependencies with Known Critical CVEs in Cryptography & Web Stack | SCA (pip-audit) | **HIGH** | Starter Code (`requirements.txt`) | Pinned dependencies contain known remote exploit vectors: `cryptography==38.0.1` (24 CVEs, memory corruption/buffer overflows), `python-multipart==0.0.6` (DoS), `python-jose==3.3.0` (algorithm confusion). |
| **SEC-10** | Unhandled Stack Trace & Path Information Disclosure in Error Handler | Manual Code Review | **MEDIUM** | Starter Code (`app/main.py`) | Unhandled 500 exceptions return the full Python traceback, filesystem directory paths, and exception messages to client callers, aiding adversary reconnaissance. |
| **SEC-11** | Server-Side Request Forgery (SSRF) in Notification Dispatcher | Manual Code Review | **MEDIUM** | Starter Code (`notify/src/dispatcher.js`) | Webhook registry accepts arbitrary URLs and dispatches HTTP POST requests with an internal service key. Could be leveraged to pivot against cloud metadata (169.254.169.254) or internal cluster endpoints. |
| **SEC-12** | Lack of Authentication on Notification Service Webhook Endpoints | Manual Code Review | **MEDIUM** | Starter Code (`notify/src/index.js`) | Endpoints `/webhooks` and `/notify` lack any authentication or authorization middleware, allowing anyone who can reach the service to inject false events or listen to scan updates. |
| **SEC-13** | Deployment to Kubernetes Default Namespace | IaC Scan (Trivy KSV-0110) | **LOW** | Deployment Artifacts (`helm/vulntracker`) | Deploying workloads without an explicit namespace defaults to the `default` namespace, reducing isolation boundaries in multi-tenant Kubernetes clusters. |

---

## Detailed Vulnerability Analysis

### 1. SEC-01 — SQL Injection in Search Query
- **Tool / Detection**: SAST (Bandit test ID `B608`), Manual Review.
- **Location**: `app/database.py`, lines 20–29 (`search_scans_by_query`).
- **Severity**: **CRITICAL** (CVSS: 9.8).
- **Technical Mechanism**: The function uses Python f-strings to concatenate the untrusted user parameter `query` directly into raw SQL:
  ```python
  sql = (
      f"SELECT id, title, description, severity, status, cve_id, "
      f"affected_component, owner_id, created_at FROM scan_results "
      f"WHERE title LIKE '%{query}%' OR description LIKE '%{query}%' "
      f"OR cve_id LIKE '%{query}%'"
  )
  ```
- **Business Impact**: A malicious user supplying `' UNION SELECT id, username, hashed_password, ... FROM users--` can extract all user password hashes. In SQLite or PostgreSQL environments, attackers can extract database schemas, exfiltrate scans from all organizations, or delete records.

### 2. SEC-02 — JWT Algorithm Confusion / "none" Algorithm Acceptance
- **Tool / Detection**: Manual Code Review.
- **Location**: `app/auth.py`, line 38 (`decode_token`).
- **Severity**: **CRITICAL** (CVSS: 9.8).
- **Technical Mechanism**: When validating tokens, `jwt.decode` specifies `algorithms=[ALGORITHM, "none"]`. By standard JWT specification behavior, an attacker can craft an unsigned JWT with header `{"alg": "none", "typ": "JWT"}` and payload `{"sub": "admin"}`. The library accepts the unsigned token as valid because `"none"` is in the allowed algorithms list.
- **Business Impact**: Complete authentication bypass. Any external adversary can impersonate any user, including administrators, without knowing `SECRET_KEY`.

### 3. SEC-03 — Plaintext Share Password Storage
- **Tool / Detection**: Manual Review of Task 1 Implementation.
- **Location**: `app/models.py` (`SharedScanLink.password`), `app/main.py`.
- **Severity**: **CRITICAL** (CVSS: 9.1).
- **Technical Mechanism**: When creating a password-protected share link in Task 1, the password string was stored directly in the `shared_scan_links` database table without hashing. Furthermore, authentication on retrieval used plain string comparison (`password != shared_link.password`) susceptible to timing side channels.
- **Business Impact**: Passwords chosen by security officers or customers are directly readable in database backups, replication logs, or through SQL injection, violating baseline cryptographic hygiene (CWE-256 / CWE-312).

### 4. SEC-04 & SEC-05 — Broken Object Level Authorization (BOLA/IDOR)
- **Tool / Detection**: Manual Code Review.
- **Location**: `app/main.py` (`GET /scans/{scan_id}`) and `app/main.py` (`POST /scans/{scan_id}/share`).
- **Severity**: **HIGH** (CVSS: 8.5).
- **Technical Mechanism**: In `GET /scans/{scan_id}`, the query executes `db.query(models.ScanResult).filter(models.ScanResult.id == scan_id).first()` without filtering by `models.ScanResult.owner_id == current_user.id`. In `POST /scans/{scan_id}/share`, the endpoint also queries only by `scan_id`, allowing any authenticated user to generate a public share link for another customer's scan.
- **Business Impact**: Complete loss of confidentiality across tenant accounts. An attacker registers a legitimate trial account and systematically enumerates integer IDs (`1..10000`) to view all vulnerability reports across the enterprise.

### 5. SEC-06 — Hardcoded Configuration Secrets
- **Tool / Detection**: SAST (Bandit `B105`).
- **Location**: `app/config.py`, lines 3, 9, 12.
- **Severity**: **HIGH** (CVSS: 8.2).
- **Technical Mechanism**: Production keys (`SECRET_KEY = "v3ry-s3cr3t-jwt-k3y-do-not-share"`, `DB_PASSWORD = "Tr@cker2024!"`, `ADMIN_API_KEY = "sk-vt-prod-8f3a2b1c9d4e5f6a7b8c9d0e1f2a3b4c"`) are hardcoded directly in Python source code.
- **Business Impact**: Anyone with read access to source code, git commits, CI logs, or decompiled container layers possesses administrative access to the database and can forge user authentication sessions.

### 6. SEC-07 — Cleartext Password Logging
- **Tool / Detection**: SAST (Bandit `B105`) / Manual Review.
- **Location**: `app/main.py`, lines 148, 151–155.
- **Severity**: **HIGH** (CVSS: 7.5).
- **Technical Mechanism**: The login handler explicitly formats the password string into stdout/stderr logs via `logger.info` and `logger.warning`:
  ```python
  logger.info("Login attempt — username: %s password: %s", payload.username, payload.password)
  ```
- **Business Impact**: Passwords are saved in plain text across cloud log streams (e.g. AWS CloudWatch, Datadog, Elasticsearch), exposing employee and customer passwords to developers, support staff, and log storage vendors.

### 7. SEC-08 — Wildcard Dynamic CORS Reflection with Credentials
- **Tool / Detection**: Manual Code Review.
- **Location**: `app/main.py`, lines 29–38 (`cors_middleware`).
- **Severity**: **HIGH** (CVSS: 7.5).
- **Technical Mechanism**: The custom middleware dynamically echoes the request's `Origin` header into `Access-Control-Allow-Origin` while simultaneously sending `Access-Control-Allow-Credentials: true`.
- **Business Impact**: This completely undermines the Same-Origin Policy (SOP). An authenticated user visiting an attacker-controlled website can have their browser silently fetch `/scans` and transmit the full inventory of corporate vulnerabilities to the attacker.

### 8. SEC-09 — High-Severity Vulnerabilities in Pinned Dependencies
- **Tool / Detection**: SCA (`pip-audit`).
- **Location**: `requirements.txt`.
- **Severity**: **HIGH** (CVSS: 7.5–9.8 across multiple CVEs).
- **Technical Mechanism**: `requirements.txt` pins `cryptography==38.0.1` (which contains 24 known CVEs including OpenSSL memory corruption flaws), `python-multipart==0.0.6` (ReDoS / payload memory exhaustion), and `python-jose==3.3.0` (unmaintained, timing flaws, algorithm confusion).
- **Business Impact**: Remote attackers can cause denial of service via memory exhaustion attacks on multipart file uploads, or trigger memory corruption in older cryptographic libraries.

---

## Remediation Prioritisation Strategy

1. **Immediate Code Fixes (Task 3)**:
   - Eliminate direct string SQL injection with parameterized SQLAlchemy filters.
   - Enforce cryptographic validation on JWT tokens (drop `"none"` algorithm).
   - Secure Task 1 share links by salting and hashing share passwords with bcrypt and enforcing tenant ownership checks on link creation.
   - Restrict `GET /scans/{scan_id}` to verify object ownership (`owner_id == current_user.id`).
   - Remove plaintext credential logging.
   - Replace dynamic CORS reflection with strict, explicit origin whitelisting.
   - Sanitize global exception responses.
   - Externalize secrets to environment variables.

2. **Deferred Work & Compensating Controls**:
   - Documented in `docs/remediation-plan.md` for dependency upgrades, SSRF protection in Node.js notification dispatchers, and network segmentation.
