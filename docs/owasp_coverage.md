# OWASP API Security Top 10 Coverage Matrix

APISec provides tailored detection checks for the OWASP API Security Top 10 vulnerability categories.

| OWASP Category | Name | Detection Check Class | Target CWE | Detection Methodology |
|---|---|---|---|---|
| **API1:2023** | Broken Object Level Authorization (BOLA) | `BOLACheck` | CWE-639 | Swaps path parameters between User A and User B tokens and verifies HTTP 200 cross-tenant data leakage. |
| **API2:2023** | Broken Authentication | `BrokenAuthCheck` | CWE-306, CWE-347 | Tests routes without credentials and with forged/corrupted bearer tokens to detect unauthenticated access. |
| **API3:2023** | Broken Object Property Level Auth | `MassAssignmentCheck` | CWE-915 | Injects administrative and privilege properties (`role: admin`, `is_admin: true`) into POST/PUT/PATCH bodies. |
| **API4:2023** | Unrestricted Resource Consumption | `RateLimitingCheck` | CWE-770 | Executes burst requests against search/query endpoints and flags absence of HTTP 429 Too Many Requests. |
| **API5:2023** | Broken Function Level Authorization (BFLA) | `BFLACheck` | CWE-285 | Tests privileged routes (`/admin/*`) with standard user tokens to identify missing role-based access control. |
| **API6:2023** | Server-Side Request Forgery (SSRF) | `SSRFCheck` | CWE-918 | Probes URL/webhook parameters with cloud metadata (`169.254.169.254`) and loopback addresses. |
| **API7:2023** | Security Misconfiguration | `SecurityMisconfigCheck` | CWE-942, CWE-209 | Checks for permissive CORS origins (`Access-Control-Allow-Origin: *` with credentials) and stack trace leakage. |
| **API8:2023** | Lack of Protection from Automated Threats | `RateLimitingCheck` | CWE-799 | High-frequency parameter fuzzing detection. |
| **API9:2023** | Improper Inventory Management | `OpenAPIParser` | CWE-1059 | Identifies undocumented, deprecated, or shadow endpoints. |
| **API10:2023**| Unsafe Consumption of APIs | `SSRFCheck` | CWE-20 | Probes outbound webhook/callback destinations for SSRF vulnerabilities. |
