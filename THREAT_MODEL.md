# AIB Threat Model

**Version:** 0.1.0  
**Author:** Thomas Nirennold — TNTECH CONSULTING SAS  
**Date:** March 2026  
**Status:** Living document — updated with each protocol binding addition  

---

## 1. Scope

This document describes the threat model for the Agent Identity Bridge (AIB) gateway — a cross-protocol identity layer that sits between AI agents and the MCP, A2A, ANP, and AG-UI protocol stacks.

AIB handles:
- **Signing and verification** of Agent Passports (JWS tokens)
- **Storage** of per-protocol credentials (OAuth tokens, API keys, DID private keys)
- **Translation** between protocol identity formats (Agent Card ↔ Server Card ↔ DID Document)
- **Proxying** of requests with automatic credential injection
- **Logging** of all cross-protocol interactions

Each of these surfaces is analyzed below.

---

## 2. Trust boundaries

```
┌─────────────────────────────────────────────────┐
│                 TRUSTED ZONE                     │
│                                                  │
│  ┌──────────┐    ┌──────────────┐    ┌────────┐ │
│  │ Passport │    │  Credential  │    │ Audit  │ │
│  │ Service  │    │    Vault     │    │ Logger │ │
│  └────┬─────┘    └──────┬───────┘    └───┬────┘ │
│       │                 │                │      │
│  ┌────┴─────────────────┴────────────────┴────┐ │
│  │              AIB Gateway                    │ │
│  └────────────────────┬───────────────────────┘ │
│                       │                         │
└───────────────────────┼─────────────────────────┘
                        │ TRUST BOUNDARY
        ┌───────────────┼───────────────────┐
        │               │                   │
   ┌────▼────┐    ┌─────▼─────┐    ┌───────▼───────┐
   │   MCP   │    │    A2A    │    │     ANP       │
   │ Servers │    │  Agents   │    │    Peers      │
   └─────────┘    └───────────┘    └───────────────┘
              UNTRUSTED ZONE
```

**Trust boundary:** The AIB gateway trusts its own passport service, credential vault, and audit logger. It does NOT trust incoming requests, external protocol endpoints, or translated identity documents.

---

## 3. Threat catalog

### T1 — Passport forgery

| Field | Value |
|-------|-------|
| **STRIDE** | Spoofing |
| **Target** | Passport Service |
| **Attack** | Attacker crafts a valid-looking passport with a forged signature to impersonate a legitimate agent |
| **Impact** | Critical — full identity takeover, unauthorized access to all bound protocols |
| **Likelihood** | High if using symmetric signing (HMAC), Low with asymmetric (RS256) |

**Mitigations:**
- **[M1.1]** Use RS256 (asymmetric) signatures. Private key never leaves the passport service. Public key exposed at `/.well-known/aib-keys.json` for verification.
- **[M1.2]** Key rotation every 90 days. Old keys remain valid for verification (grace period) but new passports use the current key.
- **[M1.3]** Include `kid` (key ID) in JWS header so verifiers know which key to use.
- **[M1.4]** Passport expiration (`exp` claim) enforced on every verification call.

**Implementation status:** ⚠️ MVP uses HMAC-SHA256. RS256 migration required before production.

---

### T2 — Credential vault breach

| Field | Value |
|-------|-------|
| **STRIDE** | Information Disclosure |
| **Target** | Credential Store |
| **Attack** | Attacker gains read access to the credential vault and extracts OAuth tokens, API keys, or DID private keys |
| **Impact** | Critical — attacker can impersonate agents on all bound protocols |
| **Likelihood** | Medium (depends on vault implementation) |

**Mitigations:**
- **[M2.1]** Credentials stored encrypted at rest (AES-256-GCM minimum).
- **[M2.2]** Passport documents contain `credential_ref` (vault reference), never the credential itself.
- **[M2.3]** Credentials never appear in API responses, logs, or error messages.
- **[M2.4]** Production deployments should use HashiCorp Vault or cloud KMS (AWS KMS, GCP KMS) instead of local file storage.
- **[M2.5]** Credential access logged in audit trail (who accessed which credential, when).

**Implementation status:** ⚠️ MVP uses plaintext JSON files. Encryption wrapper required.

---

### T3 — Translation injection (card poisoning)

| Field | Value |
|-------|-------|
| **STRIDE** | Tampering |
| **Target** | Credential Translator |
| **Attack** | Attacker provides a malicious Agent Card (A2A) or Server Card (MCP) containing crafted fields: oversized payloads, script injection in description fields, redirect URLs pointing to attacker-controlled servers, excessive scope requests |
| **Impact** | High — poisoned cards propagate to other protocols via translation, potentially granting unintended access |
| **Likelihood** | Medium — requires attacker to control an agent card |

**This is a novel attack vector specific to cross-protocol identity bridging.** No existing security research covers it because no production cross-protocol translator exists yet.

**Attack scenarios:**
1. **URL redirect poisoning:** Agent Card `url` field points to `https://evil.com` instead of the real agent. After translation to MCP Server Card, the gateway proxies requests to the attacker.
2. **Scope escalation:** Agent Card declares `skills: ["admin", "delete_all"]`. After translation, the MCP Server Card exposes tools with elevated permissions.
3. **Payload bomb:** Agent Card `description` field contains 10MB of text, causing OOM in the translator.
4. **Nested injection:** Agent Card `skills[0].description` contains JSON that, when parsed by a downstream MCP client, alters the tool's behavior.

**Mitigations:**
- **[M3.1]** Strict input validation on every field before translation:
  - URLs: must be HTTPS, valid hostname, no IP addresses, no private ranges
  - Strings: max 1000 characters, stripped of control characters
  - Arrays: max 50 items
  - Entire document: max 100KB
- **[M3.2]** Output validation: translated documents checked against JSON Schema before delivery.
- **[M3.3]** Capability allowlist: only declared capabilities in the passport are translated. Skills/tools not in the passport's `capabilities` list are stripped.
- **[M3.4]** Translation audit: every translation logged with before/after hash for forensic comparison.

**Implementation status:** ❌ Not implemented. Priority for v0.2.

---

### T4 — Gateway proxy abuse (SSRF)

| Field | Value |
|-------|-------|
| **STRIDE** | Elevation of Privilege |
| **Target** | Gateway Proxy |
| **Attack** | Attacker uses the AIB gateway as an open relay to reach internal services, cloud metadata endpoints (169.254.169.254), or localhost services |
| **Impact** | Critical — access to cloud credentials, internal APIs, database services |
| **Likelihood** | High if no URL filtering is implemented |

**Mitigations:**
- **[M4.1]** Target URL validation:
  - Must be HTTPS (no HTTP, no FTP, no file://)
  - Must resolve to a public IP (no private ranges: 10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x)
  - Must not resolve to localhost or link-local addresses
  - DNS resolution performed server-side before proxying
- **[M4.2]** Domain allowlist per passport: each passport declares which domains it can proxy to (derived from protocol binding URLs).
- **[M4.3]** Rate limiting per passport_id: 100 requests/minute default, configurable.
- **[M4.4]** Request size limit: 1MB max body.
- **[M4.5]** Response size limit: 10MB max, streaming cut off beyond limit.
- **[M4.6]** No following of redirects by default. If the target returns 3xx, return the redirect to the caller without following it.

**Implementation status:** ❌ Not implemented. Critical priority.

---

### T5 — Passport replay attack

| Field | Value |
|-------|-------|
| **STRIDE** | Spoofing, Repudiation |
| **Target** | Passport Verification |
| **Attack** | Attacker intercepts a valid passport token (e.g., via network sniffing or log exposure) and replays it to authenticate as the original agent |
| **Impact** | High — impersonation until passport expires |
| **Likelihood** | Medium — requires token interception |

**Mitigations:**
- **[M5.1]** Short-lived passports for API calls: `exp` set to 1 hour, with refresh mechanism.
- **[M5.2]** `jti` (JWT ID) claim: unique nonce per passport issuance, checked against a server-side set of seen JTIs.
- **[M5.3]** `nbf` (not before) claim: passport not valid before issuance time, preventing pre-dated forgeries.
- **[M5.4]** Binding to source IP or TLS fingerprint (optional, for high-security deployments).
- **[M5.5]** Passport tokens transmitted only over TLS. Gateway rejects non-HTTPS connections.

**Implementation status:** ⚠️ `exp` and `iat` implemented. `jti` and `nbf` not yet.

---

### T6 — Audit trail tampering

| Field | Value |
|-------|-------|
| **STRIDE** | Repudiation, Tampering |
| **Target** | Audit Logger |
| **Attack** | Attacker who compromises the gateway deletes or modifies audit entries to cover their tracks |
| **Impact** | High — loss of forensic evidence, compliance failure |
| **Likelihood** | Medium — requires gateway compromise |

**Mitigations:**
- **[M6.1]** Append-only storage: audit entries cannot be modified or deleted via the API.
- **[M6.2]** Real-time export to external collector (OTLP → Jaeger, Grafana Tempo, Datadog) that the gateway cannot write to.
- **[M6.3]** Cryptographic chaining: each audit entry includes the hash of the previous entry, creating a tamper-evident chain.
- **[M6.4]** Separate storage credentials: audit logger uses different credentials than the gateway, so gateway compromise doesn't automatically grant audit access.

**Implementation status:** ⚠️ In-memory storage only. External export not yet implemented.

---

### T7 — Dependency confusion / supply chain

| Field | Value |
|-------|-------|
| **STRIDE** | Tampering |
| **Target** | AIB Python package |
| **Attack** | Attacker publishes a malicious `agent-identity-bridge` package to PyPI before the legitimate one, or compromises a dependency |
| **Impact** | Critical — arbitrary code execution on every machine that installs AIB |
| **Likelihood** | Low-Medium |

**Mitigations:**
- **[M7.1]** Pin all dependency versions in `pyproject.toml`.
- **[M7.2]** Use `pip audit` in CI to check for known vulnerabilities.
- **[M7.3]** Publish to PyPI with 2FA-protected account.
- **[M7.4]** Provide SHA256 checksums for releases.

---

## 4. Prioritized remediation plan

| Priority | Threat | Mitigation | Effort |
|----------|--------|------------|--------|
| 🔴 P0 | T1 Passport forgery | Migrate to RS256 | 2-4h |
| 🔴 P0 | T4 SSRF | URL validation + IP blocking | 2-3h |
| 🟠 P1 | T3 Card injection | Input sanitization + schema validation | 3-4h |
| 🟠 P1 | T5 Replay | Add jti + nbf claims | 1-2h |
| 🟡 P2 | T2 Vault breach | Encrypted credential store | 4-6h |
| 🟡 P2 | T6 Audit tampering | Append-only + hash chaining | 2-3h |
| 🟢 P3 | T7 Supply chain | CI pipeline + pin deps | 1-2h |

---

## 5. Security contact

Report vulnerabilities responsibly to: **security@tntech.fr**

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

We aim to acknowledge reports within 48 hours and provide a fix within 7 days for critical issues.

---

## 6. Revision history

| Date | Version | Changes |
|------|---------|---------|
| 2026-03-24 | 0.1.0 | Initial threat model — 7 threats identified |
