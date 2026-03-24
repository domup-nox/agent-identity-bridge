# Agent Identity Bridge (AIB)

**One identity. Every protocol. Full audit trail.**

AIB is an open-source protocol and reference implementation that gives AI agents a single portable identity across MCP (Anthropic), A2A (Google), ANP (W3C DID), and AG-UI — the four layers of the 2026 AI communication stack.

## The problem

Each AI protocol has its own identity system. An agent operating across MCP + A2A + ANP has three separate identities with no link between them. This makes cross-protocol auditing impossible, credential management painful, and compliance (GDPR, SOC2) a nightmare.

## What AIB does

| Component | Purpose |
|-----------|---------|
| **Agent Passport** | A signed JSON document (JWS) that binds one agent identity to credentials for every protocol it supports |
| **Credential Translator** | Converts between A2A Agent Cards ↔ MCP Server Cards ↔ DID Documents automatically |
| **Audit Trail** | Unified OpenTelemetry traces for every cross-protocol interaction |
| **Gateway Proxy** | Reverse proxy that injects the right credentials based on target protocol |

## Quick start

```bash
# Clone and install
git clone https://github.com/tntech-consulting/agent-identity-bridge.git
cd agent-identity-bridge
pip install -e .

# Create your first Agent Passport
python -m aib.passport

# Translate between protocol formats
python -m aib.translator
```

## Agent Passport format

```json
{
  "aib_version": "0.1",
  "passport_id": "urn:aib:agent:myorg:my-agent",
  "display_name": "My Agent",
  "issuer": "urn:aib:org:myorg",
  "capabilities": ["search", "booking"],
  "protocol_bindings": {
    "mcp": { "server_card_url": "https://...", "auth_method": "oauth2" },
    "a2a": { "agent_card_url": "https://...", "auth_method": "bearer" },
    "anp": { "did": "did:web:example.com:agents:my-agent", "auth_method": "did-auth" }
  }
}
```

## Architecture

```
┌─────────────┐     ┌─────────────────┐     ┌──────────────┐
│  Your Agent  │────▶│   AIB Gateway    │────▶│  MCP Server  │
│              │     │                  │────▶│  A2A Agent   │
│  1 passport  │     │  Translates IDs  │────▶│  ANP Peer    │
│              │     │  Logs everything │     │              │
└─────────────┘     └─────────────────┘     └──────────────┘
```

## Project structure

```
aib/
├── passport.py          # Agent Passport CRUD + signing
├── translator.py        # Agent Card ↔ Server Card ↔ DID
├── credential_store.py  # Encrypted credential vault (coming)
├── gateway.py           # Protocol-aware reverse proxy (coming)
├── audit.py             # OpenTelemetry trace emitter (coming)
└── schemas.py           # Pydantic models (coming)
spec/
└── passport-schema-v0.1.json  # JSON Schema
```

## Roadmap

- [x] Spec v0.1 — Agent Passport JSON Schema
- [x] passport.py — Create, sign, verify, revoke passports
- [x] translator.py — A2A ↔ MCP ↔ DID translation
- [ ] FastAPI gateway with credential injection
- [ ] OpenTelemetry audit trail
- [ ] Docker packaging
- [ ] CLI tool (`aib create`, `aib translate`, `aib verify`)
- [ ] Managed SaaS version

## How AIB relates to existing protocols

AIB doesn't compete with MCP, A2A, or ANP — it bridges them.

- **MCP** connects agents to tools. AIB connects agents to *all protocols*.
- **A2A** coordinates agents. AIB gives each agent an identity usable in A2A *and* MCP *and* ANP.
- **ANP** provides decentralized identity (DID). AIB uses DID as one of its supported formats, not the only one.

## Contributing

This project is Apache 2.0 licensed. Contributions welcome — especially around:
- Additional protocol bindings (AG-UI, LMOS, AP2)
- Security hardening (RS256 signatures, key rotation)
- Enterprise features (SAML, SIEM export)

## Author

**Thomas Nirennold** — TNTECH CONSULTING SAS (SIREN 993811157)  
Building the identity layer the AI agent ecosystem is missing.

## License

Apache 2.0 — see [LICENSE](LICENSE)
