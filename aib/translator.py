"""
AIB - Agent Identity Bridge
translator.py — Credential Translator between protocol identity formats.

Converts between:
  - A2A Agent Card (Google) ↔ MCP Server Card (Anthropic)
  - Agent Card / Server Card → DID Document (W3C)
  - DID Document → Agent Card

This is the core interoperability engine of AIB.
"""

import json
from datetime import datetime, timezone
from typing import Optional


class CredentialTranslator:
    """
    Translates identity/capability documents between AI protocols.

    Each protocol has its own format for describing an agent:
    - MCP: Server Card (proposed .well-known/mcp.json)
    - A2A: Agent Card (.well-known/agent.json)
    - ANP: DID Document (did:web resolution)

    This translator maps fields between them so an agent registered
    in one protocol can be discovered in another.
    """

    # ── A2A Agent Card → MCP Server Card ──────────────────────────

    @staticmethod
    def a2a_to_mcp(agent_card: dict) -> dict:
        """
        Convert an A2A Agent Card to an MCP Server Card.

        A2A Agent Card structure:
          { name, description, url, version, skills: [{id, name, description}],
            authentication: {schemes: [...]}, capabilities: {streaming, pushNotifications} }

        MCP Server Card structure (proposed):
          { name, description, server_url, version, tools: [{name, description, inputSchema}],
            auth: {type, ...}, transport: "streamable-http" }
        """
        tools = []
        for skill in agent_card.get("skills", []):
            tools.append({
                "name": skill.get("id", skill.get("name", "")).replace(" ", "_").lower(),
                "description": skill.get("description", skill.get("name", "")),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "task_description": {
                            "type": "string",
                            "description": f"Description of the task for {skill.get('name', 'this skill')}"
                        }
                    },
                    "required": ["task_description"]
                }
            })

        # Map A2A auth schemes to MCP auth
        auth = {"type": "none"}
        a2a_auth = agent_card.get("authentication", {})
        schemes = a2a_auth.get("schemes", [])
        if schemes:
            first_scheme = schemes[0] if isinstance(schemes[0], str) else schemes[0].get("scheme", "bearer")
            if "oauth" in first_scheme.lower():
                auth = {"type": "oauth2", "flows": a2a_auth.get("flows", {})}
            elif "bearer" in first_scheme.lower():
                auth = {"type": "bearer"}
            elif "apikey" in first_scheme.lower() or "api_key" in first_scheme.lower():
                auth = {"type": "api_key", "header": "Authorization"}

        mcp_card = {
            "_aib_source": "a2a",
            "_aib_translated_at": datetime.now(timezone.utc).isoformat(),
            "name": agent_card.get("name", "Unknown Agent"),
            "description": agent_card.get("description", ""),
            "server_url": agent_card.get("url", ""),
            "version": agent_card.get("version", "1.0.0"),
            "tools": tools,
            "auth": auth,
            "transport": "streamable-http",
        }

        # Preserve A2A capabilities as MCP metadata
        caps = agent_card.get("capabilities", {})
        if caps:
            mcp_card["metadata"] = {
                "a2a_streaming": str(caps.get("streaming", False)).lower(),
                "a2a_push_notifications": str(caps.get("pushNotifications", False)).lower(),
            }

        return mcp_card

    # ── MCP Server Card → A2A Agent Card ──────────────────────────

    @staticmethod
    def mcp_to_a2a(server_card: dict) -> dict:
        """
        Convert an MCP Server Card to an A2A Agent Card.

        Inverse of a2a_to_mcp. Maps tools → skills, server_url → url.
        """
        skills = []
        for tool in server_card.get("tools", []):
            skills.append({
                "id": tool.get("name", "unknown"),
                "name": tool.get("name", "Unknown").replace("_", " ").title(),
                "description": tool.get("description", ""),
            })

        # Map MCP auth to A2A authentication
        auth_config = server_card.get("auth", {})
        auth_type = auth_config.get("type", "none")
        authentication = {"schemes": []}
        if auth_type == "oauth2":
            authentication["schemes"] = ["oauth2"]
            if "flows" in auth_config:
                authentication["flows"] = auth_config["flows"]
        elif auth_type == "bearer":
            authentication["schemes"] = ["bearer"]
        elif auth_type == "api_key":
            authentication["schemes"] = ["apiKey"]

        agent_card = {
            "_aib_source": "mcp",
            "_aib_translated_at": datetime.now(timezone.utc).isoformat(),
            "name": server_card.get("name", "Unknown Server"),
            "description": server_card.get("description", ""),
            "url": server_card.get("server_url", ""),
            "version": server_card.get("version", "1.0.0"),
            "skills": skills,
            "authentication": authentication,
            "capabilities": {
                "streaming": True,
                "pushNotifications": False,
            },
        }

        return agent_card

    # ── Agent Card / Server Card → DID Document ───────────────────

    @staticmethod
    def to_did_document(
        card: dict,
        source_protocol: str,
        domain: str,
        agent_slug: str,
    ) -> dict:
        """
        Generate a W3C DID Document (did:web method) from any agent card.

        The did:web method resolves to:
          https://{domain}/.well-known/did.json  (root)
          https://{domain}/agents/{slug}/did.json (path-based)

        Args:
            card: Agent Card (A2A) or Server Card (MCP)
            source_protocol: "a2a" or "mcp"
            domain: e.g. "domup-sap.fr"
            agent_slug: e.g. "booking"
        """
        did = f"did:web:{domain}:agents:{agent_slug}"

        # Extract endpoint URL
        if source_protocol == "a2a":
            service_url = card.get("url", f"https://{domain}")
            service_type = "A2AAgent"
        else:
            service_url = card.get("server_url", f"https://{domain}")
            service_type = "MCPServer"

        did_doc = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1",
            ],
            "id": did,
            "controller": did,
            "verificationMethod": [
                {
                    "id": f"{did}#key-1",
                    "type": "JsonWebKey2020",
                    "controller": did,
                    "publicKeyJwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "PLACEHOLDER_PUBLIC_KEY_X",
                        "y": "PLACEHOLDER_PUBLIC_KEY_Y",
                    }
                }
            ],
            "authentication": [f"{did}#key-1"],
            "assertionMethod": [f"{did}#key-1"],
            "service": [
                {
                    "id": f"{did}#agent-service",
                    "type": service_type,
                    "serviceEndpoint": service_url,
                    "description": card.get("description", ""),
                }
            ],
            "_aib_source": source_protocol,
            "_aib_translated_at": datetime.now(timezone.utc).isoformat(),
        }

        # Add capabilities as metadata
        capabilities = []
        if source_protocol == "a2a":
            capabilities = [s.get("name", s.get("id", "")) for s in card.get("skills", [])]
        else:
            capabilities = [t.get("name", "") for t in card.get("tools", [])]

        if capabilities:
            did_doc["service"][0]["capabilities"] = capabilities

        return did_doc

    # ── DID Document → A2A Agent Card ─────────────────────────────

    @staticmethod
    def did_to_a2a(did_doc: dict) -> dict:
        """
        Extract an A2A Agent Card from a DID Document.

        Maps service endpoints → url, capabilities → skills.
        """
        services = did_doc.get("service", [])
        primary_service = services[0] if services else {}

        skills = []
        for cap in primary_service.get("capabilities", []):
            skills.append({
                "id": cap.replace(" ", "_").lower(),
                "name": cap,
                "description": f"Capability: {cap}",
            })

        # Determine auth from verification methods
        auth_schemes = []
        if did_doc.get("authentication"):
            auth_schemes = ["did-auth"]

        return {
            "_aib_source": "did",
            "_aib_translated_at": datetime.now(timezone.utc).isoformat(),
            "name": did_doc.get("id", "Unknown DID Agent").split(":")[-1].replace("-", " ").title(),
            "description": primary_service.get("description", ""),
            "url": primary_service.get("serviceEndpoint", ""),
            "version": "1.0.0",
            "skills": skills,
            "authentication": {"schemes": auth_schemes},
            "capabilities": {"streaming": False, "pushNotifications": False},
        }

    # ── Universal translate method ────────────────────────────────

    def translate(
        self,
        source: dict,
        from_format: str,
        to_format: str,
        domain: Optional[str] = None,
        agent_slug: Optional[str] = None,
    ) -> dict:
        """
        Universal translation dispatcher.

        Args:
            source: The source document
            from_format: "a2a_agent_card" | "mcp_server_card" | "did_document"
            to_format: Same options as from_format
            domain: Required for DID generation
            agent_slug: Required for DID generation
        """
        key = f"{from_format}->{to_format}"

        translations = {
            "a2a_agent_card->mcp_server_card": lambda: self.a2a_to_mcp(source),
            "mcp_server_card->a2a_agent_card": lambda: self.mcp_to_a2a(source),
            "a2a_agent_card->did_document": lambda: self.to_did_document(
                source, "a2a", domain or "example.com", agent_slug or "agent"
            ),
            "mcp_server_card->did_document": lambda: self.to_did_document(
                source, "mcp", domain or "example.com", agent_slug or "agent"
            ),
            "did_document->a2a_agent_card": lambda: self.did_to_a2a(source),
        }

        if key not in translations:
            raise ValueError(
                f"Unsupported translation: {key}. "
                f"Supported: {list(translations.keys())}"
            )

        return translations[key]()


# ── CLI demo ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  AIB — Credential Translator Demo")
    print("=" * 60)

    translator = CredentialTranslator()

    # Sample A2A Agent Card
    sample_a2a = {
        "name": "DomUp Booking Agent",
        "description": "Books home services in French overseas territories",
        "url": "https://domup-sap.fr/agents/booking",
        "version": "1.2.0",
        "skills": [
            {"id": "book_service", "name": "Book Service", "description": "Schedule a home service appointment"},
            {"id": "check_availability", "name": "Check Availability", "description": "Check provider availability"},
            {"id": "send_notification", "name": "Send Notification", "description": "Notify clients and providers"},
        ],
        "authentication": {"schemes": ["oauth2"]},
        "capabilities": {"streaming": True, "pushNotifications": True},
    }

    print("\n📄 Source: A2A Agent Card")
    print(f"   Name: {sample_a2a['name']}")
    print(f"   Skills: {[s['id'] for s in sample_a2a['skills']]}")

    # A2A → MCP
    mcp_card = translator.translate(sample_a2a, "a2a_agent_card", "mcp_server_card")
    print(f"\n🔄 Translated to MCP Server Card:")
    print(f"   Name: {mcp_card['name']}")
    print(f"   Tools: {[t['name'] for t in mcp_card['tools']]}")
    print(f"   Auth: {mcp_card['auth']}")
    print(f"   Transport: {mcp_card['transport']}")

    # A2A → DID
    did_doc = translator.translate(
        sample_a2a, "a2a_agent_card", "did_document",
        domain="domup-sap.fr", agent_slug="booking"
    )
    print(f"\n🔄 Translated to DID Document:")
    print(f"   DID: {did_doc['id']}")
    print(f"   Service: {did_doc['service'][0]['type']} → {did_doc['service'][0]['serviceEndpoint']}")

    # MCP → A2A (round-trip test)
    back_to_a2a = translator.translate(mcp_card, "mcp_server_card", "a2a_agent_card")
    print(f"\n🔄 Round-trip MCP → A2A:")
    print(f"   Name: {back_to_a2a['name']}")
    print(f"   Skills: {[s['id'] for s in back_to_a2a['skills']]}")

    # Full JSON output
    print(f"\n{'─' * 60}")
    print("Full MCP Server Card (translated):")
    print(json.dumps(mcp_card, indent=2))

    print(f"\n{'=' * 60}")
    print("  Demo complete.")
    print("=" * 60)
