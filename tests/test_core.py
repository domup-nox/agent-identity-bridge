"""
Tests for AIB core modules: passport and translator.
Run: pytest tests/ -v
"""

import json
import pytest
from pathlib import Path
from aib.passport import PassportService, McpBinding, A2aBinding, AnpBinding
from aib.translator import CredentialTranslator
from aib.audit import AuditTrail
from aib.gateway import Gateway


# ── Fixtures ──────────────────────────────────────────────────────

@pytest.fixture
def passport_service(tmp_path):
    return PassportService(secret_key="test-secret-key", storage_path=str(tmp_path / "passports"))


@pytest.fixture
def translator():
    return CredentialTranslator()


@pytest.fixture
def sample_a2a_card():
    return {
        "name": "Test Agent",
        "description": "A test agent for unit tests",
        "url": "https://test.example.com/agents/test",
        "version": "1.0.0",
        "skills": [
            {"id": "search", "name": "Search", "description": "Search the web"},
            {"id": "book", "name": "Book", "description": "Book appointments"},
        ],
        "authentication": {"schemes": ["oauth2"]},
        "capabilities": {"streaming": True, "pushNotifications": False},
    }


@pytest.fixture
def sample_mcp_card():
    return {
        "name": "Test MCP Server",
        "description": "A test MCP server",
        "server_url": "https://test.example.com/mcp",
        "version": "1.0.0",
        "tools": [
            {"name": "search", "description": "Search tool", "inputSchema": {"type": "object"}},
            {"name": "calculate", "description": "Calculator", "inputSchema": {"type": "object"}},
        ],
        "auth": {"type": "bearer"},
        "transport": "streamable-http",
    }


# ── Passport Tests ────────────────────────────────────────────────

class TestPassportService:

    def test_create_passport(self, passport_service):
        passport, token = passport_service.create_passport(
            org_slug="testorg",
            agent_slug="agent1",
            display_name="Test Agent 1",
            capabilities=["search", "booking"],
            bindings={
                "mcp": McpBinding(auth_method="oauth2", server_card_url="https://example.com/.well-known/mcp.json"),
            },
        )
        assert passport.passport_id == "urn:aib:agent:testorg:agent1"
        assert passport.display_name == "Test Agent 1"
        assert passport.issuer == "urn:aib:org:testorg"
        assert "mcp" in passport.protocol_bindings
        assert len(token) > 50

    def test_verify_valid_passport(self, passport_service):
        _, token = passport_service.create_passport(
            org_slug="org", agent_slug="valid",
            display_name="Valid", capabilities=["test"],
            bindings={"mcp": McpBinding(auth_method="bearer", server_card_url="https://x.com")},
        )
        valid, passport, reason = passport_service.verify_passport(token)
        assert valid is True
        assert reason == "Valid"
        assert passport.passport_id == "urn:aib:agent:org:valid"

    def test_verify_tampered_token(self, passport_service):
        _, token = passport_service.create_passport(
            org_slug="org", agent_slug="tamper",
            display_name="Tamper", capabilities=["test"],
            bindings={"mcp": McpBinding(auth_method="bearer", server_card_url="https://x.com")},
        )
        tampered = token[:-5] + "XXXXX"
        valid, _, reason = passport_service.verify_passport(tampered)
        assert valid is False
        assert "signature" in reason.lower() or "invalid" in reason.lower()

    def test_revoke_passport(self, passport_service):
        passport, token = passport_service.create_passport(
            org_slug="org", agent_slug="revokeme",
            display_name="Revoke Me", capabilities=["test"],
            bindings={"mcp": McpBinding(auth_method="bearer", server_card_url="https://x.com")},
        )
        assert passport_service.revoke_passport(passport.passport_id) is True
        valid, _, reason = passport_service.verify_passport(token)
        assert valid is False
        assert "revoked" in reason.lower()

    def test_double_revoke_returns_false(self, passport_service):
        passport, _ = passport_service.create_passport(
            org_slug="org", agent_slug="double",
            display_name="Double", capabilities=["test"],
            bindings={"mcp": McpBinding(auth_method="bearer", server_card_url="https://x.com")},
        )
        assert passport_service.revoke_passport(passport.passport_id) is True
        assert passport_service.revoke_passport(passport.passport_id) is False

    def test_list_passports(self, passport_service):
        passport_service.create_passport(
            org_slug="org", agent_slug="a1",
            display_name="A1", capabilities=["test"],
            bindings={"mcp": McpBinding(auth_method="bearer", server_card_url="https://x.com")},
        )
        passport_service.create_passport(
            org_slug="org", agent_slug="a2",
            display_name="A2", capabilities=["test"],
            bindings={"a2a": A2aBinding(auth_method="bearer", agent_card_url="https://x.com")},
        )
        items = passport_service.list_passports()
        assert len(items) == 2

    def test_multi_protocol_bindings(self, passport_service):
        passport, _ = passport_service.create_passport(
            org_slug="org", agent_slug="multi",
            display_name="Multi", capabilities=["test"],
            bindings={
                "mcp": McpBinding(auth_method="oauth2", server_card_url="https://x.com"),
                "a2a": A2aBinding(auth_method="bearer", agent_card_url="https://x.com/agent.json"),
                "anp": AnpBinding(auth_method="did-auth", did="did:web:x.com:agents:multi"),
            },
        )
        assert set(passport.protocol_bindings.keys()) == {"mcp", "a2a", "anp"}


# ── Translator Tests ──────────────────────────────────────────────

class TestCredentialTranslator:

    def test_a2a_to_mcp(self, translator, sample_a2a_card):
        result = translator.translate(sample_a2a_card, "a2a_agent_card", "mcp_server_card")
        assert result["name"] == "Test Agent"
        assert len(result["tools"]) == 2
        assert result["tools"][0]["name"] == "search"
        assert result["auth"]["type"] == "oauth2"
        assert result["transport"] == "streamable-http"

    def test_mcp_to_a2a(self, translator, sample_mcp_card):
        result = translator.translate(sample_mcp_card, "mcp_server_card", "a2a_agent_card")
        assert result["name"] == "Test MCP Server"
        assert len(result["skills"]) == 2
        assert result["skills"][0]["id"] == "search"

    def test_a2a_to_did(self, translator, sample_a2a_card):
        result = translator.translate(
            sample_a2a_card, "a2a_agent_card", "did_document",
            domain="test.example.com", agent_slug="test"
        )
        assert result["id"] == "did:web:test.example.com:agents:test"
        assert len(result["service"]) == 1
        assert result["service"][0]["type"] == "A2AAgent"

    def test_roundtrip_a2a_mcp_a2a(self, translator, sample_a2a_card):
        mcp = translator.translate(sample_a2a_card, "a2a_agent_card", "mcp_server_card")
        back = translator.translate(mcp, "mcp_server_card", "a2a_agent_card")
        assert back["name"] == sample_a2a_card["name"]
        assert len(back["skills"]) == len(sample_a2a_card["skills"])

    def test_invalid_translation_raises(self, translator, sample_a2a_card):
        with pytest.raises(ValueError, match="Unsupported"):
            translator.translate(sample_a2a_card, "a2a_agent_card", "unknown_format")


# ── Audit Tests ───────────────────────────────────────────────────

class TestAuditTrail:

    def test_log_entry(self):
        audit = AuditTrail()
        entry = audit.log("urn:aib:agent:org:test", "mcp", "a2a", "task_send", "https://x.com")
        assert entry.status == "success"
        assert entry.passport_id == "urn:aib:agent:org:test"
        assert len(entry.trace_id) == 36  # UUID format

    def test_trace_context_manager(self):
        audit = AuditTrail()
        with audit.trace("urn:test", "mcp", "a2a", "proxy", "https://x.com") as entry:
            entry.metadata["test"] = "value"
        entries = audit.query(passport_id="urn:test")
        assert len(entries) == 1
        assert entries[0].status == "success"
        assert entries[0].duration_ms >= 0

    def test_trace_error(self):
        audit = AuditTrail()
        with pytest.raises(ValueError):
            with audit.trace("urn:test", "mcp", "a2a", "proxy", "https://x.com"):
                raise ValueError("test error")
        entries = audit.query(passport_id="urn:test")
        assert entries[0].status == "error"

    def test_query_filters(self):
        audit = AuditTrail()
        audit.log("urn:a", "mcp", "a2a", "task_send", "https://x.com")
        audit.log("urn:b", "a2a", "anp", "discover", "https://y.com")
        audit.log("urn:a", "mcp", "a2a", "proxy", "https://x.com", status="error")

        assert len(audit.query(passport_id="urn:a")) == 2
        assert len(audit.query(protocol="anp")) == 1
        assert len(audit.query(status="error")) == 1

    def test_stats(self):
        audit = AuditTrail()
        audit.log("urn:a", "mcp", "a2a", "task_send", "https://x.com", duration_ms=100)
        audit.log("urn:a", "mcp", "a2a", "proxy", "https://x.com", duration_ms=200)
        stats = audit.stats()
        assert stats["total"] == 2
        assert stats["avg_duration_ms"] == 150.0


# ── Gateway Tests ─────────────────────────────────────────────────

class TestGateway:

    def test_detect_protocol_mcp(self):
        gw = Gateway()
        bindings = {"mcp": {"server_card_url": "https://example.com/.well-known/mcp.json"}}
        assert gw.detect_protocol("https://example.com/api/tools", bindings) == "mcp"

    def test_detect_protocol_a2a(self):
        gw = Gateway()
        bindings = {"a2a": {"agent_card_url": "https://agent.example.com/.well-known/agent.json"}}
        assert gw.detect_protocol("https://agent.example.com/task/send", bindings) == "a2a"

    def test_detect_protocol_anp(self):
        gw = Gateway()
        bindings = {"anp": {"did": "did:web:peer.example.com:agents:x"}}
        assert gw.detect_protocol("https://peer.example.com/anp/message", bindings) == "anp"

    def test_detect_unknown(self):
        gw = Gateway()
        assert gw.detect_protocol("https://unknown.com/api", {}) == "unknown"

    def test_adapt_request_a2a(self):
        gw = Gateway()
        body = {"task": "do something"}
        result = gw._adapt_request("a2a", body)
        assert result["jsonrpc"] == "2.0"
        assert "params" in result

    def test_adapt_request_passthrough(self):
        gw = Gateway()
        body = {"jsonrpc": "2.0", "method": "test", "params": {}}
        result = gw._adapt_request("a2a", body)
        assert result == body  # Already formatted, passthrough


# ── Schema Validation Tests ───────────────────────────────────────

class TestPassportSchema:

    def test_schema_valid(self):
        schema_path = Path(__file__).parent.parent / "spec" / "passport-schema-v0.1.json"
        if schema_path.exists():
            schema = json.loads(schema_path.read_text())
            assert schema["$id"] == "https://aib.tntech.fr/schemas/passport-v0.1.json"
            assert "protocol_bindings" in schema["required"]

    def test_passport_to_dict_format(self, passport_service):
        passport, _ = passport_service.create_passport(
            org_slug="org", agent_slug="schema",
            display_name="Schema Test", capabilities=["test"],
            bindings={"mcp": McpBinding(auth_method="bearer", server_card_url="https://x.com")},
        )
        d = passport.to_dict()
        assert d["aib_version"] == "0.1"
        assert d["passport_id"].startswith("urn:aib:agent:")
        assert d["issuer"].startswith("urn:aib:org:")
        assert "mcp" in d["protocol_bindings"]
