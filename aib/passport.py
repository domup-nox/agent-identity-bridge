"""
AIB - Agent Identity Bridge
passport.py — Agent Passport creation, signing, verification, and revocation.

An Agent Passport is a JWS-signed JSON document that gives an AI agent
a single portable identity across MCP, A2A, ANP, and any future protocol.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path

# ── Lightweight JWS signing (RS256) ──────────────────────────────────
# In production, use PyJWT + cryptography. This MVP uses HMAC-SHA256
# for simplicity — swap to RS256 when deploying.
import hmac
import hashlib
import base64


AIB_VERSION = "0.1"


# ── Data models ──────────────────────────────────────────────────────

@dataclass
class ProtocolBinding:
    """Credentials for a single protocol."""
    auth_method: str
    credential_ref: Optional[str] = None


@dataclass
class McpBinding(ProtocolBinding):
    server_card_url: str = ""
    scopes: list[str] = field(default_factory=list)


@dataclass
class A2aBinding(ProtocolBinding):
    agent_card_url: str = ""
    skills: list[str] = field(default_factory=list)


@dataclass
class AnpBinding(ProtocolBinding):
    did: str = ""


@dataclass
class AgentPassport:
    """The core identity document for an AI agent."""
    passport_id: str
    display_name: str
    issuer: str
    capabilities: list[str]
    protocol_bindings: dict[str, ProtocolBinding]
    issued_at: str = ""
    expires_at: str = ""
    aib_version: str = AIB_VERSION
    revocation_endpoint: Optional[str] = None
    audit_endpoint: Optional[str] = None
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to a clean dict (for JSON encoding)."""
        d = {
            "aib_version": self.aib_version,
            "passport_id": self.passport_id,
            "display_name": self.display_name,
            "issuer": self.issuer,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "capabilities": self.capabilities,
            "protocol_bindings": {},
        }
        for proto, binding in self.protocol_bindings.items():
            d["protocol_bindings"][proto] = asdict(binding)

        if self.revocation_endpoint:
            d["revocation_endpoint"] = self.revocation_endpoint
        if self.audit_endpoint:
            d["audit_endpoint"] = self.audit_endpoint
        if self.metadata:
            d["metadata"] = self.metadata
        return d


# ── Passport Service ─────────────────────────────────────────────────

class PassportService:
    """
    Creates, signs, verifies, stores, and revokes Agent Passports.

    Storage: local JSON file (MVP). Production: PostgreSQL or Vault.
    Signing: HMAC-SHA256 (MVP). Production: RS256 with key rotation.
    """

    def __init__(self, secret_key: str, storage_path: str = "./passports"):
        self._secret = secret_key.encode()
        self._storage = Path(storage_path)
        self._storage.mkdir(parents=True, exist_ok=True)
        self._revoked: set[str] = set()
        self._load_revocations()

    # ── Create ────────────────────────────────────────────────────

    def create_passport(
        self,
        org_slug: str,
        agent_slug: str,
        display_name: str,
        capabilities: list[str],
        bindings: dict[str, ProtocolBinding],
        ttl_days: int = 365,
        metadata: Optional[dict[str, str]] = None,
    ) -> tuple[AgentPassport, str]:
        """
        Create and sign a new Agent Passport.

        Returns:
            (passport, signed_token) — the passport object and its JWS string.
        """
        now = datetime.now(timezone.utc)
        passport = AgentPassport(
            passport_id=f"urn:aib:agent:{org_slug}:{agent_slug}",
            display_name=display_name,
            issuer=f"urn:aib:org:{org_slug}",
            capabilities=capabilities,
            protocol_bindings=bindings,
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(days=ttl_days)).isoformat(),
            metadata=metadata or {},
        )

        token = self._sign(passport)
        self._store(passport, token)
        return passport, token

    # ── Verify ────────────────────────────────────────────────────

    def verify_passport(self, token: str) -> tuple[bool, Optional[AgentPassport], str]:
        """
        Verify a signed passport token.

        Returns:
            (is_valid, passport_or_none, reason)
        """
        try:
            header_b64, payload_b64, sig_b64 = token.split(".")
        except ValueError:
            return False, None, "Invalid token format"

        # Check signature
        expected_sig = self._hmac_sign(f"{header_b64}.{payload_b64}")
        if not hmac.compare_digest(sig_b64, expected_sig):
            return False, None, "Invalid signature"

        # Decode payload
        payload_json = base64.urlsafe_b64decode(payload_b64 + "==").decode()
        data = json.loads(payload_json)

        # Check expiration
        expires = datetime.fromisoformat(data["expires_at"])
        if datetime.now(timezone.utc) > expires:
            return False, None, "Passport expired"

        # Check revocation
        pid = data["passport_id"]
        if pid in self._revoked:
            return False, None, "Passport revoked"

        # Reconstruct passport (simplified — skip binding reconstruction)
        passport = AgentPassport(
            passport_id=pid,
            display_name=data["display_name"],
            issuer=data["issuer"],
            capabilities=data["capabilities"],
            protocol_bindings=data["protocol_bindings"],
            issued_at=data["issued_at"],
            expires_at=data["expires_at"],
            aib_version=data.get("aib_version", AIB_VERSION),
        )
        return True, passport, "Valid"

    # ── Revoke ────────────────────────────────────────────────────

    def revoke_passport(self, passport_id: str) -> bool:
        """Revoke a passport by ID. Returns True if newly revoked."""
        if passport_id in self._revoked:
            return False
        self._revoked.add(passport_id)
        self._save_revocations()
        return True

    # ── List ──────────────────────────────────────────────────────

    def list_passports(self) -> list[dict]:
        """List all stored passports (metadata only)."""
        results = []
        for f in self._storage.glob("*.json"):
            if f.name == "_revoked.json":
                continue
            data = json.loads(f.read_text())
            results.append({
                "passport_id": data["passport"]["passport_id"],
                "display_name": data["passport"]["display_name"],
                "issuer": data["passport"]["issuer"],
                "expires_at": data["passport"]["expires_at"],
                "revoked": data["passport"]["passport_id"] in self._revoked,
                "protocols": list(data["passport"]["protocol_bindings"].keys()),
            })
        return results

    # ── Internal: signing ─────────────────────────────────────────

    def _sign(self, passport: AgentPassport) -> str:
        """Create a JWS-like token (header.payload.signature)."""
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "AIB-PASSPORT"}).encode()
        ).rstrip(b"=").decode()

        payload = base64.urlsafe_b64encode(
            json.dumps(passport.to_dict(), ensure_ascii=False).encode()
        ).rstrip(b"=").decode()

        signature = self._hmac_sign(f"{header}.{payload}")
        return f"{header}.{payload}.{signature}"

    def _hmac_sign(self, message: str) -> str:
        return base64.urlsafe_b64encode(
            hmac.new(self._secret, message.encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()

    # ── Internal: storage ─────────────────────────────────────────

    def _store(self, passport: AgentPassport, token: str):
        slug = passport.passport_id.split(":")[-1]
        path = self._storage / f"{slug}.json"
        path.write_text(json.dumps({
            "passport": passport.to_dict(),
            "token": token,
        }, indent=2, ensure_ascii=False))

    def _load_revocations(self):
        path = self._storage / "_revoked.json"
        if path.exists():
            self._revoked = set(json.loads(path.read_text()))

    def _save_revocations(self):
        path = self._storage / "_revoked.json"
        path.write_text(json.dumps(list(self._revoked)))


# ── CLI demo ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  AIB — Agent Identity Bridge — Passport Demo")
    print("=" * 60)

    svc = PassportService(secret_key="demo-secret-change-in-prod")

    # Create a passport for the DomUp booking agent
    passport, token = svc.create_passport(
        org_slug="tntech",
        agent_slug="domup-booking",
        display_name="DomUp Booking Agent",
        capabilities=["booking", "scheduling", "notifications"],
        bindings={
            "mcp": McpBinding(
                auth_method="oauth2",
                server_card_url="https://domup-sap.fr/.well-known/mcp.json",
                credential_ref="vault://aib/mcp/domup-booking",
                scopes=["read", "write"],
            ),
            "a2a": A2aBinding(
                auth_method="bearer",
                agent_card_url="https://domup-sap.fr/.well-known/agent.json",
                credential_ref="vault://aib/a2a/domup-booking",
                skills=["home-services", "scheduling"],
            ),
        },
        metadata={"environment": "production", "region": "eu-west-1"},
    )

    print(f"\n✅ Passport created: {passport.passport_id}")
    print(f"   Display name: {passport.display_name}")
    print(f"   Protocols: {list(passport.protocol_bindings.keys())}")
    print(f"   Capabilities: {passport.capabilities}")
    print(f"   Expires: {passport.expires_at}")
    print(f"\n📝 Signed token (first 80 chars): {token[:80]}...")

    # Verify the passport
    valid, verified_passport, reason = svc.verify_passport(token)
    print(f"\n🔍 Verification: {'✅ ' + reason if valid else '❌ ' + reason}")

    # List all passports
    print(f"\n📋 Stored passports:")
    for p in svc.list_passports():
        status = "🚫 REVOKED" if p["revoked"] else "✅ Active"
        print(f"   {status} | {p['passport_id']} | {p['protocols']}")

    # Revoke and re-verify
    svc.revoke_passport(passport.passport_id)
    valid2, _, reason2 = svc.verify_passport(token)
    print(f"\n🔒 After revocation: {'✅ ' + reason2 if valid2 else '❌ ' + reason2}")

    print(f"\n{'=' * 60}")
    print("  Demo complete. Passport stored in ./passports/")
    print("=" * 60)
