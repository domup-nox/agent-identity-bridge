"""
AIB — Agent Identity Bridge — FastAPI Gateway

The main API server that exposes all AIB functionality:
  - Agent Passport CRUD
  - Credential translation
  - Protocol-aware gateway proxy
  - Unified audit trail

Run:
  uvicorn aib.main:app --reload --port 8420

Docs:
  http://localhost:8420/docs  (Swagger UI)
  http://localhost:8420/redoc (ReDoc)
"""

import os
import json
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .passport import PassportService, McpBinding, A2aBinding, AnpBinding
from .translator import CredentialTranslator
from .gateway import Gateway
from .audit import AuditTrail
from .schemas import (
    CreatePassportRequest, PassportResponse, PassportDetailResponse,
    PassportListResponse, TranslateRequest, TranslateResponse,
    GatewayRequest, GatewayResponse, AuditResponse, AuditEntry as AuditEntrySchema,
    HealthResponse,
)


# ── App lifecycle ─────────────────────────────────────────────────

SECRET_KEY = os.getenv("AIB_SECRET_KEY", "dev-secret-change-me")
STORAGE_PATH = os.getenv("AIB_STORAGE_PATH", "./data/passports")

passport_service: PassportService
translator: CredentialTranslator
gateway: Gateway
audit: AuditTrail


@asynccontextmanager
async def lifespan(app: FastAPI):
    global passport_service, translator, gateway, audit
    passport_service = PassportService(secret_key=SECRET_KEY, storage_path=STORAGE_PATH)
    translator = CredentialTranslator()
    gateway = Gateway()
    audit = AuditTrail()
    print("🚀 AIB Gateway started")
    print(f"   Storage: {STORAGE_PATH}")
    print(f"   Docs: http://localhost:8420/docs")
    yield
    print("👋 AIB Gateway stopped")


# ── App config ────────────────────────────────────────────────────

app = FastAPI(
    title="Agent Identity Bridge",
    description=(
        "**AIB** — One identity. Every protocol. Full audit trail.\n\n"
        "Portable identity for AI agents across MCP, A2A, ANP, and AG-UI.\n\n"
        "- **Passports**: Create and manage agent identities\n"
        "- **Translate**: Convert between A2A Agent Cards, MCP Server Cards, and DID Documents\n"
        "- **Gateway**: Protocol-aware proxy with credential injection\n"
        "- **Audit**: Unified trace of all cross-protocol interactions"
    ),
    version="0.1.0",
    contact={"name": "TNTECH CONSULTING", "url": "https://tntech.fr"},
    license_info={"name": "Apache 2.0", "url": "https://www.apache.org/licenses/LICENSE-2.0"},
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health ────────────────────────────────────────────────────────

@app.get("/", response_model=HealthResponse, tags=["Health"])
async def health():
    """Health check and service info."""
    passports = passport_service.list_passports()
    return HealthResponse(
        status="ok",
        version="0.1.0",
        passports_count=len(passports),
        supported_protocols=["mcp", "a2a", "anp"],
    )


# ── Passports ─────────────────────────────────────────────────────

@app.post("/passports", response_model=PassportDetailResponse, status_code=201, tags=["Passports"])
async def create_passport(req: CreatePassportRequest):
    """Create and sign a new Agent Passport."""
    bindings = {}
    if req.bindings.mcp:
        bindings["mcp"] = McpBinding(
            auth_method=req.bindings.mcp.auth_method,
            server_card_url=req.bindings.mcp.server_card_url,
            credential_ref=req.bindings.mcp.credential_ref,
            scopes=req.bindings.mcp.scopes,
        )
    if req.bindings.a2a:
        bindings["a2a"] = A2aBinding(
            auth_method=req.bindings.a2a.auth_method,
            agent_card_url=req.bindings.a2a.agent_card_url,
            credential_ref=req.bindings.a2a.credential_ref,
            skills=req.bindings.a2a.skills,
        )
    if req.bindings.anp:
        bindings["anp"] = AnpBinding(
            auth_method=req.bindings.anp.auth_method,
            did=req.bindings.anp.did,
            credential_ref=req.bindings.anp.credential_ref,
        )

    if not bindings:
        raise HTTPException(400, "At least one protocol binding is required")

    passport, token = passport_service.create_passport(
        org_slug=req.org_slug,
        agent_slug=req.agent_slug,
        display_name=req.display_name,
        capabilities=req.capabilities,
        bindings=bindings,
        ttl_days=req.ttl_days,
        metadata=req.metadata,
    )

    audit.log(
        passport_id=passport.passport_id,
        source_protocol="aib",
        target_protocol="aib",
        action="passport_created",
        target_url="/passports",
    )

    return PassportDetailResponse(
        passport_id=passport.passport_id,
        display_name=passport.display_name,
        issuer=passport.issuer,
        capabilities=passport.capabilities,
        protocols=list(passport.protocol_bindings.keys()),
        issued_at=passport.issued_at,
        expires_at=passport.expires_at,
        token=token,
        protocol_bindings=passport.to_dict()["protocol_bindings"],
    )


@app.get("/passports", response_model=PassportListResponse, tags=["Passports"])
async def list_passports():
    """List all stored passports."""
    items = passport_service.list_passports()
    return PassportListResponse(
        count=len(items),
        passports=[
            PassportResponse(
                passport_id=p["passport_id"],
                display_name=p["display_name"],
                issuer=p["issuer"],
                capabilities=[],
                protocols=p["protocols"],
                issued_at="",
                expires_at=p["expires_at"],
                revoked=p["revoked"],
            )
            for p in items
        ],
    )


@app.get("/passports/{passport_id:path}", tags=["Passports"])
async def get_passport(passport_id: str):
    """Get a passport by ID and verify its signature."""
    items = passport_service.list_passports()
    match = [p for p in items if p["passport_id"] == passport_id]
    if not match:
        raise HTTPException(404, f"Passport not found: {passport_id}")

    # Load the full passport file
    slug = passport_id.split(":")[-1]
    from pathlib import Path
    path = Path(STORAGE_PATH) / f"{slug}.json"
    if not path.exists():
        raise HTTPException(404, f"Passport file not found for: {passport_id}")

    data = json.loads(path.read_text())
    token = data["token"]
    valid, passport, reason = passport_service.verify_passport(token)

    return {
        "passport": data["passport"],
        "token": token,
        "verification": {"valid": valid, "reason": reason},
    }


@app.delete("/passports/{passport_id:path}", tags=["Passports"])
async def revoke_passport(passport_id: str):
    """Revoke an agent passport."""
    revoked = passport_service.revoke_passport(passport_id)
    if not revoked:
        raise HTTPException(409, "Passport already revoked or not found")

    audit.log(
        passport_id=passport_id,
        source_protocol="aib",
        target_protocol="aib",
        action="passport_revoked",
        target_url=f"/passports/{passport_id}",
    )

    return {"passport_id": passport_id, "status": "revoked"}


# ── Translation ───────────────────────────────────────────────────

@app.post("/translate", response_model=TranslateResponse, tags=["Translation"])
async def translate_credential(req: TranslateRequest):
    """Translate between protocol identity formats."""
    try:
        result = translator.translate(
            source=req.source,
            from_format=req.from_format,
            to_format=req.to_format,
            domain=req.domain,
            agent_slug=req.agent_slug,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))

    audit.log(
        passport_id="system",
        source_protocol=req.from_format.split("_")[0],
        target_protocol=req.to_format.split("_")[0],
        action="translate",
        target_url="/translate",
    )

    return TranslateResponse(
        from_format=req.from_format,
        to_format=req.to_format,
        result=result,
        translated_at=datetime.now(timezone.utc).isoformat(),
    )


# ── Gateway Proxy ─────────────────────────────────────────────────

@app.post("/gateway/proxy", response_model=GatewayResponse, tags=["Gateway"])
async def proxy_request(req: GatewayRequest):
    """
    Proxy a request through AIB with automatic credential injection.

    The gateway detects the target protocol from the URL and the agent's
    passport bindings, then injects the appropriate credentials.
    """
    # Load passport
    slug = req.passport_id.split(":")[-1]
    from pathlib import Path
    path = Path(STORAGE_PATH) / f"{slug}.json"
    if not path.exists():
        raise HTTPException(404, f"Passport not found: {req.passport_id}")

    data = json.loads(path.read_text())
    bindings = data["passport"]["protocol_bindings"]

    # Detect protocol
    protocol = gateway.detect_protocol(req.target_url, bindings)

    with audit.trace(
        passport_id=req.passport_id,
        source_protocol="aib",
        target_protocol=protocol,
        action="proxy",
        target_url=req.target_url,
    ) as trace_entry:
        try:
            result = await gateway.proxy_request(
                passport_id=req.passport_id,
                passport_bindings=bindings,
                target_url=req.target_url,
                method=req.method,
                body=req.body,
                extra_headers=req.headers,
            )
            trace_entry.metadata["status_code"] = result.status_code
        except httpx.RequestError as e:
            raise HTTPException(502, f"Gateway error: {str(e)}")

    return GatewayResponse(
        status_code=result.status_code,
        body=result.body,
        headers={k: v for k, v in list(result.headers.items())[:20]},
        audit_trace_id=trace_entry.trace_id,
        protocol_used=result.protocol_used,
    )


# ── Audit ─────────────────────────────────────────────────────────

@app.get("/audit/{passport_id:path}", tags=["Audit"])
async def get_audit_trail(
    passport_id: str,
    protocol: str = Query(None),
    action: str = Query(None),
    status: str = Query(None),
    limit: int = Query(100, ge=1, le=1000),
):
    """Query the unified audit trail for an agent."""
    entries = audit.query(
        passport_id=passport_id,
        protocol=protocol,
        action=action,
        status=status,
        limit=limit,
    )
    return {
        "passport_id": passport_id,
        "total_entries": len(entries),
        "entries": [e.to_dict() for e in entries],
    }


@app.get("/audit", tags=["Audit"])
async def get_audit_stats():
    """Global audit statistics."""
    return audit.stats()


# ── Well-known endpoints ──────────────────────────────────────────

@app.get("/.well-known/aib-keys.json", tags=["Discovery"])
async def well_known_keys():
    """
    Public keys for passport verification (JWK Set).
    In MVP, returns a placeholder. Production: real RSA/EC public keys.
    """
    return {
        "keys": [
            {
                "kty": "oct",
                "kid": "aib-hmac-dev-1",
                "alg": "HS256",
                "use": "sig",
                "note": "MVP key — replace with RS256 in production",
            }
        ]
    }


@app.get("/.well-known/aib.json", tags=["Discovery"])
async def well_known_aib():
    """AIB service discovery document."""
    return {
        "aib_version": "0.1",
        "service_url": "http://localhost:8420",
        "supported_protocols": ["mcp", "a2a", "anp"],
        "endpoints": {
            "passports": "/passports",
            "translate": "/translate",
            "gateway": "/gateway/proxy",
            "audit": "/audit",
            "keys": "/.well-known/aib-keys.json",
        },
        "documentation": "https://github.com/tntech-consulting/agent-identity-bridge",
    }


# ── Run ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("aib.main:app", host="0.0.0.0", port=8420, reload=True)
