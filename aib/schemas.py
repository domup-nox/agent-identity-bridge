"""
AIB — Pydantic schemas for the FastAPI gateway.
"""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


# ── Protocol Bindings ─────────────────────────────────────────────

class McpBindingSchema(BaseModel):
    server_card_url: str
    auth_method: str = "oauth2"
    credential_ref: Optional[str] = None
    scopes: list[str] = []


class A2aBindingSchema(BaseModel):
    agent_card_url: str
    auth_method: str = "bearer"
    credential_ref: Optional[str] = None
    skills: list[str] = []


class AnpBindingSchema(BaseModel):
    did: str
    auth_method: str = "did-auth"
    credential_ref: Optional[str] = None


class ProtocolBindingsSchema(BaseModel):
    mcp: Optional[McpBindingSchema] = None
    a2a: Optional[A2aBindingSchema] = None
    anp: Optional[AnpBindingSchema] = None


# ── Passport ──────────────────────────────────────────────────────

class CreatePassportRequest(BaseModel):
    org_slug: str = Field(..., pattern=r"^[a-z0-9-]+$", examples=["tntech"])
    agent_slug: str = Field(..., pattern=r"^[a-z0-9-]+$", examples=["domup-booking"])
    display_name: str = Field(..., max_length=128, examples=["DomUp Booking Agent"])
    capabilities: list[str] = Field(..., min_length=1, examples=[["booking", "scheduling"]])
    bindings: ProtocolBindingsSchema
    ttl_days: int = Field(default=365, ge=1, le=3650)
    metadata: dict[str, str] = {}


class PassportResponse(BaseModel):
    passport_id: str
    display_name: str
    issuer: str
    capabilities: list[str]
    protocols: list[str]
    issued_at: str
    expires_at: str
    revoked: bool = False


class PassportDetailResponse(PassportResponse):
    token: str
    protocol_bindings: dict


class PassportListResponse(BaseModel):
    count: int
    passports: list[PassportResponse]


# ── Translation ───────────────────────────────────────────────────

class TranslateRequest(BaseModel):
    source: dict = Field(..., description="Source document (Agent Card, Server Card, or DID Document)")
    from_format: str = Field(..., description="a2a_agent_card | mcp_server_card | did_document")
    to_format: str = Field(..., description="a2a_agent_card | mcp_server_card | did_document")
    domain: Optional[str] = Field(None, description="Required for DID generation", examples=["domup-sap.fr"])
    agent_slug: Optional[str] = Field(None, description="Required for DID generation", examples=["booking"])


class TranslateResponse(BaseModel):
    from_format: str
    to_format: str
    result: dict
    translated_at: str


# ── Gateway Proxy ─────────────────────────────────────────────────

class GatewayRequest(BaseModel):
    passport_id: str = Field(..., description="Agent passport to use for auth")
    target_url: str = Field(..., description="Target endpoint URL")
    method: str = Field(default="POST", description="HTTP method")
    body: Optional[dict] = None
    headers: dict[str, str] = {}


class GatewayResponse(BaseModel):
    status_code: int
    body: Optional[dict] = None
    headers: dict[str, str] = {}
    audit_trace_id: str
    protocol_used: str


# ── Audit ─────────────────────────────────────────────────────────

class AuditEntry(BaseModel):
    trace_id: str
    passport_id: str
    source_protocol: str
    target_protocol: str
    action: str
    target_url: str
    status: str
    timestamp: str
    duration_ms: float


class AuditResponse(BaseModel):
    passport_id: str
    total_entries: int
    entries: list[AuditEntry]


# ── Health ────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    passports_count: int
    supported_protocols: list[str]
