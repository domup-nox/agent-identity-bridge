"""
AIB — Gateway Proxy
Protocol-aware reverse proxy that injects the right credentials
based on the target protocol, using the agent's passport.
"""

import httpx
import json
from typing import Optional
from dataclasses import dataclass


@dataclass
class ProxyResult:
    status_code: int
    body: Optional[dict]
    headers: dict
    protocol_used: str
    trace_id: str = ""


class Gateway:
    """
    Reverse proxy that routes requests through the appropriate protocol
    and injects credentials from the agent's passport.
    """

    def __init__(self, timeout: float = 30.0):
        self._timeout = timeout
        # In-memory credential cache (MVP).
        # Production: read from HashiCorp Vault via credential_ref.
        self._credentials: dict[str, dict[str, str]] = {}

    def register_credential(self, passport_id: str, protocol: str, token: str):
        """Register a credential for a passport+protocol pair."""
        key = f"{passport_id}:{protocol}"
        self._credentials[key] = {"token": token}

    def _get_credential(self, passport_id: str, protocol: str) -> Optional[str]:
        key = f"{passport_id}:{protocol}"
        cred = self._credentials.get(key)
        return cred["token"] if cred else None

    def detect_protocol(self, url: str, passport_bindings: dict) -> str:
        """
        Detect which protocol a target URL belongs to,
        based on the passport's protocol bindings.
        """
        for proto, binding in passport_bindings.items():
            if proto == "mcp":
                card_url = binding.get("server_card_url", "")
                if card_url and self._same_origin(url, card_url):
                    return "mcp"
            elif proto == "a2a":
                card_url = binding.get("agent_card_url", "")
                if card_url and self._same_origin(url, card_url):
                    return "a2a"
            elif proto == "anp":
                did = binding.get("did", "")
                if did:
                    # did:web:example.com → check if URL matches example.com
                    domain = did.replace("did:web:", "").split(":")[0]
                    if domain in url:
                        return "anp"
        return "unknown"

    async def proxy_request(
        self,
        passport_id: str,
        passport_bindings: dict,
        target_url: str,
        method: str = "POST",
        body: Optional[dict] = None,
        extra_headers: Optional[dict] = None,
    ) -> ProxyResult:
        """
        Proxy a request to the target URL with protocol-appropriate credentials.

        1. Detect target protocol from URL + passport bindings
        2. Look up credential for that protocol
        3. Inject auth headers
        4. Forward request
        5. Return result
        """
        protocol = self.detect_protocol(target_url, passport_bindings)
        credential = self._get_credential(passport_id, protocol)

        # Build headers with injected auth
        headers = {
            "Content-Type": "application/json",
            "X-AIB-Passport-ID": passport_id,
            "X-AIB-Protocol": protocol,
        }

        if credential:
            binding = passport_bindings.get(protocol, {})
            auth_method = binding.get("auth_method", "bearer")

            if auth_method in ("bearer", "oauth2"):
                headers["Authorization"] = f"Bearer {credential}"
            elif auth_method == "api_key":
                headers["X-API-Key"] = credential
            elif auth_method == "did-auth":
                headers["Authorization"] = f"DID {credential}"

        if extra_headers:
            headers.update(extra_headers)

        # Adapt request format per protocol
        request_body = self._adapt_request(protocol, body)

        # Forward the request
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.request(
                method=method,
                url=target_url,
                headers=headers,
                json=request_body,
            )

            # Parse response
            try:
                response_body = response.json()
            except Exception:
                response_body = {"raw": response.text[:1000]}

            return ProxyResult(
                status_code=response.status_code,
                body=response_body,
                headers=dict(response.headers),
                protocol_used=protocol,
            )

    def _adapt_request(self, protocol: str, body: Optional[dict]) -> Optional[dict]:
        """
        Adapt request body format to match protocol expectations.
        """
        if body is None:
            return None

        if protocol == "a2a":
            # A2A expects JSON-RPC 2.0 envelope
            if "jsonrpc" not in body:
                return {
                    "jsonrpc": "2.0",
                    "id": "aib-proxy-1",
                    "method": body.get("method", "message/send"),
                    "params": body.get("params", body),
                }
        elif protocol == "mcp":
            # MCP also uses JSON-RPC 2.0
            if "jsonrpc" not in body:
                return {
                    "jsonrpc": "2.0",
                    "id": "aib-proxy-1",
                    "method": body.get("method", "tools/call"),
                    "params": body.get("params", body),
                }

        return body

    @staticmethod
    def _same_origin(url1: str, url2: str) -> bool:
        """Check if two URLs share the same origin (scheme+host)."""
        from urllib.parse import urlparse
        p1, p2 = urlparse(url1), urlparse(url2)
        return p1.scheme == p2.scheme and p1.netloc == p2.netloc
