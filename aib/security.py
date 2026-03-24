"""
AIB — Security hardening module.

Covers:
- URL validation and SSRF protection
- Input sanitization for translated documents
- Rate limiting helpers
- IP address classification

This module is the enforcement layer referenced in THREAT_MODEL.md.
"""

import ipaddress
import re
import socket
from urllib.parse import urlparse
from typing import Optional


# ── SSRF Protection (T4) ─────────────────────────────────────────

# Private/reserved IP ranges that must never be proxied to
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("10.0.0.0/8"),          # Private A
    ipaddress.ip_network("100.64.0.0/10"),       # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),         # Loopback
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local (cloud metadata!)
    ipaddress.ip_network("172.16.0.0/12"),       # Private B
    ipaddress.ip_network("192.0.0.0/24"),        # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),        # Documentation
    ipaddress.ip_network("192.168.0.0/16"),      # Private C
    ipaddress.ip_network("198.18.0.0/15"),       # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),     # Documentation
    ipaddress.ip_network("203.0.113.0/24"),      # Documentation
    ipaddress.ip_network("224.0.0.0/4"),         # Multicast
    ipaddress.ip_network("240.0.0.0/4"),         # Reserved
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),             # Loopback
    ipaddress.ip_network("fc00::/7"),            # Unique local
    ipaddress.ip_network("fe80::/10"),           # Link-local
]


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in network for network in _BLOCKED_NETWORKS)
    except ValueError:
        return True  # If we can't parse it, block it


def resolve_and_check(hostname: str) -> tuple[bool, str]:
    """
    Resolve a hostname and check if it points to a private IP.
    Returns (is_safe, resolved_ip_or_error_message).
    """
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in results:
            ip = sockaddr[0]
            if is_private_ip(ip):
                return False, f"Hostname {hostname} resolves to private IP {ip}"
        # Return first resolved IP
        first_ip = results[0][4][0] if results else "unknown"
        return True, first_ip
    except socket.gaierror:
        return False, f"Cannot resolve hostname: {hostname}"


class URLValidationError(ValueError):
    """Raised when a URL fails security validation."""
    pass


def validate_proxy_url(url: str, allowed_domains: Optional[set[str]] = None) -> str:
    """
    Validate a URL for safe proxying. Blocks SSRF vectors.

    Args:
        url: The URL to validate
        allowed_domains: Optional whitelist of allowed domains

    Returns:
        The validated URL (unchanged if valid)

    Raises:
        URLValidationError: If the URL is unsafe
    """
    # Parse
    try:
        parsed = urlparse(url)
    except Exception:
        raise URLValidationError(f"Cannot parse URL: {url}")

    # Scheme must be HTTPS
    if parsed.scheme != "https":
        raise URLValidationError(
            f"Only HTTPS URLs are allowed, got: {parsed.scheme}://"
        )

    # Must have a hostname
    hostname = parsed.hostname
    if not hostname:
        raise URLValidationError("URL has no hostname")

    # No IP addresses as hostnames (must use domain names)
    try:
        ipaddress.ip_address(hostname)
        raise URLValidationError(
            f"Direct IP addresses are not allowed: {hostname}. Use a domain name."
        )
    except ValueError:
        pass  # Not an IP address, good

    # No suspicious hostnames
    if hostname in ("localhost", "metadata.google.internal", "metadata.aws.internal"):
        raise URLValidationError(f"Blocked hostname: {hostname}")

    # Domain allowlist check
    if allowed_domains:
        if hostname not in allowed_domains:
            # Check if it's a subdomain of an allowed domain
            if not any(hostname.endswith(f".{d}") for d in allowed_domains):
                raise URLValidationError(
                    f"Domain {hostname} is not in the allowlist"
                )

    # No credentials in URL
    if parsed.username or parsed.password:
        raise URLValidationError("URLs with embedded credentials are not allowed")

    # No unusual ports that might target internal services
    port = parsed.port
    if port and port not in (443, 8443, 8080, 8420):
        raise URLValidationError(
            f"Non-standard port {port} is not allowed. "
            f"Allowed: 443, 8443, 8080, 8420"
        )

    # DNS resolution check (the actual SSRF blocker)
    is_safe, result = resolve_and_check(hostname)
    if not is_safe:
        raise URLValidationError(f"SSRF blocked: {result}")

    return url


# ── Input Sanitization (T3) ──────────────────────────────────────

# Maximum sizes for translated documents
MAX_FIELD_LENGTH = 1000       # Max characters per string field
MAX_ARRAY_ITEMS = 50          # Max items in an array (skills, tools, etc.)
MAX_DOCUMENT_SIZE = 102400    # 100KB max for any input document
MAX_URL_LENGTH = 2048         # Max URL length

# Characters that should never appear in identity documents
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class InputValidationError(ValueError):
    """Raised when input fails sanitization."""
    pass


def sanitize_string(value: str, field_name: str, max_length: int = MAX_FIELD_LENGTH) -> str:
    """
    Sanitize a string field from an identity document.

    - Strips control characters
    - Enforces maximum length
    - Strips leading/trailing whitespace
    """
    if not isinstance(value, str):
        raise InputValidationError(f"{field_name}: expected string, got {type(value).__name__}")

    # Strip control characters
    cleaned = _CONTROL_CHARS.sub("", value)

    # Strip whitespace
    cleaned = cleaned.strip()

    # Enforce length
    if len(cleaned) > max_length:
        raise InputValidationError(
            f"{field_name}: exceeds maximum length of {max_length} characters "
            f"(got {len(cleaned)})"
        )

    return cleaned


def sanitize_url(url: str, field_name: str) -> str:
    """Sanitize and validate a URL field."""
    url = sanitize_string(url, field_name, max_length=MAX_URL_LENGTH)

    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http"):
        raise InputValidationError(
            f"{field_name}: URL must use https:// or http://, got {parsed.scheme}://"
        )

    if not parsed.hostname:
        raise InputValidationError(f"{field_name}: URL has no hostname")

    # Block obviously malicious URLs
    if parsed.hostname in ("localhost", "127.0.0.1", "0.0.0.0", "metadata.google.internal"):
        raise InputValidationError(f"{field_name}: blocked hostname {parsed.hostname}")

    return url


def sanitize_array(items: list, field_name: str, max_items: int = MAX_ARRAY_ITEMS) -> list:
    """Validate array length."""
    if not isinstance(items, list):
        raise InputValidationError(f"{field_name}: expected list, got {type(items).__name__}")
    if len(items) > max_items:
        raise InputValidationError(
            f"{field_name}: exceeds maximum of {max_items} items (got {len(items)})"
        )
    return items


def validate_document_size(document: dict, max_bytes: int = MAX_DOCUMENT_SIZE) -> dict:
    """Check that a JSON document doesn't exceed size limits."""
    import json
    size = len(json.dumps(document, ensure_ascii=False).encode())
    if size > max_bytes:
        raise InputValidationError(
            f"Document exceeds maximum size of {max_bytes} bytes (got {size})"
        )
    return document


def sanitize_agent_card(card: dict) -> dict:
    """
    Full sanitization of an A2A Agent Card or MCP Server Card.
    Strips dangerous content, enforces size limits.
    """
    validate_document_size(card)

    sanitized = {}

    # String fields
    for field in ("name", "description", "version"):
        if field in card:
            sanitized[field] = sanitize_string(card[field], field)

    # URL fields
    for field in ("url", "server_url"):
        if field in card:
            sanitized[field] = sanitize_url(card[field], field)

    # Array fields
    if "skills" in card:
        skills = sanitize_array(card["skills"], "skills")
        sanitized["skills"] = []
        for i, skill in enumerate(skills):
            if isinstance(skill, dict):
                s = {}
                for sf in ("id", "name", "description"):
                    if sf in skill:
                        s[sf] = sanitize_string(skill[sf], f"skills[{i}].{sf}")
                sanitized["skills"].append(s)

    if "tools" in card:
        tools = sanitize_array(card["tools"], "tools")
        sanitized["tools"] = []
        for i, tool in enumerate(tools):
            if isinstance(tool, dict):
                t = {}
                for tf in ("name", "description"):
                    if tf in tool:
                        t[tf] = sanitize_string(tool[tf], f"tools[{i}].{tf}")
                if "inputSchema" in tool and isinstance(tool["inputSchema"], dict):
                    t["inputSchema"] = tool["inputSchema"]
                sanitized["tools"].append(t)

    # Auth (pass through but validate structure)
    if "authentication" in card and isinstance(card["authentication"], dict):
        sanitized["authentication"] = card["authentication"]
    if "auth" in card and isinstance(card["auth"], dict):
        sanitized["auth"] = card["auth"]

    # Capabilities
    if "capabilities" in card and isinstance(card["capabilities"], dict):
        sanitized["capabilities"] = card["capabilities"]

    return sanitized


# ── Rate Limiting Helper ──────────────────────────────────────────

class RateLimiter:
    """
    Simple in-memory token bucket rate limiter.
    Production: use Redis-based limiter.
    """

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self._max = max_requests
        self._window = window_seconds
        self._buckets: dict[str, list[float]] = {}

    def check(self, key: str) -> tuple[bool, int]:
        """
        Check if a request is allowed.
        Returns (allowed, remaining_requests).
        """
        import time
        now = time.time()
        cutoff = now - self._window

        if key not in self._buckets:
            self._buckets[key] = []

        # Remove expired entries
        self._buckets[key] = [t for t in self._buckets[key] if t > cutoff]

        remaining = self._max - len(self._buckets[key])

        if remaining <= 0:
            return False, 0

        self._buckets[key].append(now)
        return True, remaining - 1
