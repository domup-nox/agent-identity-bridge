"""
Tests for AIB security hardening.

Covers:
- T1: RS256 passport signing (crypto.py)
- T3: Input sanitization (security.py)
- T4: SSRF protection (security.py)
- T5: Replay prevention (crypto.py)
- Rate limiting (security.py)
"""

import pytest
import time
import json
from datetime import datetime, timezone, timedelta

from aib.security import (
    is_private_ip,
    validate_proxy_url,
    URLValidationError,
    sanitize_string,
    sanitize_url,
    sanitize_array,
    sanitize_agent_card,
    validate_document_size,
    InputValidationError,
    RateLimiter,
)
from aib.crypto import SigningKey, KeyManager, PassportSigner


# ═══════════════════════════════════════════════════════════════════
# T1 — RS256 Passport Signing
# ═══════════════════════════════════════════════════════════════════

class TestRS256Signing:

    @pytest.fixture
    def key_manager(self, tmp_path):
        return KeyManager(keys_dir=str(tmp_path / "keys"))

    @pytest.fixture
    def signer(self, key_manager):
        return PassportSigner(key_manager)

    def test_sign_and_verify(self, signer):
        payload = {
            "passport_id": "urn:aib:agent:test:agent1",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        token = signer.sign(payload)
        valid, decoded, reason = signer.verify(token)
        assert valid is True
        assert decoded["passport_id"] == "urn:aib:agent:test:agent1"
        assert reason == "Valid"

    def test_tampered_token_rejected(self, signer):
        payload = {
            "passport_id": "urn:aib:agent:test:tamper",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        token = signer.sign(payload)
        # Tamper with the payload section
        parts = token.split(".")
        parts[1] = parts[1][:10] + "XXXX" + parts[1][14:]
        tampered = ".".join(parts)
        valid, _, reason = signer.verify(tampered)
        assert valid is False

    def test_expired_passport_rejected(self, signer):
        payload = {
            "passport_id": "urn:aib:agent:test:expired",
            "iat": int(time.time()) - 7200,
            "exp": int(time.time()) - 3600,  # Expired 1 hour ago
        }
        token = signer.sign(payload)
        valid, _, reason = signer.verify(token)
        assert valid is False
        assert "expired" in reason.lower()

    def test_jti_added_automatically(self, signer):
        payload = {
            "passport_id": "urn:aib:agent:test:jti",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        token = signer.sign(payload)
        valid, decoded, _ = signer.verify(token)
        assert valid is True
        assert "jti" in decoded
        assert len(decoded["jti"]) == 36  # UUID format

    def test_different_tokens_have_different_jti(self, signer):
        payload = {
            "passport_id": "urn:aib:agent:test:unique",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        token1 = signer.sign(dict(payload))
        token2 = signer.sign(dict(payload))
        _, d1, _ = signer.verify(token1)
        _, d2, _ = signer.verify(token2)
        assert d1["jti"] != d2["jti"]


class TestKeyManagement:

    def test_auto_generates_initial_key(self, tmp_path):
        km = KeyManager(keys_dir=str(tmp_path / "keys"))
        assert km.active_key is not None
        assert km.active_key.kid.startswith("aib-")

    def test_key_rotation(self, tmp_path):
        km = KeyManager(keys_dir=str(tmp_path / "keys"))
        old_kid = km.active_key.kid
        new_key = km.rotate()
        assert new_key.kid != old_kid
        assert km.active_key.kid == new_key.kid

    def test_old_key_still_verifies(self, tmp_path):
        km = KeyManager(keys_dir=str(tmp_path / "keys"))
        signer = PassportSigner(km)

        # Sign with old key
        payload = {
            "passport_id": "urn:aib:agent:test:oldkey",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        token = signer.sign(payload)
        old_kid = km.active_key.kid

        # Rotate key
        km.rotate()
        assert km.active_key.kid != old_kid

        # Old token should still verify (grace period)
        valid, _, reason = signer.verify(token)
        assert valid is True

    def test_jwks_output(self, tmp_path):
        km = KeyManager(keys_dir=str(tmp_path / "keys"))
        jwks = km.jwks()
        assert "keys" in jwks
        assert len(jwks["keys"]) >= 1
        key = jwks["keys"][0]
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert "n" in key
        assert "e" in key

    def test_key_persistence(self, tmp_path):
        keys_dir = str(tmp_path / "keys")
        km1 = KeyManager(keys_dir=keys_dir)
        kid = km1.active_key.kid

        # Create new manager from same directory
        km2 = KeyManager(keys_dir=keys_dir)
        assert km2.active_key.kid == kid


# ═══════════════════════════════════════════════════════════════════
# T3 — Input Sanitization
# ═══════════════════════════════════════════════════════════════════

class TestInputSanitization:

    def test_sanitize_normal_string(self):
        assert sanitize_string("Hello World", "test") == "Hello World"

    def test_strip_control_characters(self):
        result = sanitize_string("Hello\x00\x01\x02World", "test")
        assert result == "HelloWorld"

    def test_reject_oversized_string(self):
        with pytest.raises(InputValidationError, match="exceeds maximum"):
            sanitize_string("x" * 1001, "test")

    def test_strip_whitespace(self):
        assert sanitize_string("  hello  ", "test") == "hello"

    def test_reject_non_string(self):
        with pytest.raises(InputValidationError, match="expected string"):
            sanitize_string(12345, "test")

    def test_sanitize_url_valid(self):
        url = sanitize_url("https://example.com/api", "test")
        assert url == "https://example.com/api"

    def test_sanitize_url_reject_ftp(self):
        with pytest.raises(InputValidationError, match="https://"):
            sanitize_url("ftp://evil.com/file", "test")

    def test_sanitize_url_reject_localhost(self):
        with pytest.raises(InputValidationError, match="blocked"):
            sanitize_url("https://localhost/api", "test")

    def test_sanitize_url_reject_metadata(self):
        with pytest.raises(InputValidationError, match="blocked"):
            sanitize_url("https://metadata.google.internal/computeMetadata", "test")

    def test_sanitize_array_valid(self):
        result = sanitize_array([1, 2, 3], "test")
        assert len(result) == 3

    def test_sanitize_array_reject_oversized(self):
        with pytest.raises(InputValidationError, match="exceeds maximum"):
            sanitize_array(list(range(51)), "test")

    def test_validate_document_size(self):
        small_doc = {"key": "value"}
        assert validate_document_size(small_doc) == small_doc

    def test_reject_oversized_document(self):
        big_doc = {"data": "x" * 200000}
        with pytest.raises(InputValidationError, match="exceeds maximum size"):
            validate_document_size(big_doc)

    def test_sanitize_agent_card_full(self):
        card = {
            "name": "Test Agent",
            "description": "A test\x00 agent",  # Control char
            "url": "https://example.com/agent",
            "version": "1.0.0",
            "skills": [
                {"id": "search", "name": "Search", "description": "Search things"},
            ],
            "authentication": {"schemes": ["bearer"]},
        }
        result = sanitize_agent_card(card)
        assert result["name"] == "Test Agent"
        assert result["description"] == "A test agent"  # Control char stripped
        assert len(result["skills"]) == 1


# ═══════════════════════════════════════════════════════════════════
# T4 — SSRF Protection
# ═══════════════════════════════════════════════════════════════════

class TestSSRFProtection:

    def test_private_ip_detection(self):
        assert is_private_ip("127.0.0.1") is True
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("169.254.169.254") is True  # Cloud metadata!
        assert is_private_ip("::1") is True

    def test_public_ip_allowed(self):
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False

    def test_reject_http_scheme(self):
        with pytest.raises(URLValidationError, match="HTTPS"):
            validate_proxy_url("http://example.com/api")

    def test_reject_ftp_scheme(self):
        with pytest.raises(URLValidationError, match="HTTPS"):
            validate_proxy_url("ftp://example.com/file")

    def test_reject_direct_ip(self):
        with pytest.raises(URLValidationError):
            validate_proxy_url("https://192.168.1.1/api")

    def test_reject_localhost(self):
        with pytest.raises(URLValidationError, match="Blocked hostname"):
            validate_proxy_url("https://localhost/api")

    def test_reject_cloud_metadata(self):
        with pytest.raises(URLValidationError, match="Blocked hostname"):
            validate_proxy_url("https://metadata.google.internal/computeMetadata/v1/")

    def test_reject_credentials_in_url(self):
        with pytest.raises(URLValidationError, match="credentials"):
            validate_proxy_url("https://user:pass@example.com/api")

    def test_domain_allowlist(self):
        allowed = {"example.com", "api.partner.com"}
        # Non-allowed domain blocked (before DNS check)
        with pytest.raises(URLValidationError, match="not in the allowlist"):
            validate_proxy_url("https://evil.com/api", allowed_domains=allowed)

    def test_reject_unusual_port(self):
        with pytest.raises(URLValidationError, match="Non-standard port"):
            validate_proxy_url("https://example.com:6379/api")  # Redis port


# ═══════════════════════════════════════════════════════════════════
# Rate Limiting
# ═══════════════════════════════════════════════════════════════════

class TestRateLimiter:

    def test_allows_under_limit(self):
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        for i in range(5):
            allowed, remaining = limiter.check("test-key")
            assert allowed is True

    def test_blocks_over_limit(self):
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            limiter.check("test-key")
        allowed, remaining = limiter.check("test-key")
        assert allowed is False
        assert remaining == 0

    def test_separate_keys(self):
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        limiter.check("key-a")
        limiter.check("key-a")
        # key-a is exhausted
        allowed_a, _ = limiter.check("key-a")
        assert allowed_a is False
        # key-b is fresh
        allowed_b, _ = limiter.check("key-b")
        assert allowed_b is True
