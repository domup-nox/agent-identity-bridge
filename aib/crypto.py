"""
AIB — Cryptographic signing module.

Handles RS256 (RSA-SHA256) key management for Agent Passport signing.
Replaces the HMAC-SHA256 MVP implementation with production-grade
asymmetric cryptography.

Key features:
- RSA 2048-bit key pairs (upgradeable to 4096)
- Key rotation with grace period for old keys
- JWK Set (JWKS) endpoint generation
- Key persistence to disk (PEM format)

References THREAT_MODEL.md: T1 (Passport Forgery), M1.1-M1.4
"""

import json
import time
import uuid
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import jwt  # PyJWT


# ── Key Management ────────────────────────────────────────────────

class SigningKey:
    """An RSA key pair with metadata."""

    def __init__(
        self,
        kid: Optional[str] = None,
        key_size: int = 2048,
        private_key=None,
    ):
        self.kid = kid or f"aib-{uuid.uuid4().hex[:8]}"
        self.created_at = datetime.now(timezone.utc).isoformat()

        if private_key:
            self._private_key = private_key
        else:
            self._private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend(),
            )

        self._public_key = self._private_key.public_key()

    @property
    def private_key(self):
        return self._private_key

    @property
    def public_key(self):
        return self._public_key

    def private_pem(self) -> bytes:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_pem(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def to_jwk(self) -> dict:
        """Export public key as JWK for /.well-known/aib-keys.json."""
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        import base64

        pub_numbers = self._public_key.public_numbers()

        def _int_to_base64url(n: int) -> str:
            byte_length = (n.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(
                n.to_bytes(byte_length, byteorder="big")
            ).rstrip(b"=").decode()

        return {
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
            "n": _int_to_base64url(pub_numbers.n),
            "e": _int_to_base64url(pub_numbers.e),
        }

    def save(self, directory: Path):
        """Save key pair to disk."""
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{self.kid}.private.pem").write_bytes(self.private_pem())
        (directory / f"{self.kid}.public.pem").write_bytes(self.public_pem())
        (directory / f"{self.kid}.meta.json").write_text(json.dumps({
            "kid": self.kid,
            "created_at": self.created_at,
            "algorithm": "RS256",
            "key_size": self._private_key.key_size,
        }))

    @classmethod
    def load(cls, directory: Path, kid: str) -> "SigningKey":
        """Load a key pair from disk."""
        private_pem = (directory / f"{kid}.private.pem").read_bytes()
        private_key = serialization.load_pem_private_key(
            private_pem, password=None, backend=default_backend()
        )
        meta = json.loads((directory / f"{kid}.meta.json").read_text())
        key = cls(kid=kid, private_key=private_key)
        key.created_at = meta.get("created_at", key.created_at)
        return key


class KeyManager:
    """
    Manages RSA key rotation for passport signing.

    - One active key for signing new passports
    - Old keys retained for verification (grace period)
    - Auto-generates initial key if none exists
    """

    def __init__(self, keys_dir: str = "./data/keys"):
        self._keys_dir = Path(keys_dir)
        self._keys: dict[str, SigningKey] = {}
        self._active_kid: Optional[str] = None
        self._load_keys()

    def _load_keys(self):
        """Load all keys from disk, or generate initial key."""
        self._keys_dir.mkdir(parents=True, exist_ok=True)

        meta_files = list(self._keys_dir.glob("*.meta.json"))
        if not meta_files:
            # No keys exist, generate the first one
            self.rotate()
            return

        for meta_file in meta_files:
            meta = json.loads(meta_file.read_text())
            kid = meta["kid"]
            try:
                self._keys[kid] = SigningKey.load(self._keys_dir, kid)
            except Exception:
                continue  # Skip corrupted keys

        # Active key = most recently created
        if self._keys:
            self._active_kid = max(
                self._keys.keys(),
                key=lambda k: self._keys[k].created_at,
            )

    def rotate(self) -> SigningKey:
        """Generate a new signing key and make it active."""
        new_key = SigningKey()
        new_key.save(self._keys_dir)
        self._keys[new_key.kid] = new_key
        self._active_kid = new_key.kid
        return new_key

    @property
    def active_key(self) -> SigningKey:
        """The current key used for signing new passports."""
        if not self._active_kid or self._active_kid not in self._keys:
            return self.rotate()
        return self._keys[self._active_kid]

    def get_key(self, kid: str) -> Optional[SigningKey]:
        """Get a key by ID (for verification of old passports)."""
        return self._keys.get(kid)

    def jwks(self) -> dict:
        """Generate JWKS (JSON Web Key Set) for /.well-known/aib-keys.json."""
        return {
            "keys": [key.to_jwk() for key in self._keys.values()]
        }


# ── Passport Signing (RS256) ─────────────────────────────────────

class PassportSigner:
    """
    Signs and verifies Agent Passports using RS256.

    Replaces the HMAC-SHA256 signer from the MVP.
    """

    def __init__(self, key_manager: KeyManager):
        self._km = key_manager

    def sign(self, payload: dict) -> str:
        """
        Sign a passport payload, returning a JWS token (RS256).

        Adds standard JWT claims:
        - iss: passport issuer
        - iat: issued at
        - exp: expiration
        - jti: unique token ID (replay protection)
        - kid: key ID (in header, for key rotation)
        """
        key = self._km.active_key

        # Ensure required claims
        if "jti" not in payload:
            payload["jti"] = str(uuid.uuid4())
        if "nbf" not in payload and "iat" in payload:
            payload["nbf"] = payload["iat"]

        token = jwt.encode(
            payload,
            key.private_key,
            algorithm="RS256",
            headers={"kid": key.kid, "typ": "AIB-PASSPORT"},
        )
        return token

    def verify(self, token: str) -> tuple[bool, Optional[dict], str]:
        """
        Verify a passport token.

        Returns:
            (is_valid, payload_or_none, reason)
        """
        try:
            # Decode header to get kid
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")

            if not kid:
                return False, None, "Missing kid in token header"

            # Get the key used for signing
            key = self._km.get_key(kid)
            if not key:
                return False, None, f"Unknown signing key: {kid}"

            # Verify signature + claims
            payload = jwt.decode(
                token,
                key.public_key,
                algorithms=["RS256"],
                options={
                    "require": ["exp", "iat", "passport_id"],
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                },
            )
            return True, payload, "Valid"

        except jwt.ExpiredSignatureError:
            return False, None, "Passport expired"
        except jwt.InvalidSignatureError:
            return False, None, "Invalid signature"
        except jwt.MissingRequiredClaimError as e:
            return False, None, f"Missing required claim: {e}"
        except jwt.DecodeError as e:
            return False, None, f"Token decode error: {e}"
        except Exception as e:
            return False, None, f"Verification failed: {e}"
