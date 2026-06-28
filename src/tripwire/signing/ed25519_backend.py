"""Ed25519 signing backend — the credibility upgrade. Gated behind ``[signing]`` extra.

Per RFC-0002 (#31). Implements the same ``SigningBackend`` Protocol as
``HmacBackend`` — same boundary, different math. Sign with the private key,
verify with the public key, no shared secret needed for third-party verification.
That's the property the README's "portable, independently-verifiable" promise
actually requires.

Wire format choices (RFC-0002 §"Wire format"):

- ``sig`` is the **base64-urlsafe-no-pad** encoding of the raw 64-byte Ed25519
  signature (RFC 4648 §5). Hex would also work; b64 keeps payloads compact.
- ``alg`` string is ``"Ed25519"`` exactly.

The ``cryptography`` import is **lazy** — performed inside the constructor and
methods, not at module scope. A base install without the ``[signing]`` extra
can still ``from tripwire.signing.ed25519_backend import Ed25519Backend`` and
the class object exists; instantiating it raises a clear install hint.
"""

from __future__ import annotations

import base64

ALG = "Ed25519"


def _require_cryptography():
    """Lazy-import the optional ``cryptography`` package with a helpful error."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as e:  # pragma: no cover - import-error path is environment
        raise ImportError(
            "Ed25519 signing requires the `cryptography` package. Install with "
            "`pip install 'mcp-tripwire[signing]'` (or `uv pip install cryptography`)."
        ) from e
    return serialization, ed25519


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _canonical(payload: dict) -> bytes:
    """Same canonical encoding as HmacBackend — sorted keys, no spaces, ASCII."""
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


class Ed25519Backend:
    """Ed25519 backend. Sign with the private key; verify with the public key.

    Can be constructed in three shapes:

    - ``private_key_pem`` only — derives the public key from the private. Both
      ``sign`` and ``verify`` work.
    - ``public_key_pem`` only — verify-only. ``sign`` raises.
    - Both — explicit, useful if the public key file is the canonical artifact.

    Keys are PEM-encoded (PKCS#8 for private, SubjectPublicKeyInfo for public).
    Anything else raises ``ValueError`` from ``cryptography``.
    """

    alg: str = ALG

    def __init__(
        self,
        *,
        private_key_pem: bytes | None = None,
        public_key_pem: bytes | None = None,
    ) -> None:
        if private_key_pem is None and public_key_pem is None:
            raise ValueError("Ed25519Backend requires private_key_pem and/or public_key_pem")

        serialization, _ed = _require_cryptography()

        self._private = None
        self._public = None

        if private_key_pem is not None:
            self._private = serialization.load_pem_private_key(private_key_pem, password=None)
            # Derive the matching public key.
            self._public = self._private.public_key()

        if public_key_pem is not None:
            self._public = serialization.load_pem_public_key(public_key_pem)
            # If both were supplied, sanity-check they agree.
            if private_key_pem is not None:
                derived = self._private.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                supplied = self._public.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                if derived != supplied:
                    raise ValueError(
                        "Ed25519Backend: provided public_key_pem does not match "
                        "the public key derived from private_key_pem"
                    )

    @classmethod
    def generate(cls) -> Ed25519Backend:
        """Generate a fresh keypair. Used by the CLI ``tripwire key gen`` command."""
        serialization, ed25519 = _require_cryptography()
        priv = ed25519.Ed25519PrivateKey.generate()
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return cls(private_key_pem=priv_pem)

    def public_key_pem(self) -> bytes:
        """Export the public key as PEM bytes (PEM SubjectPublicKeyInfo)."""
        serialization, _ed = _require_cryptography()
        if self._public is None:
            raise ValueError("Ed25519Backend has no public key to export")
        return self._public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def private_key_pem(self) -> bytes:
        """Export the private key as PEM bytes (PKCS8, unencrypted)."""
        serialization, _ed = _require_cryptography()
        if self._private is None:
            raise ValueError("Ed25519Backend is verify-only (no private key)")
        return self._private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def sign(self, payload: dict) -> str:
        if self._private is None:
            raise ValueError("Ed25519Backend is verify-only; cannot sign")
        sig = self._private.sign(_canonical(payload))
        return _b64encode(sig)

    def verify(self, badge: dict) -> tuple[bool, str]:
        if "sig" not in badge:
            return False, "missing signature"
        if self._public is None:
            return False, "Ed25519Backend has no public key configured"
        _serialization, _ed = _require_cryptography()
        from cryptography.exceptions import InvalidSignature

        payload = {k: v for k, v in badge.items() if k != "sig"}
        try:
            raw = _b64decode(str(badge["sig"]))
        except Exception:
            return False, "signature is not valid base64"
        try:
            self._public.verify(raw, _canonical(payload))
        except InvalidSignature:
            return False, "signature mismatch — badge or payload was tampered with"
        return True, "valid"
