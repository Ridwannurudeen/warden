"""Ed25519 guard keypair — generate once, persist locally with 0600 perms.

The private key lives at `$WARDEN_GUARD_KEY` (default `~/.warden/guard_key`)
as the unpadded-base64url raw 32-byte seed. The public key (as `ed25519:...`)
is what the heartbeat publishes and what an issuer binds to the endpoint host.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden_guard.apa import b64u_decode, b64u_encode

_KEY_ENV = "WARDEN_GUARD_KEY"


def key_path() -> Path:
    return Path(os.environ.get(_KEY_ENV) or Path.home() / ".warden" / "guard_key")


def load_or_create_key() -> Ed25519PrivateKey:
    """Load the persisted guard key, generating (and persisting) one on first run."""
    path = key_path()
    if path.exists():
        raw = b64u_decode(path.read_text(encoding="utf-8").strip())
        return Ed25519PrivateKey.from_private_bytes(raw)
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    encoded = b64u_encode(key.private_bytes_raw(), "ed25519-priv")
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(encoded, encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return key


def public_key_str(key: Ed25519PrivateKey) -> str:
    """`ed25519:...` public key string as published in the Protection Proof."""
    return b64u_encode(key.public_key().public_bytes_raw(), "ed25519")
