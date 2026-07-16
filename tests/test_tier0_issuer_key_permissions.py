"""Regression coverage for secure local APA issuer-key creation."""

import os
import stat

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import protection
from warden.badges import b64u_encode


def test_fallback_issuer_key_is_atomically_published_at_mode_600(tmp_path, monkeypatch):
    key_path = tmp_path / "apa_issuer.key"
    created_modes = []
    linked_paths = []
    real_open = os.open
    real_link = os.link

    def tracked_open(path, flags, mode=0o777):
        created_modes.append(mode)
        return real_open(path, flags, mode)

    def tracked_link(source, destination):
        linked_paths.append((source, destination))
        return real_link(source, destination)

    monkeypatch.delenv("WARDEN_ISSUER_KEY", raising=False)
    monkeypatch.setattr(protection, "_issuer_key_path", lambda: key_path)
    monkeypatch.setattr(protection.os, "open", tracked_open)
    monkeypatch.setattr(protection.os, "link", tracked_link)

    first = protection.issuer_private_key().private_bytes_raw()
    second = protection.issuer_private_key().private_bytes_raw()

    assert first == second
    assert created_modes == [0o600]
    assert len(linked_paths) == 1
    assert linked_paths[0][1] == key_path
    assert not list(tmp_path.glob("*.tmp"))
    if os.name != "nt":
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


def test_configured_issuer_key_is_preferred_without_creating_a_file(tmp_path, monkeypatch):
    key_path = tmp_path / "apa_issuer.key"
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    monkeypatch.setenv("WARDEN_ISSUER_KEY", b64u_encode(seed, "ed25519-seed"))
    monkeypatch.setattr(protection, "_issuer_key_path", lambda: key_path)

    loaded = protection.issuer_private_key().private_bytes_raw()

    assert loaded == seed
    assert not key_path.exists()
