"""warden-guard — one-line payload firewall for agent services (APA v0.1)."""

from importlib.metadata import version as _distribution_version

from warden_guard.aio import AsyncWardenClient
from warden_guard.client import ScanResult, WardenBlocked, WardenClient, WardenError
from warden_guard.decorator import guard
from warden_guard.middleware import WardenGuard
from warden_guard.pipeline import AsyncTextGuard, GuardedText, TextGuard
from warden_guard.proof import ProtectionProofApp, protection_proof
from warden_guard.proxy import WardenReverseProxy

__version__ = _distribution_version("warden-guard")

__all__ = [
    "AsyncTextGuard",
    "AsyncWardenClient",
    "GuardedText",
    "ProtectionProofApp",
    "ScanResult",
    "TextGuard",
    "WardenBlocked",
    "WardenClient",
    "WardenError",
    "WardenGuard",
    "WardenReverseProxy",
    "guard",
    "protection_proof",
    "__version__",
]
