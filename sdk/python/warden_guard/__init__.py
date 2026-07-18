"""warden-agent-guard — one-line payload firewall for agent services (APA v0.1)."""

from importlib.metadata import version as _distribution_version

from warden_guard.aio import AsyncWardenClient
from warden_guard.client import (
    AsyncX402PaymentHandler,
    FeedbackResult,
    ScanResult,
    WardenBlocked,
    WardenClient,
    WardenError,
    X402Challenge,
    X402PaymentHandler,
    X402PaymentRequirement,
)
from warden_guard.decorator import guard
from warden_guard.middleware import WardenGuard
from warden_guard.pipeline import AsyncTextGuard, GuardedText, TextGuard
from warden_guard.proof import ProtectionProofApp, protection_proof
from warden_guard.proxy import WardenReverseProxy

__version__ = _distribution_version("warden-agent-guard")

__all__ = [
    "AsyncTextGuard",
    "AsyncWardenClient",
    "AsyncX402PaymentHandler",
    "FeedbackResult",
    "GuardedText",
    "ProtectionProofApp",
    "ScanResult",
    "TextGuard",
    "WardenBlocked",
    "WardenClient",
    "WardenError",
    "WardenGuard",
    "WardenReverseProxy",
    "X402Challenge",
    "X402PaymentHandler",
    "X402PaymentRequirement",
    "guard",
    "protection_proof",
    "__version__",
]
