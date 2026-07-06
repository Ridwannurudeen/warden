"""Warden custom analyzers."""

from warden.analyzers.drain_address import DrainAddressAnalyzer
from warden.analyzers.exfiltration import ExfiltrationAnalyzer
from warden.analyzers.links import MaliciousLinkAnalyzer
from warden.analyzers.tool_hijack import ToolHijackAnalyzer

__all__ = [
    "DrainAddressAnalyzer",
    "ExfiltrationAnalyzer",
    "MaliciousLinkAnalyzer",
    "ToolHijackAnalyzer",
]
