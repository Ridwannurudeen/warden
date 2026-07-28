"""Deterministic ASP task-executor for the OKX A2A task marketplace.

This package contains only the deterministic seller-side machinery: inbox
firewalling, in-process work execution, guardrails, and the system-event
handler. LLM negotiation is a separate future component (see negotiator.py).
"""
