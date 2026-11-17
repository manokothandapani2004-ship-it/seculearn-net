"""
Phase 3: Post-Exam Blockchain State Auditor & Tamper Detection Module
Monitors the local Hyperledger Fabric ledger and dispatches security alerts
upon hash verification mismatch.
"""

from .tamper_daemon import verify_entire_ledger

__all__ = ["verify_entire_ledger"]