"""
Phase 1: Institution & Faculty Portal Module
Handles exam paper ingestion, AES-256-GCM encryption, (T, N) Shamir's Secret Sharing,
time-locked validator node coordination, and exam access code generation.
"""

from .faculty_server import app as faculty_app

__all__ = ["faculty_app"]