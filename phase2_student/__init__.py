"""
Phase 2: Student Examination & Edge AI Proctoring Module
Handles access code verification, camera/mic permissions, local RAM proctoring,
and 11-parameter Federated Averaging (FedAvg) updates.
"""

from .edge_ai import LogisticViolationScorer, FedAvgAggregator
from .student_server import app as student_app

__all__ = [
    "LogisticViolationScorer",
    "FedAvgAggregator",
    "student_app"
]