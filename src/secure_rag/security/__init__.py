"""Layer di sicurezza: anonimizzazione PII, guardrails e audit trail."""

from secure_rag.security.audit import AuditLogger, AuditRecord
from secure_rag.security.guardrails import (
    ContextScanResult,
    GuardVerdict,
    scan_context,
    validate_input,
    validate_output,
)
from secure_rag.security.ner import NerEngine, NerSpan, build_ner_engine
from secure_rag.security.pii import (
    MaskingResult,
    PIIEntity,
    PIIMasker,
    build_masker,
    mask_pii_data,
)

__all__ = [
    "AuditLogger",
    "AuditRecord",
    "ContextScanResult",
    "GuardVerdict",
    "MaskingResult",
    "NerEngine",
    "NerSpan",
    "PIIEntity",
    "PIIMasker",
    "build_masker",
    "build_ner_engine",
    "mask_pii_data",
    "scan_context",
    "validate_input",
    "validate_output",
]
