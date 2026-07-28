"""Audit trail delle interazioni con l'LLM.

In un'assicurazione ogni interazione con un sistema che tratta dati di polizza deve essere
ricostruibile a posteriori: chi ha chiesto cosa, quali documenti sono stati consultati, quali
controlli di sicurezza sono scattati. Questo modulo scrive un log **append-only** in formato JSONL,
adatto a essere spedito a un SIEM.

Nota di privacy: nel log non finisce mai la query in chiaro né la risposta. Viene salvato un hash
della domanda (per correlare richieste ripetute o campagne di attacco) e i soli metadati.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from secure_rag.config import Settings, get_settings


@dataclass
class AuditRecord:
    """Una riga dell'audit trail."""

    timestamp: str
    role: str
    query_hash: str
    query_length: int
    input_verdict: str
    input_rule: str
    scope: str = "corpus"
    context_sources: list[str] = field(default_factory=list)
    uploaded_sources: list[str] = field(default_factory=list)
    quarantined_sources: list[str] = field(default_factory=list)
    pii_masked_in_context: int = 0
    output_verdict: str = ""
    output_rule: str = ""
    latency_ms: int = 0
    provider: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


class AuditLogger:
    """Scrittore append-only dell'audit trail."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._path: Path = self._settings.audit_log_path

    @property
    def path(self) -> Path:
        return self._path

    def log(self, record: AuditRecord) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(record.to_json() + "\n")

    def tail(self, limit: int = 20) -> list[dict]:
        """Ultime righe del log, per ispezione da CLI o UI."""
        if not self._path.exists():
            return []
        lines = self._path.read_text(encoding="utf-8").strip().splitlines()
        return [json.loads(line) for line in lines[-limit:]]


def hash_query(query: str) -> str:
    """Hash stabile e non reversibile della domanda, per correlare senza conservare il testo."""
    return hashlib.sha256(query.strip().lower().encode("utf-8")).hexdigest()[:16]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
