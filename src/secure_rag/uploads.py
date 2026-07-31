"""Ingestion di documenti caricati dall'utente in sessione.

Un file caricato è **input non fidato per definizione**: è il vettore naturale della prompt
injection indiretta (un payload nascosto in un PDF di perizia, un commento HTML in un allegato).
Riceve quindi lo stesso trattamento del corpus aziendale, con due controlli in più:

1. **Limiti di ingresso** — dimensione massima e numero massimo di chunk, per evitare che un file
   enorme saturi il contesto e i costi (OWASP LLM04).
2. **Referto di sicurezza immediato** — l'utente vede subito quante PII sono state rimosse e se il
   documento contiene istruzioni rivolte all'assistente, invece di scoprirlo solo al momento della
   risposta.

I chunk sospetti vengono comunque indicizzati e marcati: il context guard li fermerà a runtime.
È una scelta di difesa in profondità coerente con ADR-005 — un documento manomesso è un incidente
da rendere visibile, non da far sparire in silenzio.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from datetime import datetime, timezone

from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter

from secure_rag.config import Settings, get_settings
from secure_rag.ingestion import CLEARANCE_LEVELS
from secure_rag.security.guardrails import scan_context
from secure_rag.security.pii import PIIMasker, build_masker

SUPPORTED_SUFFIXES = (".pdf", ".txt", ".md")
PREVIEW_CHARS = 600


@dataclass
class UploadReport:
    """Referto di sicurezza di un singolo file caricato."""

    file_name: str
    accepted: bool = False
    error: str = ""
    size_kb: float = 0.0
    chunks: int = 0
    pii_types: list[str] = field(default_factory=list)
    pii_count: int = 0
    suspicious_chunks: int = 0
    findings: list[str] = field(default_factory=list)
    preview_original: str = ""
    preview_masked: str = ""
    clearance: str = "agent"
    uploaded_at: str = ""
    # Livelli di anonimizzazione applicati a questo file: fa parte del referto quanto il conteggio.
    anonymization_levels: str = ""
    # Domande sensate su *questo* documento, per non lasciare l'utente davanti a un campo vuoto.
    suggested_questions: list[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return self.accepted and self.suspicious_chunks == 0

    @property
    def summary(self) -> str:
        if not self.accepted:
            return f"Rifiutato: {self.error}"
        parts = [f"{self.chunks} chunk", f"{self.pii_count} PII rimosse"]
        if self.suspicious_chunks:
            parts.append(f"{self.suspicious_chunks} chunk sospetti")
        return " · ".join(parts)


def extract_text(file_name: str, data: bytes) -> str:
    """Estrae il testo da un file caricato. Solleva ValueError sui formati non supportati."""
    lowered = file_name.lower()
    if lowered.endswith(".pdf"):
        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(data))
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    if lowered.endswith((".txt", ".md")):
        return data.decode("utf-8", errors="replace")
    raise ValueError(
        f"Formato non supportato: {file_name}. Ammessi: {', '.join(SUPPORTED_SUFFIXES)}."
    )


# Dal lessico presente nel documento alla domanda che ha senso porgli. L'ordine è quello in cui le
# domande vengono proposte: prima gli importi, che sono ciò che si cerca per primo in una polizza.
_DOMANDE_SUGGERITE: tuple[tuple[tuple[str, ...], str], ...] = (
    (("massimale",), "Qual è il massimale previsto?"),
    (("franchigia", "scoperto"), "A quanto ammonta la franchigia?"),
    (("esclus", "non sono coperti"), "Che cosa è escluso dalla copertura?"),
    (("denuncia", "denunciare"), "Entro quanto va denunciato un sinistro?"),
    (("indennizzo", "risarcimento", "liquidazione"), "Come viene calcolato l'indennizzo?"),
    (("retroattiv", "postuma", "ultrattiv"), "La copertura vale anche dopo la cessazione?"),
    (("premio",), "A quanto ammonta il premio?"),
    (("decorrenza", "scadenza", "durata"), "Qual è il periodo di validità?"),
)

MAX_DOMANDE_SUGGERITE = 3


def suggerisci_domande(testo: str) -> list[str]:
    """Domande sensate su questo documento, ricavate dal lessico che contiene.

    Deliberatamente **deterministiche**: generarle con il modello costerebbe una chiamata per ogni
    file caricato, prima ancora che l'utente abbia deciso di chiedere qualcosa, e su un'istanza
    pubblica con un tetto di spesa sarebbe la spesa peggiore possibile — pagata sempre, utile
    qualche volta.

    Lavorano sul testo **già anonimizzato**, che è l'unico che il resto del sistema conosce.
    """
    testo_normalizzato = testo.lower()
    trovate = [
        domanda
        for chiavi, domanda in _DOMANDE_SUGGERITE
        if any(chiave in testo_normalizzato for chiave in chiavi)
    ]
    # Un documento che non contiene nessuno di questi termini non è necessariamente una polizza:
    # meglio una domanda generica che nessuna, perché il campo vuoto non suggerisce cosa farne.
    return trovate[:MAX_DOMANDE_SUGGERITE] or ["Di che cosa tratta questo documento?"]


def process_upload(
    file_name: str,
    data: bytes,
    clearance: str = "agent",
    settings: Settings | None = None,
    masker: PIIMasker | None = None,
) -> tuple[list[Document], UploadReport]:
    """Anonimizza, segmenta e analizza un file caricato.

    Restituisce i chunk pronti per l'indicizzazione e il referto da mostrare all'utente. Non
    scrive nulla sul vector store: l'indicizzazione è un passo separato e volontario.
    """
    settings = settings or get_settings()
    masker = masker or build_masker(settings)
    report = UploadReport(
        file_name=file_name,
        size_kb=round(len(data) / 1024, 1),
        clearance=clearance if clearance in CLEARANCE_LEVELS else "agent",
        uploaded_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        anonymization_levels=masker.active_levels,
    )

    # --- Controlli di ingresso -------------------------------------------------
    if len(data) > settings.max_upload_mb * 1024 * 1024:
        report.error = (
            f"file di {report.size_kb / 1024:.1f} MB, oltre il limite di {settings.max_upload_mb} MB"
        )
        return [], report

    try:
        raw_text = extract_text(file_name, data)
    except ValueError as error:
        report.error = str(error)
        return [], report
    except Exception as error:  # PDF corrotto, encoding illeggibile…
        report.error = f"impossibile leggere il file ({type(error).__name__})"
        return [], report

    if not raw_text.strip():
        report.error = "nessun testo estraibile (PDF scansionato? servirebbe OCR)"
        return [], report

    # --- Anonimizzazione, prima di qualsiasi altra cosa -------------------------
    masking = masker.mask(raw_text)
    report.pii_count = masking.count
    report.pii_types = masking.entity_types
    report.preview_original = raw_text[:PREVIEW_CHARS]
    report.preview_masked = masking.masked_text[:PREVIEW_CHARS]
    report.suggested_questions = suggerisci_domande(masking.masked_text)

    # --- Segmentazione ---------------------------------------------------------
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=settings.chunk_size,
        chunk_overlap=settings.chunk_overlap,
        separators=["\n## ", "\n### ", "\n\n", "\n", ". ", " "],
    )
    texts = splitter.split_text(masking.masked_text)

    if len(texts) > settings.max_upload_chunks:
        report.error = (
            f"documento troppo esteso: {len(texts)} chunk, oltre il limite di "
            f"{settings.max_upload_chunks}"
        )
        return [], report

    # --- Scansione preventiva: il referto arriva prima della prima domanda ------
    candidates = [
        Document(page_content=text, metadata={"source": file_name}) for text in texts
    ]
    scan = scan_context(candidates)
    suspicious_texts = {
        document.page_content for document in candidates if document not in scan.documents
    }
    report.suspicious_chunks = len(suspicious_texts)
    report.findings = scan.findings

    documents = [
        Document(
            page_content=text,
            metadata={
                "source": file_name,
                "policy_id": "documento caricato in sessione",
                "title": file_name,
                "clearance": report.clearance,
                "chunk_index": index,
                "uploaded": True,
                "suspicious": text in suspicious_texts,
            },
        )
        for index, text in enumerate(texts)
    ]

    report.chunks = len(documents)
    report.accepted = True
    return documents, report
