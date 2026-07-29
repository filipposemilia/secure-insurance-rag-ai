"""Pipeline di ingestion: load → anonimizzazione → chunking → metadati.

Ordine dei passaggi (non modificabile senza rompere il modello di sicurezza):

    documento grezzo → **PII masking** → text splitting → embedding → vector store

Il masking avviene *prima* dello splitting perché deve vedere il documento intero: un codice
fiscale spezzato a metà tra due chunk non sarebbe più riconoscibile da nessuna regex.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter

from secure_rag.config import Settings, get_settings
from secure_rag.security.pii import PIIMasker
from secure_rag.security.vault import VaultStore

# Livelli di clearance, dal più basso al più alto. Un utente vede il proprio livello e i sottostanti.
CLEARANCE_LEVELS: tuple[str, ...] = ("public", "agent", "management")

_FRONT_MATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


@dataclass
class IngestionReport:
    """Riepilogo di un'operazione di ingestion, mostrato dalla CLI."""

    documents: int = 0
    chunks: int = 0
    masked_entities: int = 0
    entity_types: list[str] = None  # type: ignore[assignment]
    files: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.entity_types = self.entity_types or []
        self.files = self.files or []


def _parse_front_matter(text: str) -> tuple[dict[str, str], str]:
    """Estrae i metadati YAML minimali in testa al documento."""
    match = _FRONT_MATTER_RE.match(text)
    if not match:
        return {}, text
    metadata: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            metadata[key.strip()] = value.strip()
    return metadata, text[match.end() :]


def _read_file(path: Path) -> str:
    if path.suffix.lower() == ".pdf":
        from pypdf import PdfReader

        reader = PdfReader(str(path))
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    return path.read_text(encoding="utf-8")


def load_documents(settings: Settings | None = None) -> list[tuple[Path, dict[str, str], str]]:
    """Carica i documenti sorgente con i relativi metadati, senza ancora anonimizzarli."""
    settings = settings or get_settings()
    directory = settings.policies_dir
    if not directory.exists():
        raise FileNotFoundError(f"Cartella documenti non trovata: {directory}")

    loaded: list[tuple[Path, dict[str, str], str]] = []
    for path in sorted(directory.iterdir()):
        if path.suffix.lower() not in {".md", ".txt", ".pdf"}:
            continue
        metadata, body = _parse_front_matter(_read_file(path))
        loaded.append((path, metadata, body))
    return loaded


def build_documents(
    settings: Settings | None = None,
    masker: PIIMasker | None = None,
) -> tuple[list[Document], IngestionReport]:
    """Costruisce i chunk anonimizzati pronti per l'indicizzazione.

    Restituisce anche un report con il numero di entità PII rimosse: è il dato che dimostra, in
    demo, che nel vector store non è finito nulla di personale.
    """
    settings = settings or get_settings()
    masker = masker or PIIMasker()

    # Il vault di un'indicizzazione precedente viene ripreso, così lo stesso IBAN conserva il
    # medesimo segnaposto fra un ingest e l'altro. Senza chiave configurata è un'operazione nulla.
    store = VaultStore(settings.pii_vault_path, settings.pii_vault_key)
    masker.load_vault(store.load())

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=settings.chunk_size,
        chunk_overlap=settings.chunk_overlap,
        separators=["\n## ", "\n### ", "\n\n", "\n", ". ", " "],
    )

    documents: list[Document] = []
    report = IngestionReport()

    for path, metadata, body in load_documents(settings):
        result = masker.mask(body)
        report.documents += 1
        report.files.append(path.name)
        report.masked_entities += result.count
        for entity_type in result.entity_types:
            if entity_type not in report.entity_types:
                report.entity_types.append(entity_type)

        clearance = metadata.get("clearance", "public")
        if clearance not in CLEARANCE_LEVELS:
            clearance = "public"

        for index, chunk in enumerate(splitter.split_text(result.masked_text)):
            documents.append(
                Document(
                    page_content=chunk,
                    metadata={
                        "source": path.name,
                        "policy_id": metadata.get("policy_id", path.stem),
                        "title": metadata.get("title", path.stem),
                        "clearance": clearance,
                        "chunk_index": index,
                    },
                )
            )

    # La mappa viene salvata solo se esiste una chiave: è ciò che rende il masking reversibile
    # per chi è autorizzato, senza lasciare in giro un archivio in chiaro per tutti gli altri.
    store.save(masker.vault)

    report.chunks = len(documents)
    return documents, report


def allowed_clearances(role: str) -> list[str]:
    """Livelli di clearance visibili a un ruolo, secondo il modello RBAC del PoC."""
    if role not in CLEARANCE_LEVELS:
        raise ValueError(
            f"Ruolo sconosciuto: {role!r}. Ruoli disponibili: {', '.join(CLEARANCE_LEVELS)}"
        )
    return list(CLEARANCE_LEVELS[: CLEARANCE_LEVELS.index(role) + 1])
