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
from secure_rag.security.pii import PIIMasker, build_masker
from secure_rag.security.vault import VaultStore

# Livelli di clearance, dal più basso al più alto. Un utente vede il proprio livello e i sottostanti.
CLEARANCE_LEVELS: tuple[str, ...] = ("public", "agent", "management")

_FRONT_MATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)

# Nome del file che registra con quali livelli di anonimizzazione è stato costruito un indice.
# Vive nella directory dell'indice, quindi è per provider, come l'indice stesso.
_STAMP_NAME = ".anonymization"


@dataclass
class IngestionReport:
    """Riepilogo di un'operazione di ingestion, mostrato dalla CLI."""

    documents: int = 0
    chunks: int = 0
    masked_entities: int = 0
    entity_types: list[str] = None  # type: ignore[assignment]
    files: list[str] = None  # type: ignore[assignment]
    # Con quali livelli di anonimizzazione è stato costruito l'indice: la stessa frase produce
    # segnaposto diversi a livello 1 e a livello 1+2, quindi va registrato accanto al conteggio.
    anonymization_levels: str = ""

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
    masker = masker or build_masker(settings)

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
    report = IngestionReport(anonymization_levels=masker.active_levels)

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


def index_stamp_path(settings: Settings) -> Path:
    """File che registra i livelli di anonimizzazione usati per costruire l'indice."""
    return settings.chroma_dir / _STAMP_NAME


def write_index_stamp(settings: Settings, levels: str) -> None:
    """Registra accanto all'indice con quali livelli è stato costruito.

    Senza questa marca non esiste modo di sapere, guardando un indice, se i suoi segnaposto vengono
    dalle sole regex o anche dal NER. È l'informazione che permette di accorgersi che la
    configurazione è cambiata e che l'indice va rifatto.
    """
    percorso = index_stamp_path(settings)
    percorso.parent.mkdir(parents=True, exist_ok=True)
    percorso.write_text(f"{levels}\n", encoding="utf-8")


def read_index_stamp(settings: Settings) -> str:
    """Livelli con cui l'indice è stato costruito, o stringa vuota se non è registrato."""
    try:
        return index_stamp_path(settings).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def ingest_decision(settings: Settings | None = None) -> tuple[bool, str]:
    """Se l'indice va (ri)costruito, e perché. Usata dall'entrypoint del container.

    Il caso che rende necessaria questa funzione: l'indice sopravvive ai riavvii su un volume, e
    l'ingestion viene saltata quando è già popolato. Cambiando il livello di anonimizzazione, però,
    un indice già presente resta quello di **prima** — con i segnaposto del vecchio livello — mentre
    l'interfaccia dichiara il nuovo. Sarebbe un'incoerenza silenziosa fra ciò che il sistema afferma
    e ciò che il retrieval contiene, e questo progetto non ne ammette.

    Un indice senza marca è di provenienza ignota: viene rifatto. Costa un'indicizzazione una volta
    sola, e vale più della certezza che si sta cercando.
    """
    # Import locale: `vectorstore` importa questo modulo, quindi a livello di file sarebbe un ciclo.
    from secure_rag.vectorstore import collection_size

    settings = settings or get_settings()
    attivi = build_masker(settings).active_levels

    try:
        chunk = collection_size(settings)
    except Exception:
        return True, "indice non leggibile"

    if chunk == 0:
        return True, "indice assente"

    registrati = read_index_stamp(settings)
    if not registrati:
        return True, f"indice di provenienza ignota ({chunk} chunk, nessun livello registrato)"
    if registrati != attivi:
        return True, f"livelli cambiati: indice «{registrati}», configurazione «{attivi}»"

    return False, f"indice già presente e coerente ({chunk} chunk, livelli {registrati})"


def allowed_clearances(role: str) -> list[str]:
    """Livelli di clearance visibili a un ruolo, secondo il modello RBAC del PoC."""
    if role not in CLEARANCE_LEVELS:
        raise ValueError(
            f"Ruolo sconosciuto: {role!r}. Ruoli disponibili: {', '.join(CLEARANCE_LEVELS)}"
        )
    return list(CLEARANCE_LEVELS[: CLEARANCE_LEVELS.index(role) + 1])
