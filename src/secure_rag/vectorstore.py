"""Storage layer: ChromaDB persistente con filtro RBAC sul retrieval.

Il controllo degli accessi è applicato **nella query al vector store**, non a valle sulla risposta:
i chunk che l'utente non è autorizzato a vedere non entrano mai nel prompt. È la ragione principale
per cui in ambito assicurativo il RAG è preferibile al fine-tuning — con un modello addestrato sui
documenti riservati non esiste modo di "togliere" un contenuto a un utente non autorizzato.
"""

from __future__ import annotations

from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_core.vectorstores import VectorStoreRetriever

from secure_rag.config import Settings, get_settings
from secure_rag.ingestion import allowed_clearances
from secure_rag.providers import get_embeddings


def get_vectorstore(settings: Settings | None = None) -> Chroma:
    """Apre (o crea) la collection persistente su disco."""
    settings = settings or get_settings()
    settings.chroma_dir.mkdir(parents=True, exist_ok=True)
    return Chroma(
        collection_name=settings.collection_name,
        embedding_function=get_embeddings(settings),
        persist_directory=str(settings.chroma_dir),
    )


def reset_collection(settings: Settings | None = None) -> None:
    """Svuota la collection: l'ingestion è idempotente, non accumula duplicati."""
    settings = settings or get_settings()
    store = get_vectorstore(settings)
    try:
        store.delete_collection()
    except Exception:  # collection inesistente al primo avvio
        pass


def index_documents(documents: list[Document], settings: Settings | None = None) -> int:
    """Indicizza i chunk già anonimizzati. Restituisce il numero di chunk scritti."""
    settings = settings or get_settings()
    reset_collection(settings)
    store = get_vectorstore(settings)
    if documents:
        store.add_documents(documents)
    return len(documents)


def get_retriever(role: str, settings: Settings | None = None) -> VectorStoreRetriever:
    """Retriever filtrato sul livello di clearance del ruolo richiedente."""
    settings = settings or get_settings()
    store = get_vectorstore(settings)
    levels = allowed_clearances(role)
    return store.as_retriever(
        search_kwargs={
            "k": settings.retriever_k,
            "filter": {"clearance": {"$in": levels}},
        }
    )


def collection_size(settings: Settings | None = None) -> int:
    """Numero di chunk attualmente indicizzati."""
    settings = settings or get_settings()
    try:
        return get_vectorstore(settings)._collection.count()
    except Exception:
        return 0
