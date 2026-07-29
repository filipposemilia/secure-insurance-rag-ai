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


def add_documents(documents: list[Document], settings: Settings | None = None) -> int:
    """Aggiunge chunk senza azzerare la collection.

    Usato dai documenti caricati in sessione, che si accumulano su una collection separata invece
    di sostituire il corpus aziendale.
    """
    settings = settings or get_settings()
    if not documents:
        return 0
    get_vectorstore(settings).add_documents(documents)
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


def remove_source(source: str, settings: Settings | None = None) -> int:
    """Elimina tutti i chunk di un documento. Restituisce quanti ne sono stati rimossi.

    Serve a mantenere l'indice allineato a ciò che l'utente vede: un file tolto dall'elenco deve
    sparire anche dal retrieval. Senza, un documento caricato per errore — un CV, un contratto —
    resterebbe interrogabile pur non comparendo più da nessuna parte nell'interfaccia.
    """
    settings = settings or get_settings()
    try:
        collection = get_vectorstore(settings)._collection
        prima = collection.count()
        collection.delete(where={"source": source})
        return prima - collection.count()
    except Exception:
        return 0


def drop_collections_with_prefix(prefix: str, settings: Settings | None = None) -> list[str]:
    """Elimina tutte le collection il cui nome inizia con `prefix`.

    Le collection di upload sono per sessione, e una sessione web non ha una chiusura su cui
    agganciarsi in modo affidabile: si accumulerebbero. La pulizia avviene all'avvio del processo,
    quando per definizione nessuna sessione precedente è più valida.
    """
    settings = settings or get_settings()
    rimosse: list[str] = []
    try:
        client = get_vectorstore(settings)._client
        for collection in client.list_collections():
            nome = collection if isinstance(collection, str) else collection.name
            if nome.startswith(prefix):
                client.delete_collection(nome)
                rimosse.append(nome)
    except Exception:
        return rimosse
    return rimosse
