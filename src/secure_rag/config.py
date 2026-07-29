"""Configurazione centralizzata, caricata da variabili d'ambiente e da `.env`.

Tenere i parametri qui (e non sparsi nel codice) è quello che permette di cambiare provider LLM,
modello o soglie di sicurezza senza toccare una riga di logica applicativa.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]

ProviderName = Literal["openai", "azure", "ollama", "fake"]


class Settings(BaseSettings):
    """Impostazioni dell'applicazione."""

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Provider LLM ---
    llm_provider: ProviderName = "fake"

    openai_api_key: str = ""
    openai_chat_model: str = "gpt-4o-mini"
    openai_embedding_model: str = "text-embedding-3-small"

    azure_openai_api_key: str = ""
    azure_openai_endpoint: str = ""
    azure_openai_api_version: str = "2024-10-21"
    azure_chat_deployment: str = "gpt-4o-mini"
    azure_embedding_deployment: str = "text-embedding-3-small"

    ollama_base_url: str = "http://localhost:11434"
    ollama_chat_model: str = "llama3.1"
    ollama_embedding_model: str = "nomic-embed-text"

    # --- Parametri RAG ---
    chunk_size: int = 800
    chunk_overlap: int = 120
    retriever_k: int = 4
    llm_temperature: float = 0.0

    # --- Percorsi ---
    policies_dir: Path = PROJECT_ROOT / "data" / "policies"
    chroma_base_dir: Path = PROJECT_ROOT / "chroma_db"
    audit_log_path: Path = PROJECT_ROOT / "logs" / "audit.jsonl"
    collection_name: str = "insurance_policies"

    @property
    def is_offline(self) -> bool:
        """True quando gira senza rete né API key (provider `fake`)."""
        return self.llm_provider == "fake"

    @property
    def embedding_model_name(self) -> str:
        """Modello di embedding effettivamente in uso, secondo il provider attivo."""
        return {
            "openai": self.openai_embedding_model,
            "azure": self.azure_embedding_deployment,
            "ollama": self.ollama_embedding_model,
            "fake": "deterministic-256",
        }[self.llm_provider]

    @property
    def chroma_dir(self) -> Path:
        """Directory dell'indice, separata per provider e modello di embedding.

        Modelli diversi producono vettori di dimensione diversa (256 per il provider `fake`, 1536
        per `text-embedding-3-small`): tenerli in indici distinti evita l'errore di dimensione
        quando si passa da un provider all'altro, e permette di conservare più indici in parallelo.
        """
        slug = f"{self.llm_provider}__{self.embedding_model_name}".replace("/", "-")
        return self.chroma_base_dir / slug

    @property
    def upload_collection_prefix(self) -> str:
        """Prefisso comune delle collection di upload, usato per riconoscerle e ripulirle."""
        return f"{self.collection_name}_uploads"

    @property
    def upload_collection_name(self) -> str:
        """Collection degli upload non isolata per sessione.

        Resta per l'uso locale a utente singolo. Su un'istanza raggiungibile da più persone va
        usata `upload_collection_for()`: qui un documento caricato sarebbe visibile a chiunque
        abbia la clearance sufficiente.
        """
        return self.upload_collection_prefix

    def upload_collection_for(self, session_id: str) -> str:
        """Collection degli upload riservata a una singola sessione.

        Tenere i file caricati fuori dalla collection principale evita che contaminino il corpus
        aziendale; separarli **anche per sessione** evita che il documento di un visitatore
        diventi leggibile dagli altri. Su un'istanza pubblica la sola clearance non basta: due
        visitatori diversi con lo stesso ruolo si vedrebbero i documenti a vicenda.
        """
        pulito = "".join(carattere for carattere in session_id if carattere.isalnum() or carattere == "-")
        return f"{self.upload_collection_prefix}_{pulito or 'anonimo'}"

    def with_provider(self, provider: ProviderName) -> "Settings":
        """Copia delle impostazioni con un provider diverso (usata dalla scelta interattiva)."""
        return self.model_copy(update={"llm_provider": provider})

    def with_collection(self, name: str) -> "Settings":
        """Copia delle impostazioni puntata a un'altra collection dello stesso indice."""
        return self.model_copy(update={"collection_name": name})

    # --- Limiti sui file caricati (mitigazione LLM04: Model Denial of Service) ---
    max_upload_mb: float = 5.0
    max_upload_chunks: int = 120

    # --- Istanza pubblica ---
    # Distingue la vetrina raggiungibile da chiunque dall'uso locale. In pubblico spariscono i
    # controlli da amministratore: cambio del provider e reindicizzazione, che costa embedding e
    # non è protetta dai limiti di frequenza (quelli valgono per le domande).
    public_mode: bool = False

    # --- Limiti di frequenza sull'istanza pubblica (mitigazione LLM04) ---
    # Servono quando la demo è esposta in rete con una API key a carico di chi la pubblica:
    # senza, chiunque può consumare token altrui. In locale restano disattivabili.
    rate_limit_enabled: bool = False
    rate_limit_per_ip_hour: int = 10
    rate_limit_global_day: int = 300


@lru_cache
def get_settings() -> Settings:
    """Istanza singleton delle impostazioni."""
    return Settings()
