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

    def with_provider(self, provider: ProviderName) -> "Settings":
        """Copia delle impostazioni con un provider diverso (usata dalla scelta interattiva)."""
        return self.model_copy(update={"llm_provider": provider})


@lru_cache
def get_settings() -> Settings:
    """Istanza singleton delle impostazioni."""
    return Settings()
