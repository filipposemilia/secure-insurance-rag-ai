"""Factory dei provider LLM ed embeddings.

L'applicazione non istanzia mai direttamente `ChatOpenAI`: passa da qui. È il punto in cui, in un
contesto assicurativo reale, si sostituisce OpenAI pubblico con **Azure OpenAI** (dove i dati non
vengono usati per addestrare i modelli, requisito tipico di compliance GDPR) o con un modello
**Ollama on-premise**, senza toccare la pipeline RAG.

Il provider `fake` è deterministico e non richiede rete: serve ai test e permette di eseguire la
demo anche senza API key.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import urllib.request
from dataclasses import dataclass
from typing import Any, Sequence
from urllib.error import URLError

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.embeddings import Embeddings
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from secure_rag.config import ProviderName, Settings, get_settings

# ---------------------------------------------------------------------------
# Provider deterministico per test e demo offline
# ---------------------------------------------------------------------------

_EMBEDDING_DIM = 256
_TOKEN_RE = re.compile(r"\w+", re.UNICODE)


def _tokenize(text: str) -> list[str]:
    return [token.lower() for token in _TOKEN_RE.findall(text)]


class DeterministicEmbeddings(Embeddings):
    """Embedding hash-based: nessuna rete, stesso input → stesso vettore.

    Non ha qualità semantica paragonabile a un modello reale (è di fatto una bag-of-words
    proiettata su uno spazio a dimensione fissa), ma è sufficiente perché il retrieval trovi i
    chunk giusti nei documenti di test, ed è totalmente riproducibile.
    """

    def _embed(self, text: str) -> list[float]:
        vector = [0.0] * _EMBEDDING_DIM
        for token in _tokenize(text):
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            index = int.from_bytes(digest[:4], "big") % _EMBEDDING_DIM
            sign = 1.0 if digest[4] % 2 == 0 else -1.0
            vector[index] += sign
        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0:
            return vector
        return [value / norm for value in vector]

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._embed(text) for text in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._embed(text)


class DeterministicChatModel(BaseChatModel):
    """Modello finto che risponde estraendo dal contesto le frasi più pertinenti.

    Simula il comportamento atteso da un LLM ben istruito: risponde solo con quello che trova nel
    contesto e dichiara l'assenza dell'informazione quando il contesto non la contiene. Questo
    permette di verificare la **pipeline** (retrieval, guardrails, citazioni) in modo deterministico,
    separandola dalla variabilità del modello.
    """

    max_sentences: int = 3

    @property
    def _llm_type(self) -> str:
        return "deterministic-fake"

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        prompt = "\n".join(str(message.content) for message in messages)
        context = _extract_between(prompt, "<<<CONTESTO>>>", "<<<FINE_CONTESTO>>>")
        question = _extract_after(prompt, "DOMANDA UTENTE:")
        answer = self._answer(context, question)
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=answer))])

    def _answer(self, context: str, question: str) -> str:
        if not context.strip():
            return "Informazione non presente nella documentazione della polizza."

        question_tokens = {token for token in _tokenize(question) if len(token) > 3}

        # Il contesto arriva come blocchi separati, ciascuno introdotto dalla propria fonte:
        # tenerli distinti permette di citare la fonte giusta per ogni estratto.
        candidates: list[tuple[int, int, str, str]] = []  # (score, posizione, frase, fonte)
        position = 0
        for block in context.split("\n\n---\n\n"):
            source_match = re.search(r"\[fonte: ([^\]]+)\]", block)
            source = source_match.group(1) if source_match else "documento sconosciuto"
            body = re.sub(r"\[fonte: [^\]]+\]", "", block)
            for sentence in re.split(r"(?<=[.;])\s+|\n", body):
                sentence = sentence.strip()
                if len(sentence) <= 30:
                    continue
                score = len(question_tokens & set(_tokenize(sentence)))
                candidates.append((score, position, sentence, source))
                position += 1

        # Selezione per pertinenza, presentazione nell'ordine originale: gli estratti restano
        # leggibili invece di apparire rimescolati.
        ranked = sorted(candidates, key=lambda item: (-item[0], item[1]))
        best = [item for item in ranked[: self.max_sentences] if item[0] > 0]

        if not best:
            return "Informazione non presente nella documentazione della polizza."

        best.sort(key=lambda item: item[1])
        body_lines = "\n".join(f"- {sentence}" for _, _, sentence, _ in best)
        used_sources = sorted({source for _, _, _, source in best})
        citation = "\n\nFonti: " + "; ".join(used_sources)
        return f"Dalla documentazione risulta quanto segue:\n{body_lines}{citation}"


def _extract_between(text: str, start: str, end: str) -> str:
    """Estrae il blocco di contesto reale.

    Usa `rsplit` sul marcatore di apertura perché i delimitatori compaiono due volte nel prompt:
    una prima volta citati nel testo delle regole operative, e poi come delimitatori veri. Il
    blocco che conta è sempre l'ultimo.
    """
    if start not in text or end not in text:
        return ""
    return text.rsplit(start, 1)[1].split(end, 1)[0]


def _extract_after(text: str, marker: str) -> str:
    if marker not in text:
        return text
    return text.split(marker, 1)[1]


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def get_chat_model(settings: Settings | None = None) -> BaseChatModel:
    """Restituisce il modello conversazionale configurato in `.env`.

    `temperature=0` è una scelta obbligata in ambito assicurativo: le risposte devono essere
    deterministiche e riproducibili, non creative.
    """
    settings = settings or get_settings()
    provider = settings.llm_provider

    if provider == "fake":
        return DeterministicChatModel()

    if provider == "openai":
        from langchain_openai import ChatOpenAI

        _require(settings.openai_api_key, "OPENAI_API_KEY")
        return ChatOpenAI(
            model=settings.openai_chat_model,
            temperature=settings.llm_temperature,
            api_key=settings.openai_api_key,
        )

    if provider == "azure":
        from langchain_openai import AzureChatOpenAI

        _require(settings.azure_openai_api_key, "AZURE_OPENAI_API_KEY")
        _require(settings.azure_openai_endpoint, "AZURE_OPENAI_ENDPOINT")
        return AzureChatOpenAI(
            azure_deployment=settings.azure_chat_deployment,
            azure_endpoint=settings.azure_openai_endpoint,
            api_key=settings.azure_openai_api_key,
            api_version=settings.azure_openai_api_version,
            temperature=settings.llm_temperature,
        )

    if provider == "ollama":
        from langchain_ollama import ChatOllama

        return ChatOllama(
            model=settings.ollama_chat_model,
            base_url=settings.ollama_base_url,
            temperature=settings.llm_temperature,
        )

    raise ValueError(f"Provider LLM non supportato: {provider!r}")


def get_embeddings(settings: Settings | None = None) -> Embeddings:
    """Restituisce il modello di embedding configurato in `.env`."""
    settings = settings or get_settings()
    provider = settings.llm_provider

    if provider == "fake":
        return DeterministicEmbeddings()

    if provider == "openai":
        from langchain_openai import OpenAIEmbeddings

        _require(settings.openai_api_key, "OPENAI_API_KEY")
        return OpenAIEmbeddings(
            model=settings.openai_embedding_model,
            api_key=settings.openai_api_key,
        )

    if provider == "azure":
        from langchain_openai import AzureOpenAIEmbeddings

        _require(settings.azure_openai_api_key, "AZURE_OPENAI_API_KEY")
        return AzureOpenAIEmbeddings(
            azure_deployment=settings.azure_embedding_deployment,
            azure_endpoint=settings.azure_openai_endpoint,
            api_key=settings.azure_openai_api_key,
            api_version=settings.azure_openai_api_version,
        )

    if provider == "ollama":
        from langchain_ollama import OllamaEmbeddings

        return OllamaEmbeddings(
            model=settings.ollama_embedding_model,
            base_url=settings.ollama_base_url,
        )

    raise ValueError(f"Provider embeddings non supportato: {provider!r}")


# ---------------------------------------------------------------------------
# Rilevamento della disponibilità (usato dalla scelta interattiva all'avvio)
# ---------------------------------------------------------------------------


@dataclass
class ProviderStatus:
    """Disponibilità di un provider sulla macchina corrente."""

    name: ProviderName
    label: str
    detail: str
    available: bool
    hint: str = ""


def probe_ollama(settings: Settings | None = None, timeout: float = 1.5) -> tuple[bool, list[str]]:
    """Verifica se il servizio Ollama risponde e quali modelli ha scaricato.

    Usa solo la libreria standard: il rilevamento non deve dipendere da un pacchetto opzionale.
    """
    settings = settings or get_settings()
    url = settings.ollama_base_url.rstrip("/") + "/api/tags"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310
            payload = json.loads(response.read().decode("utf-8"))
    except (URLError, TimeoutError, OSError, json.JSONDecodeError):
        return False, []
    models = [str(model.get("name", "")) for model in payload.get("models", [])]
    return True, models


def probe_providers(settings: Settings | None = None) -> list[ProviderStatus]:
    """Elenco dei provider con la loro disponibilità effettiva, in ordine di presentazione."""
    settings = settings or get_settings()
    statuses: list[ProviderStatus] = []

    # --- OpenAI ---
    has_key = bool(settings.openai_api_key)
    statuses.append(
        ProviderStatus(
            name="openai",
            label="OpenAI (in rete)",
            detail=f"{settings.openai_chat_model} · embeddings {settings.openai_embedding_model}",
            available=has_key,
            hint="" if has_key else "imposta OPENAI_API_KEY in .env",
        )
    )

    # --- Ollama locale ---
    running, models = probe_ollama(settings)
    chat_ready = any(model.startswith(settings.ollama_chat_model) for model in models)
    embed_ready = any(model.startswith(settings.ollama_embedding_model) for model in models)
    if not running:
        hint = (
            "servizio non raggiungibile su "
            f"{settings.ollama_base_url} — installa Ollama da ollama.com, poi: "
            f"ollama pull {settings.ollama_chat_model} && ollama pull {settings.ollama_embedding_model}"
        )
    elif not (chat_ready and embed_ready):
        mancanti = [
            model
            for model, ready in (
                (settings.ollama_chat_model, chat_ready),
                (settings.ollama_embedding_model, embed_ready),
            )
            if not ready
        ]
        hint = "modelli mancanti — esegui: " + " && ".join(f"ollama pull {m}" for m in mancanti)
    else:
        hint = ""
    statuses.append(
        ProviderStatus(
            name="ollama",
            label="Ollama (locale, on-premise)",
            detail=f"{settings.ollama_chat_model} · embeddings {settings.ollama_embedding_model}",
            available=running and chat_ready and embed_ready,
            hint=hint,
        )
    )

    # --- Azure: mostrato solo se configurato, è il percorso enterprise ---
    if settings.azure_openai_endpoint and settings.azure_openai_api_key:
        statuses.append(
            ProviderStatus(
                name="azure",
                label="Azure OpenAI (enterprise)",
                detail=f"deployment {settings.azure_chat_deployment}",
                available=True,
            )
        )

    # --- Fake: sempre disponibile ---
    statuses.append(
        ProviderStatus(
            name="fake",
            label="Offline deterministico",
            detail="nessuna rete, nessun token consumato — usato dai test",
            available=True,
        )
    )

    return statuses


def _require(value: str, name: str) -> None:
    if not value:
        raise RuntimeError(
            f"{name} non configurata. Impostala in .env oppure usa LLM_PROVIDER=fake "
            "per eseguire la demo offline."
        )


def describe_provider(settings: Settings | None = None) -> str:
    """Descrizione leggibile del provider attivo, mostrata nella CLI e nella UI."""
    settings = settings or get_settings()
    mapping = {
        "fake": "deterministico offline (nessuna chiamata di rete)",
        "openai": f"OpenAI · {settings.openai_chat_model}",
        "azure": f"Azure OpenAI · {settings.azure_chat_deployment}",
        "ollama": f"Ollama on-premise · {settings.ollama_chat_model}",
    }
    return mapping.get(settings.llm_provider, settings.llm_provider)


__all__: Sequence[str] = (
    "DeterministicChatModel",
    "DeterministicEmbeddings",
    "ProviderStatus",
    "describe_provider",
    "get_chat_model",
    "get_embeddings",
    "probe_ollama",
    "probe_providers",
)
