"""Test dei percorsi in un'installazione non sorgente (container).

`Settings` deriva i percorsi predefiniti da `PROJECT_ROOT`, che risale di due livelli dal modulo:
corretto quando il codice sta in `src/secure_rag/`, **sbagliato** quando il pacchetto è installato e
vive in `site-packages` — lì la root calcolata sarebbe la directory di Python, non quella del
progetto.

Nell'immagine Docker il pacchetto è installato, ed è per questo che il Dockerfile dichiara
esplicitamente `POLICIES_DIR`, `CHROMA_BASE_DIR` e `AUDIT_LOG_PATH`. Questi test verificano che quel
meccanismo funzioni: se qualcuno rendesse i percorsi non più configurabili dall'ambiente, il
container tornerebbe a cercare i documenti nel posto sbagliato e ripartirebbe in ciclo.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from secure_rag.config import Settings
from secure_rag.ingestion import (
    index_stamp_path,
    ingest_decision,
    read_index_stamp,
    write_index_stamp,
)


@dataclass
class _MaskerFinto:
    """Sostituisce il mascheratore per dichiarare un livello senza caricare un modello NER."""

    active_levels: str


def test_i_percorsi_sono_sovrascrivibili_dall_ambiente(monkeypatch, tmp_path):
    """Regressione: nel container i default derivati dal modulo puntano fuori dal progetto."""
    documenti = tmp_path / "app" / "data" / "policies"
    indice = tmp_path / "app" / "chroma_db"
    audit = tmp_path / "app" / "logs" / "audit.jsonl"

    monkeypatch.setenv("POLICIES_DIR", str(documenti))
    monkeypatch.setenv("CHROMA_BASE_DIR", str(indice))
    monkeypatch.setenv("AUDIT_LOG_PATH", str(audit))

    settings = Settings()

    assert settings.policies_dir == documenti
    assert settings.chroma_base_dir == indice
    assert settings.audit_log_path == audit


def test_l_indice_resta_separato_per_provider_anche_con_percorsi_esterni(monkeypatch, tmp_path):
    """La separazione per modello di embedding non deve perdersi cambiando la radice."""
    monkeypatch.setenv("CHROMA_BASE_DIR", str(tmp_path / "indici"))

    offline = Settings(llm_provider="fake")
    in_rete = Settings(llm_provider="openai")

    assert offline.chroma_dir != in_rete.chroma_dir
    assert offline.chroma_dir.parent == tmp_path / "indici"


def test_i_percorsi_sono_assoluti_quando_dichiarati(monkeypatch):
    """Un percorso relativo dipenderebbe dalla working directory del processo."""
    monkeypatch.setenv("POLICIES_DIR", "/app/data/policies")

    settings = Settings()

    assert settings.policies_dir == Path("/app/data/policies")
    assert settings.policies_dir.is_absolute()


# --------------------------------------------------------------------------
# Coerenza fra indice e livello di anonimizzazione
#
# Nel container l'indice vive su un volume e sopravvive ai riavvii: l'ingestion viene saltata quando
# è già popolato. Cambiando il livello di anonimizzazione, un indice già presente resterebbe quello
# di prima — con i segnaposto del vecchio livello — mentre l'interfaccia dichiara il nuovo.
# --------------------------------------------------------------------------


def test_la_marca_registra_i_livelli_dell_indice(monkeypatch, tmp_path):
    monkeypatch.setenv("CHROMA_BASE_DIR", str(tmp_path / "indici"))
    settings = Settings(llm_provider="fake")

    assert read_index_stamp(settings) == ""  # indice mai costruito

    write_index_stamp(settings, "1+2 (regex + NER it_core_news_lg)")

    assert read_index_stamp(settings) == "1+2 (regex + NER it_core_news_lg)"
    assert index_stamp_path(settings).parent == settings.chroma_dir


def test_un_indice_assente_va_costruito(monkeypatch, tmp_path):
    monkeypatch.setenv("CHROMA_BASE_DIR", str(tmp_path / "indici"))

    serve, motivo = ingest_decision(Settings(llm_provider="fake"))

    assert serve
    assert "assente" in motivo


def test_un_indice_coerente_non_viene_rifatto(monkeypatch, tmp_path):
    """Rifare un indice già valido ripaga gli embedding a ogni riavvio del container."""
    monkeypatch.setenv("CHROMA_BASE_DIR", str(tmp_path / "indici"))
    settings = Settings(llm_provider="fake")
    monkeypatch.setattr("secure_rag.vectorstore.collection_size", lambda _s: 14)
    # Livello dichiarato a mano: il test non deve dipendere dal `.env` della macchina che lo esegue.
    monkeypatch.setattr(
        "secure_rag.ingestion.build_masker", lambda *_a, **_k: _MaskerFinto("1 (regex)")
    )
    write_index_stamp(settings, "1 (regex)")

    serve, motivo = ingest_decision(settings)

    assert not serve
    assert "coerente" in motivo


def test_livelli_cambiati_impongono_un_nuovo_ingest(monkeypatch, tmp_path):
    """È il caso del passaggio a Presidio in produzione: il volume ha già un indice a livello 1."""
    monkeypatch.setenv("CHROMA_BASE_DIR", str(tmp_path / "indici"))
    settings = Settings(llm_provider="fake")
    monkeypatch.setattr("secure_rag.vectorstore.collection_size", lambda _s: 14)
    write_index_stamp(settings, "1 (regex)")
    # Va sostituito il riferimento importato in `ingestion`, non quello di origine: il modulo lo ha
    # già risolto al proprio import.
    monkeypatch.setattr(
        "secure_rag.ingestion.build_masker",
        lambda *_a, **_k: _MaskerFinto("1+2 (regex + NER it_core_news_lg)"),
    )

    serve, motivo = ingest_decision(settings)

    assert serve
    assert "livelli cambiati" in motivo


def test_un_indice_di_provenienza_ignota_va_rifatto(monkeypatch, tmp_path):
    """Indici costruiti prima che la marca esistesse: non si può affermare con cosa sono stati fatti."""
    monkeypatch.setenv("CHROMA_BASE_DIR", str(tmp_path / "indici"))
    monkeypatch.setattr("secure_rag.vectorstore.collection_size", lambda _s: 14)

    serve, motivo = ingest_decision(Settings(llm_provider="fake"))

    assert serve
    assert "ignota" in motivo
