"""Test del vault dei dati personali e del ripristino in uscita.

Il vault è ciò che distingue la **pseudonimizzazione** dall'anonimizzazione irreversibile: senza,
i segnaposto non sono più riconducibili ai valori originali da nessuno, nemmeno da chi è
autorizzato. Ma è a sua volta un archivio di dati personali, quindi il comportamento predefinito —
nessuna chiave, nessun file scritto — è quello che questi test controllano per primo.
"""

from __future__ import annotations

import pytest

from secure_rag.config import Settings
from secure_rag.ingestion import build_documents
from secure_rag.rag import SecureRAGPipeline, format_context
from secure_rag.security.pii import PIIMasker
from secure_rag.security.vault import CIFRATURA_DISPONIBILE, VaultStore, genera_chiave
from secure_rag.vectorstore import index_documents

from langchain_core.documents import Document

cifratura = pytest.mark.skipif(
    not CIFRATURA_DISPONIBILE, reason="richiede la dipendenza opzionale `cryptography`"
)


# ------------------------------------------------- comportamento predefinito


def test_senza_chiave_il_vault_non_scrive_nulla(tmp_path):
    """Il default è l'anonimizzazione irreversibile: nessun archivio di dati personali su disco."""
    percorso = tmp_path / "vault.enc"
    store = VaultStore(percorso, key="")

    assert not store.available
    assert store.save({"[CF_001]": "FRRMRC80E15F205K"}) is False
    assert not percorso.exists()
    assert store.load() == {}


def test_senza_chiave_il_ripristino_e_disattivato(tmp_path):
    settings = Settings(
        llm_provider="fake",
        chroma_base_dir=tmp_path / "chroma",
        audit_log_path=tmp_path / "audit.jsonl",
        pii_vault_path=tmp_path / "vault.enc",
        pii_vault_key="",
        unmask_roles="management",
    )
    documenti, _ = build_documents(settings)
    index_documents(documenti, settings)

    pipeline = SecureRAGPipeline(settings)

    assert pipeline._puo_ripristinare("management") is False


# ------------------------------------------------------- ciclo completo


@cifratura
def test_il_vault_sopravvive_al_processo(tmp_path):
    """Ingestion e interrogazione sono processi distinti: la mappa deve passare da uno all'altro."""
    percorso = tmp_path / "vault.enc"
    chiave = genera_chiave()

    scrittore = VaultStore(percorso, chiave)
    assert scrittore.save({"[NOME_001]": "Marco Ferrini", "[CF_001]": "FRRMRC80E15F205K"})

    # Istanza nuova, come sarebbe in un altro processo: nessuno stato condiviso in memoria.
    lettore = VaultStore(percorso, chiave)
    mappa = lettore.load()

    assert mappa["[NOME_001]"] == "Marco Ferrini"

    masker = PIIMasker()
    masker.load_vault(mappa)
    assert masker.unmask("Il contraente [NOME_001]") == "Il contraente Marco Ferrini"


@cifratura
def test_il_file_del_vault_non_e_leggibile_in_chiaro(tmp_path):
    percorso = tmp_path / "vault.enc"
    VaultStore(percorso, genera_chiave()).save({"[CF_001]": "FRRMRC80E15F205K"})

    contenuto = percorso.read_bytes()

    assert b"FRRMRC80E15F205K" not in contenuto
    # Leggibile solo dall'utente che esegue il processo.
    assert oct(percorso.stat().st_mode)[-3:] == "600"


@cifratura
def test_una_chiave_errata_non_interrompe_il_servizio(tmp_path):
    """Meglio degradare in modalità irreversibile che smettere di rispondere."""
    percorso = tmp_path / "vault.enc"
    VaultStore(percorso, genera_chiave()).save({"[CF_001]": "FRRMRC80E15F205K"})

    assert VaultStore(percorso, genera_chiave()).load() == {}


@cifratura
def test_solo_i_ruoli_autorizzati_ripristinano(tmp_path):
    settings = Settings(
        llm_provider="fake",
        chroma_base_dir=tmp_path / "chroma",
        audit_log_path=tmp_path / "audit.jsonl",
        pii_vault_path=tmp_path / "vault.enc",
        pii_vault_key=genera_chiave(),
        unmask_roles="management",
    )
    documenti, _ = build_documents(settings)
    index_documents(documenti, settings)

    pipeline = SecureRAGPipeline(settings)

    assert pipeline._puo_ripristinare("management") is True
    assert pipeline._puo_ripristinare("agent") is False
    assert pipeline._puo_ripristinare("public") is False


# --------------------------------------- identificativo fuori dal prompt


def test_il_numero_di_polizza_non_entra_nel_contesto():
    """Regressione: viveva nei metadati, che il masking dell'ingestion non attraversa."""
    documento = Document(
        page_content="La franchigia è di 2.500 EUR.",
        metadata={"source": "polizza.md", "policy_id": "MRI-2026-004417"},
    )

    contesto = format_context([documento], PIIMasker())

    assert "MRI-2026-004417" not in contesto
    assert "[PRATICA_001]" in contesto
    # Il nome del file resta: è un riferimento documentale, non un dato personale.
    assert "polizza.md" in contesto


def test_senza_masker_il_contesto_resta_invariato():
    """La firma con masker opzionale non deve cambiare il comportamento di chi non lo passa."""
    documento = Document(
        page_content="Testo.", metadata={"source": "x.md", "policy_id": "MRI-2026-004417"}
    )

    assert "MRI-2026-004417" in format_context([documento])
