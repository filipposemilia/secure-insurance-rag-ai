"""Test del layer di anonimizzazione PII."""

from __future__ import annotations

from secure_rag.security.pii import PIIMasker, mask_pii_data

SAMPLE = (
    "Contraente: Ferrini Meccanica S.r.l.\n"
    "Codice Fiscale / P.IVA: 04812339071\n"
    "Referente: Marco Ferrini, nato il 15/05/1980, CF: FRRMRC80E15F205K\n"
    "Recapito: marco.ferrini@ferrinimeccanica.example, +39 348 1122334\n"
    "IBAN per addebito premi: IT60X0542811101000000123456\n"
    "Massimale: 250.000 EUR per evento."
)


def test_maschera_tutti_i_tipi_di_pii():
    result = PIIMasker().mask(SAMPLE)

    for sensitive in (
        "FRRMRC80E15F205K",
        "IT60X0542811101000000123456",
        "04812339071",
        "marco.ferrini@ferrinimeccanica.example",
        "348 1122334",
        "15/05/1980",
    ):
        assert sensitive not in result.masked_text, f"{sensitive} non è stato mascherato"

    assert {"CF", "IBAN", "PIVA", "EMAIL", "TELEFONO", "DATA_NASCITA"} <= set(result.entity_types)


def test_non_altera_i_dati_non_personali():
    """Gli importi contrattuali devono restare leggibili: sono il contenuto utile della polizza."""
    result = PIIMasker().mask(SAMPLE)
    assert "250.000 EUR per evento" in result.masked_text


def test_placeholder_stabili_tra_documenti():
    """Lo stesso IBAN deve ricevere lo stesso segnaposto in documenti diversi."""
    masker = PIIMasker()
    first = masker.mask("IBAN: IT60X0542811101000000123456")
    second = masker.mask("Rimborso su IT60X0542811101000000123456 come da polizza.")

    placeholder = first.entities[0].placeholder
    assert placeholder in second.masked_text
    assert placeholder == second.entities[0].placeholder


def test_unmask_ripristina_solo_lato_applicativo():
    masker = PIIMasker()
    result = masker.mask("CF: FRRMRC80E15F205K")
    assert masker.unmask(result.masked_text) == "CF: FRRMRC80E15F205K"


def test_detect_ignora_i_segnaposto():
    """L'output guard non deve scambiare un segnaposto per un dato reale."""
    masker = PIIMasker()
    assert masker.detect("Il riferimento è [CF_001] e [IBAN_001].") == []
    assert masker.detect("Il CF è FRRMRC80E15F205K") != []


def test_scorciatoia_senza_stato():
    assert "FRRMRC80E15F205K" not in mask_pii_data(SAMPLE)


# ------------------------------------- categorie dell'elenco GDPR del legale


SINISTRO_AUTO = (
    "Sinistro n. SIN-2026-118234, polizza RCA-2025-889201.\n"
    "Veicolo: targa AB123CD, telaio ZFA31200000123456.\n"
    "Conducente: patente AB1234567, residente in Via Giuseppe Garibaldi 42.\n"
    "Massimale RC: 5.000.000 EUR. Franchigia: 250 EUR."
)


def test_maschera_gli_identificativi_indiretti():
    """Numero di polizza, sinistro, targa e telaio riportano a una persona quanto il nome."""
    result = PIIMasker().mask(SINISTRO_AUTO)

    for sensibile in (
        "SIN-2026-118234",
        "RCA-2025-889201",
        "AB123CD",
        "ZFA31200000123456",
        "AB1234567",
    ):
        assert sensibile not in result.masked_text, f"{sensibile} non è stato mascherato"

    assert {"PRATICA", "TARGA", "TELAIO", "DOCUMENTO"} <= set(result.entity_types)


def test_maschera_l_indirizzo():
    result = PIIMasker().mask("Immobile assicurato in Via Giuseppe Garibaldi 42, Milano.")

    assert "Via Giuseppe Garibaldi 42" not in result.masked_text
    assert "INDIRIZZO" in result.entity_types


def test_i_dati_contrattuali_restano_intatti():
    """I falsi positivi qui costano più dei falsi negativi: corrompono il testo che l'LLM legge.

    Importi, massimali, franchigie e riferimenti di articolo servono al modello per rispondere e
    non identificano nessuno: devono attraversare il masking senza una modifica.
    """
    contrattuali = [
        "Franchigia Cyber: 2.500 EUR per sinistro.",
        "Rimborso fino a 100.000 EUR per attacco ransomware.",
        "ARTICOLO 14-bis — POSTUMA DECENNALE E ULTRATTIVITA",
        "Margine di trattativa fino al 12% del danno peritato.",
        "Massimale RC 5.000.000 EUR, premio annuo 600 EUR.",
        "Denuncia entro 72 ore dalla scoperta dell'evento.",
    ]

    for testo in contrattuali:
        assert PIIMasker().mask(testo).masked_text == testo, f"alterato: {testo}"


def test_il_vault_riprende_i_contatori_senza_collisioni():
    """Regressione: ripartire da zero sovrascriverebbe il significato dei segnaposto esistenti."""
    masker = PIIMasker()
    masker.load_vault({"[CF_001]": "AAABBB00A00A000A", "[CF_002]": "CCCDDD11B11B111B"})

    nuovo = masker.mask("CF: FRRMRC80E15F205K")

    assert "[CF_003]" in nuovo.masked_text
    assert masker.unmask("[CF_001]") == "AAABBB00A00A000A"


def test_il_vault_caricato_conserva_la_coerenza_dei_segnaposto():
    """Lo stesso valore deve ricevere lo stesso segnaposto anche in un processo diverso."""
    primo = PIIMasker()
    primo.mask("IBAN: IT60X0542811101000000123456")

    secondo = PIIMasker()
    secondo.load_vault(primo.vault)
    risultato = secondo.mask("Bonifico su IT60X0542811101000000123456")

    assert "[IBAN_001]" in risultato.masked_text
