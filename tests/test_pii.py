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
