"""Test del livello 2 dell'anonimizzazione: NER sui nomi in testo libero.

Nessun test qui installa Presidio né scarica un modello linguistico: il protocollo `NerEngine` è
stretto a due proprietà e un metodo **proprio** per rendere possibile un doppio di prova. I test
sull'integrazione — precedenza fra i livelli, offset, soglie, vault — sono quelli che possono
rompersi modificando il codice, e devono girare offline in un secondo.

Gli ultimi due test girano invece sul Presidio reale, e si saltano da sé quando non è disponibile.
"""

from __future__ import annotations

import logging

import pytest

from secure_rag.config import Settings
from secure_rag.security.ner import (
    NER_DISPONIBILE,
    NerSpan,
    _avvisa_libreria_assente,
    _load_analyzer,
    build_ner_engine,
    is_contract_term,
    modello_installato,
    ner_unavailable_reason,
)
from secure_rag.security.pii import PIIMasker, build_masker


class StubNer:
    """Motore finto: «riconosce» le stringhe che gli sono state dichiarate.

    Le posizioni vengono calcolate sul testo reale, così ogni test dichiara *cosa* il modello vede
    invece di offset scritti a mano, che sarebbero da ricalcolare a ogni modifica della frase.
    """

    model_name = "stub"
    available = True

    def __init__(self, attesi: list[tuple[str, str, float]]) -> None:
        self._attesi = attesi  # (testo, tipo di entità, punteggio di confidenza)

    def analyze(self, text: str, threshold: float) -> list[NerSpan]:
        trovati: list[NerSpan] = []
        for valore, tipo, score in self._attesi:
            if score < threshold:
                continue
            posizione = text.find(valore)
            while posizione != -1:
                trovati.append(NerSpan(posizione, posizione + len(valore), tipo, score))
                posizione = text.find(valore, posizione + len(valore))
        return sorted(trovati, key=lambda span: span.start)


FRASE = "Il testimone Andrea Gallo ha dichiarato di aver visto l'incidente."


# --------------------------------------------------------- la lacuna che colma


def test_maschera_un_nome_in_testo_libero():
    """È la lacuna dichiarata in docs/SECURITY.md: nessuna regex può vedere questo nome."""
    masker = PIIMasker(ner=StubNer([("Andrea Gallo", "NOME", 0.9)]))
    risultato = masker.mask(FRASE)

    assert "Andrea Gallo" not in risultato.masked_text
    assert "[NOME_001]" in risultato.masked_text
    assert "NOME" in risultato.entity_types
    assert masker.unmask(risultato.masked_text) == FRASE


def test_senza_motore_il_comportamento_e_quello_di_sempre():
    """La garanzia di regressione zero: con `ner=None` il livello 2 non esiste."""
    assert "Andrea Gallo" in PIIMasker().mask(FRASE).masked_text


# ------------------------------------------- precedenza fra i due livelli


def test_non_rimaschera_un_segnaposto_del_livello_1():
    """Uno span che cade su `[CF_001]` va scartato: il livello 1 ha già risposto lì."""
    masker = PIIMasker(ner=StubNer([("[CF_001]", "NOME", 0.99)]))
    risultato = masker.mask("Il CF è FRRMRC80E15F205K.")

    assert risultato.masked_text == "Il CF è [CF_001]."
    assert risultato.entity_types == ["CF"]


def test_il_livello_1_vince_sul_nome_che_ha_gia_riconosciuto():
    """Un nome introdotto da un ruolo contrattuale non viene mascherato due volte."""
    masker = PIIMasker(ner=StubNer([("Marco Ferrini", "NOME", 0.9)]))
    risultato = masker.mask("Referente: Marco Ferrini, CF FRRMRC80E15F205K, targa AB123CD.")

    assert risultato.masked_text.count("[NOME_") == 1
    assert "Marco Ferrini" not in risultato.masked_text
    assert {"NOME", "CF", "TARGA"} <= set(risultato.entity_types)


def test_fra_span_sovrapposti_vince_il_punteggio_piu_alto():
    stub = StubNer([("Gallo", "ORGANIZZAZIONE", 0.7), ("Andrea Gallo", "NOME", 0.95)])
    risultato = PIIMasker(ner=stub).mask("Presente Andrea Gallo alla perizia.")

    assert risultato.masked_text == "Presente [NOME_001] alla perizia."
    assert risultato.entity_types == ["NOME"]


# --------------------------------------------------- sostituzione e segnaposto


def test_tre_nomi_nella_stessa_frase_conservano_gli_offset():
    """Sostituire da sinistra invaliderebbe gli offset degli span successivi."""
    stub = StubNer(
        [
            ("Andrea Gallo", "NOME", 0.9),
            ("Chiara Neri", "NOME", 0.9),
            ("Luca Fanti", "NOME", 0.9),
        ]
    )
    risultato = PIIMasker(ner=stub).mask(
        "Presenti Andrea Gallo, Chiara Neri e Luca Fanti alla perizia."
    )

    assert risultato.masked_text == "Presenti [NOME_001], [NOME_002] e [NOME_003] alla perizia."
    # Le entità vanno registrate in ordine di lettura, non di sostituzione.
    assert [entita.original for entita in risultato.entities] == [
        "Andrea Gallo",
        "Chiara Neri",
        "Luca Fanti",
    ]


def test_lo_stesso_nome_riceve_sempre_lo_stesso_segnaposto():
    masker = PIIMasker(ner=StubNer([("Andrea Gallo", "NOME", 0.9)]))
    primo = masker.mask("Andrea Gallo ha firmato il verbale.")
    secondo = masker.mask("La perizia di Andrea Gallo è allegata.")

    assert "[NOME_001]" in primo.masked_text
    assert "[NOME_001]" in secondo.masked_text


def test_il_vault_conserva_la_coerenza_fra_processi_diversi():
    """Ingestion e interrogazione sono processi distinti anche per le entità del livello 2."""
    stub = StubNer([("Andrea Gallo", "NOME", 0.9)])
    primo = PIIMasker(ner=stub)
    primo.mask(FRASE)

    secondo = PIIMasker(ner=stub)
    secondo.load_vault(primo.vault)
    risultato = secondo.mask("Il perito ha confermato quanto detto da Andrea Gallo.")

    assert "[NOME_001]" in risultato.masked_text


def test_gli_spazi_ai_bordi_non_entrano_nel_segnaposto():
    """Includere lo spazio incollerebbe le parole vicine: il testo che l'LLM legge va integro."""
    stub = StubNer([(" Andrea Gallo ", "NOME", 0.9)])
    risultato = PIIMasker(ner=stub).mask("Il perito Andrea Gallo ha firmato.")

    assert risultato.masked_text == "Il perito [NOME_001] ha firmato."


# --------------------------------------------------- lessico contrattuale


def test_il_lessico_contrattuale_non_e_un_nome():
    """Regressione dal confronto sul corpus reale: il modello aveva prodotto `## [NOME_006] 1`."""
    assert is_contract_term("SEZIONE")
    assert is_contract_term("Assicurato")
    assert is_contract_term(" beneficiario ")
    assert not is_contract_term("Alessandro Nardi")
    assert not is_contract_term("Nardi")


def test_un_termine_contrattuale_non_viene_mascherato():
    """Il punteggio non può separarlo da un nome vero: spaCy assegna 0,85 a entrambi."""
    stub = StubNer([("SEZIONE", "NOME", 0.85), ("Assicurato", "NOME", 0.85)])
    testo = "## SEZIONE 1 — l'Assicurato ha diritto all'indennizzo."

    assert PIIMasker(ner=stub).mask(testo).masked_text == testo


def test_l_output_guard_non_sopprime_una_risposta_che_cita_una_clausola():
    """Senza il filtro, ogni risposta contenente «Assicurato» verrebbe bloccata."""
    stub = StubNer([("Assicurato", "NOME", 0.95)])
    masker = PIIMasker(ner=stub, ner_detect_threshold=0.85)

    assert masker.detect("L'Assicurato ha diritto all'indennizzo entro 30 giorni.") == []


# ------------------------------------------------------------------- soglie


def test_sotto_la_soglia_di_confidenza_non_maschera():
    masker = PIIMasker(ner=StubNer([("Andrea Gallo", "NOME", 0.4)]), ner_threshold=0.6)
    assert "Andrea Gallo" in masker.mask(FRASE).masked_text


def test_la_soglia_in_uscita_e_piu_severa_di_quella_in_ingresso():
    """Asimmetria voluta: in uscita un falso positivo sopprime una risposta già pagata in token."""
    stub = StubNer([("Andrea Gallo", "NOME", 0.7)])
    masker = PIIMasker(ner=stub, ner_threshold=0.6, ner_detect_threshold=0.85)

    assert "[NOME_001]" in masker.mask(FRASE).masked_text
    assert masker.detect("La perizia è di Andrea Gallo.") == []


def test_l_output_guard_vede_un_nome_sopra_la_soglia_severa():
    stub = StubNer([("Andrea Gallo", "NOME", 0.95)])
    masker = PIIMasker(ner=stub, ner_detect_threshold=0.85)

    trovati = masker.detect("Il perito incaricato è Andrea Gallo.")
    assert [entita.entity_type for entita in trovati] == ["NOME"]


# ----------------------------------------------- attivazione e fallback


def test_spento_per_default():
    """Il default è il livello 1: la demo offline deve restare installabile in un minuto."""
    assert Settings.model_fields["pii_ner_enabled"].default is False
    assert build_ner_engine(Settings(pii_ner_enabled=False)) is None

    masker = build_masker(Settings(pii_ner_enabled=False))
    assert not masker.ner_active
    assert masker.active_levels == "1 (regex)"


def test_fallback_alle_regex_quando_la_libreria_manca(monkeypatch):
    monkeypatch.setattr("secure_rag.security.ner.NER_DISPONIBILE", False)
    masker = build_masker(Settings(pii_ner_enabled=True))

    assert not masker.ner_active
    # Il livello 1 continua a lavorare: il fallback non è una rinuncia al masking.
    assert "FRRMRC80E15F205K" not in masker.mask("CF: FRRMRC80E15F205K").masked_text


def test_il_fallback_viene_dichiarato(monkeypatch, caplog):
    """Nessuna degradazione silenziosa: chi ha chiesto il livello 2 deve saperlo."""
    monkeypatch.setattr("secure_rag.security.ner.NER_DISPONIBILE", False)
    _avvisa_libreria_assente.cache_clear()

    with caplog.at_level(logging.WARNING, logger="secure_rag.security.ner"):
        build_masker(Settings(pii_ner_enabled=True))

    assert "presidio-analyzer is not installed" in caplog.text


def test_un_modello_assente_non_scatena_un_download(monkeypatch):
    """Regressione: Presidio, davanti a un modello mancante, prova a scaricarlo (~540 MB) e spaCy
    chiude il processo con `SystemExit`. Un livello opzionale non può fare né l'una né l'altra cosa.
    """
    chiamate: list[str] = []
    monkeypatch.setattr(
        "secure_rag.security.ner.NlpEngineProvider",
        lambda **_: chiamate.append("costruito"),  # type: ignore[arg-type,return-value]
    )
    _load_analyzer.cache_clear()

    engine = build_ner_engine(
        Settings(pii_ner_enabled=True, pii_ner_model="it_core_news_inesistente")
    )

    assert engine is None
    assert not modello_installato("it_core_news_inesistente")
    # Presidio non è stato nemmeno costruito: il controllo avviene prima.
    assert chiamate == []


def test_il_motivo_dell_indisponibilita_e_dichiarato(monkeypatch):
    """Un livello di sicurezza spento va dichiarato dove lo si cerca, non solo nei log."""
    assert ner_unavailable_reason(Settings(pii_ner_enabled=False)) == ""

    if NER_DISPONIBILE:
        # La libreria c'è ma il modello no: sono due cause distinte e vanno distinte anche a schermo.
        _load_analyzer.cache_clear()
        motivo = ner_unavailable_reason(
            Settings(pii_ner_enabled=True, pii_ner_model="it_core_news_inesistente")
        )
        assert "it_core_news_inesistente" in motivo
        assert "spacy download" in motivo

    monkeypatch.setattr("secure_rag.security.ner.NER_DISPONIBILE", False)
    assert "presidio-analyzer" in ner_unavailable_reason(Settings(pii_ner_enabled=True))


def test_il_livello_attivo_e_dichiarato_con_il_nome_del_modello():
    masker = PIIMasker(ner=StubNer([]))
    assert masker.active_levels == "1+2 (regex + NER stub)"
    assert masker.ner_active


# --------------------------------------------------------- Presidio reale


presidio_richiesto = pytest.mark.skipif(
    not NER_DISPONIBILE, reason="presidio-analyzer non installato"
)


@pytest.fixture(scope="module")
def masker_presidio() -> PIIMasker:
    engine = build_ner_engine(Settings(pii_ner_enabled=True))
    if engine is None:
        pytest.skip("modello linguistico italiano non scaricato")
    return PIIMasker(ner=engine)


@presidio_richiesto
def test_presidio_riconosce_un_nome_in_testo_libero(masker_presidio: PIIMasker):
    risultato = masker_presidio.mask(FRASE)

    assert "Andrea Gallo" not in risultato.masked_text
    assert "NOME" in risultato.entity_types


@presidio_richiesto
def test_presidio_non_altera_il_testo_contrattuale(masker_presidio: PIIMasker):
    """I falsi positivi qui costano più dei falsi negativi: corrompono ciò che l'LLM interpreta."""
    contrattuali = [
        "Franchigia Cyber: 2.500 EUR per sinistro.",
        "Massimale RC 5.000.000 EUR, premio annuo 600 EUR.",
        "Denuncia entro 72 ore dalla scoperta dell'evento.",
        # Le due righe che il confronto sul corpus reale ha visto corrompere.
        "## SEZIONE 1 — INCENDIO ED EVENTI ATMOSFERICI",
        "In caso di cessazione definitiva dell'attività professionale, l'Assicurato ha diritto a un"
        " periodo di copertura postuma.",
    ]

    for testo in contrattuali:
        assert masker_presidio.mask(testo).masked_text == testo, f"alterato: {testo}"


@presidio_richiesto
def test_presidio_vede_il_nome_che_le_regex_non_vedono(masker_presidio: PIIMasker):
    """Il caso reale del corpus: «Referente per la circolare:» non è fra i prefissi delle regex."""
    riga = "Referente per la circolare: Alessandro Nardi, Direzione Sinistri."

    assert "Alessandro Nardi" not in masker_presidio.mask(riga).masked_text
    assert "Alessandro Nardi" in PIIMasker().mask(riga).masked_text  # livello 1 da solo è cieco
