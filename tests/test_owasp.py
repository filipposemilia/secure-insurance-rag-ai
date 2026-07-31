"""Test del catalogo OWASP.

Esistono per una ragione concreta: la stessa informazione viveva in tre posti — `docs/SECURITY.md`,
il `README.md` e il campo `owasp` degli scenari — e aveva già divergato senza che nessuno se ne
accorgesse. La tabella del modello di sicurezza aveva **dieci righe e nove codici**: `LLM01`
compariva due volte e `LLM05` non compariva mai.

Il primo test qui sotto è quello che l'avrebbe trovata in un millisecondo.
"""

from __future__ import annotations

from secure_rag.cli import SCENARIOS
from secure_rag.owasp import OWASP_RISKS, rischio


def test_il_catalogo_copre_tutti_e_dieci_i_rischi():
    """Regressione: `LLM05 — Supply Chain` mancava dalla documentazione, e si vedeva solo contando."""
    codici = [voce.codice for voce in OWASP_RISKS]

    assert codici == [f"LLM{numero:02d}" for numero in range(1, 11)]
    assert len(codici) == len(set(codici)), "codici duplicati nel catalogo"


def test_ogni_scenario_dichiarato_esiste_davvero():
    """Il catalogo referenzia gli scenari per nome: se uno viene rinominato, questo test lo dice.

    Senza, il collegamento si romperebbe in silenzio e la scheda mostrerebbe un rischio senza il
    pulsante che dichiara di avere.
    """
    nomi_reali = {scenario.name for scenario in SCENARIOS}

    for voce in OWASP_RISKS:
        for nome in voce.scenari:
            assert nome in nomi_reali, f"{voce.codice} referenzia uno scenario inesistente: {nome}"


def test_ogni_scenario_eseguibile_e_raggiungibile_o_dichiarato_a_parte():
    """Nessuno scenario deve sparire dall'interfaccia perché nessun rischio lo cita.

    Quelli non collegati sono legittimi — il termine di paragone non è un attacco — ma devono
    essere pochi e voluti, non il risultato di una dimenticanza.
    """
    collegati = {nome for voce in OWASP_RISKS for nome in voce.scenari}
    scollegati = [s.name for s in SCENARIOS if s.name not in collegati]

    assert scollegati == ["1. Query legittima"]


def test_i_rischi_non_applicabili_spiegano_perche():
    """Una scheda che dice «non applicabile» senza motivo vale meno di una scheda assente."""
    for voce in OWASP_RISKS:
        if not voce.applicabile:
            assert voce.sintesi.strip(), f"{voce.codice} non spiega perché non si applica"
            assert voce.nota.strip(), f"{voce.codice} non dice cosa lo renderebbe applicabile"
            assert not voce.scenari, f"{voce.codice} non è applicabile ma dichiara uno scenario"


def test_ogni_rischio_ha_una_sintesi():
    for voce in OWASP_RISKS:
        assert voce.sintesi.strip(), f"{voce.codice} senza sintesi"
        assert voce.titolo.strip(), f"{voce.codice} senza titolo"


def test_la_ricerca_per_codice_e_esplicita():
    """Restituire `None` per un codice sbagliato nasconderebbe l'errore fino all'interfaccia."""
    assert rischio("LLM06").titolo == "Sensitive Information Disclosure"

    try:
        rischio("LLM99")
    except KeyError:
        pass
    else:  # pragma: no cover - il test fallisce prima
        raise AssertionError("un codice inesistente deve sollevare KeyError")


def test_i_rischi_dimostrabili_sono_la_maggioranza_ma_non_tutti():
    """La griglia non deve né essere tutta verde né tutta grigia: entrambe sarebbero sospette."""
    eseguibili = [voce for voce in OWASP_RISKS if voce.eseguibile]
    non_applicabili = [voce for voce in OWASP_RISKS if not voce.applicabile]

    assert len(eseguibili) >= 5
    assert non_applicabili, "dichiarare cosa non si applica fa parte del modello di sicurezza"
    # LLM05 è mitigato ma non ha un attacco eseguibile: è il terzo stato, e deve restare distinto.
    assert any(voce.applicabile and not voce.eseguibile for voce in OWASP_RISKS)
