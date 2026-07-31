"""Test dell'interfaccia Streamlit con `streamlit.testing.v1.AppTest`.

Girano offline con il provider `fake`, su un indice temporaneo costruito dalla fixture.

Coprono in particolare il comportamento dei **pulsanti degli scenari**, che è la parte della UI
mostrata dal vivo: uno scenario deve produrre il suo esito subito e con il ruolo che gli è proprio,
non con quello selezionato in barra laterale. Senza questi test i due difetti che coprono erano
passati inosservati, perché la UI non è esercitata dagli altri test.
"""

from __future__ import annotations

import os

import pytest
from streamlit.testing.v1 import AppTest

from secure_rag.config import get_settings
from secure_rag.ingestion import build_documents
from secure_rag.owasp import OWASP_RISKS
from secure_rag.vectorstore import index_documents

APP_PATH = "app/streamlit_app.py"


@pytest.fixture(scope="module")
def indexed_app(tmp_path_factory):
    """Indice temporaneo e variabili d'ambiente puntate su di esso, per la durata del modulo."""
    tmp = tmp_path_factory.mktemp("ui")
    previous = {
        key: os.environ.get(key)
        for key in ("LLM_PROVIDER", "CHROMA_BASE_DIR", "AUDIT_LOG_PATH")
    }
    os.environ["LLM_PROVIDER"] = "fake"
    os.environ["CHROMA_BASE_DIR"] = str(tmp / "chroma")
    os.environ["AUDIT_LOG_PATH"] = str(tmp / "audit.jsonl")

    get_settings.cache_clear()
    settings = get_settings()
    documents, _ = build_documents(settings)
    index_documents(documents, settings)

    yield settings

    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    get_settings.cache_clear()


def run_app() -> AppTest:
    app = AppTest.from_file(APP_PATH, default_timeout=120)
    app.run()
    return app



def esegui_scenario(app: AppTest, nome: str) -> AppTest:
    """Preme «Esegui» dello scenario indicato, cercandolo per nome.

    Le chiavi dei pulsanti contengono il codice OWASP e il nome dello scenario: selezionarli per
    nome invece che per posizione tiene i test leggibili e li rende insensibili all'ordine con cui
    i rischi compaiono nella scheda.
    """
    codice = next(
        (r.codice for r in OWASP_RISKS if nome in r.scenari),
        "base",  # il termine di paragone non appartiene ad alcun rischio
    )
    return app.button(key=f"esegui_{codice}_{nome}").click().run()


def test_l_app_si_avvia_senza_eccezioni(indexed_app):
    app = run_app()

    assert not app.exception
    assert len(app.tabs) == 3


def test_la_scheda_sicurezza_dichiara_i_livelli_di_anonimizzazione(indexed_app):
    """Un anonimizzatore che non dice con quale motore ha lavorato non è verificabile.

    Nei test il livello 2 è spento, quindi ciò che deve comparire è la dichiarazione del livello 1 —
    non l'assenza di qualunque dichiarazione.
    """
    app = run_app()

    testi = [markdown.value for markdown in app.markdown]
    assert any("Livelli attivi su questa istanza" in testo for testo in testi)
    assert any("1 (regex)" in testo for testo in testi)


def test_la_risposta_mostra_l_estratto_su_cui_si_basa(indexed_app):
    """La citazione deve essere verificabile, non dichiarata: un nome di file si inventa,
    l'estratto che il modello ha letto no.
    """
    app = run_app()
    pronte = [b for b in app.button if b.label == "Franchigia cyber"]
    assert pronte, "la domanda di esempio deve essere presente a conversazione vuota"
    pronte[0].click().run()

    assert not app.exception
    testi = [markdown.value for markdown in app.markdown]
    assert any("Su cosa si basa questa risposta" in testo for testo in testi)
    # L'estratto mostrato è quello anonimizzato, cioè quello davvero inviato al modello.
    assert any(testo.startswith(">") for testo in testi)


def test_lo_scenario_produce_l_esito_al_primo_click(indexed_app):
    """Regressione: il click rimandava la domanda al rerun successivo, che non arrivava mai.

    Cambiare scheda in Streamlit non provoca un rerun: chi cliccava «Esegui» e apriva la Chat la
    trovava vuota.
    """
    app = run_app()
    esegui_scenario(app, "1. Query legittima")

    assert not app.exception
    assert "scenario_result" in app.session_state
    assert app.session_state["scenario_result"]["response"].answer


def test_lo_scenario_usa_il_proprio_ruolo_non_quello_della_sidebar(indexed_app):
    """Regressione: gli scenari giravano con il ruolo della barra laterale.

    Il confronto fra lo scenario 5 (`agent`) e il 6 (`management`) — la dimostrazione dell'RBAC —
    dava lo stesso risultato in entrambi i casi.
    """
    app = run_app()
    assert app.selectbox[0].value == "agent", "il ruolo di partenza in sidebar è «agent»"

    esegui_scenario(app, "6. Stessa domanda con ruolo autorizzato")
    esito = app.session_state["scenario_result"]["response"]

    assert esito.role == "management"


def test_rbac_visibile_dal_confronto_fra_gli_scenari_5_e_6(indexed_app):
    """La stessa domanda, due clearance: la circolare riservata compare solo alla direzione."""
    app = run_app()

    esegui_scenario(app, "5. Violazione RBAC (documento riservato alla direzione)")  # scenario 5 — ruolo agent
    agente = app.session_state["scenario_result"]["response"]

    esegui_scenario(app, "6. Stessa domanda con ruolo autorizzato")  # scenario 6 — ruolo management
    direzione = app.session_state["scenario_result"]["response"]

    assert agente.role == "agent"
    assert direzione.role == "management"
    assert "circolare_interna_liquidazioni.md" not in agente.sources
    assert "circolare_interna_liquidazioni.md" in direzione.sources



def test_il_selettore_di_profilo_sovrascrive_il_ruolo_dello_scenario(indexed_app):
    """L'altra faccia di ADR-012: il ruolo proprio è il default, non una gabbia.

    Lo scenario 5 è pensato per l'agente e mostra un accesso negato. Cambiando profilo in
    «Direzione Sinistri» la stessa domanda deve recuperare la circolare riservata: è la prova che il
    selettore agisce sul retrieval e non sulla presentazione.
    """
    nome = "5. Violazione RBAC (documento riservato alla direzione)"
    app = run_app()

    app.selectbox(key=f"ruolo_LLM06_{nome}").select("management").run()
    esegui_scenario(app, nome)

    esito = app.session_state["scenario_result"]["response"]
    assert esito.role == "management"
    assert "circolare_interna_liquidazioni.md" in esito.sources


def test_la_scheda_sicurezza_elenca_tutti_e_dieci_i_rischi(indexed_app):
    """Chi prova la demo non apre docs/SECURITY.md: la copertura va vista dove si guarda."""
    app = run_app()

    testi = " ".join(m.value for m in app.markdown) + " ".join(c.value for c in app.caption)
    for numero in range(1, 11):
        assert f"LLM{numero:02d}" in testi, f"LLM{numero:02d} assente dalla scheda"

    # I rischi non applicabili non devono avere un pulsante: sarebbero dimostrazioni di altro.
    assert "Non applicabile a questo sistema" in testi


def test_lo_scenario_di_injection_diretta_resta_bloccato_dalla_ui(indexed_app):
    app = run_app()
    esegui_scenario(app, "2. Prompt injection diretta")

    esito = app.session_state["scenario_result"]["response"]
    assert esito.blocked
    assert esito.blocked_stage == "input"


# ------------------------------------------------------- limiti di frequenza


# ------------------------------------------------------- istanza pubblica


def modalita_pubblica(monkeypatch, attiva: bool) -> None:
    import streamlit as st

    monkeypatch.setenv("PUBLIC_MODE", "true" if attiva else "false")
    get_settings.cache_clear()
    st.cache_resource.clear()


def test_in_pubblico_niente_controlli_da_amministratore(indexed_app, monkeypatch):
    """Il pulsante di indicizzazione non è coperto dai limiti di frequenza, che valgono per le
    domande: lasciato in pagina, chiunque potrebbe far ripagare gli embedding a ripetizione."""
    modalita_pubblica(monkeypatch, attiva=True)
    app = run_app()

    etichette = [pulsante.label for pulsante in app.button]
    assert not any("Rigenera" in etichetta for etichetta in etichette)
    # Nessun selettore del modello: in pubblico il provider non si cambia.
    assert not any(radio.label == "Modello che genera le risposte" for radio in app.radio)


def test_in_locale_i_controlli_restano(indexed_app, monkeypatch):
    """La demo dal vivo deve poter cambiare modello e reindicizzare."""
    modalita_pubblica(monkeypatch, attiva=False)
    app = run_app()

    etichette = [pulsante.label for pulsante in app.button]
    assert any("Rigenera" in etichetta for etichetta in etichette)


def test_le_domande_pronte_producono_una_risposta(indexed_app, monkeypatch):
    """Chi apre il link deve poter provare senza inventare una domanda sui documenti."""
    modalita_pubblica(monkeypatch, attiva=True)
    app = run_app()

    pronte = [b for b in app.button if b.label in {"Franchigia cyber", "Rimborso ransomware"}]
    assert pronte, "le domande di esempio devono essere presenti a conversazione vuota"

    pronte[0].click().run()

    assert len(app.session_state["history"]) == 1
    assert app.session_state["history"][0]["response"].answer


def limiti(monkeypatch, per_ip: str) -> None:
    """Attiva i limiti di frequenza sull'app sotto test."""
    import streamlit as st

    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_PER_IP_HOUR", per_ip)
    monkeypatch.setenv("RATE_LIMIT_GLOBAL_DAY", "500")
    get_settings.cache_clear()
    st.cache_resource.clear()  # il RateLimiter è condiviso fra le sessioni: va ricreato


@pytest.fixture(autouse=True)
def ripristina_impostazioni():
    """Le variabili d'ambiente sono per-processo: ogni test riparte pulito."""
    import streamlit as st

    yield
    get_settings.cache_clear()
    st.cache_resource.clear()


def test_a_quota_esaurita_la_richiesta_non_raggiunge_il_modello(indexed_app, monkeypatch):
    """Con la quota esaurita la pipeline non viene nemmeno interpellata."""
    limiti(monkeypatch, per_ip="0")
    app = run_app()

    esegui_scenario(app, "1. Query legittima")
    esito = app.session_state["scenario_result"]["response"]

    assert esito.blocked
    assert esito.blocked_stage == "rate_limit"
    assert esito.rate_limit == "quota_visitatore"
    # Nessuna chiamata al modello significa nessun prompt costruito e nessun token speso.
    assert esito.prompt_sent == ""
    assert not esito.sources


def test_i_tre_ambiti_di_ricerca_sono_sempre_disponibili(indexed_app):
    """Le opzioni non compaiono solo quando esistono documenti caricati.

    Nasconderle finché la collection degli upload è vuota rende invisibile una funzione del
    sistema a chi apre la demo per la prima volta.
    """
    app = run_app()

    # Si verificano numero e selezionabilità, non le etichette: quelle sono una scelta di
    # presentazione che può cambiare senza che il comportamento cambi.
    ambiti = next(radio for radio in app.radio if radio.label == "Dove cercare")
    assert len(ambiti.options) == 3
    assert all(etichetta.strip() for etichetta in ambiti.options)


def test_ambito_senza_documenti_caricati_avvisa_invece_di_rispondere_a_vuoto(indexed_app):
    app = run_app()

    app.radio[0].set_value("uploads").run()

    assert any("Nessun documento caricato" in str(w.value) for w in app.warning)


def test_il_provider_offline_non_consuma_quota(indexed_app, monkeypatch):
    """Il limite protegge la spesa, non l'uso: senza costo non c'è ragione di limitare.

    L'indice di test gira sul provider `fake`, che non effettua chiamate di rete: per quante
    domande si pongano, la quota resta intatta.
    """
    limiti(monkeypatch, per_ip="2")
    app = run_app()

    for _ in range(4):
        esegui_scenario(app, "1. Query legittima")

    esito = app.session_state["scenario_result"]["response"]
    assert not esito.blocked
    assert esito.rate_limit == "rate_ok"
