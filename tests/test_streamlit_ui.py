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


def test_l_app_si_avvia_senza_eccezioni(indexed_app):
    app = run_app()

    assert not app.exception
    assert len(app.tabs) == 3


def test_lo_scenario_produce_l_esito_al_primo_click(indexed_app):
    """Regressione: il click rimandava la domanda al rerun successivo, che non arrivava mai.

    Cambiare scheda in Streamlit non provoca un rerun: chi cliccava «Esegui» e apriva la Chat la
    trovava vuota.
    """
    app = run_app()
    app.button(key="scenario_0").click().run()

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

    app.button(key="scenario_5").click().run()
    esito = app.session_state["scenario_result"]["response"]

    assert esito.role == "management"


def test_rbac_visibile_dal_confronto_fra_gli_scenari_5_e_6(indexed_app):
    """La stessa domanda, due clearance: la circolare riservata compare solo alla direzione."""
    app = run_app()

    app.button(key="scenario_4").click().run()  # scenario 5 — ruolo agent
    agente = app.session_state["scenario_result"]["response"]

    app.button(key="scenario_5").click().run()  # scenario 6 — ruolo management
    direzione = app.session_state["scenario_result"]["response"]

    assert agente.role == "agent"
    assert direzione.role == "management"
    assert "circolare_interna_liquidazioni.md" not in agente.sources
    assert "circolare_interna_liquidazioni.md" in direzione.sources


def test_lo_scenario_di_injection_diretta_resta_bloccato_dalla_ui(indexed_app):
    app = run_app()
    app.button(key="scenario_1").click().run()

    esito = app.session_state["scenario_result"]["response"]
    assert esito.blocked
    assert esito.blocked_stage == "input"
