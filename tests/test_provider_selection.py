"""Test della scelta del provider: rilevamento disponibilità, menu e isolamento degli indici."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from secure_rag import providers
from secure_rag.cli import choose_provider, resolve_settings
from secure_rag.config import Settings
from secure_rag.providers import ProviderStatus, probe_providers


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        llm_provider="fake",
        openai_api_key="sk-test",
        chroma_base_dir=tmp_path / "chroma",
        audit_log_path=tmp_path / "audit.jsonl",
    )


# ------------------------------------------------------- isolamento degli indici


def test_indici_separati_per_provider(settings: Settings):
    """Modelli con dimensioni diverse non devono condividere la stessa collection Chroma."""
    fake_dir = settings.chroma_dir
    openai_dir = settings.with_provider("openai").chroma_dir

    assert fake_dir != openai_dir
    assert "fake" in fake_dir.name
    assert settings.openai_embedding_model in openai_dir.name


def test_with_provider_non_altera_l_originale(settings: Settings):
    modificato = settings.with_provider("openai")
    assert modificato.llm_provider == "openai"
    assert settings.llm_provider == "fake"


# ------------------------------------------------------------------ rilevamento


def test_ollama_non_disponibile_se_il_servizio_non_risponde(settings, monkeypatch):
    monkeypatch.setattr(providers, "probe_ollama", lambda *_, **__: (False, []))
    statuses = {status.name: status for status in probe_providers(settings)}

    assert not statuses["ollama"].available
    assert "ollama.com" in statuses["ollama"].hint


def test_ollama_disponibile_con_i_modelli_scaricati(settings, monkeypatch):
    monkeypatch.setattr(
        providers,
        "probe_ollama",
        lambda *_, **__: (True, [f"{settings.ollama_chat_model}:latest", settings.ollama_embedding_model]),
    )
    statuses = {status.name: status for status in probe_providers(settings)}

    assert statuses["ollama"].available
    assert statuses["ollama"].hint == ""


def test_ollama_segnala_i_modelli_mancanti(settings, monkeypatch):
    monkeypatch.setattr(providers, "probe_ollama", lambda *_, **__: (True, ["mistral"]))
    statuses = {status.name: status for status in probe_providers(settings)}

    assert not statuses["ollama"].available
    assert "ollama pull" in statuses["ollama"].hint


def test_openai_indisponibile_senza_chiave(tmp_path, monkeypatch):
    monkeypatch.setattr(providers, "probe_ollama", lambda *_, **__: (False, []))
    settings = Settings(openai_api_key="", chroma_base_dir=tmp_path)
    statuses = {status.name: status for status in probe_providers(settings)}

    assert not statuses["openai"].available
    assert "OPENAI_API_KEY" in statuses["openai"].hint


def test_il_provider_offline_e_sempre_disponibile(settings, monkeypatch):
    monkeypatch.setattr(providers, "probe_ollama", lambda *_, **__: (False, []))
    statuses = {status.name: status for status in probe_providers(settings)}
    assert statuses["fake"].available


def test_probe_ollama_gestisce_host_irraggiungibile(tmp_path):
    """Un endpoint inesistente non deve sollevare eccezioni: deve solo risultare indisponibile."""
    settings = Settings(ollama_base_url="http://127.0.0.1:1", chroma_base_dir=tmp_path)
    running, models = providers.probe_ollama(settings, timeout=0.5)
    assert running is False
    assert models == []


# ------------------------------------------------------------------------ menu


STATUSES = [
    ProviderStatus("openai", "OpenAI", "gpt-4o-mini", available=True),
    ProviderStatus("ollama", "Ollama", "llama3.1", available=False, hint="installa Ollama"),
    ProviderStatus("fake", "Offline", "nessuna rete", available=True),
]


def test_invio_conferma_il_default(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "")
    assert choose_provider(STATUSES, "openai") == "openai"


def test_selezione_numerica(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "3")
    assert choose_provider(STATUSES, "openai") == "fake"


def test_ripete_la_domanda_su_scelta_non_disponibile(monkeypatch):
    risposte = iter(["2", "1"])
    monkeypatch.setattr("builtins.input", lambda _: next(risposte))
    assert choose_provider(STATUSES, "fake") == "openai"


def test_ripete_la_domanda_su_input_non_valido(monkeypatch):
    risposte = iter(["banana", "99", "1"])
    monkeypatch.setattr("builtins.input", lambda _: next(risposte))
    assert choose_provider(STATUSES, "fake") == "openai"


def test_default_non_disponibile_ripiega_su_uno_valido(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "")
    assert choose_provider(STATUSES, "ollama") in {"openai", "fake"}


# -------------------------------------------------------------------- risoluzione


def test_flag_provider_salta_il_menu(monkeypatch):
    def esplodi(_):
        raise AssertionError("il menu non deve comparire quando --provider è esplicito")

    monkeypatch.setattr("builtins.input", esplodi)
    args = argparse.Namespace(provider="fake", no_prompt=False)
    assert resolve_settings(args).llm_provider == "fake"


def test_no_prompt_usa_la_configurazione(monkeypatch):
    def esplodi(_):
        raise AssertionError("il menu non deve comparire con --no-prompt")

    monkeypatch.setattr("builtins.input", esplodi)
    args = argparse.Namespace(provider=None, no_prompt=True)
    resolve_settings(args)  # non deve sollevare


def test_nessun_menu_quando_stdin_non_e_un_terminale(monkeypatch):
    """Negli script e nella CI la scelta deve restare deterministica."""

    def esplodi(_):
        raise AssertionError("il menu non deve comparire fuori da un terminale")

    monkeypatch.setattr("builtins.input", esplodi)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    args = argparse.Namespace(provider=None, no_prompt=False)
    resolve_settings(args)  # non deve sollevare
