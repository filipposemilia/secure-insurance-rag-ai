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

from pathlib import Path

from secure_rag.config import Settings


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
