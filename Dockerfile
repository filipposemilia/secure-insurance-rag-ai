# Immagine dell'istanza pubblica.
#
# Due stadi: il primo installa le dipendenze, il secondo contiene solo ciò che serve a eseguire.
# Python 3.12 è un vincolo del progetto (`requires-python = ">=3.10,<3.13"`): chromadb non ha
# ancora wheel per 3.13.

# --- Stadio 1: dipendenze ----------------------------------------------------
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_LINK_MODE=copy

RUN pip install uv

WORKDIR /build

# Copiati per primi: finché non cambiano, il livello delle dipendenze resta in cache e la
# ricostruzione dopo una modifica al codice è di pochi secondi.
COPY pyproject.toml README.md ./
COPY src/ ./src/

# L'extra `presidio` porta il livello 2 dell'anonimizzazione (NER sui nomi in testo libero).
# Il modello linguistico non sta su PyPI: si installa dalla release di spaCy, con la versione
# **fissata**. `python -m spacy download` risolverebbe la versione compatibile al momento della
# build, e due build a distanza di mesi produrrebbero immagini diverse a partire dallo stesso
# Dockerfile.
#
# Costo: circa 700 MB di immagine fra spaCy, le sue dipendenze e il modello (541 MB da soli). A
# runtime il modello aggiunge **~870 MB di RSS misurati**, caricati una volta sola per processo e
# condivisi da tutte le sessioni: non è un costo per visitatore.
ARG MODELLO_NER=it_core_news_lg
ARG VERSIONE_NER=3.8.0

RUN uv venv /opt/venv --python 3.12 \
    && VIRTUAL_ENV=/opt/venv uv pip install --no-cache ".[presidio]" \
    && VIRTUAL_ENV=/opt/venv uv pip install --no-cache \
       "https://github.com/explosion/spacy-models/releases/download/${MODELLO_NER}-${VERSIONE_NER}/${MODELLO_NER}-${VERSIONE_NER}-py3-none-any.whl"

# --- Stadio 2: runtime -------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    STREAMLIT_SERVER_HEADLESS=true

# I percorsi vanno dichiarati esplicitamente.
#
# `Settings` li deriva da `PROJECT_ROOT`, che risale di due livelli dal modulo: corretto quando il
# codice sta in `src/secure_rag/`, sbagliato qui, dove il pacchetto è **installato** e quindi vive
# in `site-packages` — la root calcolata diventerebbe `/opt/venv/lib/python3.12`.
#
# Sono campi di `Settings`, quindi pydantic-settings li legge dall'ambiente senza modifiche al
# codice. Il compose può comunque sovrascriverli.
ENV POLICIES_DIR=/app/data/policies \
    CHROMA_BASE_DIR=/app/chroma_db \
    AUDIT_LOG_PATH=/app/logs/audit.jsonl

# Utente non privilegiato: se l'applicazione viene compromessa, non è root a eseguirla.
RUN useradd --create-home --uid 10001 secure

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY --chown=secure:secure src/ ./src/
COPY --chown=secure:secure app/ ./app/
COPY --chown=secure:secure data/ ./data/
COPY --chown=secure:secure .streamlit/ ./.streamlit/
COPY --chown=secure:secure docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chown=secure:secure pyproject.toml README.md ./

RUN chmod +x /usr/local/bin/entrypoint.sh \
    && mkdir -p /app/chroma_db /app/logs \
    && chown -R secure:secure /app

USER secure

EXPOSE 8501

# Streamlit espone un endpoint di salute dedicato: è quello che il container deve dichiarare.
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8501/_stcore/health', timeout=4).status==200 else 1)"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
