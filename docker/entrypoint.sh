#!/usr/bin/env bash
# Avvio dell'istanza pubblica.
#
# L'indicizzazione è condizionale: viene eseguita solo se l'indice del provider attivo è vuoto.
# Con il volume persistente montato, un riavvio del container non rifà l'ingestion e quindi non
# ripaga gli embedding.
set -euo pipefail

PROVIDER="${LLM_PROVIDER:-fake}"
DOCUMENTI="${POLICIES_DIR:-/app/data/policies}"

echo "→ Provider attivo: ${PROVIDER}"
echo "→ Cartella documenti: ${DOCUMENTI}"

# Verifica esplicita: senza, un percorso errato produrrebbe un ciclo di riavvii in cui l'unico
# indizio è un messaggio d'errore che scorre via fra due intestazioni di ingestion.
if [ ! -d "${DOCUMENTI}" ]; then
  echo "✗ La cartella dei documenti non esiste: ${DOCUMENTI}" >&2
  echo "  Verifica la variabile POLICIES_DIR e che l'immagine sia stata costruita con data/ dentro." >&2
  echo "  Contenuto di /app:" >&2
  ls -la /app >&2 || true
  exit 1
fi

if [ "${PROVIDER}" = "fake" ]; then
  echo "  Nota: provider deterministico offline. Per usare il modello in rete imposta"
  echo "  LLM_PROVIDER=openai e OPENAI_API_KEY nel file .env."
fi

# Verifica l'indice senza toccarlo. Si tiene solo l'ultima riga e la si valida: eventuali
# messaggi delle librerie su stdout non devono trasformarsi in un confronto numerico fallito,
# che bloccherebbe l'avvio in produzione.
CHUNKS=$(python - 2>/dev/null <<'PY' | tail -n 1
from secure_rag.config import get_settings
from secure_rag.vectorstore import collection_size

try:
    print(collection_size(get_settings()))
except Exception:
    print(0)
PY
)

case "${CHUNKS}" in
  ''|*[!0-9]*) CHUNKS=0 ;;
esac

if [ "${CHUNKS}" -gt 0 ]; then
  echo "→ Indice già presente: ${CHUNKS} chunk. Ingestion saltata."
else
  echo "→ Indice assente: eseguo l'ingestion con anonimizzazione dei dati personali."
  # `--no-prompt` è obbligatorio: senza, il menu di scelta del provider resterebbe in attesa di
  # input su uno standard input che nel container non esiste, e l'avvio non terminerebbe mai.
  secure-rag ingest --provider "${PROVIDER}" --no-prompt
fi

echo "→ Avvio dell'interfaccia su :8501"
exec streamlit run app/streamlit_app.py \
  --server.address=0.0.0.0 \
  --server.port=8501 \
  --server.headless=true
