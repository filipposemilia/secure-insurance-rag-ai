#!/usr/bin/env bash
# Avvio dell'istanza pubblica.
#
# L'indicizzazione è condizionale: viene eseguita solo se l'indice del provider attivo è vuoto.
# Con il volume persistente montato, un riavvio del container non rifà l'ingestion e quindi non
# ripaga gli embedding.
set -euo pipefail

PROVIDER="${LLM_PROVIDER:-fake}"

echo "→ Provider attivo: ${PROVIDER}"

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
