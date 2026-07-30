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

# Verifica l'indice senza toccarlo. Non è solo un conteggio: un indice popolato può essere stato
# costruito con un livello di anonimizzazione diverso da quello configurato ora, e in quel caso va
# rifatto — altrimenti l'interfaccia dichiarerebbe un livello che i segnaposto nell'indice non hanno.
# Si tiene solo l'ultima riga: eventuali messaggi delle librerie su stdout non devono confondere il
# parsing e bloccare l'avvio in produzione.
DECISIONE=$(python - 2>/dev/null <<'PY' | tail -n 1
from secure_rag.config import get_settings
from secure_rag.ingestion import ingest_decision

try:
    serve, motivo = ingest_decision(get_settings())
except Exception as errore:
    serve, motivo = True, f"verifica non riuscita ({type(errore).__name__})"
print(f"{'SI' if serve else 'NO'}|{motivo}")
PY
)

# Output vuoto o illeggibile: si indicizza. Un indice ricostruito senza bisogno costa embedding,
# uno mancante o incoerente costa la correttezza.
case "${DECISIONE}" in
  SI\|*|NO\|*) ;;
  *) DECISIONE="SI|verifica non riuscita" ;;
esac

SERVE="${DECISIONE%%|*}"
MOTIVO="${DECISIONE#*|}"

if [ "${SERVE}" = "NO" ]; then
  echo "→ Ingestion saltata: ${MOTIVO}."
else
  echo "→ Eseguo l'ingestion con anonimizzazione dei dati personali: ${MOTIVO}."
  # `--no-prompt` è obbligatorio: senza, il menu di scelta del provider resterebbe in attesa di
  # input su uno standard input che nel container non esiste, e l'avvio non terminerebbe mai.
  secure-rag ingest --provider "${PROVIDER}" --no-prompt
fi

echo "→ Avvio dell'interfaccia su :8501"
exec streamlit run app/streamlit_app.py \
  --server.address=0.0.0.0 \
  --server.port=8501 \
  --server.headless=true
