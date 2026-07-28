#!/usr/bin/env bash
# Demo end-to-end da mostrare dal vivo: ingestion → query legittima → scenari di attacco → audit.
#
# Uso:
#   bash scripts/demo.sh            # usa il provider configurato in .env
#   bash scripts/demo.sh openai     # forza il modello in rete
#   bash scripts/demo.sh fake       # forza la modalità offline deterministica
#
# Il provider viene scelto una volta sola e riusato da tutti i comandi, così il menu di selezione
# non ricompare a ogni passo.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -x .venv/bin/secure-rag ]]; then
  echo "Ambiente non pronto. Esegui prima:"
  echo "  uv venv --python 3.12 && uv pip install -e \".[dev]\""
  exit 1
fi

if [[ -n "${1:-}" ]]; then
  PROVIDER=(--provider "$1")
  echo "Provider forzato: $1"
else
  PROVIDER=(--no-prompt)
  echo "Provider: quello configurato in .env (passa 'openai' o 'fake' come argomento per forzarlo)"
fi

pausa() {
  if [[ -t 0 ]]; then
    read -rp $'\n[invio per continuare] '
  fi
}

.venv/bin/secure-rag ingest "${PROVIDER[@]}"
pausa

.venv/bin/secure-rag ask "${PROVIDER[@]}" \
  "Quali sono le condizioni per ottenere il rimborso in caso di attacco ransomware?"
pausa

.venv/bin/secure-rag attack-demo "${PROVIDER[@]}"
pausa

.venv/bin/secure-rag audit --limit 3
