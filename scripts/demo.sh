#!/usr/bin/env bash
# Demo end-to-end da mostrare dal vivo: ingestion → query legittima → scenari di attacco → audit.
# Uso: bash scripts/demo.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -x .venv/bin/secure-rag ]]; then
  echo "Ambiente non pronto. Esegui prima:"
  echo "  uv venv --python 3.12 && uv pip install -e \".[dev]\""
  exit 1
fi

pausa() {
  if [[ -t 0 ]]; then
    read -rp $'\n[invio per continuare] '
  fi
}

.venv/bin/secure-rag ingest
pausa

.venv/bin/secure-rag ask "Quali sono le condizioni per ottenere il rimborso in caso di attacco ransomware?"
pausa

.venv/bin/secure-rag attack-demo
pausa

.venv/bin/secure-rag audit --limit 3
