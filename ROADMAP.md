# Roadmap

## Fatto

| Fase | Contenuto | Stato |
| :--- | :--- | :--- |
| 0 | Scaffolding, ambiente `uv` su Python 3.12, governance (`CLAUDE.md`, sessioni, memorie) | ✅ |
| 1 | Core RAG: ingestion anonimizzata, ChromaDB con RBAC, provider intercambiabili, catena LCEL, CLI | ✅ |
| 2 | Security layer: input guard, context guard (injection indiretta), output guard, audit trail JSONL, sei scenari di attacco | ✅ |
| 3 | UI Streamlit con selettore di ruolo, pannello sicurezza, citazioni, prompt ispezionabile | ✅ |
| 4 | Documentazione: README, architettura, modello di sicurezza con mapping OWASP, ADR | ✅ |

Test: 32, tutti offline (`.venv/bin/pytest -q`).

## Future work

Non implementato per scelta, dato il vincolo di tempo di 24 ore. Ogni voce indica cosa
aggiungerebbe e perché è stata esclusa.

### Sicurezza

| Voce | Cosa aggiunge | Perché non ora | Sforzo |
| :--- | :--- | :--- | :--- |
| **Microsoft Presidio** al posto delle regex | NER sui nomi in contesto libero, riconoscitori italiani, punteggi di confidenza | Il PoC deve restare installabile in un minuto; Presidio porta spaCy e modelli linguistici | ~4 h |
| **Classificatore di prompt injection** | Regge le riformulazioni che eludono le regole deterministiche | Richiede un dataset di attacchi e una valutazione seria per non generare falsi positivi | ~1 g |
| **NeMo Guardrails / Guardrails AI** | Policy dichiarative su argomenti ammessi e formato delle risposte | Sovrapposto a quanto già dimostrato dai guard a regole | ~4 h |
| **Autenticazione reale (OIDC/JWT)** | Il ruolo verificato da un identity provider invece che dichiarato | Fuori dallo scopo di un PoC senza backend | ~1 g |
| **Rate limiting e quote per utente** | Mitigazione LLM04 (denial of service e abuso di costi) | Va a livello di API gateway, non di applicazione | ~2 h |

### Qualità del retrieval

| Voce | Cosa aggiunge | Perché non ora | Sforzo |
| :--- | :--- | :--- | :--- |
| **Hybrid search (BM25 + vettoriale)** | Trova i riferimenti esatti ("articolo 14-bis") che l'embedding sbaglia | Richiede un secondo indice e la fusione dei ranking | ~4 h |
| **Re-ranking con cross-encoder** | Passa all'LLM 3 chunk davvero pertinenti invece di 4 approssimativi: meno token, più precisione | Aggiunge un modello locale da scaricare | ~3 h |
| **Chunking gerarchico per articoli** | Rispetta la struttura contrattuale invece di tagliare a lunghezza fissa | Richiede un parser dedicato per il formato delle polizze | ~5 h |
| **Valutazione automatica (Ragas / LLM-as-a-judge)** | Misura groundedness e faithfulness su un dataset di riferimento, invece del proxy lessicale attuale | Richiede un dataset annotato di domande e risposte attese | ~1 g |

### Architettura

| Voce | Cosa aggiunge | Perché non ora | Sforzo |
| :--- | :--- | :--- | :--- |
| **LangGraph con human-in-the-loop** | Istruttoria sinistri a più passi con checkpoint di approvazione umana | Il PoC è read-only per scelta: non compie azioni, quindi non serve un grafo a stati | ~1 g |
| **Qdrant o pgvector** | Vector store gestito, con replica, backup e filtri più espressivi | ChromaDB locale basta a dimostrare l'architettura | ~3 h |
| **Azure OpenAI in esercizio** | Compliance GDPR: i dati non alimentano i modelli pubblici | **Già implementato** in `providers.py`: manca solo un tenant Azure su cui configurarlo | ~1 h |
| **FastAPI + frontend React** | Interfaccia multiutente con sessioni e autenticazione | Streamlit copre la demo con un decimo del codice | ~2 g |
| **LangSmith tracing attivo** | Costi per query, latenza, debugging delle catene, audit delle risposte | Le variabili sono già in `.env.example`: serve solo una API key | ~30 min |
| **Ingestion di PDF scansionati (OCR)** | Copre le perizie acquisite come immagine, caso reale frequente | Il loader PDF attuale gestisce solo testo estraibile | ~4 h |

### Operatività

| Voce | Cosa aggiunge | Perché non ora | Sforzo |
| :--- | :--- | :--- | :--- |
| **Docker Compose** | Ambiente riproducibile con vector store esterno | `uv` rende l'avvio locale già immediato | ~2 h |
| **Export dell'audit verso SIEM** | Correlazione degli eventi di sicurezza con il resto dell'infrastruttura | Il formato JSONL è già pronto per essere spedito | ~2 h |
| **Suite di red teaming** | Batteria sistematica di attacchi con metriche di elusione | I sei scenari attuali sono casi scelti, non una suite statistica | ~1 g |
