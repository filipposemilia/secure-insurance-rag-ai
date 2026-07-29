# Roadmap

## Fatto

| Fase | Contenuto | Stato |
| :--- | :--- | :--- |
| 0 | Scaffolding, ambiente `uv` su Python 3.12, governance (log di sessione, ADR) | ✅ |
| 1 | Core RAG: ingestion anonimizzata, ChromaDB con RBAC, provider intercambiabili, catena LCEL, CLI | ✅ |
| 2 | Security layer: input guard, context guard (injection indiretta), output guard, audit trail JSONL, sei scenari di attacco | ✅ |
| 3 | UI Streamlit a schede: chat con selettore di ambito, upload documenti con referto di sicurezza, pannello scenari e audit | ✅ |
| 3b | Scelta interattiva del provider all'avvio (OpenAI / Ollama / offline) con rilevamento della disponibilità, indici separati per modello | ✅ |
| 4 | Documentazione: README, architettura, modello di sicurezza con mapping OWASP, ADR | ✅ |
| 5 | Istanza pubblica: limiti di frequenza (LLM04) con degradazione al motore offline, immagine Docker, deploy dietro reverse proxy con TLS | ✅ |

Test: 107, tutti offline (`.venv/bin/pytest -q`), inclusi quelli di regressione su interfaccia e
limiti di frequenza.

**Cosa gira oggi in produzione.** La generazione usa **OpenAI `gpt-4o-mini`**, un modello esterno.
Il percorso on-premise è implementato in `providers.py` (Ollama, Azure OpenAI) ma **non è attivo**:
un modello locale richiederebbe risorse che l'attuale VPS non ha. L'anonimizzazione, che è la parte
che tratta i dati in chiaro, gira invece **interamente in locale** con regex deterministiche — non
esce dal perimetro nemmeno oggi. I livelli 2 e 3 previsti da ADR-019 (Presidio e LLM locale) restano
future work vincolato all'hardware.

## Future work

Non implementato per scelta. Ogni voce indica cosa aggiungerebbe e perché è stata esclusa: alcune
sono state escluse dal vincolo di tempo iniziale, altre — quelle segnate come vincolate all'hardware
— dalle risorse della macchina che ospita l'istanza pubblica.

### Sicurezza

| Voce | Cosa aggiunge | Perché non ora | Sforzo |
| :--- | :--- | :--- | :--- |
| **Microsoft Presidio** affiancato alle regex | NER sui nomi in testo libero e riconoscitori italiani già pronti (codice fiscale, patente, carta d'identità), con punteggi di confidenza. Da affiancare, non sostituire: le regex attuali sono deterministiche e testate | Porta spaCy e un modello linguistico: con `it_core_news_lg` l'immagine cresce di ~540 MB. Va importato in modo opzionale, con fallback alle regex, perché la demo offline resti installabile in un minuto | ~4 h |
| **Riconoscimento di dati sanitari e giudiziari** (Art. 9 e 10 GDPR) | Diagnosi, percentuali di invalidità, verbali: **le uniche categorie dell'elenco legale che restano scoperte**, perché non hanno una forma riconoscibile da una regex | Richiede un classificatore addestrato o un NER medico-legale italiano, più un dataset annotato per misurarne i falsi negativi | ~2 g |
| **LLM locale come terzo livello di anonimizzazione** (ADR-019) | Copre proprio ciò che regex e NER non vedono: dati sanitari, giudiziari e narrativa identificante. Girando su infrastruttura propria non c'è trasferimento a terzi, quindi l'obiezione che vale per i modelli esterni decade | **Vincolo di risorse**: un modello da 8B quantizzato richiede ~5 GB di RAM, e la VPS attuale non ha margine. Va applicato solo ai segmenti che i primi due livelli non risolvono, altrimenti il costo per pagina passa da microsecondi a secondi | ~1 g + hardware |
| **Servizi in compartimenti separati** (ADR-019) | Quattro container — applicazione, anonimizzazione, vector store, inferenza — con il container di inferenza **senza accesso a internet**: la garanzia diventa verificabile guardando la rete, invece che dichiarata. Permette anche di spostare l'inferenza su una macchina con GPU senza toccare il codice | Ha senso solo insieme all'LLM locale, quindi condivide lo stesso vincolo di risorse. Presidio ha già immagini Docker ufficiali, quindi un container su quattro esiste pronto | ~4 h |
| **Classificatore di prompt injection** | Regge le riformulazioni che eludono le regole deterministiche | Richiede un dataset di attacchi e una valutazione seria per non generare falsi positivi | ~1 g |
| **NeMo Guardrails / Guardrails AI** | Policy dichiarative su argomenti ammessi e formato delle risposte | Sovrapposto a quanto già dimostrato dai guard a regole | ~4 h |
| **Autenticazione reale (OIDC/JWT)** | Il ruolo verificato da un identity provider invece che dichiarato | Fuori dallo scopo di un PoC senza backend | ~1 g |
| **Antivirus sui file caricati** | Blocca allegati malevoli oltre al payload testuale (macro, PDF con JavaScript) | Richiede un servizio esterno tipo ClamAV | ~3 h |

### Qualità del retrieval

| Voce | Cosa aggiunge | Perché non ora | Sforzo |
| :--- | :--- | :--- | :--- |
| **Soglia minima di similarità sul retrieval** | Oggi il retriever restituisce sempre i primi `k=4` chunk, anche quando sono debolmente attinenti: su un corpus da 14 chunk questo fa scattare la nota di quarantena quasi a ogni domanda (*alert fatigue*) | Va tarata su un corpus realistico: con 14 documenti qualunque soglia sarebbe arbitraria | ~2 h |
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
| **Export dell'audit verso SIEM** | Correlazione degli eventi di sicurezza con il resto dell'infrastruttura | Il formato JSONL è già pronto per essere spedito | ~2 h |
| **Suite di red teaming** | Batteria sistematica di attacchi con metriche di elusione | I sei scenari attuali sono casi scelti, non una suite statistica | ~1 g |
