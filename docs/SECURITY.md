# Modello di sicurezza

## Threat model sintetico

Sistema: assistente conversazionale su documentazione assicurativa, accessibile alla rete agenziale
e alla direzione. Dati trattati: polizze, perizie, circolari interne. Categorie di dati personali:
anagrafica, codice fiscale, IBAN, contatti, dati di sinistro.

| Attore | Capacità | Obiettivo plausibile |
| :--- | :--- | :--- |
| Agente di rete curioso | Accesso legittimo alla chat | Ottenere margini negoziali interni o dati di clienti non propri |
| Cliente malintenzionato | Accesso al canale pubblico | Estrarre dati di altri assicurati, far dichiarare al bot coperture inesistenti |
| Attaccante esterno | Capacità di far arrivare un documento nella pipeline di ingestion (allegato a un sinistro, PDF di perizia) | Prompt injection indiretta: far approvare liquidazioni o esfiltrare dati |
| Insider | Accesso ai log | Ricostruire domande e dati personali dagli archivi di sistema |

## Mapping OWASP Top 10 for LLM Applications

| Rischio | Mitigazione implementata | Dove | Limite dichiarato |
| :--- | :--- | :--- | :--- |
| **LLM01 — Prompt Injection (diretta)** | Input guard a pattern: override istruzioni, cambio ruolo, system override, jailbreak. Blocco prima della chiamata al modello. | `security/guardrails.py::validate_input` | Le regole sono deterministiche: un attacco riformulato con sinonimi o in altra lingua può eluderle. In produzione serve un classificatore addestrato. |
| **LLM01 — Prompt Injection (indiretta)** | Scansione dei chunk recuperati: istruzioni rivolte all'assistente e contenuto nascosto (commenti HTML, testo invisibile) mandano il chunk in quarantena. Il system prompt dichiara inoltre che il contesto è dato, non istruzione, ed è racchiuso in delimitatori espliciti. | `security/guardrails.py::scan_context`, `rag.py::SYSTEM_PROMPT` | Stessa fragilità delle regole. Non copre payload steganografici o in immagini. |
| **LLM02 — Insecure Output Handling** | La risposta non viene mai eseguita né interpretata: è testo mostrato in UI. Output guard su PII. | `security/guardrails.py::validate_output` | Non c'è sanitizzazione HTML perché non esiste rendering di HTML generato dal modello. |
| **LLM03 — Training Data Poisoning** | Non applicabile: nessun fine-tuning. È uno dei motivi per cui il RAG è preferibile in questo dominio. | — | Il corpus indicizzato **è** avvelenabile: è esattamente lo scenario coperto dal context guard. |
| **LLM04 — Model Denial of Service** | Limite di lunghezza sulla query (`MAX_QUERY_LENGTH`), `k` di retrieval fisso. | `security/guardrails.py` | Nessun rate limiting per utente: va aggiunto a livello di API gateway. |
| **LLM06 — Sensitive Information Disclosure** | PII masking **prima** dell'embedding: nel vector store non esiste un dato personale in chiaro. RBAC sul retrieval. Output guard che blocca PII in risposta. Audit senza query in chiaro. | `security/pii.py`, `vectorstore.py`, `security/audit.py` | Il riconoscimento è a regex: nomi non introdotti da un ruolo contrattuale possono sfuggire. Presidio risolve questo punto. |
| **LLM07 — Insecure Plugin Design** | Non applicabile: nessun tool né azione eseguibile dal modello. Il PoC è read-only per costruzione. | — | Con LangGraph e azioni di liquidazione servirebbe human-in-the-loop obbligatorio. |
| **LLM08 — Excessive Agency** | Il modello non può compiere azioni: nessuna scrittura, nessuna approvazione, nessuna chiamata a sistemi terzi. Lo scenario 3 della demo mostra un documento che *chiede* di approvare 50.000 EUR e resta senza effetto. | Architettura | — |
| **LLM09 — Overreliance** | Obbligo di citare la fonte, risposta forzata a "informazione non presente" quando il contesto non copre la domanda, controllo di groundedness sull'output. | `rag.py`, `guardrails.py::_is_grounded` | Il controllo di groundedness è lessicale, non semantico: è un proxy, non una garanzia. |
| **LLM10 — Model Theft** | Non applicabile: nessun modello proprietario ospitato. | — | — |

## Difesa in profondità: cosa succede se un layer cede

Il PII masking è applicato **due volte** di proposito: in ingestion (prima dell'embedding) e sul
contesto recuperato (prima del prompt). Se un documento entrasse nell'indice per una via che salta
l'ingestion, il secondo passaggio lo intercetterebbe comunque.

Analogamente, la protezione contro l'esfiltrazione di dati personali non dipende dal solo input
guard: anche se una query malevola lo superasse, **nel vector store i dati personali non ci sono**.
Il layer che conta davvero è l'anonimizzazione, non il filtro sulla domanda.

## Privacy dell'audit trail

Il log registra: timestamp, ruolo, **hash** della domanda, lunghezza, verdetti dei guard, fonti
consultate, documenti in quarantena, latenza, provider. Non registra la domanda in chiaro né la
risposta — un audit log che conserva le query diventa esso stesso un archivio di dati personali.
L'hash consente comunque di correlare richieste ripetute e riconoscere campagne di attacco.

## Cosa questo PoC non fa

Dichiarato esplicitamente, perché un modello di sicurezza sopravvalutato è peggio di uno modesto:

- nessuna autenticazione reale: il ruolo è dichiarato dall'utente, non verificato da un IdP;
- nessun rate limiting né quota per utente;
- nessuna cifratura at-rest del vector store;
- nessuna gestione del ciclo di vita dei dati (retention, cancellazione su richiesta GDPR);
- nessun red teaming sistematico: gli scenari della demo sono sei casi scelti, non una suite.
