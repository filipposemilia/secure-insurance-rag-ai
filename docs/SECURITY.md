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
| **LLM04 — Model Denial of Service** | Limite di lunghezza sulla query (`MAX_QUERY_LENGTH`), `k` di retrieval fisso, tetto di dimensione e di chunk sui file caricati, e **limiti di frequenza** sull'istanza pubblica: quota oraria per visitatore e tetto giornaliero complessivo. | `security/guardrails.py`, `uploads.py`, `security/ratelimit.py` | I contatori vivono nella memoria del processo: con più repliche servirebbe uno store condiviso. |
| **LLM06 — Sensitive Information Disclosure** | PII masking **prima** dell'embedding: nel vector store non esiste un dato personale in chiaro. Coperti anche gli identificativi indiretti — numero di polizza, sinistro, targa, telaio — compreso quello nei metadati che compone il blocco fonte del prompt. RBAC sul retrieval. Output guard che blocca PII in risposta. Audit senza query in chiaro. | `security/pii.py`, `rag.py::format_context`, `vectorstore.py`, `security/audit.py` | Il riconoscimento è a regex: restano fuori i nomi in testo libero e, soprattutto, i dati sanitari e giudiziari, che non hanno una forma riconoscibile. Vedi la tabella di copertura GDPR più sotto. |
| **LLM07 — Insecure Plugin Design** | Non applicabile: nessun tool né azione eseguibile dal modello. Il PoC è read-only per costruzione. | — | Con LangGraph e azioni di liquidazione servirebbe human-in-the-loop obbligatorio. |
| **LLM08 — Excessive Agency** | Il modello non può compiere azioni: nessuna scrittura, nessuna approvazione, nessuna chiamata a sistemi terzi. Lo scenario 3 della demo mostra un documento che *chiede* di approvare 50.000 EUR e resta senza effetto. | Architettura | — |
| **LLM09 — Overreliance** | Obbligo di citare la fonte, risposta forzata a "informazione non presente" quando il contesto non copre la domanda, controllo di groundedness sull'output. | `rag.py`, `guardrails.py::_is_grounded` | Il controllo di groundedness è lessicale, non semantico: è un proxy, non una garanzia. |
| **LLM10 — Model Theft** | Non applicabile: nessun modello proprietario ospitato. | — | — |

## Copertura GDPR delle categorie di dati personali

Categorie tratte da un parere legale sul trattamento di documentazione assicurativa. La distinzione
che conta è fra ciò che ha una **forma riconoscibile** e ciò che non ne ha: le regex vedono le
prime, sulle seconde sono cieche per costruzione.

| Categoria | Esempi | Stato |
| :--- | :--- | :--- |
| Identificativi diretti | Nome, codice fiscale, email, telefono, data di nascita | ✅ `security/pii.py` |
| Documenti d'identità | Patente, carta d'identità, passaporto | ✅ pattern `DOCUMENTO` |
| Indirizzo | Residenza, ubicazione dell'immobile assicurato | ✅ pattern `INDIRIZZO` |
| Identificativi indiretti | Numero di polizza, sinistro, pratica; IBAN; partita IVA | ✅ pattern `PRATICA`, `IBAN`, `PIVA` |
| Beni riconducibili | Targa, numero di telaio | ✅ pattern `TARGA`, `TELAIO` |
| **Dati sanitari (Art. 9)** | Diagnosi, referti, percentuali di invalidità | ❌ **non coperti** |
| **Dati giudiziari (Art. 10)** | Verbali, contenziosi, precedenti | ❌ **non coperti** |
| **Nomi di terzi in testo libero** | Testimoni, medici curanti, controparti | ⚠️ solo se introdotti da un ruolo contrattuale |
| **Dettagli narrativi identificanti** | "Infortunio del giorno X presso la ditta Y" | ❌ **non coperti** |

Le tre voci non coperte **non sono una svista**: diagnosi e verbali non hanno un formato, e nessuna
espressione regolare potrà individuarli. Servono NER o un classificatore addestrato — Microsoft
Presidio con un modello italiano è la strada indicata in `ROADMAP.md`. Dichiararle è preferibile a
lasciar credere che il masking a regex copra l'Art. 9.

### Pseudonimizzazione reversibile

I segnaposto sono stabili (`[IBAN_001]` resta lo stesso ovunque) e la mappa inversa vive in un vault
cifrato con Fernet, con permessi `600`, mai nel vector store e mai nel prompt.

**Il comportamento predefinito è irreversibile**: senza `PII_VAULT_KEY` il vault non viene scritto e
nessuno può ricostruire i valori originali. È la scelta più prudente, ed è quella attiva
sull'istanza pubblica. Con la chiave configurata, i ruoli in `UNMASK_ROLES` vedono i dati reali
ripristinati **a schermo, dopo l'output guard** — mai nel testo inviato al modello, mai nell'audit.

Il vault è a sua volta un archivio di dati personali: introdurlo aumenta il valore del sistema e la
sua superficie di rischio insieme, e va acceso solo dove esiste un controllo di accesso reale.

## Superficie di attacco dei documenti caricati dall'utente

L'upload in chat è il punto in cui un attaccante ha il controllo più diretto sul contenuto che il
sistema leggerà. Riceve quindi lo stesso trattamento del corpus aziendale, più tre controlli
specifici:

| Controllo | Cosa impedisce | Dove |
| :--- | :--- | :--- |
| Formato ammesso (`.pdf`, `.md`, `.txt`) e limite di dimensione e di chunk | Saturazione del contesto e dei costi, file eseguibili | `uploads.py::process_upload` |
| Anonimizzazione PII **prima** dell'indicizzazione | Che i dati personali del file caricato raggiungano il provider LLM | `uploads.py`, `security/pii.py` |
| Scansione anti-injection al momento del caricamento, con referto all'utente | Che un payload nascosto agisca prima che qualcuno se ne accorga | `uploads.py`, `security/guardrails.py::scan_context` |

Quattro proprietà di isolamento:

- i documenti caricati vanno in una **collection separata**, svuotabile, che non contamina in modo
  permanente il corpus aziendale;
- ereditano la **clearance del ruolo che li ha caricati**, quindi un file caricato dalla direzione
  non diventa visibile alla rete agenziale attraverso la chat;
- la collection è **per sessione**: su un'istanza raggiungibile da più persone la sola clearance non
  basterebbe, perché due visitatori con lo stesso ruolo si vedrebbero i documenti a vicenda;
- **togliere un file dall'elenco ne elimina i chunk** dall'indice, e le collection rimaste da
  sessioni concluse vengono rimosse all'avvio del processo. Un documento caricato per errore non
  deve restare interrogabile dopo essere sparito dall'interfaccia.

I chunk sospetti vengono indicizzati e marcati, non scartati: il context guard li esclude comunque
a ogni interrogazione. Così l'attacco resta visibile nell'audit trail invece di sparire in silenzio,
e l'utente riceve una nota esplicita nella risposta.

**Limite dichiarato.** La collection degli upload è unica per l'istanza: in un deployment
multiutente andrebbe partizionata per sessione o per utente, non solo per clearance.

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
- i limiti di frequenza sono per processo e in memoria: non reggono più repliche, e un riavvio
  azzera i contatori;
- l'identità del visitatore è l'indirizzo IP inoltrato dal proxy: sufficiente contro l'abuso
  occasionale, aggirabile da chi cambia indirizzo;
- nessuna cifratura at-rest del vector store;
- nessuna gestione del ciclo di vita dei dati (retention, cancellazione su richiesta GDPR);
- nessun red teaming sistematico: gli scenari della demo sono sei casi scelti, non una suite.
