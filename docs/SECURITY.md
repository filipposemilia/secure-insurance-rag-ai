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

> Questa tabella è il testo discorsivo. La **forma strutturata** vive in `src/secure_rag/owasp.py`,
> è ciò che la scheda 🛡️ Sicurezza mostra, ed è coperta da test: che i dieci codici ci siano tutti,
> che ogni scenario dichiarato esista davvero, che ogni rischio non applicabile spieghi perché.
> Prima esisteva solo la prosa, e la prosa aveva perso una riga senza che nessuno se ne accorgesse
> (ADR-024).

| Rischio | Mitigazione implementata | Dove | Limite dichiarato |
| :--- | :--- | :--- | :--- |
| **LLM01 — Prompt Injection (diretta)** | Input guard a pattern: override istruzioni, cambio ruolo, system override, jailbreak. Blocco prima della chiamata al modello. | `security/guardrails.py::validate_input` | Le regole sono deterministiche: un attacco riformulato con sinonimi o in altra lingua può eluderle. In produzione serve un classificatore addestrato. |
| **LLM01 — Prompt Injection (indiretta)** | Scansione dei chunk recuperati: istruzioni rivolte all'assistente e contenuto nascosto (commenti HTML, testo invisibile) mandano il chunk in quarantena. Il system prompt dichiara inoltre che il contesto è dato, non istruzione, ed è racchiuso in delimitatori espliciti. | `security/guardrails.py::scan_context`, `rag.py::SYSTEM_PROMPT` | Stessa fragilità delle regole. Non copre payload steganografici o in immagini. |
| **LLM02 — Insecure Output Handling** | La risposta non viene mai eseguita né interpretata: è testo mostrato in UI. Output guard su PII, applicato **anche durante lo streaming**: il testo compare mentre viene generato, ma solo dopo essere stato verificato (ADR-023). | `security/guardrails.py::validate_output`, `::StreamingOutputGuard` | Non c'è sanitizzazione HTML perché non esiste rendering di HTML generato dal modello. |
| **LLM03 — Training Data Poisoning** | Non applicabile: nessun fine-tuning. È uno dei motivi per cui il RAG è preferibile in questo dominio. | — | Il corpus indicizzato **è** avvelenabile: è esattamente lo scenario coperto dal context guard. |
| **LLM04 — Model Denial of Service** | Limite di lunghezza sulla query (`MAX_QUERY_LENGTH`), `k` di retrieval fisso, tetto di dimensione e di chunk sui file caricati, e **limiti di frequenza** sull'istanza pubblica: quota oraria per visitatore e tetto giornaliero complessivo. | `security/guardrails.py`, `uploads.py`, `security/ratelimit.py` | I contatori vivono nella memoria del processo: con più repliche servirebbe uno store condiviso. |
| **LLM05 — Supply Chain Vulnerabilities** | Dipendenze dichiarate in `pyproject.toml`, immagine costruita da `python:3.12-slim`, e modello linguistico installato da un wheel con **versione fissata** nel Dockerfile invece che risolta al momento della build: due build a mesi di distanza producono la stessa immagine. | `pyproject.toml`, `Dockerfile` | È la voce più scoperta del mapping: nessuna verifica di firma, nessun SBOM, nessuna scansione delle vulnerabilità in integrazione continua. Non è nemmeno dimostrabile con uno scenario, perché è una proprietà della catena di costruzione e non un attacco a runtime. |
| **LLM06 — Sensitive Information Disclosure** | PII masking **prima** dell'embedding: nel vector store non esiste un dato personale in chiaro. Coperti anche gli identificativi indiretti — numero di polizza, sinistro, targa, telaio — compreso quello nei metadati che compone il blocco fonte del prompt. RBAC sul retrieval. Output guard che blocca PII in risposta. Audit senza query in chiaro. | `security/pii.py`, `security/ner.py`, `rag.py::format_context`, `vectorstore.py`, `security/audit.py` | Il livello 1 è a regex, il livello 2 è a NER: entrambi attivi sull'istanza pubblica, il secondo opzionale nell'installazione da sorgente. Restano fuori in ogni caso i dati sanitari e giudiziari, che non sono entità ma affermazioni. Vedi la tabella di copertura GDPR più sotto. |
| **LLM07 — Insecure Plugin Design** | Non applicabile: nessun tool né azione eseguibile dal modello. Il PoC è read-only per costruzione. | — | Con LangGraph e azioni di liquidazione servirebbe human-in-the-loop obbligatorio. |
| **LLM08 — Excessive Agency** | Il modello non può compiere azioni: nessuna scrittura, nessuna approvazione, nessuna chiamata a sistemi terzi. Lo scenario 3 della demo mostra un documento che *chiede* di approvare 50.000 EUR e resta senza effetto. | Architettura | — |
| **LLM09 — Overreliance** | Obbligo di citare la fonte, risposta forzata a "informazione non presente" quando il contesto non copre la domanda, controllo di groundedness sull'output. | `rag.py`, `guardrails.py::_is_grounded` | Il controllo verifica che **ogni cifra della risposta esista nel contesto** — è l'allucinazione che fa danno in una polizza — più una soglia lessicale minima. Resta un proxy: una cifra corretta attribuita alla voce sbagliata lo supera, e un'affermazione falsa senza numeri è coperta solo dalla soglia debole (ADR-022). |
| **LLM10 — Model Theft** | Non applicabile: nessun modello proprietario ospitato. | — | — |

## Copertura GDPR delle categorie di dati personali

Categorie tratte da un parere legale sul trattamento di documentazione assicurativa. La distinzione
che conta è fra ciò che ha una **forma riconoscibile**, ciò che è un'**entità linguistica** e ciò che
non è né l'una né l'altra: le regex vedono le prime, il NER le seconde, e sulle terze — un'invalidità,
una diagnosi — nessuno dei due strumenti può fare nulla.

| Categoria | Esempi | Stato |
| :--- | :--- | :--- |
| Identificativi diretti | Nome, codice fiscale, email, telefono, data di nascita | ✅ `security/pii.py` |
| Documenti d'identità | Patente, carta d'identità, passaporto | ✅ pattern `DOCUMENTO` |
| Indirizzo | Residenza, ubicazione dell'immobile assicurato | ✅ pattern `INDIRIZZO` |
| Identificativi indiretti | Numero di polizza, sinistro, pratica; IBAN; partita IVA | ✅ pattern `PRATICA`, `IBAN`, `PIVA` |
| Beni riconducibili | Targa, numero di telaio | ✅ pattern `TARGA`, `TELAIO` |
| **Dati sanitari (Art. 9)** | Diagnosi, referti, percentuali di invalidità | ❌ **non coperti** |
| **Dati giudiziari (Art. 10)** | Verbali, contenziosi, precedenti | ❌ **non coperti** |
| **Nomi di terzi in testo libero** | Testimoni, medici curanti, controparti | ✅ **livello 2** (attivo in produzione) · ⚠️ senza di esso, solo se introdotti da un ruolo contrattuale |
| **Dettagli narrativi identificanti** | "Infortunio del giorno X presso la ditta Y" | ❌ **non coperti** |
| **Nomi di persona nel nome di un file** | `perizia Mario Rossi.pdf` | ❌ **non coperti** — sui metadati gira il solo livello 1 |

Le due voci non coperte **non sono una svista**: diagnosi e verbali non hanno un formato, e nessuna
espressione regolare potrà individuarli. Nemmeno il NER li vede, perché non sono entità: sono
affermazioni. Servono un classificatore o un LLM, ed è il livello 3 di ADR-019, non ancora scritto.
Dichiararle è preferibile a lasciar credere che il masking copra l'Art. 9.

### I due livelli di anonimizzazione

| Livello | Motore | Vede | Costo misurato |
| :--- | :--- | :--- | :--- |
| 1 | Regex (`security/pii.py`) | Ciò che ha una forma: CF, IBAN, polizza, targa, telaio, indirizzo, nomi dopo un ruolo contrattuale | ~1 ms per documento |
| 2 | Presidio + `it_core_news_lg` (`security/ner.py`) | Nomi di persona in **testo libero**: «il testimone Andrea Gallo ha dichiarato» | ~50-80 ms per documento |

Il livello 1 gira per primo e **resta autoritativo** sui formati rigidi: dove un pattern
deterministico ha già risposto, un modello probabilistico non rimette in discussione l'esito. Il
livello 2 è **attivo sull'istanza pubblica** (il modello sta nell'immagine Docker e aggiunge ~870 MB
di RSS al processo) e resta una dipendenza **opzionale, spenta per default**, nell'installazione da
sorgente.

Due proprietà di questo livello vanno dette per intero, perché sono ciò che lo distingue dal primo:

- **Il punteggio di confidenza non discrimina.** Il riconoscitore spaCy assegna `0,85` a *ogni*
  entità `PERSON`: lo stesso valore a «Alessandro Nardi» e all'intestazione «SEZIONE». Alzare la
  soglia non separa i due casi, li elimina entrambi. La difesa è un **elenco esplicito di lessico
  contrattuale** (`_TERMINI_CONTRATTUALI` in `security/ner.py`) escluso dal riconoscimento: senza,
  il modello trasformava una clausola in `l'[NOME_009] ha diritto a…`, cioè corrompeva il testo che
  l'LLM deve interpretare. È un elenco da mantenere, ed è il costo che un livello probabilistico
  impone.
- **Un mancato riconoscimento è silenzioso.** Una regex che non trova nulla non ha trovato nulla; un
  modello che non trova un nome non produce alcun segnale. Il livello 2 aumenta la copertura, non la
  garanzia: resta un rilevatore, e va comunicato come tale.

Quando il livello 2 è configurato ma non disponibile (libreria o modello assenti), il sistema torna
alle sole regex **dichiarandolo** — nella riga di esito di `secure-rag ingest`, nella scheda
🛡️ Sicurezza e in un warning sui log. Non esiste un percorso in cui il masking si riduca senza che
qualcuno lo veda. Per la stessa ragione l'indice porta una marca con i livelli usati per costruirlo e
viene rifatto quando non coincidono con la configurazione: un indice con segnaposto di livello 1 sotto
un'interfaccia che dichiara il livello 2 sarebbe un'incoerenza fra ciò che il sistema afferma e ciò
che il retrieval contiene.

**I metadati che entrano nel prompt passano dal livello 1, non dal 2.** Il blocco `[fonte: … ·
polizza …]` che rende citabile una risposta è composto a runtime dai metadati, che l'anonimizzazione
dell'ingestion non attraversa: senza mascherarli, un identificativo tolto dal contenuto rientrerebbe
da lì. Vale per il numero di polizza e per il **nome del file**, che su un documento caricato lo
sceglie l'utente — e un allegato di sinistro, nel mondo reale, si chiama con il numero di sinistro.

Il livello 2 è escluso da questo passaggio di proposito: un nome di file è una stringa breve senza
contesto linguistico, e il modello vi riconosce nomi di persona che non ci sono
(`polizza_multirischio_impresa.md` → `[NOME_001]`), distruggendo la citazione. Il limite che ne
deriva è nella tabella sopra.

Scelte e alternative scartate di questo livello: **ADR-020** in `docs/DECISIONS.md`.

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
| Anonimizzazione PII **prima** dell'indicizzazione, con gli stessi due livelli del corpus | Che i dati personali del file caricato raggiungano il provider LLM | `uploads.py`, `security/pii.py`, `security/ner.py` |
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

**Limite dichiarato.** L'isolamento è per **sessione del browser**, non per identità: chi apre una
scheda nuova ottiene una collection nuova, e chi condivide il proprio token di sessione condivide i
documenti. Senza un identity provider non si può fare di meglio — è lo stesso limite
dell'autenticazione, non uno in più.

## Difesa in profondità: cosa succede se un layer cede

Il PII masking è applicato **due volte** di proposito: in ingestion (prima dell'embedding) e sul
contesto recuperato (prima del prompt). Se un documento entrasse nell'indice per una via che salta
l'ingestion, il secondo passaggio lo intercetterebbe comunque.

Analogamente, la protezione contro l'esfiltrazione di dati personali non dipende dal solo input
guard: anche se una query malevola lo superasse, **nel vector store i dati personali non ci sono**.
Il layer che conta davvero è l'anonimizzazione, non il filtro sulla domanda.

## L'output guard durante lo streaming

La risposta compare mentre il modello la produce, e questo di norma significa mandare in pagina i
token **prima** di qualunque controllo. Qui non accade: `StreamingOutputGuard` sta fra il modello e
lo schermo e rilascia solo ciò che ha già superato le verifiche.

| Controllo | Quando |
| :--- | :--- |
| Dati personali nella risposta | **Preventivo**: il testo non esce se contiene PII |
| Cifre non presenti nei documenti | **Preventivo**: un massimale inventato non compare |
| Soglia lessicale di groundedness | **A posteriori**, alla chiusura: su un frammento il rapporto sarebbe rumore |

La garanzia non è un'attenzione, è strutturale: **gli ultimi 96 caratteri del buffer non vengono mai
rilasciati**, e la coda è più lunga del più esteso pattern riconosciuto. Un dato personale è quindi
per intero dentro al buffer — e già verificato — prima che il suo primo carattere possa comparire a
schermo. Dettaglio e alternative scartate: ADR-023.

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
