# Decisioni architetturali (ADR)

Registro sintetico delle scelte non ovvie e delle alternative scartate.

---

## ADR-001 — Anonimizzazione a monte dell'embedding, non a valle

**Contesto.** I documenti di polizza contengono anagrafica, CF, IBAN e contatti. Il sistema invia
testo a un provider LLM esterno.

**Decisione.** Il masking avviene nella pipeline di ingestion, prima della generazione degli
embedding, e viene riapplicato sul contesto recuperato prima della composizione del prompt.

**Alternative scartate.** Filtrare solo la risposta finale: inutile, perché i dati sarebbero già
usciti dal perimetro al momento dell'embedding. Cifrare i chunk: impedisce la ricerca semantica.

**Conseguenze.** Nel vector store non esiste un dato personale in chiaro. La ri-identificazione è
possibile solo lato applicativo tramite il vault in memoria. Il doppio passaggio costa poco ed è
una difesa in profondità voluta.

---

## ADR-002 — Segnaposto stabili e numerati invece di redazione secca

**Contesto.** Sostituire ogni PII con `[REDACTED]` distrugge la capacità del modello di collegare
riferimenti alla stessa entità in punti diversi del corpus.

**Decisione.** Segnaposto tipizzati e progressivi (`[IBAN_001]`, `[CF_002]`), stabili tra documenti
grazie a un vault condiviso nell'istanza `PIIMasker`.

**Conseguenze.** Il modello può ragionare su "la stessa persona" senza conoscerne l'identità. Il
masker diventa stateful: va riusata la stessa istanza per l'intero ingest.

---

## ADR-003 — Guardrail fuori dalla catena LCEL

**Contesto.** LangChain permetterebbe di inserire i controlli come `RunnableLambda` nella catena.

**Decisione.** I controlli restano in codice Python esplicito attorno alla catena; la catena LCEL
copre solo `prompt | llm | parser`.

**Alternative scartate.** Guard come anelli della catena: renderebbe più difficile interrompere
prima della chiamata al modello e complicherebbe i test (servirebbe mockare l'LLM).

**Conseguenze.** Una richiesta bloccata ha latenza ~0 ms e costo zero. Ogni guard è testabile in
isolamento come funzione pura.

---

## ADR-004 — Verdetti come oggetti, non booleani

**Contesto.** Un audit trail utile deve spiegare *perché* qualcosa è stato bloccato.

**Decisione.** `GuardVerdict(allowed, rule, reason, matches)` per ogni controllo.

**Conseguenze.** Il log e la UI mostrano la regola scattata e la motivazione; il costo è qualche
riga di dataclass in più.

---

## ADR-005 — Chunk in quarantena, non scartati in silenzio

**Contesto.** Un chunk che contiene istruzioni rivolte all'assistente potrebbe essere semplicemente
filtrato via.

**Decisione.** Il chunk viene escluso dal contesto, ma l'evento è registrato nell'audit e dichiarato
all'utente con una nota di sicurezza.

**Conseguenze.** Un documento manomesso viene trattato come incidente di sicurezza segnalabile, non
come rumore da nascondere. È anche l'elemento più efficace da mostrare in demo.

---

## ADR-006 — Provider `fake` deterministico come cittadino di prima classe

**Contesto.** La demo doveva poter girare in colloquio senza rete e senza dipendere da una API key
funzionante — decisione poi rivelatasi necessaria, dato che il progetto OpenAI utilizzato in
sviluppo era senza credito.

**Decisione.** `LLM_PROVIDER=fake` fornisce embedding hash-based e un modello che estrae dal
contesto le frasi più pertinenti. Tutta la suite di test gira su questo provider.

**Alternative scartate.** Mock nei soli test: non avrebbe reso eseguibile la demo offline.

**Conseguenze.** Test veloci (< 2 s) e senza costi, demo sempre eseguibile. In compenso la qualità
delle risposte in modalità offline è visibilmente inferiore a quella di un modello reale: va detto
esplicitamente quando si mostra la demo in questa modalità.

---

## ADR-007 — Un indice per provider, non un indice condiviso

**Contesto.** Modelli di embedding diversi producono vettori di dimensione diversa (1536 per
`text-embedding-3-small`, 768 per `nomic-embed-text`, 256 per il provider deterministico).
Scrivendoli nella stessa collection Chroma, il primo cambio di provider fa fallire la query.

**Decisione.** `Settings.chroma_dir` è una property che compone `chroma_db/<provider>__<modello>`.

**Alternative scartate.** Un solo indice con re-indicizzazione forzata a ogni cambio: costa tempo e
token a ogni switch, e in demo è un rischio inutile.

**Conseguenze.** Si può alternare fra OpenAI e modalità offline senza re-indicizzare, il che è
comodo quando la rete al colloquio non è affidabile. In cambio, il primo uso di un provider nuovo
richiede un `ingest` dedicato, segnalato con un messaggio esplicito.

---

## ADR-008 — Menu di scelta del provider all'avvio, con rilevamento della disponibilità

**Contesto.** Il provider era configurabile solo da `.env`. Passare da cloud a locale richiedeva di
editare un file, e non c'era modo di sapere se Ollama fosse effettivamente utilizzabile.

**Decisione.** I comandi che usano un LLM mostrano un menu che elenca i provider **verificati sulla
macchina**: la chiave OpenAI presente, il servizio Ollama raggiungibile e con i modelli scaricati.
Le opzioni non disponibili restano visibili, ma non selezionabili, con l'istruzione per abilitarle.

**Alternative scartate.** Elencare tutti i provider senza verifica: sposta l'errore a valle, dopo il
retrieval, con un messaggio incomprensibile. Rilevare la disponibilità con una chiamata di
fatturazione a OpenAI: costa una richiesta a ogni avvio.

**Conseguenze.** Il menu va saltato con `--provider` o `--no-prompt` negli script; viene inoltre
saltato automaticamente quando `stdin` non è un terminale, così pipe e CI restano deterministiche.
Il probe di Ollama usa solo `urllib` della libreria standard, per non dipendere da un pacchetto
opzionale proprio nel punto in cui si verifica se quel pacchetto serve.

---

## ADR-009 — Documenti caricati in una collection separata, non nel corpus

**Contesto.** L'interfaccia permette di caricare un file e interrogarlo. Indicizzarlo nella
collection principale sarebbe stato più semplice.

**Decisione.** I file caricati finiscono in `<collection>_uploads`, con `uploaded: true` nei
metadati e clearance ereditata dal ruolo attivo. Lo scope della ricerca è scelto dall'utente:
corpus, solo caricati, o entrambi.

**Alternative scartate.** Collection unica con un flag nei metadati: un errore nel filtro
renderebbe permanente la contaminazione del corpus aziendale con contenuto non verificato.

**Conseguenze.** Gli upload si svuotano con un pulsante senza toccare l'indice ufficiale, e il
filtro RBAC continua ad applicarsi anche a essi. Limite noto: la collection è unica per istanza,
quindi in un deployment multiutente andrebbe partizionata per sessione.

---

## ADR-010 — Referto di sicurezza al caricamento, prima della prima domanda

**Contesto.** Un file caricato è il vettore naturale della prompt injection indiretta. Con il solo
context guard a runtime, l'utente scoprirebbe il problema solo di riflesso, dentro una risposta.

**Decisione.** `process_upload` esegue subito masking e scansione, e restituisce un `UploadReport`
con conteggio e tipo delle PII rimosse, confronto prima/dopo del testo, e numero di blocchi che
contengono istruzioni rivolte all'assistente.

**Conseguenze.** Il rischio è visibile nel momento in cui entra nel sistema. I chunk sospetti
vengono comunque indicizzati e marcati, così il guard a runtime li ferma una seconda volta: due
livelli indipendenti, coerente con ADR-005.

---

## ADR-011 — Chunk da 800 caratteri con overlap 120

**Contesto.** Il documento di partenza proponeva 300/50.

**Decisione.** 800/120.

**Motivo.** Le clausole assicurative sono periodi lunghi con condizioni concatenate ("a condizione
che… salvo che…"). Chunk da 300 caratteri spezzano la condizione dalla sua eccezione, producendo
risposte formalmente ancorate ma sostanzialmente sbagliate.

---

## ADR-012 — Gli scenari di attacco portano con sé il proprio ruolo

**Contesto.** Nell'interfaccia, i pulsanti degli scenari impostavano una domanda "in attesa" che la
scheda Chat avrebbe eseguito al rerun successivo, con il ruolo selezionato in barra laterale. Due
conseguenze, entrambe emerse solo alla prova generale: cambiare scheda in Streamlit non provoca un
rerun, quindi la domanda non partiva; e lo scenario 6 (`management`) girava come `agent`, annullando
proprio il confronto RBAC che deve dimostrare.

**Decisione.** Lo scenario viene eseguito nel momento del click, con `run_query(..., as_role=
scenario.role)`, e l'esito compare nella scheda in cui è stato lanciato. Il meccanismo della domanda
"in attesa" è stato rimosso.

**Conseguenze.** L'esito di uno scenario non dipende più dallo stato della barra laterale: gli
scenari 5 e 6 sono confrontabili con due click. Il ruolo di ciascuno scenario è dichiarato sulla
scheda, così chi guarda vede che la differenza sta nella clearance e non nella domanda. La UI, che
non era coperta da alcun test, ha ora cinque test di regressione in `tests/test_streamlit_ui.py`.
