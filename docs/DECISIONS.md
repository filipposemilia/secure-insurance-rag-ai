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

---

## ADR-013 — Al tetto di spesa si degrada, non si blocca

**Contesto.** Esporre pubblicamente l'istanza con una API key a carico di chi la pubblica apre il
rischio LLM04: chiunque può consumare token altrui. Serve un tetto, ma un tetto che rifiuti le
richieste trasforma un limite di costo in un'interruzione di servizio — cioè proprio il denial of
service da cui ci si difende. Chi arriva per ultimo troverebbe una demo che non risponde.

**Decisione.** Due soglie con esiti diversi (`security/ratelimit.py`):
- **quota oraria per visitatore** → la richiesta viene rifiutata; protegge dal singolo abusante;
- **tetto giornaliero complessivo** → la richiesta viene servita dal provider deterministico
  offline, dichiarandolo nell'interfaccia.

La quota si consuma **solo** quando il modello in rete viene davvero interrogato: una query fermata
dai guard, o servita offline, non è costata nulla e non intacca il budget di chi la subisce. Per
questo `check()` e `record()` sono separati.

**Conseguenze.** Il link resta sempre navigabile e la spesa ha un massimo garantito. La pipeline
non sa di essere esposta: il limite è applicato dall'entry point pubblico (`app/streamlit_app.py`),
mentre la CLI, che è locale, resta senza limiti. I contatori vivono in memoria: corretto per un
container singolo, insufficiente con più repliche — dichiarato in `docs/SECURITY.md` invece di
essere taciuto.

---

## ADR-014 — Porta esposta solo su loopback

**Contesto.** I limiti di frequenza identificano il visitatore tramite `X-Forwarded-For`, un header
che il client può scrivere a piacere. Se il container fosse raggiungibile direttamente
dall'esterno, chiunque potrebbe falsificarlo e presentarsi ogni volta come un visitatore diverso.

**Decisione.** `docker-compose.yml` pubblica la porta su `127.0.0.1:8501` e non su `0.0.0.0`. Il
solo percorso verso l'applicazione passa dal reverse proxy, che sovrascrive l'header.

**Conseguenze.** L'header diventa attendibile perché esiste un unico punto di ingresso controllato.
La configurazione del proxy non è un dettaglio operativo ma parte del modello di sicurezza, ed è
per questo documentata in `docs/DEPLOY.md` insieme alla verifica che l'audit registri l'indirizzo
reale del visitatore e non quello del proxy.

---

## ADR-015 — Collection di upload per sessione, e indice allineato a ciò che l'utente vede

**Contesto.** Emerso in esercizio, sull'istanza pubblica. Due difetti distinti che si sommavano:

1. La collection degli upload era **unica per istanza**. Bastava che un visitatore caricasse un
   documento perché diventasse raggiungibile da chiunque altro avesse clearance sufficiente: la
   clearance separa i ruoli, non le persone. Era dichiarato in roadmap come accettabile «per una
   demo locale» — una motivazione decaduta nel momento in cui l'istanza è stata pubblicata, senza
   che la voce venisse rivalutata.
2. Togliere un file dall'elenco **non ne rimuoveva i chunk**: l'unico svuotamento era il pulsante
   che azzerava tutto. Un documento caricato per errore restava interrogabile e continuava a
   comparire fra le fonti pur essendo sparito dall'interfaccia.

**Decisione.** La collection è derivata dal token di sessione (`upload_collection_for()`), lo stesso
usato per i limiti di frequenza. La rimozione di un file dall'elenco elimina i suoi chunk
(`remove_source()`), e le collection rimaste da sessioni precedenti vengono cancellate all'avvio del
processo (`drop_collections_with_prefix()`), perché una sessione web non offre una chiusura su cui
agganciarsi in modo affidabile.

**Conseguenze.** Ciò che l'interfaccia mostra e ciò che il retrieval può raggiungere coincidono: è
questa la proprietà che conta, perché un utente giudica cosa il sistema "sa" da cosa vede. Il token
di sessione entra in un nome di collection, quindi viene ripulito dei caratteri non alfanumerici.
Resta un limite: l'isolamento vale per sessione del browser, non per identità verificata — chi
riapre il link ottiene una sessione nuova e vuota, che per una demo è il comportamento desiderabile.

---

## ADR-016 — Due livelli di lettura, e controlli da amministratore fuori dalla vetrina

**Contesto.** L'interfaccia era scritta per chi già sa cos'è un sistema RAG: «Provider LLM»,
«Indici · Corpus 14», «Ruolo del richiedente», istruzioni per installare Ollama, e una chat vuota
che non suggerisce nulla — senza sapere quali documenti esistano, un visitatore non può nemmeno
formulare una domanda. Ma il progetto resta una prova tecnica su AI e sicurezza: cancellare il
vocabolario specialistico significherebbe rinunciare a mostrare padronanza.

**Decisione.** Il gergo non viene rimosso, viene **spostato di un livello**. In superficie
linguaggio comune («Chi sta facendo la domanda», «Documenti consultabili», «Anomalie rilevate»); il
termine esatto — RBAC, anonimizzazione prima dell'indicizzazione, OWASP LLM01 — resta nei tooltip,
negli expander e nella scheda Sicurezza, che è dichiaratamente la parte tecnica.

Il controllo degli accessi è il caso esemplare: invece di spiegare cos'è l'RBAC, la barra laterale
dichiara **cosa quel profilo vede e cosa non vede**, e cambiando profilo la stessa domanda cambia
risposta. Il meccanismo si capisce osservandolo, non leggendone la definizione.

Separatamente, `public_mode` distingue la vetrina dall'uso locale. In pubblico spariscono la scelta
del modello e il pulsante di reindicizzazione: **quest'ultimo non è coperto dai limiti di frequenza,
che valgono per le domande**, e lasciato in pagina permetterebbe a chiunque di far ripagare gli
embedding a chi ospita l'istanza. Era un problema di costo, non di ordine visivo.

**Conseguenze.** Un'unica base di codice serve due pubblici. Il rischio è la deriva: ogni testo
nuovo va scritto pensando a chi non conosce il dominio, con il termine tecnico come
approfondimento e non come etichetta. Le quattro domande pronte in chat sono verificate sui
documenti realmente indicizzati — una di esse è riservata alla direzione, così un clic mostra il
controllo degli accessi in azione invece di descriverlo.
