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

---

## ADR-017 — L'anonimizzazione non passa da un LLM esterno

**Contesto.** La tentazione, potendo chiamare un modello, è chiedergli «rimuovi i dati personali da
questo documento». È l'approccio che un parere legale sul GDPR per il settore assicurativo scarta
esplicitamente, e le ragioni reggono da sole.

**Decisione.** Il masking resta deterministico e locale (`security/pii.py`), eseguito **prima** di
qualunque chiamata di rete. L'evoluzione prevista è Presidio con un modello NER italiano — sempre in
locale — non un LLM.

**Motivo.** Tre problemi, in ordine di gravità:
1. **Sarebbe una violazione in sé**: si invierebbero i dati personali in chiaro al fornitore esterno
   proprio per chiedergli di rimuoverli. Il trattamento avviene nel momento dell'invio.
2. **Un generatore di testo può saltare un nome o riscrivere una clausola.** Un mancato
   riconoscimento è una fuga di dati; una riscrittura è un contratto alterato. Le regex sbagliano in
   modo prevedibile e verificabile con un test.
3. Costo e latenza per un compito che una regex risolve in microsecondi.

**Precisazione importante — vale solo per gli LLM esterni.** La prima obiezione, che è la più
grave, **cade completamente** se il modello gira su infrastruttura propria: non esiste un terzo e
non c'è alcun trasferimento fuori dal perimetro. Restano la seconda e la terza, che dipendono dalla
natura dello strumento e non da dove è ospitato.

Ne segue che un LLM locale non va escluso, va **assegnato al compito giusto**: non i formati rigidi,
che una regex risolve meglio e più in fretta, ma i dati sanitari, giudiziari e la narrativa
identificante — le uniche categorie che né le regex né il NER possono vedere. Si veda ADR-019.

**Conseguenze.** Il limite è dichiarato invece che aggirato: dati sanitari e giudiziari restano
scoperti perché non hanno una forma riconoscibile, ed è scritto in `docs/SECURITY.md`. Il masking
copre ora anche gli identificativi indiretti dell'elenco legale — polizza, sinistro, targa, telaio,
documenti d'identità, indirizzo — compreso il numero di polizza nei **metadati**, che viveva fuori
dal testo dei chunk e finiva nel prompt in chiaro attraverso il blocco `[fonte: …]`.

---

## ADR-018 — Vault cifrato opzionale, spento per impostazione predefinita

**Contesto.** I segnaposto erano stabili ma la mappa inversa moriva con il processo: `ingest` gira da
riga di comando, l'interfaccia altrove. Il progetto si presentava come pseudonimizzazione mentre in
pratica faceva anonimizzazione irreversibile, e `unmask()` esisteva senza essere mai chiamato.

**Decisione.** `security/vault.py` persiste la mappa cifrata con Fernet, chiave da `PII_VAULT_KEY`,
file con permessi `600`. Il ripristino avviene in `rag.py` **dopo l'output guard** e solo per i ruoli
in `UNMASK_ROLES`.

L'ordine non è un dettaglio: il guard verifica che il modello non abbia rigenerato per conto suo dati
personali che non gli erano stati forniti. Ripristinare prima lo farebbe scattare sui segnaposto
sostituiti da noi, bloccando risposte legittime e — peggio — mascherando il caso che il controllo
esiste per intercettare.

**Senza chiave non viene scritto nulla** e il ripristino resta disattivato. Il default è il
comportamento irreversibile, ed è quello attivo sull'istanza pubblica, dove non esiste un operatore
autorizzato da distinguere.

**Conseguenze.** Il ciclo descritto dal parere legale è chiuso, ma introduce ciò che prima non
c'era: **un archivio di dati personali da proteggere**. È un aumento di capacità e di rischio
insieme, e per questo è opt-in. `cryptography` è una dipendenza opzionale (`.[vault]`): se manca, il
sistema si comporta come se la chiave fosse assente invece di scrivere in chiaro.

---

## ADR-019 — Anonimizzazione a tre livelli e servizi in compartimenti separati

**Contesto.** ADR-017 scarta l'uso di un LLM per anonimizzare, ma la sua obiezione principale — si
manderebbero i dati in chiaro a un terzo — riguarda i **modelli esterni**. Con un modello ospitato
sull'infrastruttura della compagnia quell'argomento non esiste, e restano scoperte proprio le
categorie che regex e NER non possono vedere: dati sanitari (Art. 9), giudiziari (Art. 10) e
narrativa identificante («infortunio durante il turno presso la ditta X il giorno Y»).

Serve quindi distinguere *dove* gira il modello da *cosa* gli si chiede di fare.

**Decisione — anonimizzazione a livelli, ciascuno per ciò che sa fare.**

| Livello | Strumento | Copre | Ordine di grandezza |
| :--- | :--- | :--- | :--- |
| 1 | Regex deterministiche (`security/pii.py`) | Formati rigidi: CF, IBAN, polizza, targa, telaio | microsecondi |
| 2 | Presidio + NER italiano | Nomi e organizzazioni in testo libero | millisecondi |
| 3 | **LLM locale** | Dati sanitari e giudiziari, narrativa identificante | secondi |

Il livello 3 si applica **solo ai segmenti che i primi due non hanno risolto**, non all'intero
documento: è ciò che rende sostenibile un costo per pagina di secondi invece di microsecondi. Ed è
un ordine di precedenza, non un'alternativa: dove una regex basta, l'LLM è lo strumento peggiore —
più lento e non ripetibile.

**Decisione — servizi separati, con l'inferenza isolata dalla rete.**

```
[app]  →  [anonimizzatore]  →  [vector db]
             ↓ (rete interna, nessun egress)
        [llm locale]
```

Quattro container distinti: applicazione, anonimizzazione (Presidio ha immagini Docker ufficiali),
vector store, inferenza. Le ragioni, in ordine di importanza:

1. **Il container di inferenza non ha accesso a internet.** L'argomento di compliance non è più
   «garantiamo che i dati non escano», ma «non esiste un percorso attraverso cui possano uscire». È
   verificabile da un auditor guardando la configurazione di rete.
2. **Il modello che anonimizza va tenuto distinto da quello che genera.** Se coincidessero,
   un'istruzione nascosta in un documento potrebbe influenzare entrambi — e il primo è quello che
   vede i dati **in chiaro**, prima del mascheramento.
3. Profili di risorse diversi: l'inferenza vuole GPU o molta RAM, il vector store vuole disco,
   l'applicazione quasi nulla. Separarli permette di collocarli su macchine diverse senza toccare il
   codice.

**Conseguenze.** L'anonimizzatore **tratta dati personali in chiaro**: rientra nel perimetro come
qualunque altro componente, quindi log delle richieste disattivati e nessuna persistenza del
contesto. È un punto che sfugge facilmente, perché lo si pensa come "il componente che protegge" e
non come "un componente che vede tutto".

Il costo è in risorse, e i due livelli mancanti non costavano lo stesso: Presidio con il modello
linguistico grande occupa ~870 MB di RSS (misurati), un modello da 8 miliardi di parametri
quantizzato ne vuole circa 5 GB. Sui 12 GB del VPS il **livello 2 sta comodamente**, ed è stato
attivato (ADR-020); il **livello 3 resta future work**, perché a quel punto la generazione andrebbe
spostata su hardware con GPU o molta più RAM.

L'architettura a container è ciò che permette di aggiungerlo in seguito, anche su una macchina
diversa, senza riscrivere l'applicazione: `providers.py` astrae già il fornitore, e `PIIMasker` la
firma del mascheratore — il livello 2 si è agganciato lì senza toccare la pipeline.

---

## ADR-020 — Presidio affiancato alle regex, opzionale e senza degradazione silenziosa

**Contesto.** ADR-019 stabilisce *cosa* deve fare il livello 2; qui si decide *come* installarlo in
un progetto che deve continuare a girare offline. Tre vincoli in tensione: la lacuna è reale (nessuna
regex vede «il testimone Andrea Gallo ha dichiarato»), Presidio porta spaCy e un modello da ~540 MB,
e la demo deve restare installabile in un minuto.

**Decisione.**

1. **Affiancato, non sostitutivo, con precedenza al livello 1.** Le regex girano per prime e restano
   autoritative sui formati rigidi; il NER lavora sul testo già mascherato. Dove un pattern
   deterministico ha risposto, un modello probabilistico non rimette in discussione l'esito.
2. **Dipendenza opzionale, spenta per default** (`PII_NER_ENABLED=false`). Un protocollo di due
   proprietà e un metodo (`NerEngine` in `security/ner.py`) separa il masker dal motore: è ciò che
   permette di provare tutta la logica di integrazione con un doppio, senza installare nulla.
3. **Nessuna degradazione silenziosa.** Se il livello 2 è configurato ma non disponibile, il motivo
   viene dichiarato dove lo si cerca — riga di esito della CLI, scheda 🛡️ Sicurezza — oltre che nei
   log. Un livello di sicurezza spento senza che nessuno lo sappia è peggio di un livello assente.
4. **Nessun download implicito.** Presidio, davanti a un modello mancante, prova a scaricarlo e
   spaCy chiude il processo con `SystemExit`. Il modello viene quindi verificato *prima*
   (`modello_installato()`): un flag di configurazione non deve poter aprire una connessione da
   centinaia di MB né far cadere l'applicazione.
5. **Elenco esplicito di lessico contrattuale escluso dal riconoscimento.** Scoperta dal confronto
   sul corpus reale: il modello mascherava `## SEZIONE 1` e `l'Assicurato`, corrompendo il testo che
   l'LLM deve interpretare. Il punteggio di confidenza **non aiuta** — spaCy assegna `0,85` a ogni
   `PERSON`, nome vero o intestazione — quindi la soglia non può essere la difesa. Il filtro vale su
   entrambi i lati: senza, l'output guard sopprimerebbe ogni risposta che cita una clausola.
6. **Due soglie, in ingresso e in uscita.** In ingresso mascherare di troppo costa un segnaposto; in
   uscita un falso positivo sopprime una risposta già pagata in token. Con `it_core_news_lg` i
   punteggi sono costanti e il meccanismo è latente: diventa effettivo con un modello che produca
   confidenze graduate.

**Alternative scartate.** *Sostituire le regex con Presidio*: si perderebbero determinismo,
ripetibilità e i test che coprono i formati italiani, in cambio di un rilevatore che sugli stessi
formati non è migliore. *`PresidioReversibleAnonymizer` di `langchain-experimental`*: repository
archiviato il 26/05/2026 e non manutenuto. *Presidio come microservizio Docker* (immagini ufficiali
esistono): è la strada di ADR-019, ma aggiunge un container che il VPS attuale non ospita.
*Alzare la soglia di confidenza* per contenere i falsi positivi: inefficace, perché il punteggio è
costante.

**Conseguenze.** La copertura sui nomi in testo libero passa da «solo dopo un ruolo contrattuale» a
«anche in mezzo a una frase», al costo di ~50-80 ms per documento contro ~1 ms (misurato su
`data/policies/`). In cambio entrano due oneri nuovi: l'elenco del lessico contrattuale va mantenuto
quando cambia il vocabolario dei documenti, e **un mancato riconoscimento non produce alcun segnale**
— un rilevatore probabilistico aumenta la copertura, non la garanzia.

**Sull'istanza pubblica il livello 2 è attivo**: il modello è nell'immagine Docker con la versione
fissata, e `PII_NER_ENABLED` vale `true` nel compose. Nell'installazione da sorgente resta spento,
perché lì il vincolo non è la RAM ma il tempo di installazione.

Vincolo operativo che ne deriva: **cambiare `PII_NER_ENABLED` impone un nuovo `ingest`**, perché il
corpus indicizzato porta i segnaposto del livello attivo al momento dell'indicizzazione. Lasciarlo
come avvertenza nella documentazione non bastava — su un volume persistente l'ingestion viene
saltata, quindi un indice di livello 1 sarebbe sopravvissuto sotto un'interfaccia che dichiara il
livello 2. L'indice porta perciò una **marca** con i livelli usati per costruirlo
(`.anonymization`), e `ingest_decision()` reindicizza quando non coincide con la configurazione, o
quando manca: un indice di provenienza ignota non permette di affermare nulla sui propri segnaposto.
