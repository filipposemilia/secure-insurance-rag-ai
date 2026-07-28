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

## ADR-007 — Chunk da 800 caratteri con overlap 120

**Contesto.** Il documento di partenza proponeva 300/50.

**Decisione.** 800/120.

**Motivo.** Le clausole assicurative sono periodi lunghi con condizioni concatenate ("a condizione
che… salvo che…"). Chunk da 300 caratteri spezzano la condizione dalla sua eccezione, producendo
risposte formalmente ancorate ma sostanzialmente sbagliate.
