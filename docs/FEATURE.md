# Evoluzione enterprise: dove va il progetto dentro una compagnia

> **Come si distingue da `ROADMAP.md`.** La roadmap elenca ciò che manca a *questo* codice, con lo
> sforzo per aggiungerlo: è il backlog di un repository. Questo documento guarda un passo più in là —
> cosa diventa il progetto quando entra nell'infrastruttura di una compagnia assicurativa, con un SOC
> che vigila, un CISO che detta le policy e un identity provider che dice chi è chi. Diverse sono le
> domande a cui rispondono: la roadmap risponde a «cosa non ho ancora scritto», questo a «cosa
> cambierebbe se il sistema smettesse di essere mio».
>
> Sei delle otto proposte hanno una voce corrispondente in roadmap, indicata nella tabella. Quando i
> due documenti si sovrappongono, **la stima di sforzo autorevole è quella della roadmap**: qui
> l'ampiezza è maggiore e i numeri lo sarebbero altrettanto.

| # | Proposta | Voce in `ROADMAP.md` | Sforzo |
| :--- | :--- | :--- | :--- |
| 1 | Integrazione SOC (Sentinel / Splunk) | Export dell'audit verso SIEM | ~2 h il connettore, ~1 g le regole |
| 2 | DLP e classificazione centralizzata | — | ~1 g |
| 3 | Confidential computing | — | alto, è infrastruttura |
| 4 | Agentic RAG con LangGraph | LangGraph con human-in-the-loop | ~1 g |
| 5 | Autenticazione reale e multiutente | Autenticazione reale (OIDC/JWT) + FastAPI | ~1 g + ~2 g |
| 6 | Red teaming automatico in CI | Suite di red teaming | ~1 g |
| 7 | Hybrid search | Hybrid search (BM25 + vettoriale) | ~4 h |
| 8 | OCR sui PDF scansionati | Ingestion di PDF scansionati (OCR) | ~4 h |

## 1. Dal file di audit al SOC

L'audit trail è oggi un JSONL su volume: sufficiente perché un revisore ricostruisca una risposta a
mesi di distanza, insufficiente perché qualcuno se ne accorga *mentre* accade. Il formato è già
quello giusto da spedire — una riga per interazione, con verdetti dei guard, fonti e quarantene.

Quello che cambia in azienda non è il trasporto, sono le **regole di correlazione**. Alcuni esempi
che hanno senso proprio per un sistema RAG, e che un SIEM generico non porta con sé:

- più di tre tentativi di prompt injection dallo stesso soggetto in cinque minuti;
- un profilo che interroga un volume anomalo di polizze in un'ora — è comportamento da esfiltrazione,
  non da consultazione, e si riconosce solo confrontando con la baseline dell'utente (UEBA);
- un documento che entra nell'indice e finisce in quarantena: è un tentativo di injection indiretta,
  cioè qualcuno che ha usato un canale legittimo — un allegato di sinistro — come vettore.

La risposta automatica (SOAR: revocare la sessione, sospendere il profilo) è la parte più
appariscente ed è anche quella **che dipende dalla proposta 5**: senza identità verificata non c'è
niente da revocare, perché oggi il ruolo è dichiarato da chi apre la pagina. Vale la pena dirlo
nell'ordine giusto, invece di presentare l'automazione come immediata.

## 2. Classificazione dei dati gestita dal CISO, non dal RAG

L'anonimizzazione gira su due livelli in locale — regex e NER (ADR-020). Funziona, ma incorpora una
decisione che in azienda non spetta a chi scrive il RAG: **cosa conta come dato sensibile**. Oggi
quella definizione vive in `_PATTERNS` e nell'elenco delle entità NER, cioè in un file di codice.

In un ecosistema strutturato la stessa definizione esiste già altrove — etichette di sensibilità di
Microsoft Purview, policy DLP, tassonomie di classificazione — ed è gestita da chi ne risponde. Il
guadagno non è tecnico: è che il RAG smette di avere una propria opinione sulla materia e ne eredita
una coerente con il resto dell'azienda.

**Un vincolo da non aggirare**, che vale la pena conoscere prima di scegliere il servizio: ADR-017
scarta l'anonimizzazione delegata a un servizio esterno, perché per farsi rimuovere i dati personali
bisognerebbe prima inviarli — il trattamento avviene nel momento dell'invio. L'argomento decade solo
se il servizio sta **dentro il perimetro del titolare**: un tenant Azure della compagnia, con i
propri accordi sul trattamento, non è un fornitore terzo nello stesso senso in cui lo è un'API
pubblica. È una distinzione contrattuale prima che tecnica, e va verificata con chi segue la
compliance, non assunta.

L'aggancio nel codice esiste già: il protocollo `NerEngine` in `security/ner.py` è la firma con cui
un motore esterno entrerebbe al posto — o accanto — a Presidio.

## 3. Confidential computing: cifrare anche verso l'amministratore

L'architettura software difende dagli utenti del sistema. Non difende da chi ha privilegi
sull'infrastruttura che lo ospita: un amministratore del cloud può leggere la memoria di un processo.
Eseguire i container in enclave hardware (Azure Confidential VM con AMD SEV-SNP, Intel TDX) cifra la
memoria a livello di CPU e toglie anche quella possibilità.

**Dove serve davvero, in questo sistema specifico.** Vale la pena essere precisi, perché il guadagno
non è uniforme:

| Componente | Cosa contiene | Guadagno |
| :--- | :--- | :--- |
| Vector store | Solo segnaposto: l'anonimizzazione precede l'embedding | Modesto — è la conseguenza voluta di ADR-001 |
| Processo che anonimizza | **Dati in chiaro**, prima del mascheramento | Il più alto di tutti |
| Vault dei segnaposto | La mappa verso i valori reali | Alto, dove il vault è acceso (ADR-018) |
| Prompt in transito | Testo mascherato più la domanda dell'utente | Medio |

L'ordine dice qualcosa di più generale: il componente da proteggere non è quello che *conserva* i
dati, è quello che li **vede in chiaro**. È la stessa osservazione di ADR-019 sull'anonimizzatore che
va trattato come parte del perimetro invece che come il custode del perimetro.

## 4. Da read-only ad agentico, con l'approvazione umana come nodo esplicito

Il sistema oggi è deliberatamente read-only: non compie azioni, ed è la ragione per cui l'Excessive
Agency (LLM08) resta un rischio basso — basso per **ambito**, non perché sia stato reso sicuro.
Passare a LangGraph significa rinunciare a quella
proprietà in cambio di lavoro istruttorio automatizzato — bozze di liquidazione, raccolta dei
documenti mancanti, verifica delle coperture.

Il punto che rende la cosa accettabile in ambito assicurativo è che l'approvazione umana diventa un
**nodo del grafo**, non un controllo aggiunto attorno: il flusso non può proseguire senza passarci.
Sotto una certa soglia di importo si può automatizzare, sopra si ferma e attende.

Va detto per intero: da quel momento il modello ha effetti economici, e l'intera sezione «cosa
succede se un layer cede» di `docs/SECURITY.md` va riscritta. Un'allucinazione in un sistema read-only è
una risposta sbagliata; in un sistema che agisce è una liquidazione sbagliata.

## 5. Identità verificata, e tutto ciò che ne dipende

Il ruolo è oggi scelto da un menu a tendina. È una scelta consapevole per una demo — serve a mostrare
l'effetto dell'RBAC sul retrieval facendo cambiare risposta alla stessa domanda — ed è dichiarata fra
i limiti in `docs/SECURITY.md`.

Con OIDC verso Entra ID i claim del token diventano il filtro di clearance sul vector store, e non
cambia una riga della logica di retrieval: `allowed_clearances(role)` riceve un ruolo verificato
invece che dichiarato. Il resto della catena non se ne accorge, ed è il segno che il confine era
tracciato nel punto giusto.

Tre cose che oggi non si possono fare, e che questa proposta sblocca in un colpo solo: revocare una
sessione (proposta 1), isolare i documenti caricati **per persona** invece che per sessione del
browser, e attribuire una riga di audit a qualcuno invece che a un indirizzo IP.

## 6. Red teaming come test di regressione, non come esercizio

I nove scenari della demo sono casi scelti a mano: servono a mostrare, non a misurare. Un sistema in
esercizio ha bisogno di sapere se un aggiornamento del modello lo ha reso vulnerabile — e quello
succede senza che nessuno tocchi il codice, perché la superficie di attacco di un LLM cambia quando
cambia l'LLM.

Framework come **PyRIT** o **Garak** eseguono migliaia di tecniche note in pipeline, e il risultato
utile è una soglia: se il tasso di elusione supera il valore concordato, la build si ferma. È
l'unico modo per trasformare «i guardrail sono a regole e una riformulazione creativa li elude» — che
oggi è un limite dichiarato onestamente — in un numero che si può vedere peggiorare.

Si combina con la voce di roadmap sulla **misura dei falsi negativi del livello 2**: sono lo stesso
problema visto da due lati, cioè quanto lascia passare una difesa che non è deterministica.

## 7. Hybrid search per la terminologia contrattuale

Un embedding trova male «articolo 14-bis», perché la somiglianza semantica non è la strada giusta per
un riferimento esatto. BM25 lo trova, e la fusione dei due ranking copre sia i concetti sia i codici.

In una polizza questo è più importante che in altri domini: le domande che contano citano articoli,
massimali e clausole per nome. La voce è in roadmap con lo sforzo stimato, e insieme al re-ranking
con cross-encoder risolve anche l'*alert fatigue* delle quarantene — meno chunk debolmente attinenti
recuperati significa meno documenti compromessi tirati dentro per caso.

## 8. OCR: i documenti veri arrivano come immagini

Perizie, referti, denunce firmate a mano: nel mondo assicurativo reale una quota rilevante di ciò che
entra nella pipeline è una scansione. Il loader attuale estrae solo testo nativo e su un PDF
scansionato restituisce l'errore «nessun testo estraibile (PDF scansionato? servirebbe OCR)» —
esplicito di proposito, per non far credere che il documento sia vuoto.

Un motore OCR (Azure Document Intelligence, o Tesseract in locale) estende il tipo di documenti
supportati. **La scelta fra i due non è solo di qualità**: un OCR in cloud vede il documento
*prima* dell'anonimizzazione, quindi rientra nello stesso ragionamento della proposta 2 e va dentro
il perimetro. È il tipo di conseguenza che si scopre tardi se non la si annota subito.

---

**Da dove partire.** Le prime due voci per rapporto fra valore e sforzo sono la **1** (il formato
dell'audit è già pronto: manca il trasporto e le regole) e la **6** (non tocca l'applicazione, si
aggancia alla CI). La **5** è quella che ne sblocca di più, ed è anche la più invasiva, perché
introduce un backend dove oggi c'è solo Streamlit.
