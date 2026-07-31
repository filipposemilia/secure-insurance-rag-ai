"""Catalogo dei dieci rischi OWASP Top 10 for LLM Applications, e di come questo sistema li tratta.

Esiste per una ragione precisa: la stessa informazione viveva in **tre posti** — la tabella di
`docs/SECURITY.md`, quella del `README.md` e il campo `owasp` degli scenari in `cli.py` — e aveva
già divergato. Contando le righe di `SECURITY.md` se ne trovavano dieci, ma coprivano nove codici:
`LLM01` compariva due volte e **`LLM05` non compariva mai**. Una lacuna che nessuno nota rileggendo,
e che un test trova in un millisecondo.

Da qui la scelta di tenere il catalogo nel codice: l'interfaccia lo mostra, i test lo verificano, e
la documentazione resta il testo discorsivo invece della fonte dei dati.

**Tre stati, non due.** La distinzione che conta non è «coperto / non coperto» ma:

- `applicabile=True` con scenari → si può premere un pulsante e guardare cosa succede;
- `applicabile=True` senza scenari → il rischio esiste ed è mitigato, ma non si dimostra con un
  clic: la catena di fornitura non ha un attacco da eseguire a runtime;
- `applicabile=False` → il rischio **non si applica a questo sistema**, e il motivo è dichiarato.

L'ultimo caso è il più importante da mostrare invece che nascondere. Riempire la griglia con dieci
pulsanti darebbe l'impressione di una copertura completa; chi verifica scoprirebbe che tre di quei
pulsanti dimostrano qualcos'altro, e a quel punto perderebbe fiducia anche nei sette veri.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class OwaspRisk:
    """Un rischio del catalogo OWASP e il modo in cui questo sistema lo affronta."""

    codice: str
    titolo: str
    applicabile: bool
    sintesi: str
    # Il limite dichiarato, se il rischio è mitigato; cosa lo renderebbe applicabile, se non lo è.
    nota: str = ""
    # Nomi degli scenari eseguibili, come compaiono in `cli.SCENARIOS`. Il riferimento è per nome e
    # non per oggetto per non legare questo catalogo alla CLI: un test verifica che esistano.
    scenari: tuple[str, ...] = field(default_factory=tuple)

    @property
    def eseguibile(self) -> bool:
        return bool(self.scenari)


OWASP_RISKS: tuple[OwaspRisk, ...] = (
    OwaspRisk(
        codice="LLM01",
        titolo="Prompt Injection",
        applicabile=True,
        sintesi=(
            "Input guard a pattern sulla domanda, e scansione dei documenti recuperati per la "
            "variante indiretta — quella nascosta dentro un allegato che il sistema legge in "
            "buona fede."
        ),
        nota=(
            "Le regole sono deterministiche: un attacco riformulato con sinonimi o in un'altra "
            "lingua può eluderle. Servirebbe un classificatore addestrato."
        ),
        scenari=(
            "2. Prompt injection diretta",
            "3. Prompt injection indiretta (payload nel documento)",
        ),
    ),
    OwaspRisk(
        codice="LLM02",
        titolo="Insecure Output Handling",
        applicabile=True,
        sintesi=(
            "La risposta non viene mai eseguita né interpretata: è testo. L'output guard è "
            "applicato anche durante lo streaming, quindi ciò che compare a schermo è già stato "
            "verificato."
        ),
        nota=(
            "Non esiste sanitizzazione HTML perché non esiste rendering di HTML generato dal "
            "modello: sarebbe una difesa per un percorso che non c'è."
        ),
        scenari=("4. Esfiltrazione di dati personali",),
    ),
    OwaspRisk(
        codice="LLM03",
        titolo="Training Data Poisoning",
        applicabile=False,
        sintesi=(
            "Non si applica: nessun fine-tuning, nessun addestramento. È uno dei motivi per cui "
            "in questo dominio il RAG è preferibile a un modello addestrato sui documenti."
        ),
        nota=(
            "Il corpus indicizzato **è** però avvelenabile, ed è l'equivalente del rischio per un "
            "sistema RAG: lo mostra lo scenario di prompt injection indiretta."
        ),
    ),
    OwaspRisk(
        codice="LLM04",
        titolo="Model Denial of Service",
        applicabile=True,
        sintesi=(
            "Limite di lunghezza sulla domanda, numero di documenti recuperati fisso, tetto di "
            "dimensione sui file caricati, e limiti di frequenza sull'istanza pubblica: quota per "
            "visitatore e tetto di spesa giornaliero."
        ),
        nota=(
            "I contatori vivono nella memoria del processo: con più repliche servirebbe uno store "
            "condiviso, e un riavvio li azzera."
        ),
        scenari=("7. Query fuori misura",),
    ),
    OwaspRisk(
        codice="LLM05",
        titolo="Supply Chain Vulnerabilities",
        applicabile=True,
        sintesi=(
            "Dipendenze dichiarate in `pyproject.toml`, immagine costruita da `python:3.12-slim`, "
            "e il modello linguistico installato da un wheel con **versione fissata** nel "
            "Dockerfile invece che risolta al momento della build."
        ),
        nota=(
            "Non è dimostrabile con un clic: è una proprietà della catena di costruzione, non un "
            "attacco a runtime. Manca il resto: nessuna verifica di firma, nessun SBOM, nessuna "
            "scansione delle vulnerabilità in integrazione continua."
        ),
    ),
    OwaspRisk(
        codice="LLM06",
        titolo="Sensitive Information Disclosure",
        applicabile=True,
        sintesi=(
            "Anonimizzazione prima dell'embedding: nel vector store non esiste un dato personale "
            "in chiaro. Controllo degli accessi applicato al recupero, non alla risposta. Output "
            "guard sulle PII e audit senza la domanda in chiaro."
        ),
        nota=(
            "Restano fuori i dati sanitari e giudiziari: non sono entità ma affermazioni, e non li "
            "vede né una regola né un riconoscitore di entità."
        ),
        scenari=(
            "4. Esfiltrazione di dati personali",
            "5. Violazione RBAC (documento riservato alla direzione)",
            "6. Stessa domanda con ruolo autorizzato",
        ),
    ),
    OwaspRisk(
        codice="LLM07",
        titolo="Insecure Plugin Design",
        applicabile=False,
        sintesi=(
            "Non si applica: il modello non dispone di alcuno strumento. Non c'è nulla da "
            "invocare, quindi nulla di cui abusare."
        ),
        nota=(
            "Diventerebbe applicabile con LangGraph e azioni di liquidazione: lì servirebbe "
            "l'approvazione umana come nodo obbligatorio del flusso, non come controllo aggiunto "
            "attorno."
        ),
    ),
    OwaspRisk(
        codice="LLM08",
        titolo="Excessive Agency",
        applicabile=True,
        sintesi=(
            "Il sistema è read-only per costruzione: nessuna scrittura, nessuna approvazione, "
            "nessuna chiamata a sistemi terzi. Le richieste di far agire il sistema sulla "
            "liquidazione sono inoltre fermate dall'input guard."
        ),
        nota=(
            "Il rischio è basso perché il sistema può fare poco, non perché sia stato reso "
            "sicuro: è una proprietà dell'ambito, e cambierebbe il giorno in cui il modello "
            "preparasse una bozza di liquidazione."
        ),
        scenari=("8. Tentativo di far agire il sistema",),
    ),
    OwaspRisk(
        codice="LLM09",
        titolo="Overreliance",
        applicabile=True,
        sintesi=(
            "Temperatura a zero, obbligo di citare la fonte, formula esplicita di non-risposta "
            "quando il contesto non copre la domanda, e un controllo che blocca le risposte "
            "contenenti cifre assenti dai documenti."
        ),
        nota=(
            "Resta un proxy: una cifra corretta attribuita alla voce sbagliata lo supera, e "
            "un'affermazione falsa senza numeri è coperta solo dalla soglia lessicale."
        ),
        scenari=("9. Domanda fuori dal corpus",),
    ),
    OwaspRisk(
        codice="LLM10",
        titolo="Model Theft",
        applicabile=False,
        sintesi=(
            "Non si applica: nessun modello proprietario è ospitato qui. Il modello che genera è "
            "di un fornitore esterno, quelli locali sono pubblici e scaricabili da chiunque."
        ),
        nota=(
            "Diventerebbe applicabile con un modello addestrato sui dati della compagnia, che è "
            "esattamente la strada che il RAG evita."
        ),
    ),
)


def rischio(codice: str) -> OwaspRisk:
    """Il rischio con questo codice. Solleva `KeyError` se non esiste, invece di restituire `None`."""
    for voce in OWASP_RISKS:
        if voce.codice == codice:
            return voce
    raise KeyError(f"Rischio OWASP sconosciuto: {codice}")
