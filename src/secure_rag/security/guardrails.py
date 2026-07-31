"""Guardrails di input, di contesto e di output.

Tre punti di controllo distinti, perché gli attacchi arrivano da tre direzioni diverse:

1. **Input guard** — la query dell'utente (prompt injection *diretta*, tentativi di esfiltrazione,
   domande fuori ambito). Mappa su OWASP LLM01 e LLM02.
2. **Context guard** — i chunk recuperati dal vector store (prompt injection *indiretta*: il payload
   è nascosto dentro un documento indicizzato in buona fede). È il vettore d'attacco più insidioso
   nei sistemi RAG, perché il testo malevolo non passa mai dalla chat.
3. **Output guard** — la risposta generata (fuga di dati personali, risposte non ancorate al
   contesto). Mappa su LLM06 e LLM09.

Implementazione a regole deterministiche: leggibile, testabile e senza costi di inferenza. In
produzione questo layer va affiancato (non sostituito) da NeMo Guardrails o Guardrails AI e da un
classificatore di injection addestrato, mantenendo le stesse firme di funzione.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from langchain_core.documents import Document

from secure_rag.security.pii import PIIMasker, build_masker

# ---------------------------------------------------------------------------
# Verdetti
# ---------------------------------------------------------------------------


@dataclass
class GuardVerdict:
    """Esito di un controllo di sicurezza.

    Non è un booleano: `reason` e `matches` finiscono nell'audit trail, ed è quello che permette a
    un revisore di ricostruire *perché* una richiesta è stata bloccata.
    """

    allowed: bool
    rule: str = ""
    reason: str = ""
    matches: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return not self.allowed


@dataclass
class ContextScanResult:
    """Esito della scansione dei chunk recuperati."""

    documents: list[Document]
    quarantined: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return not self.quarantined


# ---------------------------------------------------------------------------
# 1. Input guard — prompt injection diretta e uso improprio
# ---------------------------------------------------------------------------

MAX_QUERY_LENGTH = 1200

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "override_istruzioni",
        re.compile(
            r"ignor[ae]\s+(?:tutte\s+)?(?:le\s+)?(?:tue\s+)?istruzioni"
            r"|dimentica\s+(?:tutte\s+)?le\s+(?:tue\s+)?(?:istruzioni|regole)"
            r"|ignore\s+(?:all\s+)?(?:your\s+)?(?:previous\s+)?instructions"
            r"|disregard\s+(?:the\s+)?(?:above|previous)",
            re.IGNORECASE,
        ),
    ),
    (
        "cambio_ruolo",
        re.compile(
            r"\bsei\s+ora\b|\bda\s+ora\s+in\s+poi\s+sei\b|\bagisci\s+come\b"
            r"|\byou\s+are\s+now\b|\bact\s+as\b|\bpretend\s+to\s+be\b"
            r"|modalit[àa]\s+(?:amministrat|sviluppat|developer|admin)"
            r"|\bdeveloper\s+mode\b|\bDAN\b|\bjailbreak\b",
            re.IGNORECASE,
        ),
    ),
    (
        "system_override",
        re.compile(
            r"system\s*(?:override|prompt|:)\s*|<\s*\|?\s*(?:im_start|system)\s*\|?\s*>"
            r"|\bprompt\s+di\s+sistema\b|\brivela\s+(?:il\s+)?(?:tuo\s+)?prompt\b",
            re.IGNORECASE,
        ),
    ),
    (
        "esfiltrazione_dati",
        re.compile(
            r"\b(?:mostrami|dammi|elenca|rivela|stampa)\b.{0,40}"
            r"\b(?:iban|codice\s+fiscale|password|api\s*key|chiave|credenzial)"
            r"|\bdati\s+(?:personali|sensibili)\s+(?:dell|di)\b"
            r"|\btutti\s+i\s+(?:clienti|nominativi|contraenti)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "manipolazione_liquidazione",
        re.compile(
            r"\bapprova\b.{0,40}\b(?:risarciment|liquidazion|sinistr)"
            r"|\bautorizza\b.{0,40}\bpagament"
            r"|\bsenza\s+perizia\b|\bsenza\s+autorizzazione\b",
            re.IGNORECASE,
        ),
    ),
]


def validate_input(query: str) -> GuardVerdict:
    """Controlla la query dell'utente prima che raggiunga il retrieval e l'LLM."""
    stripped = query.strip()

    if not stripped:
        return GuardVerdict(False, "query_vuota", "La domanda è vuota.")

    if len(stripped) > MAX_QUERY_LENGTH:
        return GuardVerdict(
            False,
            "lunghezza_anomala",
            f"Query di {len(stripped)} caratteri: oltre il limite di {MAX_QUERY_LENGTH}. "
            "Lunghezze anomale sono un vettore tipico di context stuffing.",
        )

    for rule, pattern in _INJECTION_PATTERNS:
        found = pattern.findall(stripped)
        if found:
            return GuardVerdict(
                False,
                rule,
                "Rilevato un pattern riconducibile a prompt injection diretta "
                f"(regola: {rule}).",
                matches=[m if isinstance(m, str) else " ".join(m) for m in found][:5],
            )

    return GuardVerdict(True, "input_ok", "Nessun pattern sospetto rilevato.")


# ---------------------------------------------------------------------------
# 2. Context guard — prompt injection indiretta nei documenti recuperati
# ---------------------------------------------------------------------------

_INDIRECT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "istruzioni_nel_documento",
        re.compile(
            r"ignor[ae]\s+(?:tutte\s+)?(?:le\s+)?istruzioni"
            r"|istruzioni\s+di\s+sistema"
            r"|system\s*override"
            r"|priorit[àa]\s+massima"
            r"|quando\s+l['’]assistente\s+legge"
            r"|modalit[àa]\s+amministrativa"
            r"|non\s+menzionare\s+(?:all['’]utente|queste)"
            r"|deve\s+approvare\s+automaticamente",
            re.IGNORECASE,
        ),
    ),
    (
        "contenuto_nascosto",
        re.compile(r"<!--.*?-->|\bdisplay\s*:\s*none\b|color\s*:\s*#fff", re.IGNORECASE | re.DOTALL),
    ),
]


def scan_context(documents: Iterable[Document]) -> ContextScanResult:
    """Isola i chunk che contengono istruzioni rivolte all'assistente.

    I chunk sospetti non vengono semplicemente scartati: vengono **messi in quarantena** e
    l'evento viene registrato. Scartarli in silenzio nasconderebbe un tentativo di manomissione
    dei documenti, che è di per sé un incidente di sicurezza da segnalare.
    """
    safe: list[Document] = []
    quarantined: list[str] = []
    findings: list[str] = []

    for document in documents:
        matched_rules = [
            rule for rule, pattern in _INDIRECT_PATTERNS if pattern.search(document.page_content)
        ]
        if matched_rules:
            source = str(document.metadata.get("source", "sconosciuto"))
            quarantined.append(source)
            findings.extend(f"{source}: {rule}" for rule in matched_rules)
        else:
            safe.append(document)

    return ContextScanResult(documents=safe, quarantined=quarantined, findings=findings)


# ---------------------------------------------------------------------------
# 3. Output guard — fuga di PII e risposte non ancorate
# ---------------------------------------------------------------------------

_REFUSAL_MARKERS = ("informazione non presente", "non è presente nella documentazione")


def validate_output(answer: str, context_used: str = "", masker: PIIMasker | None = None) -> GuardVerdict:
    """Controlla la risposta generata prima di mostrarla all'utente."""
    # La pipeline passa il proprio masker, che condivide il vault e il livello di anonimizzazione
    # attivo. Il ripiego serve a chi chiama il guard da solo.
    masker = masker or build_masker()

    leaked = masker.detect(answer)
    if leaked:
        types = sorted({entity.entity_type for entity in leaked})
        return GuardVerdict(
            False,
            "pii_in_output",
            "La risposta contiene dati personali in chiaro: bloccata prima della consegna "
            f"(tipi rilevati: {', '.join(types)}).",
            matches=types,
        )

    lowered = answer.lower()
    is_refusal = any(marker in lowered for marker in _REFUSAL_MARKERS)
    if context_used and not is_refusal and not _is_grounded(answer, context_used):
        return GuardVerdict(
            False,
            "risposta_non_ancorata",
            "La risposta non risulta sufficientemente ancorata al contesto recuperato: "
            "possibile allucinazione.",
        )

    return GuardVerdict(True, "output_ok", "Nessun dato personale in chiaro, risposta ancorata al contesto.")


# Fine di una frase: punto, punto e virgola, due punti o a capo, seguiti da spazio o fine testo.
# È l'unità con cui il guard rilascia il testo durante lo streaming.
_FINE_FRASE_RE = re.compile(r"(?<=[.;:!?])\s+|\n+")

# Caratteri finali del buffer che non vengono mai rilasciati durante lo streaming. Va tenuta più
# lunga del più esteso pattern riconosciuto — l'indirizzo, che con nome di via e civico arriva
# intorno ai sessanta caratteri — perché nessun dato personale possa essere mostrato a metà,
# quando ancora non corrisponde ad alcuna regola.
_CODA_SICURA = 96


class StreamingOutputGuard:
    """Output guard applicato **mentre** la risposta viene generata.

    Serve a tenere insieme due proprietà che sembrano incompatibili: mostrare il testo man mano che
    arriva, e non mostrare mai testo non verificato. Lo streaming ingenuo le rompe — manda in pagina
    i token appena il modello li produce, quindi *prima* di qualunque controllo, e un massimale
    inventato o un codice fiscale rigenerato sono già stati letti quando il guard interviene.
    Ritirarli dopo non li fa dimenticare a chi li ha visti.

    L'osservazione che scioglie il nodo: **i controlli non hanno bisogno della risposta intera.**
    Un dato personale e una cifra inventata si riconoscono su un frammento esattamente come sul
    testo completo. Quello che serve è non rilasciare mai un frammento prima di averlo verificato.

    Come funziona:

    1. Il testo che arriva si accumula in un buffer, e a ogni frase completata **l'intero buffer**
       viene rivalidato — non solo la parte nuova.
    2. Gli ultimi `_CODA_SICURA` caratteri non vengono **mai** rilasciati. È il dettaglio che rende
       la garanzia solida invece che probabile: la coda è più lunga del più lungo pattern
       riconosciuto, quindi qualunque dato personale è per intero dentro al buffer — e quindi già
       verificato — prima che il suo primo carattere superi il confine del rilascio.
    3. Si rilascia per frasi, non per caratteri: un testo che compare a metà parola si legge peggio
       di uno che compare a piccoli blocchi.
    4. Se un controllo scatta, il rilascio si ferma lì. Ciò che è già a schermo ha superato i
       controlli; il resto non compare.

    **Cosa resta a posteriori, e va detto:** la soglia lessicale di groundedness ha senso solo sul
    testo completo — su tre parole qualunque rapporto è rumore — quindi viene applicata alla
    chiusura. È il controllo debole, quello contro le risposte inventate di sana pianta; i due che
    riguardano dati personali e cifre sono preventivi.
    """

    def __init__(self, context: str, masker: PIIMasker | None = None) -> None:
        self._context = context
        self._masker = masker or build_masker()
        self._numeri_contesto = _numeri(context)
        self._buffer = ""
        self._rilasciato = 0
        self.verdict: GuardVerdict | None = None

    @property
    def blocked(self) -> bool:
        return self.verdict is not None and self.verdict.blocked

    @property
    def testo_completo(self) -> str:
        """Tutto ciò che il modello ha prodotto, rilasciato o no."""
        return self._buffer

    def feed(self, chunk: str) -> str:
        """Aggiunge un pezzo generato e restituisce il testo che può essere mostrato.

        Restituisce stringa vuota finché non c'è una frase interamente verificata da rilasciare.
        """
        if self.blocked:
            return ""

        self._buffer += chunk

        # Confine del rilascio: mai dentro alla coda di sicurezza.
        frontiera = len(self._buffer) - _CODA_SICURA
        fine = max(
            (posizione for posizione in self._frasi_complete() if posizione <= frontiera),
            default=0,
        )
        if fine <= self._rilasciato:
            return ""

        verdetto = self._verifica_preventiva(self._buffer)
        if verdetto is not None:
            self.verdict = verdetto
            return ""

        emesso = self._buffer[self._rilasciato : fine]
        self._rilasciato = fine
        return emesso

    def close(self) -> tuple[str, GuardVerdict]:
        """Chiude lo stream: verifica il testo completo e restituisce la coda non ancora rilasciata."""
        if self.blocked:
            return "", self.verdict  # type: ignore[return-value]

        verdetto = validate_output(self._buffer, context_used=self._context, masker=self._masker)
        self.verdict = verdetto
        if verdetto.blocked:
            return "", verdetto

        coda = self._buffer[self._rilasciato :]
        self._rilasciato = len(self._buffer)
        return coda, verdetto

    # -------------------------------------------------------------- interni

    def _frasi_complete(self) -> list[int]:
        """Posizioni di fine delle frasi concluse, esclusa quella ancora in formazione."""
        return [trovato.end() for trovato in _FINE_FRASE_RE.finditer(self._buffer)]

    def _verifica_preventiva(self, testo: str) -> GuardVerdict | None:
        """I due controlli che non richiedono la risposta intera. `None` se il testo può passare."""
        leaked = self._masker.detect(testo)
        if leaked:
            tipi = sorted({entita.entity_type for entita in leaked})
            return GuardVerdict(
                False,
                "pii_in_output",
                "La risposta contiene dati personali in chiaro: interrotta prima della consegna "
                f"(tipi rilevati: {', '.join(tipi)}).",
                matches=tipi,
            )

        # Una cifra che tocca la fine del buffer può essere ancora in formazione: «5.000» che
        # diventerà «5.000.000». Bloccarla sarebbe un falso positivo generato dallo streaming
        # stesso, cioè il difetto peggiore che questo meccanismo potesse introdurre.
        inventate = _numeri(testo, ignora_finale=True) - self._numeri_contesto
        if inventate:
            return GuardVerdict(
                False,
                "risposta_non_ancorata",
                "La risposta contiene cifre che non compaiono nei documenti recuperati "
                f"({', '.join(sorted(inventate))}): interrotta prima della consegna.",
                matches=sorted(inventate),
            )
        return None


# Cifre della risposta, con i separatori italiani di migliaia e decimali.
_NUMERI_RE = re.compile(r"\d[\d.,]*")


def _numeri(testo: str, ignora_finale: bool = False) -> set[str]:
    """Valori numerici normalizzati, per confrontarli a prescindere dalla formattazione.

    `5.000.000`, `5000000` e `5.000.000,00` devono risultare lo stesso valore: è la stessa cifra
    scritta in tre modi, e un controllo che li distinguesse bloccherebbe risposte corrette.

    `ignora_finale` scarta una cifra che tocca la fine del testo: serve durante lo streaming, dove
    il testo è un frammento e l'ultima cifra può non essere ancora finita.
    """
    trovati = set()
    for trovato in _NUMERI_RE.finditer(testo):
        if ignora_finale and trovato.end() == len(testo):
            continue
        pulito = trovato.group(0).rstrip(".,").replace(".", "").replace(",", "")
        if pulito:
            trovati.add(pulito.lstrip("0") or "0")
    return trovati


def _is_grounded(answer: str, context: str, threshold: float = 0.2) -> bool:
    """Proxy di groundedness, in due controlli con pesi diversi.

    **1. Ogni cifra della risposta deve esistere nel contesto.** È il controllo che conta: in una
    polizza l'allucinazione dannosa non è una parola fuori posto, è un massimale inventato, una
    franchigia sbagliata, un articolo che non esiste. Chi legge agisce su quei numeri.

    **2. Una soglia lessicale minima**, contro le risposte costruite di sana pianta che non
    condividono nemmeno il vocabolario del contesto.

    La versione precedente aveva **solo** il secondo controllo, con soglia 0,35, e confondeva la
    parafrasi con l'invenzione: una risposta corretta che spiegava il dato con parole proprie veniva
    soppressa, mentre una che ricopiava il lessico del contesto cambiando una cifra passava. Era il
    contrario di quello che serve — e si è visto solo chiedendo al modello risposte più discorsive.

    Resta un proxy, non una misura semantica: in produzione servirebbe un valutatore basato su
    modello (LLM-as-a-judge o Ragas) tracciato su LangSmith.
    """
    numeri_inventati = _numeri(answer) - _numeri(context)
    if numeri_inventati:
        return False

    answer_tokens = {token for token in re.findall(r"\w{5,}", answer.lower())}
    if not answer_tokens:
        return True
    context_tokens = set(re.findall(r"\w{5,}", context.lower()))
    return len(answer_tokens & context_tokens) / len(answer_tokens) >= threshold
