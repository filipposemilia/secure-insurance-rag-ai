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

from secure_rag.security.pii import PIIMasker

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
    masker = masker or PIIMasker()

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


def _is_grounded(answer: str, context: str, threshold: float = 0.35) -> float | bool:
    """Proxy di groundedness: quota di termini significativi della risposta presenti nel contesto.

    È volutamente una euristica lessicale, non una misura semantica. In produzione si userebbe un
    valutatore basato su modello (LLM-as-a-judge o Ragas) tracciato su LangSmith.
    """
    answer_tokens = {
        token for token in re.findall(r"\w{5,}", answer.lower())
    }
    if not answer_tokens:
        return True
    context_tokens = set(re.findall(r"\w{5,}", context.lower()))
    overlap = len(answer_tokens & context_tokens) / len(answer_tokens)
    return overlap >= threshold
