"""Layer di anonimizzazione PII.

Questo è il primo layer di sicurezza della pipeline: il testo viene ripulito dai dati personali
**prima** di essere trasformato in embedding e **prima** di finire in un prompt inviato all'LLM.
Il vector database e il provider LLM non vedono mai un codice fiscale o un IBAN in chiaro.

Le categorie coperte seguono l'elenco di un parere legale sul GDPR per il settore assicurativo:
identificativi diretti (nome, codice fiscale, recapiti, documenti d'identità, indirizzo) e
identificativi indiretti (numero di polizza, di sinistro e di pratica, IBAN, targa, telaio). Questi
ultimi contano quanto il nome: anche togliendo il nominativo, un numero di polizza riporta a una
persona sola.

**Restano scoperti**, e vanno dichiarati invece che sottintesi: i dati sanitari (Art. 9) e giudiziari
(Art. 10) — diagnosi, percentuali di invalidità, verbali — che **non hanno una forma riconoscibile**
e nessuna regex potrà mai individuare. Servono NER o un classificatore addestrato.

Scelta implementativa: regex deterministiche + dizionario di entità note, con un **livello 2
opzionale** (`security/ner.py`: Microsoft Presidio e un NER italiano) che si affianca alle regex per
i nomi in testo libero. Le regex girano per prime e restano autoritative sui formati rigidi — sono
ripetibili e coperte da test; il modello lavora su ciò che resta. Senza il livello 2 attivo il
comportamento è identico a quello di sempre, ed è il default.

I placeholder sono **stabili e numerati** (`[CF_001]`): la stessa entità riceve lo stesso segnaposto
in tutti i documenti, così il modello può ancora ragionare su "la stessa persona" senza conoscerne
l'identità. La mappa segnaposto → valore reale resta in memoria applicativa (`vault`) e può essere
usata per la ri-identificazione lato client, sotto controllo di accesso.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Pattern

from secure_rag.config import Settings, get_settings
from secure_rag.security.ner import NerEngine, NerSpan, build_ner_engine, is_contract_term


@dataclass(frozen=True)
class PIIEntity:
    """Una singola occorrenza di dato personale individuata nel testo."""

    entity_type: str
    original: str
    placeholder: str


@dataclass
class MaskingResult:
    """Esito di un'operazione di masking."""

    masked_text: str
    entities: list[PIIEntity] = field(default_factory=list)

    @property
    def entity_types(self) -> list[str]:
        """Tipi di PII trovati, senza duplicati, in ordine di apparizione."""
        seen: list[str] = []
        for entity in self.entities:
            if entity.entity_type not in seen:
                seen.append(entity.entity_type)
        return seen

    @property
    def count(self) -> int:
        return len(self.entities)


# L'ordine conta: i pattern più specifici vengono applicati per primi, altrimenti un pattern
# generico (es. sequenze numeriche) "mangia" pezzi di entità più strutturate come l'IBAN.
_PATTERNS: list[tuple[str, Pattern[str]]] = [
    # IBAN italiano ed europeo
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    # Codice fiscale persona fisica
    ("CF", re.compile(r"\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b")),
    # Numero di telaio (VIN): 17 caratteri, senza I, O e Q per non confonderle con 1 e 0.
    # Prima dei pattern più corti, che altrimenti ne mangerebbero un frammento.
    ("TELAIO", re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b")),
    # Numero di polizza, sinistro o pratica. Identificano un contratto riferibile a una persona:
    # per il GDPR sono identificativi indiretti quanto il nome.
    ("PRATICA", re.compile(r"\b[A-Z]{2,4}-\d{4}-\d{4,8}\b")),
    # Carta di credito (gruppi di 4 cifre, separatore opzionale)
    ("CARTA", re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b")),
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b")),
    # Telefono italiano, con o senza prefisso internazionale
    ("TELEFONO", re.compile(r"(?:\+39[ .-]?)?\b3\d{2}[ .-]?\d{6,7}\b")),
    # Targa automobilistica, formato in uso dal 1994
    ("TARGA", re.compile(r"\b[A-Z]{2}\d{3}[A-Z]{2}\b")),
    # Patente, carta d'identità, passaporto: condividono la forma due lettere + sette cifre
    ("DOCUMENTO", re.compile(r"\b[A-Z]{2}\d{7}[A-Z]?\b")),
    # Partita IVA / codice fiscale societario: 11 cifre isolate
    ("PIVA", re.compile(r"\b\d{11}\b")),
    # Indirizzo di residenza o dell'immobile assicurato: localizza una persona con la stessa
    # precisione di un recapito telefonico.
    (
        "INDIRIZZO",
        re.compile(
            r"\b(?:Via|Viale|Piazza|Piazzale|Corso|Largo|Vicolo|Strada)\s+"
            r"[A-Z][\w']+(?:\s+(?:degli|della|dei|del|di|de)?\s*[A-Z][\w']+)*,?\s+\d+[A-Za-z]?\b"
        ),
    ),
    # Data di nascita in formato gg/mm/aaaa, solo se preceduta da un indicatore
    ("DATA_NASCITA", re.compile(r"(?<=nato il )\d{2}/\d{2}/\d{4}|(?<=nata il )\d{2}/\d{2}/\d{4}")),
    # Nome proprio introdotto da un ruolo contrattuale (euristica; in produzione: NER)
    (
        "NOME",
        re.compile(
            r"(?<=Contraente: )[A-Z][\w']+(?: [A-Z][\w']+)+"
            r"|(?<=Referente: )[A-Z][\w']+(?: [A-Z][\w']+)+"
            r"|(?<=Assicurato: )[A-Z][\w']+(?: [A-Z][\w']+)+"
            r"|(?<=Beneficiario: )[A-Z][\w']+(?: [A-Z][\w']+)+"
            r"|(?<=Perito incaricato: )[A-Z][\w']+(?: [A-Z][\w']+)+"
            r"|\bSig(?:\.|ra\.?|nor[ae]?) [A-Z][\w']+(?: [A-Z][\w']+)+"
        ),
    ),
]

# Sequenze già mascherate: non devono essere ri-processate dai pattern successivi.
_PLACEHOLDER_RE = re.compile(r"\[[A-Z_]+_\d{3}\]")

# Scompone un segnaposto nei suoi due elementi, per riprendere i contatori da un vault caricato.
_PLACEHOLDER_PARTS = re.compile(r"\[([A-Z_]+)_(\d{3})\]")


class PIIMasker:
    """Maschera i dati personali mantenendo un vault stabile segnaposto → valore originale.

    L'istanza è **stateful di proposito**: riusare lo stesso masker su tutti i documenti di un
    ingest garantisce che lo stesso IBAN diventi sempre `[IBAN_001]`, preservando la coerenza
    referenziale tra chunk diversi.
    """

    def __init__(
        self,
        extra_names: Iterable[str] | None = None,
        ner: NerEngine | None = None,
        ner_threshold: float = 0.6,
        ner_detect_threshold: float = 0.85,
    ) -> None:
        self._vault: dict[str, str] = {}  # placeholder -> valore originale
        self._reverse: dict[str, str] = {}  # valore originale -> placeholder
        self._counters: dict[str, int] = {}
        # Nomi noti da mascherare anche quando compaiono senza ruolo contrattuale davanti. È il
        # ripiego di quando il livello 2 non è disponibile: un elenco compilato a mano.
        self._extra_names = sorted(set(extra_names or []), key=len, reverse=True)
        # Livello 2 (`security/ner.py`), assente per default. Con `ner=None` questa classe si
        # comporta esattamente come prima che il livello esistesse.
        self._ner = ner
        self._ner_threshold = ner_threshold
        self._ner_detect_threshold = ner_detect_threshold

    # ------------------------------------------------------------------ API

    def mask(self, text: str) -> MaskingResult:
        """Restituisce il testo anonimizzato e l'elenco delle entità sostituite."""
        entities: list[PIIEntity] = []
        masked = text

        for entity_type, pattern in _PATTERNS:
            masked = pattern.sub(
                lambda match, _type=entity_type: self._substitute(match.group(0), _type, entities),
                masked,
            )

        for name in self._extra_names:
            if name in masked:
                placeholder = self._placeholder_for(name, "NOME", entities)
                masked = masked.replace(name, placeholder)

        # Il livello 2 arriva per ultimo, sul testo già ripulito dalle regex: è l'ordine di
        # precedenza di ADR-019. Dove un pattern deterministico ha già risposto, un modello
        # probabilistico non deve poter rimettere in discussione l'esito.
        masked = self._apply_ner(masked, entities)

        return MaskingResult(masked_text=masked, entities=entities)

    @property
    def ner_active(self) -> bool:
        """True quando il livello 2 sta effettivamente lavorando, non solo quando è configurato."""
        return self._ner is not None

    @property
    def active_levels(self) -> str:
        """Livelli di anonimizzazione realmente attivi, da dichiarare a schermo.

        Un anonimizzatore che non dice con quale motore ha lavorato non è verificabile: la stessa
        frase produce risultati diversi a livello 1 e a livello 1+2.
        """
        if self._ner is None:
            return "1 (regex)"
        return f"1+2 (regex + NER {self._ner.model_name})"

    def detect(self, text: str) -> list[PIIEntity]:
        """Individua PII senza modificare il vault: usato dall'output guard.

        Serve a verificare che nella risposta generata dall'LLM non sia ricomparso un dato
        personale (per esempio perché il modello lo ha ricostruito o l'utente lo ha iniettato).

        Il livello 2, quando attivo, gira anche qui — ma con una **soglia più severa** che in
        ingresso. L'asimmetria è voluta: mascherare di troppo un documento costa un segnaposto,
        mentre in uscita un falso positivo sopprime una risposta per cui i token sono già stati
        spesi.
        """
        found: list[PIIEntity] = []
        cleaned = _PLACEHOLDER_RE.sub(" ", text)
        for entity_type, pattern in _PATTERNS:
            for match in pattern.finditer(cleaned):
                found.append(
                    PIIEntity(entity_type=entity_type, original=match.group(0), placeholder="")
                )

        if self._ner is not None:
            for span in self._ner_spans(cleaned, self._ner_detect_threshold):
                found.append(
                    PIIEntity(
                        entity_type=span.entity_type,
                        original=cleaned[span.start : span.end],
                        placeholder="",
                    )
                )
        return found

    def unmask(self, text: str) -> str:
        """Ripristina i valori originali. Da usare **solo** lato applicativo, mai verso l'LLM."""
        restored = text
        for placeholder, original in self._vault.items():
            restored = restored.replace(placeholder, original)
        return restored

    @property
    def vault(self) -> dict[str, str]:
        """Mappa segnaposto → valore reale. Non deve mai essere serializzata nel vector store."""
        return dict(self._vault)

    def load_vault(self, mapping: dict[str, str]) -> None:
        """Riprende una mappa prodotta da un'esecuzione precedente.

        Serve perché ingestion e interrogazione sono processi distinti: senza, lo stesso IBAN
        riceverebbe segnaposto diversi nei due momenti, e il testo indicizzato non corrisponderebbe
        più a quello che l'applicazione sa ricostruire.

        I contatori ripartono dal massimo già assegnato per ciascun tipo, altrimenti un segnaposto
        nuovo collirebbe con uno esistente sovrascrivendone il significato.
        """
        for placeholder, original in mapping.items():
            self._vault[placeholder] = original
            self._reverse[original] = placeholder

            match = _PLACEHOLDER_PARTS.fullmatch(placeholder)
            if match:
                entity_type, numero = match.group(1), int(match.group(2))
                self._counters[entity_type] = max(self._counters.get(entity_type, 0), numero)

    # -------------------------------------------------------------- interni

    def _ner_spans(self, text: str, threshold: float) -> list[NerSpan]:
        """Span del livello 2, già ripuliti dal lessico contrattuale.

        Il filtro sta qui e non nel motore perché vale per **entrambi** i lati: se «Assicurato»
        fosse trattato come un nome, non solo corromperebbe i documenti in ingresso, ma l'output
        guard sopprimerebbe qualunque risposta che cita una clausola.
        """
        if self._ner is None:
            return []
        return [
            span
            for span in self._ner.analyze(text, threshold)
            if not is_contract_term(text[span.start : span.end])
        ]

    def _apply_ner(self, text: str, entities: list[PIIEntity]) -> str:
        """Sostituisce le entità individuate dal modello, se il livello 2 è attivo."""
        if self._ner is None:
            return text

        spans = self._ner_spans(text, self._ner_threshold)
        if not spans:
            return text

        # Intervalli già occupati da un segnaposto del livello 1: `[CF_001]` non deve diventare
        # `[NOME_004]`, e un modello NER lo scambia volentieri per un codice.
        protetti = [(trovato.start(), trovato.end()) for trovato in _PLACEHOLDER_RE.finditer(text)]

        # Punteggio decrescente: fra due span sovrapposti vince quello in cui il modello crede di
        # più, non quello che arriva prima nel testo.
        scelti: list[NerSpan] = []
        for span in sorted(spans, key=lambda voce: (-voce.score, voce.start)):
            span_pulito = _restringi(span, text)
            if span_pulito is None:
                continue
            if any(
                span_pulito.start < fine and inizio < span_pulito.end
                for inizio, fine in protetti
            ):
                continue
            if any(
                span_pulito.start < altro.end and altro.start < span_pulito.end for altro in scelti
            ):
                continue
            scelti.append(span_pulito)

        scelti.sort(key=lambda voce: voce.start)

        # Le entità vengono registrate in ordine di lettura — `entity_types` promette «in ordine di
        # apparizione» — ma la sostituzione avviene da destra a sinistra: rimpiazzare da sinistra
        # invaliderebbe gli offset di tutti gli span successivi.
        sostituzioni = [
            (span, self._placeholder_for(text[span.start : span.end], span.entity_type, entities))
            for span in scelti
        ]
        for span, placeholder in reversed(sostituzioni):
            text = text[: span.start] + placeholder + text[span.end :]
        return text

    def _substitute(self, value: str, entity_type: str, entities: list[PIIEntity]) -> str:
        if _PLACEHOLDER_RE.fullmatch(value):
            return value
        return self._placeholder_for(value, entity_type, entities)

    def _placeholder_for(self, value: str, entity_type: str, entities: list[PIIEntity]) -> str:
        placeholder = self._reverse.get(value)
        if placeholder is None:
            self._counters[entity_type] = self._counters.get(entity_type, 0) + 1
            placeholder = f"[{entity_type}_{self._counters[entity_type]:03d}]"
            self._vault[placeholder] = value
            self._reverse[value] = placeholder
        entities.append(
            PIIEntity(entity_type=entity_type, original=value, placeholder=placeholder)
        )
        return placeholder


def _restringi(span: NerSpan, text: str) -> NerSpan | None:
    """Toglie gli spazi ai bordi di uno span, o `None` se non resta nulla.

    Un modello NER può includere uno spazio o un ritorno a capo nei propri confini: sostituirlo
    insieme all'entità incollerebbe fra loro le parole vicine, e il testo che l'LLM deve
    interpretare non va corrotto per un carattere.
    """
    valore = text[span.start : span.end]
    ripulito = valore.strip()
    if not ripulito:
        return None
    if valore == ripulito:
        return span
    inizio = span.start + (len(valore) - len(valore.lstrip()))
    return NerSpan(
        start=inizio,
        end=inizio + len(ripulito),
        entity_type=span.entity_type,
        score=span.score,
    )


def build_masker(
    settings: Settings | None = None,
    extra_names: Iterable[str] | None = None,
) -> PIIMasker:
    """Il mascheratore configurato secondo le impostazioni: unico punto di costruzione.

    Esiste perché il livello 2 va montato in modo identico in tutti i punti che anonimizzano —
    ingestion, upload, contesto del prompt, output guard — e sette costruzioni indipendenti
    finirebbero prima o poi per divergere.
    """
    settings = settings or get_settings()
    return PIIMasker(
        extra_names=extra_names,
        ner=build_ner_engine(settings),
        ner_threshold=settings.pii_ner_threshold,
        ner_detect_threshold=settings.pii_ner_detect_threshold,
    )


def mask_pii_data(text: str) -> str:
    """Scorciatoia senza stato a sole regex: restituisce solo il testo anonimizzato."""
    return PIIMasker().mask(text).masked_text
