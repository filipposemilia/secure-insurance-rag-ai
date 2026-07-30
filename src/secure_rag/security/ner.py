"""Livello 2 dell'anonimizzazione: riconoscimento di entità in testo libero.

Le regex di `security/pii.py` vedono ciò che ha una **forma**: un codice fiscale, un IBAN, una targa.
Non vedono un nome che compare in mezzo a una frase — «il testimone Andrea Gallo ha dichiarato» —
perché non c'è nulla di regolare da riconoscere. Quel limite è strutturale, non un difetto di scrittura
dei pattern: serve un modello che capisca il ruolo delle parole nella frase.

Questo modulo introduce quel modello (Microsoft Presidio con un NER italiano) **affiancandolo** alle
regex, secondo l'ordine di precedenza di ADR-019:

1. le regex girano per prime e restano autoritative sui formati rigidi — sono deterministiche,
   ripetibili e coperte da test;
2. il NER lavora su ciò che resta, e solo lì porta valore.

Tre proprietà che valgono più della copertura in sé:

- **Import opzionale.** Presidio porta spaCy e un modello linguistico da centinaia di MB. Senza il
  pacchetto installato il modulo si comporta come se il livello 2 fosse spento, così la demo offline
  resta installabile in un minuto (regola 5 di `CLAUDE.md`).
- **Nessuna degradazione silenziosa.** Se il livello 2 è stato *chiesto* (`PII_NER_ENABLED=true`) ma
  la libreria o il modello mancano, viene emesso un warning: chi ha configurato il NER deve sapere
  che sta girando a regex.
- **Nessun fallimento che sembri un successo.** Un errore *durante* l'analisi non viene inghiottito:
  un anonimizzatore che restituisce «nessuna entità trovata» perché si è rotto è indistinguibile da
  uno che ha lavorato, ed è il modo peggiore in cui questo layer può fallire.

Il modello NER è **probabilistico**: assegna un punteggio di confidenza, e le due soglie configurate
non sono un dettaglio di taratura. In ingresso si può essere generosi (mascherare di troppo costa un
segnaposto in più); in uscita, dove un falso positivo sopprime una risposta già pagata in token, la
soglia è più severa.
"""

from __future__ import annotations

import importlib.util
import logging
from dataclasses import dataclass
from functools import lru_cache
from typing import Protocol

from secure_rag.config import Settings, get_settings

logger = logging.getLogger(__name__)

try:  # dipendenza opzionale: senza, il livello 2 è semplicemente non disponibile
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    NER_DISPONIBILE = True
except ImportError:  # pragma: no cover - dipende dall'ambiente, non dalla logica
    AnalyzerEngine = None  # type: ignore[assignment,misc]
    NlpEngineProvider = None  # type: ignore[assignment,misc]
    NER_DISPONIBILE = False

LINGUA = "it"

# Dai tipi di Presidio al vocabolario già in uso in `security/pii.py`. Riusare i tipi esistenti
# tiene uniformi vault, report di ingestion e referto di upload: `NOME` resta `NOME` da qualunque
# livello arrivi, e il ripristino non deve sapere chi ha mascherato.
_ENTITY_MAP = {
    "PERSON": "NOME",
    "LOCATION": "INDIRIZZO",
    "ORGANIZATION": "ORGANIZZAZIONE",
}

# Lessico contrattuale che il modello scambia per nomi di persona. In italiano questi termini si
# scrivono con la maiuscola — «l'Assicurato», «il Contraente», «SEZIONE 1» — e un modello addestrato
# sulla lingua comune non ha alcun motivo per distinguerli da un cognome.
#
# È un elenco esplicito perché **il punteggio non aiuta**: il riconoscitore spaCy assegna a ogni
# entità `PERSON` lo stesso 0,85, sia che si tratti di «Alessandro Nardi» sia dell'intestazione di
# una sezione. Alzare la soglia non separa i due casi, li elimina entrambi.
#
# Mascherare questi termini non aggiungerebbe privacy — non identificano nessuno — e corromperebbe
# il testo contrattuale che il modello deve interpretare: un massimale in una clausola diventata
# `l'[NOME_009] ha diritto a…` non è più citabile. Nessuna voce qui è un cognome italiano
# plausibile: è il criterio con cui l'elenco va esteso.
_TERMINI_CONTRATTUALI = frozenset(
    {
        # Struttura del documento
        "sezione",
        "sezioni",
        "articolo",
        "articoli",
        "capitolo",
        "allegato",
        "premessa",
        "definizioni",
        "condizioni",
        "clausola",
        "clausole",
        # Ruoli contrattuali
        "assicurato",
        "assicurata",
        "assicuratore",
        "contraente",
        "beneficiario",
        "beneficiaria",
        "aderente",
        "perito",
        "periti",
        "liquidatore",
        "intermediario",
        "broker",
        # Oggetto della polizza
        "polizza",
        "sinistro",
        "sinistri",
        "massimale",
        "franchigia",
        "scoperto",
        "premio",
        "indennizzo",
        "risarcimento",
        "garanzia",
        "garanzie",
        "esclusione",
        "esclusioni",
        "denuncia",
        "scadenza",
        "decorrenza",
        "retroattività",
        "ultrattività",
        # Organizzazione
        "direzione",
        "compagnia",
        "agenzia",
    }
)


def is_contract_term(valore: str) -> bool:
    """True se il testo individuato è lessico contrattuale, non un nome di persona.

    Il confronto è insensibile alle maiuscole: è proprio la maiuscola che trae in inganno il
    modello, quindi non può essere il criterio per fidarsi di lui.
    """
    return valore.strip().lower() in _TERMINI_CONTRATTUALI


@dataclass(frozen=True)
class NerSpan:
    """Un'entità individuata dal modello, con la sua posizione nel testo e la confidenza."""

    start: int
    end: int
    entity_type: str  # già tradotto: `PERSON` → `NOME`
    score: float


class NerEngine(Protocol):
    """Ciò che `PIIMasker` si aspetta dal livello 2, e nulla di più.

    Un protocollo di due proprietà e un metodo: è quello che permette di provare l'integrazione con
    un motore finto, senza installare Presidio né scaricare un modello nei test.
    """

    @property
    def available(self) -> bool: ...

    @property
    def model_name(self) -> str: ...

    def analyze(self, text: str, threshold: float) -> list[NerSpan]: ...


def modello_installato(model_name: str) -> bool:
    """True se il modello linguistico è già presente sulla macchina.

    Il controllo non è una comodità, è una barriera. Presidio, davanti a un modello mancante, prova
    a **scaricarlo**: spaCy apre una connessione verso GitHub per centinaia di MB e, se qualcosa non
    torna, chiude il processo con `SystemExit` — cioè un livello di anonimizzazione opzionale
    farebbe cadere l'applicazione e violerebbe la proprietà di funzionare offline. Il modello si
    installa a mano, deliberatamente, non come effetto collaterale di un flag.

    I modelli spaCy sono pacchetti Python importabili per nome, quindi `find_spec` basta.
    """
    try:
        return importlib.util.find_spec(model_name) is not None
    except (ImportError, ValueError):  # nome non valido come modulo
        return False


@lru_cache(maxsize=2)
def _load_analyzer(model_name: str) -> "AnalyzerEngine | None":
    """Costruisce l'analizzatore una sola volta per modello.

    Caricare spaCy costa secondi, e la pipeline costruisce un masker a ogni richiesta: senza cache
    il livello 2 sarebbe inutilizzabile a runtime. La cache conserva anche il fallimento, ed è ciò
    che rende il warning «modello assente» una riga sola invece di una per domanda.
    """
    if not NER_DISPONIBILE:  # pragma: no cover - il chiamante ha già verificato
        return None

    if not modello_installato(model_name):
        logger.warning(
            "NER level 2 requested but the language model %s is not installed. Falling back to "
            "regex only. Install it with: python -m spacy download %s",
            model_name,
            model_name,
        )
        return None

    try:
        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": LINGUA, "model_name": model_name}],
            }
        )
        return AnalyzerEngine(
            nlp_engine=provider.create_engine(), supported_languages=[LINGUA]
        )
    # `SystemExit` è incluso di proposito: spaCy segnala gli errori con l'idioma di una CLI e chiude
    # il processo. Qui non siamo in una CLI, e un modello incompatibile non deve fermare il servizio.
    except (Exception, SystemExit) as errore:  # versione incompatibile, modello corrotto…
        logger.warning(
            "NER level 2 requested but unavailable: cannot load model %s (%s: %s). "
            "Falling back to regex only.",
            model_name,
            type(errore).__name__,
            errore,
        )
        return None


class PresidioEngine:
    """Adattatore su Presidio: espone solo ciò che serve al masker."""

    def __init__(self, model_name: str, entities: list[str]) -> None:
        self._model_name = model_name
        # I nomi delle entità sono quelli di Presidio (`PERSON`, `LOCATION`, `ORGANIZATION`): è il
        # suo vocabolario, e la traduzione verso il nostro avviene in uscita.
        self._entities = entities

    @property
    def available(self) -> bool:
        return _load_analyzer(self._model_name) is not None

    @property
    def model_name(self) -> str:
        return self._model_name

    def analyze(self, text: str, threshold: float) -> list[NerSpan]:
        """Entità sopra la soglia di confidenza, in ordine di apparizione.

        Vengono chieste **solo** le entità configurate: Presidio esegue allora i soli riconoscitori
        pertinenti. Non si usa il registry predefinito completo, perché `IT_FISCAL_CODE`,
        `IT_VAT_CODE` e `IBAN_CODE` produrrebbero entità sovrapposte a quelle delle regex, con nomi
        di tipo diversi e un ordine di precedenza ambiguo: su quei formati il livello 1 ha già
        risposto, in modo deterministico.

        Un errore di analisi **non viene catturato**: si veda la nota in testa al modulo.
        """
        analyzer = _load_analyzer(self._model_name)
        if analyzer is None or not text.strip():
            return []

        risultati = analyzer.analyze(
            text=text,
            language=LINGUA,
            entities=self._entities,
            score_threshold=threshold,
        )
        spans = [
            NerSpan(
                start=risultato.start,
                end=risultato.end,
                entity_type=_ENTITY_MAP.get(risultato.entity_type, risultato.entity_type),
                score=float(risultato.score),
            )
            for risultato in risultati
        ]
        return sorted(spans, key=lambda span: span.start)


@lru_cache(maxsize=1)
def _avvisa_libreria_assente() -> None:
    """Warning emesso una volta sola per processo (la cache è il contatore)."""
    logger.warning(
        "NER level 2 requested but presidio-analyzer is not installed. Falling back to regex "
        'only. Install it with: uv pip install -e ".[presidio]"'
    )


def ner_unavailable_reason(settings: Settings | None = None) -> str:
    """Perché il livello 2 non sta lavorando, in una riga leggibile. Vuoto se lavora.

    Il warning su `logging` è la traccia per chi legge i log di un servizio; questa stringa serve a
    chi guarda un terminale o un'interfaccia, dove un messaggio su stderr può comparire in un punto
    qualsiasi dell'output. Un livello di sicurezza spento va dichiarato dove lo si cerca.
    """
    settings = settings or get_settings()
    if not settings.pii_ner_enabled:
        return ""
    if not NER_DISPONIBILE:
        return 'presidio-analyzer non è installato — uv pip install -e ".[presidio]"'
    if not modello_installato(settings.pii_ner_model):
        return (
            f"il modello {settings.pii_ner_model} non è installato — "
            f"python -m spacy download {settings.pii_ner_model}"
        )
    if _load_analyzer(settings.pii_ner_model) is None:
        return f"il modello {settings.pii_ner_model} non si carica (versione incompatibile?)"
    return ""


def build_ner_engine(settings: Settings | None = None) -> NerEngine | None:
    """Il motore del livello 2, o `None` quando il livello resta spento.

    `None` è il caso normale, non un errore: il default è l'anonimizzazione a sole regex, e con
    `ner=None` il masker si comporta esattamente come prima che questo modulo esistesse.
    """
    settings = settings or get_settings()
    if not settings.pii_ner_enabled:
        return None

    if not NER_DISPONIBILE:
        _avvisa_libreria_assente()
        return None

    engine = PresidioEngine(settings.pii_ner_model, settings.ner_entities)
    # Il warning sul modello mancante l'ha già emesso `_load_analyzer`.
    return engine if engine.available else None
