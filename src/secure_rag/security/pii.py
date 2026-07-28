"""Layer di anonimizzazione PII.

Questo è il primo layer di sicurezza della pipeline: il testo viene ripulito dai dati personali
**prima** di essere trasformato in embedding e **prima** di finire in un prompt inviato all'LLM.
Il vector database e il provider LLM non vedono mai un codice fiscale o un IBAN in chiaro.

Scelta implementativa: regex deterministiche + dizionario di entità note. In produzione questo
modulo va sostituito da Microsoft Presidio (NER + riconoscitori italiani), mantenendo la stessa
firma `PIIMasker.mask(text) -> MaskingResult`: il resto della pipeline non cambia.

I placeholder sono **stabili e numerati** (`[CF_001]`): la stessa entità riceve lo stesso segnaposto
in tutti i documenti, così il modello può ancora ragionare su "la stessa persona" senza conoscerne
l'identità. La mappa segnaposto → valore reale resta in memoria applicativa (`vault`) e può essere
usata per la ri-identificazione lato client, sotto controllo di accesso.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Pattern


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
    # Carta di credito (gruppi di 4 cifre, separatore opzionale)
    ("CARTA", re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b")),
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b")),
    # Telefono italiano, con o senza prefisso internazionale
    ("TELEFONO", re.compile(r"(?:\+39[ .-]?)?\b3\d{2}[ .-]?\d{6,7}\b")),
    # Partita IVA / codice fiscale societario: 11 cifre isolate
    ("PIVA", re.compile(r"\b\d{11}\b")),
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


class PIIMasker:
    """Maschera i dati personali mantenendo un vault stabile segnaposto → valore originale.

    L'istanza è **stateful di proposito**: riusare lo stesso masker su tutti i documenti di un
    ingest garantisce che lo stesso IBAN diventi sempre `[IBAN_001]`, preservando la coerenza
    referenziale tra chunk diversi.
    """

    def __init__(self, extra_names: Iterable[str] | None = None) -> None:
        self._vault: dict[str, str] = {}  # placeholder -> valore originale
        self._reverse: dict[str, str] = {}  # valore originale -> placeholder
        self._counters: dict[str, int] = {}
        # Nomi noti da mascherare anche quando compaiono senza ruolo contrattuale davanti.
        self._extra_names = sorted(set(extra_names or []), key=len, reverse=True)

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

        return MaskingResult(masked_text=masked, entities=entities)

    def detect(self, text: str) -> list[PIIEntity]:
        """Individua PII senza modificare il vault: usato dall'output guard.

        Serve a verificare che nella risposta generata dall'LLM non sia ricomparso un dato
        personale (per esempio perché il modello lo ha ricostruito o l'utente lo ha iniettato).
        """
        found: list[PIIEntity] = []
        cleaned = _PLACEHOLDER_RE.sub(" ", text)
        for entity_type, pattern in _PATTERNS:
            for match in pattern.finditer(cleaned):
                found.append(
                    PIIEntity(entity_type=entity_type, original=match.group(0), placeholder="")
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

    # -------------------------------------------------------------- interni

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


def mask_pii_data(text: str) -> str:
    """Scorciatoia senza stato: restituisce solo il testo anonimizzato."""
    return PIIMasker().mask(text).masked_text
