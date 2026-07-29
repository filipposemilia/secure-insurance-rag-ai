"""Limiti di frequenza per l'istanza pubblica.

Quando la demo è esposta in rete usando una API key a carico di chi la pubblica, il rischio non è
più teorico: chiunque apra il link può consumare token altrui. È OWASP **LLM04 — Model Denial of
Service**, che riguarda tanto la saturazione del servizio quanto l'abuso economico.

Due soglie indipendenti, con esiti deliberatamente diversi:

1. **Per visitatore** (finestra scorrevole di un'ora) — superata, la richiesta viene **rifiutata**.
   Protegge dal singolo abusante senza penalizzare gli altri.
2. **Globale giornaliera** — superata, la richiesta **non viene rifiutata**: il verdetto porta
   `degraded=True` e chi chiama passa al provider deterministico offline. La demo resta navigabile a
   costo zero invece di mostrare un errore a chi arriva per ultimo.

La distinzione è il punto: un tetto di spesa non è una minaccia da respingere, è una condizione
operativa da gestire. Rifiutare tutto al raggiungimento del budget trasformerebbe un limite di costo
in un'interruzione di servizio — cioè esattamente il denial of service da cui ci si difende.

**Limite dichiarato.** Lo stato vive nella memoria del processo: corretto per un container singolo,
insufficiente con più repliche, dove servirebbe uno store condiviso (Redis) perché i contatori non
siano per-istanza. Riavviare il processo azzera i contatori.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field

from secure_rag.config import Settings, get_settings

_ORA_IN_SECONDI = 3600
_GIORNO_IN_SECONDI = 86400


@dataclass
class RateVerdict:
    """Esito di un controllo di frequenza.

    Come gli altri componenti di sicurezza del progetto, non restituisce un booleano: `rule` e
    `reason` finiscono nell'audit trail e nell'interfaccia, ed è ciò che permette di distinguere
    una richiesta rifiutata da una servita in modalità degradata.
    """

    allowed: bool
    degraded: bool = False
    rule: str = "rate_ok"
    reason: str = ""
    remaining_ip: int = 0
    remaining_global: int = 0
    retry_after_seconds: int = 0

    @property
    def blocked(self) -> bool:
        return not self.allowed


@dataclass
class _Contatore:
    """Finestra scorrevole di istanti di richiesta."""

    istanti: deque[float] = field(default_factory=deque)

    def scarta_i_vecchi(self, adesso: float, finestra: int) -> None:
        limite = adesso - finestra
        while self.istanti and self.istanti[0] <= limite:
            self.istanti.popleft()


class RateLimiter:
    """Contatori a finestra scorrevole per visitatore e per l'intera istanza.

    Thread-safe: Streamlit serve ogni sessione in un thread distinto, e i contatori sono condivisi.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._per_ip: dict[str, _Contatore] = {}
        self._globale = _Contatore()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ API

    def check(self, identity: str, now: float | None = None) -> RateVerdict:
        """Verifica se `identity` può effettuare una richiesta, **senza** registrarla.

        Separare la verifica dalla registrazione evita di consumare quota per richieste che
        verranno poi bloccate dai guard: una query di prompt injection non deve intaccare il budget
        di chi la subisce.
        """
        if not self._settings.rate_limit_enabled:
            return RateVerdict(
                allowed=True,
                rule="rate_disabilitato",
                reason="Limiti di frequenza non attivi su questa istanza.",
                remaining_ip=self._settings.rate_limit_per_ip_hour,
                remaining_global=self._settings.rate_limit_global_day,
            )

        adesso = now if now is not None else time.time()
        limite_ip = self._settings.rate_limit_per_ip_hour
        limite_globale = self._settings.rate_limit_global_day

        with self._lock:
            contatore_ip = self._per_ip.setdefault(identity, _Contatore())
            contatore_ip.scarta_i_vecchi(adesso, _ORA_IN_SECONDI)
            self._globale.scarta_i_vecchi(adesso, _GIORNO_IN_SECONDI)

            usate_ip = len(contatore_ip.istanti)
            usate_globali = len(self._globale.istanti)
            residue_ip = max(limite_ip - usate_ip, 0)
            residue_globali = max(limite_globale - usate_globali, 0)

            if usate_ip >= limite_ip:
                # Con soglia a zero (istanza chiusa a chiave) non esiste una richiesta precedente
                # da cui calcolare l'attesa: si indica la finestra intera.
                attesa = (
                    int(contatore_ip.istanti[0] + _ORA_IN_SECONDI - adesso) + 1
                    if contatore_ip.istanti
                    else _ORA_IN_SECONDI
                )
                return RateVerdict(
                    allowed=False,
                    rule="quota_visitatore",
                    reason=(
                        f"Raggiunto il limite di {limite_ip} domande all'ora per visitatore. "
                        f"Riprova fra circa {max(attesa // 60, 1)} minuti."
                    ),
                    remaining_ip=0,
                    remaining_global=residue_globali,
                    retry_after_seconds=max(attesa, 1),
                )

            if usate_globali >= limite_globale:
                return RateVerdict(
                    allowed=True,
                    degraded=True,
                    rule="quota_globale",
                    reason=(
                        f"Raggiunto il tetto giornaliero di {limite_globale} richieste al modello "
                        "in rete: la demo prosegue in modalità deterministica offline."
                    ),
                    remaining_ip=residue_ip,
                    remaining_global=0,
                )

            return RateVerdict(
                allowed=True,
                rule="rate_ok",
                reason="Entro i limiti previsti.",
                remaining_ip=residue_ip,
                remaining_global=residue_globali,
            )

    def record(self, identity: str, now: float | None = None) -> None:
        """Registra una richiesta effettivamente servita dal modello in rete.

        Va chiamata **solo** quando una chiamata al provider è davvero avvenuta: le risposte servite
        offline, o bloccate dai guard, non costano nulla e non devono consumare quota.
        """
        if not self._settings.rate_limit_enabled:
            return
        adesso = now if now is not None else time.time()
        with self._lock:
            self._per_ip.setdefault(identity, _Contatore()).istanti.append(adesso)
            self._globale.istanti.append(adesso)

    def snapshot(self, identity: str, now: float | None = None) -> tuple[int, int]:
        """Quota residua (visitatore, globale), per mostrarla nell'interfaccia."""
        verdict = self.check(identity, now)
        return verdict.remaining_ip, verdict.remaining_global

    def reset(self) -> None:
        """Azzera i contatori. Usato dai test."""
        with self._lock:
            self._per_ip.clear()
            self._globale = _Contatore()


def client_identity(headers: dict[str, str] | None, fallback: str = "sconosciuto") -> str:
    """Ricava l'identità del visitatore dagli header inoltrati dal reverse proxy.

    `X-Forwarded-For` può contenere una catena di indirizzi: il primo è il client originale. Se
    l'applicazione fosse raggiungibile **senza** passare dal proxy, l'header sarebbe controllato dal
    chiamante e quindi falsificabile; nel deployment previsto solo il proxy espone il servizio, ed è
    lui a impostarlo.
    """
    if not headers:
        return fallback

    normalizzati = {chiave.lower(): valore for chiave, valore in headers.items()}

    inoltrato = normalizzati.get("x-forwarded-for", "")
    if inoltrato:
        primo = inoltrato.split(",")[0].strip()
        if primo:
            return primo

    reale = normalizzati.get("x-real-ip", "").strip()
    if reale:
        return reale

    return fallback
