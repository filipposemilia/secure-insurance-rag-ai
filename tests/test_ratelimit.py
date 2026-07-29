"""Test dei limiti di frequenza per l'istanza pubblica.

Il tempo è iniettato (`now=`) invece di essere atteso: la finestra scorrevole va verificata sul
suo comportamento, non sulla pazienza di chi esegue la suite.
"""

from __future__ import annotations

import pytest

from secure_rag.config import Settings
from secure_rag.security.ratelimit import RateLimiter, client_identity


@pytest.fixture
def settings() -> Settings:
    return Settings(
        llm_provider="fake",
        rate_limit_enabled=True,
        rate_limit_per_ip_hour=3,
        rate_limit_global_day=5,
    )


@pytest.fixture
def limiter(settings: Settings) -> RateLimiter:
    return RateLimiter(settings)


# ------------------------------------------------------------- limite per IP


def test_entro_la_soglia_le_richieste_passano(limiter: RateLimiter):
    for _ in range(3):
        verdetto = limiter.check("10.0.0.1", now=1000.0)
        assert verdetto.allowed
        assert not verdetto.degraded
        limiter.record("10.0.0.1", now=1000.0)


def test_superata_la_soglia_del_visitatore_la_richiesta_e_rifiutata(limiter: RateLimiter):
    for _ in range(3):
        limiter.record("10.0.0.1", now=1000.0)

    verdetto = limiter.check("10.0.0.1", now=1000.0)

    assert verdetto.blocked
    assert verdetto.rule == "quota_visitatore"
    assert verdetto.remaining_ip == 0
    assert verdetto.retry_after_seconds > 0


def test_il_limite_e_per_visitatore_non_globale(limiter: RateLimiter):
    for _ in range(3):
        limiter.record("10.0.0.1", now=1000.0)

    assert limiter.check("10.0.0.1", now=1000.0).blocked
    assert limiter.check("10.0.0.2", now=1000.0).allowed


def test_la_finestra_scorre_e_libera_la_quota(limiter: RateLimiter):
    for _ in range(3):
        limiter.record("10.0.0.1", now=1000.0)
    assert limiter.check("10.0.0.1", now=1000.0).blocked

    # Un'ora e un secondo più tardi le richieste precedenti sono uscite dalla finestra.
    assert limiter.check("10.0.0.1", now=1000.0 + 3601).allowed


# --------------------------------------------------------- tetto globale


def test_il_tetto_globale_degrada_invece_di_bloccare(limiter: RateLimiter):
    """Superato il budget giornaliero la demo resta utilizzabile, ma smette di costare."""
    for indirizzo in ("10.0.0.1", "10.0.0.2"):
        for _ in range(2):
            limiter.record(indirizzo, now=1000.0)
    limiter.record("10.0.0.3", now=1000.0)  # quinta richiesta: tetto raggiunto

    verdetto = limiter.check("10.0.0.4", now=1000.0)

    assert verdetto.allowed, "la richiesta non deve essere rifiutata"
    assert verdetto.degraded, "deve essere servita dal provider offline"
    assert verdetto.rule == "quota_globale"
    assert verdetto.remaining_global == 0


def test_la_quota_del_visitatore_ha_precedenza_sul_tetto_globale(limiter: RateLimiter):
    """Chi ha esaurito la propria quota resta bloccato anche a budget globale esaurito."""
    for _ in range(3):
        limiter.record("10.0.0.1", now=1000.0)
    for _ in range(2):
        limiter.record("10.0.0.9", now=1000.0)

    verdetto = limiter.check("10.0.0.1", now=1000.0)

    assert verdetto.blocked
    assert verdetto.rule == "quota_visitatore"


# ------------------------------------------------------------- disattivato


def test_soglia_a_zero_blocca_tutto_senza_errori():
    """Regressione: con soglia 0 non esiste una richiesta precedente da cui calcolare l'attesa."""
    limiter = RateLimiter(
        Settings(llm_provider="fake", rate_limit_enabled=True, rate_limit_per_ip_hour=0)
    )

    verdetto = limiter.check("10.0.0.1", now=1000.0)

    assert verdetto.blocked
    assert verdetto.rule == "quota_visitatore"
    assert verdetto.retry_after_seconds > 0


def test_disattivato_non_limita_nulla():
    limiter = RateLimiter(Settings(llm_provider="fake", rate_limit_enabled=False))

    for _ in range(50):
        limiter.record("10.0.0.1")

    verdetto = limiter.check("10.0.0.1")
    assert verdetto.allowed
    assert not verdetto.degraded
    assert verdetto.rule == "rate_disabilitato"


def test_le_richieste_non_servite_dal_modello_non_consumano_quota(limiter: RateLimiter):
    """`check` non registra: una query bloccata dai guard non intacca il budget di chi la subisce."""
    for _ in range(10):
        limiter.check("10.0.0.1", now=1000.0)

    assert limiter.check("10.0.0.1", now=1000.0).allowed


# --------------------------------------------------- identità del visitatore


def test_identita_dal_primo_indirizzo_della_catena():
    headers = {"X-Forwarded-For": "203.0.113.7, 10.0.0.1, 172.17.0.1"}
    assert client_identity(headers) == "203.0.113.7"


def test_identita_case_insensitive_sugli_header():
    assert client_identity({"x-forwarded-for": "203.0.113.7"}) == "203.0.113.7"


def test_identita_ripiega_su_x_real_ip():
    assert client_identity({"X-Real-IP": "203.0.113.9"}) == "203.0.113.9"


def test_identita_senza_header_usa_il_ripiego():
    assert client_identity(None) == "sconosciuto"
    assert client_identity({}, fallback="sessione-1") == "sessione-1"
