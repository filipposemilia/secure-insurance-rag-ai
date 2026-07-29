"""Interfaccia demo Streamlit.

Pensata per essere proiettata durante un colloquio: ogni risposta mostra, accanto al testo, **cosa
ha fatto il layer di sicurezza** — quali documenti sono stati recuperati per quel ruolo, quali sono
finiti in quarantena, e il prompt effettivamente inviato al modello (già anonimizzato).

Tre schede:
  • Chat       — domande sul corpus aziendale e/o sui documenti caricati in sessione
  • Documenti  — caricamento file con referto di sicurezza (PII rimosse, istruzioni sospette)
  • Sicurezza  — scenari di attacco pronti e audit trail

Avvio:  streamlit run app/streamlit_app.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

import streamlit as st

# Consente l'avvio anche senza installazione del pacchetto (`pip install -e .`).
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from secure_rag.cli import SCENARIOS  # noqa: E402
from secure_rag.config import Settings, get_settings  # noqa: E402
from secure_rag.ingestion import CLEARANCE_LEVELS, build_documents  # noqa: E402
from secure_rag.providers import describe_provider, probe_providers  # noqa: E402
from secure_rag.rag import RAGResponse, SecureRAGPipeline  # noqa: E402
from secure_rag.security.audit import AuditRecord, hash_query, utc_now  # noqa: E402
from secure_rag.security.pii import PIIMasker  # noqa: E402
from secure_rag.security.ratelimit import RateLimiter, client_identity  # noqa: E402
from secure_rag.uploads import SUPPORTED_SUFFIXES, UploadReport, process_upload  # noqa: E402
from secure_rag.vectorstore import (  # noqa: E402
    add_documents,
    collection_size,
    drop_collections_with_prefix,
    index_documents,
    remove_source,
    reset_collection,
)

st.set_page_config(
    page_title="Secure Insurance RAG",
    page_icon="🛡️",
    layout="wide",
    menu_items={"about": "PoC di RAG sicuro su documentazione assicurativa sintetica."},
)

# Ritocchi mirati: compattano l'intestazione, rendono le schede leggibili da proiettore e danno
# alle metriche un contenitore riconoscibile. Nessuna riscrittura dei componenti nativi.
st.markdown(
    """
    <style>
      .block-container { padding-top: 2.2rem; max-width: 1280px; }
      header[data-testid="stHeader"] { background: transparent; }

      .stTabs [data-baseweb="tab-list"] { gap: .35rem; }
      .stTabs [data-baseweb="tab"] {
        padding: .55rem 1.1rem;
        border-radius: .5rem .5rem 0 0;
        font-weight: 600;
      }

      div[data-testid="stMetric"] {
        background: rgba(255,255,255,.03);
        border: 1px solid rgba(255,255,255,.08);
        border-radius: .6rem;
        padding: .7rem .9rem;
      }
      div[data-testid="stMetricValue"] { font-size: 1.05rem; }

      .app-hero {
        border: 1px solid rgba(47,129,247,.35);
        background: linear-gradient(135deg, rgba(47,129,247,.10), rgba(47,129,247,.02));
        border-radius: .75rem;
        padding: 1rem 1.2rem;
        margin-bottom: 1.1rem;
      }
      .app-hero h1 { font-size: 1.45rem; margin: 0 0 .3rem 0; }
      .app-hero p { margin: 0; opacity: .8; font-size: .92rem; line-height: 1.5; }
      .app-chips { margin-top: .7rem; display: flex; flex-wrap: wrap; gap: .4rem; }
      .app-chip {
        font-size: .75rem;
        padding: .2rem .6rem;
        border-radius: 999px;
        border: 1px solid rgba(255,255,255,.14);
        background: rgba(255,255,255,.04);
        white-space: nowrap;
      }
    </style>
    """,
    unsafe_allow_html=True,
)

ROLE_LABELS = {
    "public": "Cliente (documenti pubblici)",
    "agent": "Agente di rete (polizze e perizie)",
    "management": "Direzione Sinistri (tutto, incluse circolari interne)",
}

SCOPE_LABELS = {
    "corpus": "Corpus aziendale",
    "uploads": "Solo documenti caricati",
    "both": "Corpus + documenti caricati",
}


# ---------------------------------------------------------------------------
# Risorse condivise
# ---------------------------------------------------------------------------


@st.cache_resource(show_spinner=False)
def get_pipeline(provider: str) -> SecureRAGPipeline:
    """Pipeline riusata tra i rerun. La chiave di cache è il provider attivo."""
    return SecureRAGPipeline(get_settings().with_provider(provider))


@st.cache_resource(show_spinner=False)
def get_rate_limiter() -> RateLimiter:
    """Contatori di frequenza condivisi fra tutte le sessioni del processo.

    Devono stare in `cache_resource` e non in `session_state`: un limite per sessione sarebbe
    aggirabile aprendo una scheda nuova.
    """
    return RateLimiter(get_settings())


def visitor_identity() -> str:
    """Identità del visitatore, dagli header inoltrati dal reverse proxy.

    Fuori da un deployment con proxy (esecuzione locale, test) gli header non ci sono: si ripiega
    su un identificativo di sessione, che tiene il comportamento coerente senza fingere di
    conoscere l'indirizzo reale.
    """
    if "session_token" not in st.session_state:
        st.session_state["session_token"] = f"sessione-{uuid4().hex[:12]}"
    try:
        headers = dict(st.context.headers)
    except Exception:  # fuori da un contesto di script (AppTest, esecuzione bare)
        headers = {}
    return client_identity(headers, fallback=st.session_state["session_token"])


@st.cache_data(ttl=30, show_spinner=False)
def get_provider_statuses() -> list[tuple[str, str, str, bool, str]]:
    """Disponibilità dei provider, in forma serializzabile per la cache di Streamlit."""
    return [
        (status.name, status.label, status.detail, status.available, status.hint)
        for status in probe_providers(get_settings())
    ]


@st.cache_resource(show_spinner=False)
def pulisci_upload_orfani() -> list[str]:
    """Elimina le collection di upload rimaste da esecuzioni precedenti.

    Gira una sola volta per processo, grazie alla cache. Una sessione web non ha una chiusura
    affidabile su cui agganciare la pulizia: il momento sicuro è l'avvio, quando nessuna sessione
    precedente è più valida.
    """
    base = get_settings()
    return drop_collections_with_prefix(base.upload_collection_prefix, base)


def upload_settings(settings: Settings) -> Settings:
    """Impostazioni puntate alla collection di upload **della sessione corrente**.

    L'isolamento per sessione è ciò che impedisce che un documento caricato da un visitatore
    diventi leggibile dagli altri: su un'istanza pubblica la sola clearance non basterebbe, perché
    due persone diverse con lo stesso ruolo si vedrebbero i file a vicenda.
    """
    if "session_token" not in st.session_state:
        st.session_state["session_token"] = f"sessione-{uuid4().hex[:12]}"
    return settings.with_collection(
        settings.upload_collection_for(st.session_state["session_token"])
    )


def run_ingestion(settings: Settings) -> dict:
    masker = PIIMasker()
    documents, report = build_documents(settings, masker)
    index_documents(documents, settings)
    return {
        "documents": report.documents,
        "chunks": report.chunks,
        "entities": report.masked_entities,
        "types": report.entity_types,
        "files": report.files,
    }


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

base_settings = get_settings()
pulisci_upload_orfani()  # una volta per processo: rimuove gli upload di sessioni concluse
statuses = get_provider_statuses()
selectable = [status for status in statuses if status[3]]

with st.sidebar:
    st.title("🛡️ Secure Insurance RAG")
    st.caption("PoC di RAG sicuro su documentazione assicurativa")

    st.subheader("Modello")
    default_index = next(
        (index for index, status in enumerate(selectable) if status[0] == base_settings.llm_provider),
        0,
    )
    provider = st.radio(
        "Provider LLM",
        options=[status[0] for status in selectable],
        index=default_index,
        format_func=lambda name: next(s[1] for s in selectable if s[0] == name),
        help="Ogni provider ha il proprio indice: cambiando modello va rieseguita l'indicizzazione.",
    )
    st.caption(next(status[2] for status in selectable if status[0] == provider))

    for name, label, _, available, hint in statuses:
        if not available:
            st.caption(f"○ {label} — non disponibile · {hint}")

    settings = base_settings.with_provider(provider)
    if settings.is_offline:
        st.info("Modalità offline: nessuna chiamata di rete, nessun token consumato.", icon="🔌")

    st.subheader("Accesso")
    role = st.selectbox(
        "Ruolo del richiedente",
        options=list(CLEARANCE_LEVELS),
        index=1,
        format_func=lambda value: ROLE_LABELS[value],
        help="Determina quali documenti il retriever può recuperare (RBAC applicato sui vettori).",
    )

    show_prompt = st.toggle("Mostra il prompt inviato all'LLM", value=False)

    st.subheader("Indici")
    corpus_chunks = collection_size(settings)
    session_chunks = collection_size(upload_settings(settings))
    left, right = st.columns(2)
    left.metric("Corpus", corpus_chunks)
    right.metric("Caricati", session_chunks)

    if st.button("Indicizza corpus aziendale", width="stretch", type="primary"):
        with st.spinner("Anonimizzazione e indicizzazione in corso…"):
            st.session_state["ingestion"] = run_ingestion(settings)
        st.rerun()

    if report := st.session_state.get("ingestion"):
        st.success(
            f"{report['documents']} documenti · {report['chunks']} chunk · "
            f"{report['entities']} entità PII rimosse"
        )
        st.caption("Tipi rimossi: " + ", ".join(report["types"]))

    st.divider()
    st.caption(
        "I documenti in `data/policies/` sono **sintetici**. Nomi, codici fiscali, IBAN e partite "
        "IVA sono inventati e non riferibili a persone o aziende reali."
    )


# ---------------------------------------------------------------------------
# Rendering condiviso
# ---------------------------------------------------------------------------


def render_response(response: RAGResponse) -> None:
    """Mostra risposta, esiti di sicurezza e fonti."""
    if response.rate_limit == "quota_globale":
        st.info(
            "Tetto giornaliero di richieste al modello in rete raggiunto: questa risposta è stata "
            "prodotta dal motore deterministico offline. La pipeline di sicurezza è la stessa; "
            "cambia solo chi genera il testo.",
            icon="🔌",
        )

    if response.blocked:
        st.error(response.answer, icon="🛑")
    else:
        st.markdown(response.answer)

    events = response.security_events
    columns = st.columns(4)
    columns[0].metric("Ruolo", ROLE_LABELS[response.role].split(" (")[0])
    columns[1].metric("Ambito", SCOPE_LABELS.get(response.scope, response.scope))
    columns[2].metric("Latenza", f"{response.latency_ms} ms")
    columns[3].metric("Eventi di sicurezza", len(events))

    if events:
        for event in events:
            st.warning(event, icon="⚠️")
    else:
        st.success("Input pulito · contesto integro · output conforme", icon="✅")

    if response.context_scan and response.context_scan.findings:
        with st.expander("Dettaglio quarantena"):
            for finding in response.context_scan.findings:
                st.code(finding, language=None)

    if response.sources:
        badges = [
            f"📎 {source}" if source in response.uploaded_sources else f"📄 {source}"
            for source in response.sources
        ]
        st.caption("**Fonti recuperate:** " + " · ".join(badges))

    if show_prompt and response.prompt_sent:
        with st.expander("Prompt inviato all'LLM (anonimizzato)"):
            st.code(response.prompt_sent, language="markdown")


def run_query(question: str, scope: str, as_role: str | None = None) -> RAGResponse:
    """Esegue una domanda applicando l'intera pipeline di sicurezza.

    `as_role` permette a uno scenario di girare con il **proprio** ruolo invece che con quello
    selezionato in barra laterale: è ciò che rende confrontabili gli scenari 5 e 6, che pongono la
    stessa domanda con clearance diverse.

    Qui viene applicato anche il limite di frequenza, perché questa è la superficie pubblica: la
    pipeline non sa di essere esposta in rete, e non deve saperlo.
    """
    ruolo_effettivo = as_role or role
    limiter = get_rate_limiter()
    identity = visitor_identity()
    verdetto = limiter.check(identity)

    if verdetto.blocked:
        # Nessuna chiamata al modello e nessun retrieval: la richiesta si ferma qui, ma resta
        # tracciata, perché un tentativo oltre quota è un segnale operativo.
        get_pipeline(provider).audit.log(
            AuditRecord(
                timestamp=utc_now(),
                role=ruolo_effettivo,
                query_hash=hash_query(question),
                query_length=len(question),
                input_verdict="blocked",
                input_rule=verdetto.rule,
                scope=scope,
                provider=describe_provider(settings),
                rate_limit=verdetto.rule,
            )
        )
        return RAGResponse(
            answer=f"Richiesta non servita: {verdetto.reason}",
            role=ruolo_effettivo,
            blocked=True,
            blocked_stage="rate_limit",
            scope=scope,
            provider=describe_provider(settings),
            rate_limit=verdetto.rule,
        )

    # Tetto giornaliero raggiunto: si risponde comunque, ma senza spendere token.
    provider_effettivo = "fake" if verdetto.degraded else provider

    with st.spinner("Elaborazione con controlli di sicurezza…"):
        response = get_pipeline(provider_effettivo).answer(
            question, role=ruolo_effettivo, scope=scope, rate_limit=verdetto.rule
        )

    # La quota si consuma solo se il modello in rete è stato davvero interrogato. `prompt_sent` è
    # popolato unicamente quando la catena LCEL viene invocata: resta vuoto sia per le query
    # bloccate dai guard, sia quando il retrieval non restituisce nulla — per esempio cercando fra
    # i documenti caricati quando non ce ne sono. In nessuno dei due casi è stato speso un token.
    if provider_effettivo != "fake" and response.prompt_sent:
        limiter.record(identity)

    return response


def ask(question: str, scope: str) -> None:
    """Esegue una domanda e la registra nello storico della chat."""
    with st.chat_message("user"):
        st.write(question)
    with st.chat_message("assistant"):
        response = run_query(question, scope)
        render_response(response)
    st.session_state["history"].append({"question": question, "response": response})


st.session_state.setdefault("history", [])
st.session_state.setdefault("upload_reports", [])
st.session_state.setdefault("processed_uploads", set())


# --- Intestazione: cosa sta guardando chi apre il link -----------------------
_chips = [
    "PII mascherate prima dell'embedding",
    "Guardrail su input, contesto e output",
    "RBAC applicato al retrieval",
    "Audit trail di ogni interazione",
]
st.markdown(
    "<div class='app-hero'>"
    "<h1>🛡️ Secure Insurance RAG</h1>"
    "<p>Assistente sulla documentazione di polizza con i controlli di sicurezza in evidenza: "
    "ogni risposta mostra quali documenti sono stati recuperati per il ruolo attivo, quali sono "
    "stati messi in quarantena e quale prompt è arrivato al modello.</p>"
    "<div class='app-chips'>"
    + "".join(f"<span class='app-chip'>{voce}</span>" for voce in _chips)
    + "</div></div>",
    unsafe_allow_html=True,
)

if settings.rate_limit_enabled:
    _residue_ip, _residue_globali = get_rate_limiter().snapshot(visitor_identity())
    intestazione, quota_visitatore, quota_totale = st.columns([2, 1, 1])
    intestazione.caption(
        "Documenti **sintetici**: nomi, codici fiscali, IBAN e partite IVA sono inventati. "
        "Istanza dimostrativa con limiti di frequenza attivi."
    )
    quota_visitatore.metric("Domande residue", _residue_ip)
    quota_totale.metric("Quota giornaliera", _residue_globali)
    if _residue_globali == 0:
        st.info(
            "Il tetto giornaliero di richieste al modello in rete è esaurito: la demo continua a "
            "funzionare con il motore deterministico offline.",
            icon="🔌",
        )

tab_chat, tab_docs, tab_security = st.tabs(["💬 Chat", "📎 Documenti", "🛡️ Sicurezza"])


# ---------------------------------------------------------------------------
# Scheda 1 — Chat
# ---------------------------------------------------------------------------

with tab_chat:
    st.subheader("Assistente polizze")
    st.caption(
        "PII masking prima dell'embedding · guardrails su input, contesto e output · "
        "RBAC applicato al retrieval · audit trail di ogni interazione"
    )

    session_chunks = collection_size(upload_settings(settings))
    scope = st.radio(
        "Dove cercare",
        options=["corpus", "uploads", "both"],
        format_func=lambda value: SCOPE_LABELS[value],
        horizontal=True,
        help=(
            "I documenti caricati vivono in una collection separata dal corpus aziendale: "
            "restano interrogabili a parte e non lo contaminano."
        ),
    )
    if session_chunks == 0 and scope in ("uploads", "both"):
        st.warning(
            "Nessun documento caricato in questa sessione: questo ambito non ha ancora nulla su "
            "cui cercare. Caricane uno dalla scheda **Documenti** — anche una perizia con "
            "istruzioni nascoste, per vedere il referto di sicurezza.",
            icon="📎",
        )
    elif session_chunks == 0:
        st.caption("Carica un documento dalla scheda **Documenti** per interrogarlo direttamente.")

    if collection_size(settings) == 0:
        st.warning(
            f"Corpus non indicizzato per **{describe_provider(settings)}**. Usa "
            "**Indicizza corpus aziendale** nella barra laterale: ogni provider ha il proprio "
            "indice, perché i modelli di embedding producono vettori di dimensione diversa.",
            icon="📄",
        )

    for entry in st.session_state["history"]:
        with st.chat_message("user"):
            st.write(entry["question"])
        with st.chat_message("assistant"):
            render_response(entry["response"])

    question = st.chat_input("Fai una domanda sulle polizze…")

    if question:
        if collection_size(settings) == 0 and scope == "corpus":
            st.error("Indicizza prima il corpus dalla barra laterale.", icon="📄")
        else:
            ask(question, scope)

    if st.session_state["history"] and st.button("Svuota conversazione"):
        st.session_state["history"] = []
        st.rerun()


# ---------------------------------------------------------------------------
# Scheda 2 — Documenti caricati
# ---------------------------------------------------------------------------


def render_upload_report(report: UploadReport) -> None:
    """Referto di sicurezza di un file caricato."""
    if not report.accepted:
        st.error(f"**{report.file_name}** — {report.error}", icon="🚫")
        return

    icon = "⚠️" if report.suspicious_chunks else "✅"
    with st.expander(f"{icon} {report.file_name} — {report.summary}", expanded=True):
        columns = st.columns(4)
        columns[0].metric("Dimensione", f"{report.size_kb:.0f} KB")
        columns[1].metric("Chunk", report.chunks)
        columns[2].metric("PII rimosse", report.pii_count)
        columns[3].metric("Chunk sospetti", report.suspicious_chunks)

        if report.pii_types:
            st.caption("**Tipi di dato personale rimossi:** " + ", ".join(report.pii_types))

        if report.suspicious_chunks:
            st.error(
                f"Il documento contiene {report.suspicious_chunks} blocchi con istruzioni rivolte "
                "all'assistente: possibile **prompt injection indiretta** (OWASP LLM01). I blocchi "
                "restano tracciati e vengono esclusi dal contesto a ogni interrogazione.",
                icon="🧨",
            )
            for finding in report.findings:
                st.code(finding, language=None)

        st.caption(f"Visibile al livello di clearance: **{report.clearance}**")

        left, right = st.columns(2)
        with left:
            st.caption("Testo originale (resta in memoria applicativa)")
            st.text_area(
                "originale",
                report.preview_original,
                height=220,
                disabled=True,
                label_visibility="collapsed",
                key=f"orig_{report.file_name}_{report.uploaded_at}",
            )
        with right:
            st.caption("Testo anonimizzato (è questo che viene indicizzato e inviato all'LLM)")
            st.text_area(
                "anonimizzato",
                report.preview_masked,
                height=220,
                disabled=True,
                label_visibility="collapsed",
                key=f"mask_{report.file_name}_{report.uploaded_at}",
            )


with tab_docs:
    st.subheader("Documenti caricati in sessione")
    st.markdown(
        "Un file caricato è **input non fidato**: riceve lo stesso trattamento del corpus "
        "aziendale — anonimizzazione PII prima dell'embedding, scansione anti prompt injection, "
        "clearance ereditata dal ruolo attivo — più due controlli di ingresso: dimensione massima "
        f"{settings.max_upload_mb:.0f} MB e {settings.max_upload_chunks} chunk (mitigazione LLM04).\n\n"
        "I documenti restano **isolati nella tua sessione**: nessun altro visitatore può "
        "raggiungerli. Togliendo un file dall'elenco i suoi chunk vengono eliminati dall'indice, "
        "e tutto viene comunque rimosso alla chiusura della sessione."
    )

    uploaded_files = st.file_uploader(
        f"Formati ammessi: {', '.join(SUPPORTED_SUFFIXES)}",
        type=[suffix.lstrip(".") for suffix in SUPPORTED_SUFFIXES],
        accept_multiple_files=True,
    )

    # Allineamento fra ciò che l'utente vede e ciò che il retrieval può raggiungere.
    # Togliere un file dall'elenco deve eliminarne i chunk: altrimenti un documento caricato per
    # errore resterebbe interrogabile pur non comparendo più da nessuna parte nell'interfaccia.
    nomi_presenti = {uploaded.name for uploaded in (uploaded_files or [])}
    nomi_indicizzati = {
        report.file_name for report in st.session_state["upload_reports"] if report.accepted
    }
    rimossi = nomi_indicizzati - nomi_presenti

    if rimossi:
        for nome in rimossi:
            remove_source(nome, upload_settings(settings))
        st.session_state["upload_reports"] = [
            report
            for report in st.session_state["upload_reports"]
            if report.file_name not in rimossi
        ]
        st.session_state["processed_uploads"] = {
            impronta
            for impronta in st.session_state["processed_uploads"]
            if impronta.split(":", 1)[0] not in rimossi
        }
        st.session_state["ultima_rimozione"] = sorted(rimossi)
        st.rerun()

    if avviso := st.session_state.pop("ultima_rimozione", None):
        st.success(
            "Rimossi dall'indice e non più interrogabili: " + ", ".join(f"`{n}`" for n in avviso),
            icon="🧹",
        )

    if uploaded_files:
        masker = PIIMasker()
        nuovi = 0
        for uploaded in uploaded_files:
            data = uploaded.getvalue()
            fingerprint = f"{uploaded.name}:{len(data)}:{role}"
            if fingerprint in st.session_state["processed_uploads"]:
                continue

            with st.spinner(f"Analisi di sicurezza di {uploaded.name}…"):
                documents, report = process_upload(
                    uploaded.name, data, clearance=role, settings=settings, masker=masker
                )
                if report.accepted:
                    add_documents(documents, upload_settings(settings))

            st.session_state["processed_uploads"].add(fingerprint)
            st.session_state["upload_reports"].append(report)
            nuovi += 1

        if nuovi:
            st.rerun()

    if st.session_state["upload_reports"]:
        st.divider()
        for report in reversed(st.session_state["upload_reports"]):
            render_upload_report(report)

        st.divider()
        left, right = st.columns([3, 1])
        with left:
            domanda = st.text_input(
                "Domanda mirata sui documenti caricati",
                placeholder="Es. Qual è l'importo dell'indennizzo proposto?",
            )
        with right:
            st.write("")
            st.write("")
            chiedi = st.button("Chiedi", width="stretch", type="primary")

        if chiedi and domanda:
            # Eseguita qui, non rimandata alla scheda Chat: in demo il risultato deve comparire
            # dov'è stato chiesto. Finisce comunque nello storico della conversazione.
            response = run_query(domanda, scope="uploads")
            st.session_state["history"].append({"question": domanda, "response": response})
            st.markdown("**Esito**")
            render_response(response)

        if st.button("Rimuovi tutti i documenti caricati"):
            reset_collection(upload_settings(settings))
            st.session_state["upload_reports"] = []
            st.session_state["processed_uploads"] = set()
            st.rerun()
    else:
        st.info(
            "Nessun documento caricato. Prova con `data/policies/perizia_sinistro_compromessa.md`: "
            "contiene una prompt injection indiretta nascosta in un commento HTML e il referto la "
            "segnala prima ancora della prima domanda.",
            icon="🧪",
        )


# ---------------------------------------------------------------------------
# Scheda 3 — Sicurezza
# ---------------------------------------------------------------------------

with tab_security:
    st.subheader("Scenari di attacco")
    st.caption("Ogni scenario è mappato su un rischio della OWASP Top 10 for LLM Applications.")

    st.caption(
        "Ogni scenario gira con il **ruolo che gli è proprio**, indipendentemente da quello "
        "selezionato in barra laterale: è ciò che rende confrontabili il 5 e il 6, che pongono la "
        "stessa domanda con clearance diverse."
    )

    columns = st.columns(3)
    for index, scenario in enumerate(SCENARIOS):
        with columns[index % 3]:
            with st.container(border=True):
                st.markdown(f"**{scenario.name}**")
                st.caption(f"OWASP: {scenario.owasp}")
                st.caption(f"Ruolo: `{scenario.role}`")
                st.caption(scenario.expected)
                if st.button("Esegui", key=f"scenario_{index}", width="stretch"):
                    st.session_state["scenario_result"] = {
                        "name": scenario.name,
                        "question": scenario.question,
                        "expected": scenario.expected,
                        "response": run_query(
                            scenario.question, scope="corpus", as_role=scenario.role
                        ),
                    }

    if result := st.session_state.get("scenario_result"):
        st.divider()
        st.markdown(f"#### Esito — {result['name']}")
        st.caption(f"Atteso: {result['expected']}")
        st.code(result["question"], language=None)
        render_response(result["response"])

    st.divider()
    st.subheader("Audit trail")
    records = get_pipeline(provider).audit.tail(15)
    if records:
        st.dataframe(records, width="stretch")
        st.caption(
            "La domanda in chiaro non viene mai registrata: nel log resta solo un hash, "
            "insieme a ruolo, ambito di ricerca, fonti consultate, documenti in quarantena e "
            "verdetti dei guard."
        )
    else:
        st.caption("Nessuna interazione registrata.")
