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
from contextlib import nullcontext
from pathlib import Path
from uuid import uuid4

import streamlit as st

# Consente l'avvio anche senza installazione del pacchetto (`pip install -e .`).
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from secure_rag.cli import SCENARIOS  # noqa: E402
from secure_rag.config import Settings, get_settings  # noqa: E402
from secure_rag.ingestion import (  # noqa: E402
    CLEARANCE_LEVELS,
    build_documents,
    write_index_stamp,
)
from secure_rag.providers import describe_provider, probe_providers  # noqa: E402
from secure_rag.rag import RAGResponse, SecureRAGPipeline  # noqa: E402
from secure_rag.security.audit import AuditRecord, hash_query, utc_now  # noqa: E402
from secure_rag.security.ner import ner_unavailable_reason  # noqa: E402
from secure_rag.security.pii import build_masker  # noqa: E402
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
    "public": "Cliente",
    "agent": "Agente di rete",
    "management": "Direzione Sinistri",
}

# Cosa comporta ogni ruolo, detto in termini di documenti invece che di livelli di clearance.
# È il modo per rendere evidente il controllo degli accessi senza doverlo nominare: si vede che
# la stessa domanda cambia risposta al cambiare di chi la pone.
ROLE_ACCESS = {
    "public": (
        "Vede le condizioni di polizza pubbliche.",
        "Non vede polizze aziendali, perizie né documenti interni.",
    ),
    "agent": (
        "Vede le polizze e le perizie di sinistro.",
        "Non vede le circolari riservate alla direzione.",
    ),
    "management": (
        "Vede tutto, comprese le circolari interne riservate.",
        "",
    ),
}

SCOPE_LABELS = {
    "corpus": "Documenti aziendali",
    "uploads": "Solo i miei documenti",
    "both": "Entrambi",
}

# Domande di partenza, verificate sui documenti realmente indicizzati. L'ultima è deliberatamente
# riservata alla direzione: posta da un agente riceve una risposta di assenza informazione, ed è il
# modo più rapido per vedere il controllo degli accessi in funzione.
DOMANDE_ESEMPIO = [
    ("Franchigia cyber", "Qual è la franchigia prevista dalla sezione cyber?"),
    ("Rimborso ransomware", "A quali condizioni è rimborsabile un attacco ransomware?"),
    ("Postuma decennale", "Cosa prevede l'articolo 14-bis sulla postuma decennale?"),
    ("Margine di trattativa", "Qual è il margine negoziale nelle transazioni stragiudiziali?"),
]


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
    masker = build_masker(settings)
    documents, report = build_documents(settings, masker)
    index_documents(documents, settings)
    write_index_stamp(settings, report.anonymization_levels)
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
    st.caption("Assistente sulla documentazione di polizza")

    # --- Chi risponde ------------------------------------------------------
    st.subheader("Come risponde")

    if base_settings.public_mode:
        # Sulla vetrina pubblica il modello non si cambia: il visitatore non ha ragione di
        # scegliere, e reindicizzare costerebbe embedding a chi ospita l'istanza.
        provider = base_settings.llm_provider
        settings = base_settings
        st.caption(describe_provider(settings))
    else:
        default_index = next(
            (
                index
                for index, status in enumerate(selectable)
                if status[0] == base_settings.llm_provider
            ),
            0,
        )
        provider = st.radio(
            "Modello che genera le risposte",
            options=[status[0] for status in selectable],
            index=default_index,
            format_func=lambda name: next(s[1] for s in selectable if s[0] == name),
            help=(
                "Ogni modello ha il proprio archivio indicizzato, perché produce rappresentazioni "
                "numeriche di dimensione diversa: cambiandolo va rifatta l'indicizzazione."
            ),
        )
        st.caption(next(status[2] for status in selectable if status[0] == provider))

        with st.expander("Altri modelli configurabili"):
            for _, label, _, available, hint in statuses:
                if not available:
                    st.caption(f"○ **{label}** — non attivo · {hint}")
            st.caption(
                "Il sistema non è legato a un fornitore: la stessa pipeline gira su OpenAI, "
                "Azure OpenAI o un modello installato in azienda."
            )

        settings = base_settings.with_provider(provider)

    if settings.is_offline:
        st.info(
            "Motore offline: le risposte sono generate in locale, nessun dato lascia questa "
            "macchina e non viene consumato alcun credito.",
            icon="🔌",
        )

    # --- Chi fa la domanda -------------------------------------------------
    st.subheader("Chi sta facendo la domanda")
    role = st.selectbox(
        "Profilo",
        options=list(CLEARANCE_LEVELS),
        index=1,
        format_func=lambda value: ROLE_LABELS[value],
        label_visibility="collapsed",
        help=(
            "Il profilo decide **quali documenti vengono cercati**, non quali risposte vengono "
            "filtrate dopo: i contenuti non autorizzati non entrano mai nel testo inviato al "
            "modello. In gergo: controllo degli accessi applicato al recupero (RBAC)."
        ),
    )
    vede, non_vede = ROLE_ACCESS[role]
    st.caption(f"✅ {vede}")
    if non_vede:
        st.caption(f"🚫 {non_vede}")

    # --- Cosa può consultare -----------------------------------------------
    st.subheader("Documenti consultabili")
    corpus_chunks = collection_size(settings)
    session_chunks = collection_size(upload_settings(settings))

    left, right = st.columns(2)
    left.metric(
        "Aziendali",
        f"{corpus_chunks} sezioni",
        help=(
            "Ogni documento è diviso in sezioni di lunghezza omogenea: la ricerca lavora sulle "
            "sezioni, così la risposta cita il passaggio esatto invece dell'intero contratto."
        ),
    )
    right.metric(
        "Caricati da te",
        f"{session_chunks} sezioni",
        help="Restano nella tua sessione e non sono raggiungibili dagli altri visitatori.",
    )

    if not base_settings.public_mode:
        if st.button("Rigenera l'archivio", width="stretch", type="primary"):
            with st.spinner("Rimozione dei dati personali e indicizzazione in corso…"):
                st.session_state["ingestion"] = run_ingestion(settings)
            st.rerun()

        if report := st.session_state.get("ingestion"):
            st.success(
                f"{report['documents']} documenti · {report['chunks']} sezioni · "
                f"{report['entities']} dati personali rimossi"
            )
            st.caption("Tipi rimossi: " + ", ".join(report["types"]))

    show_prompt = st.toggle(
        "Mostra il testo inviato al modello",
        value=False,
        help=(
            "Rende visibile il contenuto esatto che raggiunge il modello, con i dati personali "
            "già sostituiti da segnaposto."
        ),
    )

    st.divider()
    st.caption(
        "⚠️ Tutti i documenti di esempio sono **inventati**: nomi, codici fiscali, IBAN e partite "
        "IVA non appartengono a persone o aziende reali."
    )


# ---------------------------------------------------------------------------
# Rendering condiviso
# ---------------------------------------------------------------------------


def render_response(response: RAGResponse, answer_shown: bool = False) -> None:
    """Mostra risposta, esiti di sicurezza e fonti.

    `answer_shown` dice che il testo è già comparso durante lo streaming: qui resta da mostrare
    tutto il resto, e ristamparlo raddoppierebbe la risposta.
    """
    if response.rate_limit == "quota_globale":
        st.info(
            "Tetto giornaliero di richieste al modello in rete raggiunto: questa risposta è stata "
            "prodotta dal motore deterministico offline. La pipeline di sicurezza è la stessa; "
            "cambia solo chi genera il testo.",
            icon="🔌",
        )

    if response.blocked:
        st.error(response.answer, icon="🛑")
    elif not answer_shown:
        st.markdown(response.answer)

    # Il verdetto di sicurezza prima dei numeri: è la riga che conta per chi legge, e i quattro
    # riquadri uguali di prima la mettevano sullo stesso piano della latenza.
    events = response.security_events
    if events:
        for event in events:
            st.warning(event, icon="⚠️")
    else:
        st.success(
            "Nessuna anomalia: la domanda non conteneva tentativi di manipolazione, i documenti "
            "consultati erano integri e la risposta non contiene dati personali.",
            icon="✅",
        )

    st.caption(
        f"👤 {ROLE_LABELS.get(response.role, response.role)}  ·  "
        f"🔍 {SCOPE_LABELS.get(response.scope, response.scope)}  ·  "
        f"⏱ {response.latency_ms / 1000:.1f} s  ·  "
        f"🤖 {response.provider}"
    )

    if response.context_scan and response.context_scan.findings:
        with st.expander("Perché un documento è stato scartato"):
            st.caption(
                "Il documento conteneva testo rivolto all'assistente invece che al lettore — "
                "tipicamente istruzioni nascoste per alterare la risposta. È stato escluso dal "
                "materiale inviato al modello."
            )
            for finding in response.context_scan.findings:
                st.code(finding, language=None)

    if response.citations:
        st.markdown("**Su cosa si basa questa risposta**")
        for indice, citazione in enumerate(response.citations, start=1):
            icona = "📎" if citazione.uploaded else "📄"
            with st.expander(f"{icona} {citazione.source}", expanded=False):
                st.caption(
                    "Estratto realmente inviato al modello, con i dati personali già sostituiti "
                    "dai segnaposto. È la citazione resa verificabile: non «fidati», ma «guarda»."
                )
                st.markdown(f"> {citazione.excerpt.replace(chr(10), chr(10) + '> ')}")
    elif response.sources:
        badges = [
            f"📎 {source}" if source in response.uploaded_sources else f"📄 {source}"
            for source in response.sources
        ]
        st.caption("**Documenti consultati:** " + " · ".join(badges))

    if show_prompt and response.prompt_sent:
        with st.expander("Il testo esatto ricevuto dal modello"):
            st.caption(
                "I dati personali sono già sostituiti da segnaposto come `[CF_001]`: al modello "
                "non arriva mai un codice fiscale o un IBAN in chiaro."
            )
            st.code(response.prompt_sent, language="markdown")


def run_query(
    question: str,
    scope: str,
    as_role: str | None = None,
    stream: bool = True,
) -> RAGResponse:
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

    # I passi compaiono mentre avvengono, e il testo mentre viene generato. Il contenitore della
    # risposta sta sotto lo stato, così quando questo si richiude il testo resta al suo posto.
    # `stream=False` serve dove la risposta viene mostrata **altrove**, come negli scenari: il
    # testo comparirebbe dentro la scheda del pulsante e poi di nuovo sotto, in «Esito».
    stato = st.status("Controlli di sicurezza in corso…", expanded=True) if stream else None
    contenitore = st.empty() if stream else None
    pezzi: list[str] = []

    def mostra(pezzo: str) -> None:
        """Riceve dalla pipeline solo testo già verificato: si può scrivere a schermo così com'è."""
        pezzi.append(pezzo)
        contenitore.markdown("".join(pezzi))  # type: ignore[union-attr]

    # Senza streaming non c'è testo che compare: serve almeno un segnale che qualcosa sta girando.
    attesa = st.spinner("Controlli di sicurezza in corso…") if not stream else nullcontext()
    with attesa:
        response = get_pipeline(provider_effettivo).answer(
            question,
            role=ruolo_effettivo,
            scope=scope,
            rate_limit=verdetto.rule,
            # I documenti caricati vivono in una collection per sessione, e la pipeline non
            # conosce la sessione: senza questo passaggio cercherebbe in quella condivisa, vuota.
            upload_collection=upload_settings(settings).collection_name,
            on_step=(lambda descrizione: stato.write(f"✓ {descrizione}")) if stato else None,
            on_token=mostra if stream else None,
        )
    if stato is not None:
        stato.update(
            label=f"Sette controlli attraversati in {response.latency_ms / 1000:.1f} s",
            state="complete",
            expanded=False,
        )

    if not stream:
        st.session_state["risposta_gia_mostrata"] = False
    elif response.blocked:
        # Ciò che era comparso aveva superato i controlli, ma una risposta troncata sarebbe
        # fuorviante: il contenitore lascia il posto al messaggio di blocco.
        contenitore.empty()  # type: ignore[union-attr]
    else:
        # La versione definitiva può contenere aggiunte successive alla generazione, come la nota
        # di quarantena: si riscrive il contenitore invece di lasciare il testo dei soli pezzi.
        contenitore.markdown(response.answer)  # type: ignore[union-attr]

    if stream:
        st.session_state["risposta_gia_mostrata"] = not response.blocked

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
        render_response(response, answer_shown=st.session_state.pop("risposta_gia_mostrata", False))
    st.session_state["history"].append({"question": question, "response": response})


st.session_state.setdefault("history", [])
st.session_state.setdefault("upload_reports", [])
st.session_state.setdefault("processed_uploads", set())


# --- Intestazione: cosa sta guardando chi apre il link -----------------------
_chips = [
    "I dati personali non lasciano il perimetro",
    "Difesa dalle istruzioni nascoste nei documenti",
    "Ognuno vede solo ciò a cui è autorizzato",
    "Ogni interazione è tracciata",
]
st.markdown(
    "<div class='app-hero'>"
    "<h1>🛡️ Secure Insurance RAG</h1>"
    "<p>Fai domande sulla documentazione di polizza e ottieni risposte con la fonte citata. "
    "Accanto a ogni risposta vedi <b>cosa ha fatto il sistema per proteggerla</b>: quali documenti "
    "ha potuto consultare il tuo profilo, quali ha scartato perché manomessi, e il testo esatto "
    "arrivato al modello.</p>"
    "<div class='app-chips'>"
    + "".join(f"<span class='app-chip'>{voce}</span>" for voce in _chips)
    + "</div></div>",
    unsafe_allow_html=True,
)

if settings.rate_limit_enabled:
    _residue_ip, _residue_globali = get_rate_limiter().snapshot(visitor_identity())
    intestazione, quota_visitatore, quota_totale = st.columns([2, 1, 1])
    intestazione.caption(
        "Dimostrazione pubblica su documenti **inventati**. Per non lasciare scoperta la spesa "
        "del modello, il numero di domande è limitato."
    )
    quota_visitatore.metric(
        "Le tue domande",
        _residue_ip,
        help="Quante ne puoi ancora fare in quest'ora. Si ricaricano da sole.",
    )
    quota_totale.metric(
        "Disponibili oggi",
        _residue_globali,
        help=(
            "Tetto complessivo giornaliero. Una volta esaurito il servizio non si ferma: "
            "continua a rispondere con il motore offline."
        ),
    )
    if _residue_globali == 0:
        st.info(
            "Le domande al modello in rete sono esaurite per oggi. Il servizio continua a "
            "funzionare con il motore offline: le risposte sono più essenziali, ma i controlli di "
            "sicurezza restano identici.",
            icon="🔌",
        )

tab_chat, tab_docs, tab_security = st.tabs(["💬 Chat", "📎 Documenti", "🛡️ Sicurezza"])


# ---------------------------------------------------------------------------
# Scheda 1 — Chat
# ---------------------------------------------------------------------------

with tab_chat:
    st.subheader("Assistente polizze")
    st.markdown(
        "L'archivio contiene **quattro documenti**: una polizza multirischio impresa (con sezione "
        "cyber), una RC professionale, una perizia di sinistro e una circolare interna della "
        "direzione. Le risposte citano sempre il documento da cui provengono."
    )

    session_chunks = collection_size(upload_settings(settings))
    scope = st.radio(
        "Dove cercare",
        options=["corpus", "uploads", "both"],
        format_func=lambda value: SCOPE_LABELS[value],
        horizontal=True,
        help=(
            "I documenti che carichi restano separati da quelli aziendali: puoi interrogarli da "
            "soli, e non entrano a far parte dell'archivio comune."
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
        if base_settings.public_mode:
            st.error(
                "L'archivio non è al momento disponibile. Riprova fra qualche minuto.", icon="⚠️"
            )
        else:
            st.warning(
                f"Nessun archivio indicizzato per **{describe_provider(settings)}**. Usa "
                "**Rigenera l'archivio** nella barra laterale: ogni modello ha il proprio indice, "
                "perché produce rappresentazioni numeriche di dimensione diversa.",
                icon="📄",
            )

    # Domande pronte: senza, chi arriva deve inventare una domanda su documenti che non ha letto.
    if not st.session_state["history"]:
        st.caption("**Non sai da dove iniziare?** Prova una di queste:")
        colonne = st.columns(len(DOMANDE_ESEMPIO))
        for colonna, (etichetta, testo) in zip(colonne, DOMANDE_ESEMPIO):
            if colonna.button(etichetta, width="stretch", help=testo):
                st.session_state["domanda_scelta"] = testo
                st.rerun()

    for entry in st.session_state["history"]:
        with st.chat_message("user"):
            st.write(entry["question"])
        with st.chat_message("assistant"):
            render_response(entry["response"])

    question = st.chat_input("Fai una domanda sulle polizze…")

    # Una domanda scelta fra quelle pronte segue esattamente lo stesso percorso di una digitata.
    if scelta := st.session_state.pop("domanda_scelta", None):
        question = scelta

    if question:
        if collection_size(settings) == 0 and scope == "corpus":
            st.error("L'archivio aziendale non è disponibile in questo momento.", icon="📄")
        else:
            ask(question, scope)

    if st.session_state["history"] and st.button("Ricomincia da capo"):
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
        # Verdetto in chiaro prima dei numeri: è la sola riga che conta per chi ha appena caricato.
        if report.suspicious_chunks:
            st.error(
                "**Questo documento contiene istruzioni rivolte all'assistente.** "
                f"{report.suspicious_chunks} parti cercano di alterare le risposte — è il caso in "
                "cui il testo malevolo non arriva dalla chat ma dal documento stesso. Quelle parti "
                "vengono escluse a ogni interrogazione, e l'evento resta registrato.",
                icon="🧨",
            )
            for finding in report.findings:
                st.code(finding, language=None)
        else:
            st.success(
                "Nessuna istruzione sospetta rilevata: il documento contiene solo testo destinato "
                "a essere letto.",
                icon="✅",
            )

        columns = st.columns(4)
        columns[0].metric("Dimensione", f"{report.size_kb:.0f} KB")
        columns[1].metric("Sezioni", report.chunks)
        columns[2].metric(
            "Dati personali rimossi",
            report.pii_count,
            help="Sostituiti da segnaposto prima di qualunque invio al modello.",
        )
        columns[3].metric("Parti sospette", report.suspicious_chunks)

        if report.pii_types:
            st.caption("**Tipi rimossi:** " + ", ".join(report.pii_types))

        if report.anonymization_levels:
            st.caption(
                f"**Livelli di anonimizzazione:** {report.anonymization_levels} — le regex vedono i "
                "formati rigidi (codice fiscale, IBAN, targa); il livello 2, quando attivo, aggiunge "
                "i nomi in testo libero."
            )

        st.caption(
            f"Consultabile da chi ha il profilo **{ROLE_LABELS.get(report.clearance, report.clearance)}** "
            "o superiore, e solo all'interno di questa sessione."
        )

        left, right = st.columns(2)
        with left:
            st.caption("Come l'hai caricato (resta solo qui)")
            st.text_area(
                "originale",
                report.preview_original,
                height=220,
                disabled=True,
                label_visibility="collapsed",
                key=f"orig_{report.file_name}_{report.uploaded_at}",
            )
        with right:
            st.caption("Come viene archiviato e inviato al modello")
            st.text_area(
                "anonimizzato",
                report.preview_masked,
                height=220,
                disabled=True,
                label_visibility="collapsed",
                key=f"mask_{report.file_name}_{report.uploaded_at}",
            )


with tab_docs:
    st.subheader("Carica un tuo documento")
    st.markdown(
        "Puoi caricare una polizza, una perizia o un preventivo e farci domande sopra. "
        "Prima ancora che tu possa chiedere qualcosa, il documento viene **ripulito dai dati "
        "personali** ed **esaminato**: se contiene istruzioni nascoste rivolte all'assistente, te "
        "lo diciamo subito."
    )
    st.caption(
        f"Formati: PDF, Markdown, testo · massimo {settings.max_upload_mb:.0f} MB · "
        "il documento resta **isolato nella tua sessione**, non è raggiungibile dagli altri "
        "visitatori e sparisce quando chiudi. Togliendolo dall'elenco viene cancellato subito."
    )

    uploaded_files = st.file_uploader(
        "Trascina qui un file, oppure scegline uno",
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
        masker = build_masker(settings)
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

        # Domande ricavate dal lessico dei documenti caricati, non dal modello: un campo vuoto non
        # dice cosa farne, e generare i suggerimenti con l'LLM costerebbe una chiamata per ogni
        # file, pagata anche quando l'utente non chiede nulla.
        suggerite: list[str] = []
        for report in st.session_state["upload_reports"]:
            for proposta in report.suggested_questions:
                if proposta not in suggerite:
                    suggerite.append(proposta)

        if suggerite:
            st.caption("**Da chiedere a questi documenti**")
            colonne = st.columns(len(suggerite))
            for colonna, proposta in zip(colonne, suggerite):
                if colonna.button(proposta, key=f"sugg_{proposta}", width="stretch"):
                    # Il clic riempie il campo e invia: chiedere una conferma sarebbe un passaggio
                    # in più senza informazione in più.
                    st.session_state["domanda_upload"] = proposta
                    st.session_state["chiedi_subito"] = True

        left, right = st.columns([3, 1])
        with left:
            domanda = st.text_input(
                "Chiedi qualcosa su questi documenti",
                value=st.session_state.pop("domanda_upload", ""),
                placeholder="Es. Qual è l'importo dell'indennizzo proposto?",
            )
        with right:
            st.write("")
            st.write("")
            chiedi = st.button("Chiedi", width="stretch", type="primary")

        chiedi = chiedi or st.session_state.pop("chiedi_subito", False)

        if chiedi and domanda:
            # Eseguita qui, non rimandata alla scheda Chat: in demo il risultato deve comparire
            # dov'è stato chiesto. Finisce comunque nello storico della conversazione.
            response = run_query(domanda, scope="uploads")
            st.session_state["history"].append({"question": domanda, "response": response})
            st.markdown("**Esito**")
            render_response(response, answer_shown=st.session_state.pop("risposta_gia_mostrata", False))

        if st.button("Elimina tutti i miei documenti"):
            reset_collection(upload_settings(settings))
            st.session_state["upload_reports"] = []
            st.session_state["processed_uploads"] = set()
            st.rerun()
    else:
        st.info(
            "Non hai ancora caricato nulla. Va bene qualsiasi polizza o perizia in PDF: vedrai "
            "quanti dati personali vengono rimossi e se il documento contiene istruzioni nascoste.",
            icon="🧪",
        )


# ---------------------------------------------------------------------------
# Scheda 3 — Sicurezza
# ---------------------------------------------------------------------------

with tab_security:
    st.subheader("Mettilo alla prova")
    st.markdown(
        "Sei tentativi di far sbagliare il sistema, eseguibili con un clic: chiedergli di "
        "ignorare le regole, farsi dare dati personali, leggere documenti riservati. "
        "**Ogni scenario si esegue con il profilo che gli è proprio**, indipendentemente da quello "
        "scelto in barra laterale — è ciò che rende confrontabili il quinto e il sesto, che pongono "
        "la stessa domanda con autorizzazioni diverse."
    )
    st.caption(
        "Il riferimento accanto a ciascuno (LLM01, LLM06…) è la classificazione OWASP Top 10 for "
        "LLM Applications, lo standard di settore per i rischi dei sistemi basati su modelli "
        "linguistici."
    )

    columns = st.columns(3)
    for index, scenario in enumerate(SCENARIOS):
        with columns[index % 3]:
            with st.container(border=True):
                st.markdown(f"**{scenario.name}**")
                st.caption(f"Profilo usato: **{ROLE_LABELS.get(scenario.role, scenario.role)}**")
                if scenario.owasp != "—":
                    st.caption(f"Rischio: {scenario.owasp}")
                st.caption(f"Esito atteso: {scenario.expected}")
                if st.button("Esegui", key=f"scenario_{index}", width="stretch"):
                    st.session_state["scenario_result"] = {
                        "name": scenario.name,
                        "question": scenario.question,
                        "expected": scenario.expected,
                        "response": run_query(
                            scenario.question,
                            scope="corpus",
                            as_role=scenario.role,
                            stream=False,
                        ),
                    }

    if result := st.session_state.get("scenario_result"):
        st.divider()
        st.markdown(f"#### Esito — {result['name']}")
        st.caption(f"Atteso: {result['expected']}")
        st.code(result["question"], language=None)
        render_response(result["response"])

    st.divider()
    st.subheader("Anonimizzazione in esercizio")
    masker_attivo = build_masker(settings)
    st.markdown(
        f"Livelli attivi su questa istanza: **{masker_attivo.active_levels}**."
    )
    if masker_attivo.ner_active:
        st.caption(
            "Il livello 2 riconosce i nomi in **testo libero** — «il testimone Andrea Gallo ha "
            "dichiarato» — che nessuna espressione regolare può vedere, perché non c'è alcun "
            "formato da riconoscere. È un modello, quindi assegna una confidenza: la soglia in "
            "uscita è più severa di quella in ingresso."
        )
    else:
        st.caption(
            "Solo espressioni regolari: coprono ciò che ha una forma riconoscibile — codice "
            "fiscale, IBAN, numero di polizza, targa, telaio — e i nomi introdotti da un ruolo "
            "contrattuale. Restano fuori i nomi in testo libero e, per costruzione, i dati "
            "sanitari e giudiziari. Il livello 2 (NER) esiste nel codice ed è attivo "
            "sull'istanza pubblica: qui è spento perché in un'installazione da sorgente resta "
            "opzionale (`PII_NER_ENABLED`), per non aggiungere 540 MB di modello linguistico."
        )
        if motivo := ner_unavailable_reason(settings):
            st.warning(f"Il livello 2 è configurato ma non sta lavorando: {motivo}", icon="⚠️")

    st.divider()
    st.subheader("Registro delle interazioni")
    st.markdown(
        "Ogni richiesta lascia una riga verificabile a posteriori: **chi** ha chiesto, **quali** "
        "documenti sono stati consultati, **quali controlli** sono scattati. In un settore "
        "regolamentato è ciò che permette a un revisore di ricostruire una risposta a distanza di "
        "mesi."
    )

    records = get_pipeline(provider).audit.tail(15)
    if records:
        # Intestazioni leggibili; i nomi originali dei campi restano sotto, perché è il formato
        # che verrebbe spedito a un SIEM e va riconosciuto da chi lo integra.
        etichette = {
            "timestamp": "Quando",
            "role": "Profilo",
            "query_hash": "Impronta domanda",
            "query_length": "Lunghezza",
            "input_verdict": "Controllo domanda",
            "input_rule": "Regola scattata",
            "scope": "Ambito",
            "context_sources": "Documenti consultati",
            "uploaded_sources": "Di cui caricati",
            "quarantined_sources": "Documenti scartati",
            "pii_masked_in_context": "Dati personali rimossi",
            "output_verdict": "Controllo risposta",
            "output_rule": "Regola risposta",
            "latency_ms": "Durata (ms)",
            "provider": "Modello",
            "rate_limit": "Limite di frequenza",
        }
        leggibili = [
            {etichette.get(chiave, chiave): valore for chiave, valore in record.items()}
            for record in records
        ]
        st.dataframe(leggibili, width="stretch")
        st.caption(
            "**La domanda in chiaro non viene mai registrata**: al suo posto resta un'impronta "
            "irreversibile, che consente di riconoscere richieste ripetute senza conservare il "
            "testo. Un registro che archiviasse le domande diventerebbe esso stesso un deposito di "
            "dati personali."
        )
        with st.expander("Nomi originali dei campi (formato di esportazione)"):
            st.caption(
                "Il registro è scritto in JSONL, un oggetto per riga, pronto per essere inoltrato "
                "a un sistema di correlazione eventi (SIEM). Corrispondenze:"
            )
            st.code(
                "\n".join(f"{campo:<24} → {nome}" for campo, nome in etichette.items()),
                language=None,
            )
    else:
        st.caption("Nessuna interazione registrata finora.")
