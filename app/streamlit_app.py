"""Interfaccia demo Streamlit.

Pensata per essere proiettata durante un colloquio: ogni risposta mostra, accanto al testo, **cosa
ha fatto il layer di sicurezza** — quali documenti sono stati recuperati per quel ruolo, quali sono
finiti in quarantena, e il prompt effettivamente inviato al modello (già anonimizzato).

Avvio:  streamlit run app/streamlit_app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

# Consente l'avvio anche senza installazione del pacchetto (`pip install -e .`).
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from secure_rag.cli import SCENARIOS  # noqa: E402
from secure_rag.config import get_settings  # noqa: E402
from secure_rag.ingestion import CLEARANCE_LEVELS, build_documents  # noqa: E402
from secure_rag.providers import describe_provider  # noqa: E402
from secure_rag.rag import RAGResponse, SecureRAGPipeline  # noqa: E402
from secure_rag.security.pii import PIIMasker  # noqa: E402
from secure_rag.vectorstore import collection_size, index_documents  # noqa: E402

st.set_page_config(page_title="Secure Insurance RAG", page_icon="🛡️", layout="wide")

ROLE_LABELS = {
    "public": "Cliente (documenti pubblici)",
    "agent": "Agente di rete (polizze e perizie)",
    "management": "Direzione Sinistri (tutto, incluse circolari interne)",
}


@st.cache_resource(show_spinner=False)
def get_pipeline(provider: str) -> SecureRAGPipeline:
    """Pipeline riusata tra i rerun. La chiave di cache è il provider attivo."""
    return SecureRAGPipeline()


def run_ingestion() -> dict:
    settings = get_settings()
    masker = PIIMasker()
    documents, report = build_documents(settings, masker)
    index_documents(documents, settings)
    return {
        "documents": report.documents,
        "chunks": report.chunks,
        "entities": report.masked_entities,
        "types": report.entity_types,
        "files": report.files,
        "vault_size": len(masker.vault),
    }


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

settings = get_settings()

with st.sidebar:
    st.title("🛡️ Secure Insurance RAG")
    st.caption("PoC di RAG sicuro su documentazione assicurativa")

    st.subheader("Configurazione")
    st.write(f"**Provider LLM:** {describe_provider(settings)}")
    if settings.is_offline:
        st.info("Modalità offline: nessuna chiamata di rete, nessun token consumato.", icon="🔌")

    role = st.selectbox(
        "Ruolo del richiedente",
        options=list(CLEARANCE_LEVELS),
        index=1,
        format_func=lambda value: ROLE_LABELS[value],
        help="Determina quali documenti il retriever può recuperare (RBAC applicato sui vettori).",
    )

    show_prompt = st.toggle("Mostra il prompt inviato all'LLM", value=False)

    st.subheader("Indice")
    indexed = collection_size(settings)
    st.metric("Chunk indicizzati", indexed)

    if st.button("Indicizza documenti", width="stretch", type="primary"):
        with st.spinner("Anonimizzazione e indicizzazione in corso…"):
            st.session_state["ingestion"] = run_ingestion()
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
# Corpo principale
# ---------------------------------------------------------------------------

st.title("Assistente polizze con layer di sicurezza")
st.caption(
    "PII masking prima dell'embedding · guardrails su input, contesto e output · "
    "RBAC applicato al retrieval · audit trail di ogni interazione"
)

if collection_size(settings) == 0:
    st.warning(
        "Nessun documento indicizzato. Usa **Indicizza documenti** nella barra laterale per "
        "avviare la pipeline di ingestion anonimizzata.",
        icon="📄",
    )

with st.expander("Scenari di attacco pronti (clicca per eseguirli)"):
    columns = st.columns(3)
    for index, scenario in enumerate(SCENARIOS):
        with columns[index % 3]:
            if st.button(scenario.name, key=f"scenario_{index}", width="stretch"):
                st.session_state["pending_question"] = scenario.question
                st.session_state["pending_role"] = scenario.role
                st.rerun()
            st.caption(f"OWASP: {scenario.owasp}")

st.session_state.setdefault("history", [])


def render_response(response: RAGResponse) -> None:
    """Mostra risposta, esiti di sicurezza e fonti."""
    if response.blocked:
        st.error(response.answer, icon="🛑")
    else:
        st.markdown(response.answer)

    events = response.security_events
    columns = st.columns(3)
    columns[0].metric("Ruolo", ROLE_LABELS[response.role].split(" (")[0])
    columns[1].metric("Latenza", f"{response.latency_ms} ms")
    columns[2].metric("Eventi di sicurezza", len(events))

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
        st.caption("**Fonti recuperate:** " + ", ".join(response.sources))

    if show_prompt and response.prompt_sent:
        with st.expander("Prompt inviato all'LLM (anonimizzato)"):
            st.code(response.prompt_sent, language="markdown")


for entry in st.session_state["history"]:
    with st.chat_message("user"):
        st.write(entry["question"])
    with st.chat_message("assistant"):
        render_response(entry["response"])

question = st.chat_input("Fai una domanda sulle polizze…")

if pending := st.session_state.pop("pending_question", None):
    question = pending
    role = st.session_state.pop("pending_role", role)

if question:
    if collection_size(settings) == 0:
        st.error("Indicizza prima i documenti dalla barra laterale.", icon="📄")
    else:
        with st.chat_message("user"):
            st.write(question)
        with st.chat_message("assistant"):
            with st.spinner("Elaborazione con controlli di sicurezza…"):
                response = get_pipeline(settings.llm_provider).answer(question, role=role)
            render_response(response)
        st.session_state["history"].append({"question": question, "response": response})

with st.expander("Audit trail (ultime interazioni)"):
    records = get_pipeline(settings.llm_provider).audit.tail(10)
    if records:
        st.dataframe(records, width="stretch")
        st.caption(
            "La domanda in chiaro non viene mai registrata: nel log resta solo un hash, "
            "insieme a ruolo, fonti consultate, documenti in quarantena e verdetti dei guard."
        )
    else:
        st.caption("Nessuna interazione registrata.")
