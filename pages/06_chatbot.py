# pages/06_chatbot.py — CyberSahayak AI Chatbot
import logging
import streamlit as st

# ── Page config (must be first Streamlit call) ─────────────────────────────
st.set_page_config(
    page_title="AI Chatbot | CyberSahayak",
    page_icon="🤖",
    layout="wide",
)

# ── Safe imports with fallback UI ──────────────────────────────────────────
try:
    from ui.styles import GLOBAL_CSS
    st.markdown(GLOBAL_CSS, unsafe_allow_html=True)
except ImportError:
    pass  # Continue without custom CSS

try:
    from modules.chatbot.rag_engine import rag_query, retrieve_context, get_kb_stats
    _RAG_OK = True
except Exception as e:
    _RAG_OK = False
    _RAG_ERR = str(e)

try:
    from modules.chatbot.ollama_client import (
        is_ollama_running,
        get_available_models,
        unified_llm_query,
    )
    _OLLAMA_OK = True
except Exception as e:
    _OLLAMA_OK = False

try:
    from modules.chatbot.llm_router import get_provider_status
    _ROUTER_OK = True
except Exception:
    _ROUTER_OK = False

try:
    from config import settings
    _GEMINI_KEY = settings.GEMINI_API_KEY
    _DEFAULT_MODEL = settings.OLLAMA_DEFAULT_MODEL
except Exception:
    _GEMINI_KEY = ""
    _DEFAULT_MODEL = "phi3:mini"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Initial greeting ───────────────────────────────────────────────────────
_GREETING = (
    "Namaste! 🛡️ I'm **CyberSahayak**, your AI cybercrime prevention assistant.\n\n"
    "I can help you:\n"
    "• Identify if a message / call / email is a scam\n"
    "• Understand digital arrest, UPI fraud, OTP theft\n"
    "• File a cybercrime complaint (1930 / cybercrime.gov.in)\n"
    "• Understand your rights under the IT Act\n\n"
    "**If you're a victim right now — call 1930 immediately.**\n\n"
    "How can I help you today?"
)

# ── Sidebar ────────────────────────────────────────────────────────────────
with st.sidebar:
    st.error("### 🚨 Emergency\nHelpline: **1930**")
    st.info("**Report:** cybercrime.gov.in")
    st.success(f"**Active Case:**\n{st.session_state.get('case_id', 'None')}")
    st.divider()

    # ── AI Status ──────────────────────────────────────────────────────────
    st.markdown("**🤖 AI Status**")

    selected_model = _DEFAULT_MODEL

    if _OLLAMA_OK:
        try:
            ollama_live = is_ollama_running()
        except Exception:
            ollama_live = False

        if ollama_live:
            try:
                models = get_available_models()
            except Exception:
                models = []

            if models:
                st.success(f"✅ Ollama: Online ({len(models)} model(s))")
                selected_model = st.selectbox("Model", models, key="ollama_model")
            else:
                st.warning("⚠️ Ollama: Online but no models pulled")
                st.code("ollama pull qwen2.5:3b")
        else:
            st.warning("⚠️ Ollama: Offline")
            st.caption("Start with: `ollama serve`")
    else:
        st.warning("⚠️ Ollama: Unavailable")

    if _GEMINI_KEY:
        st.success("✅ Gemini: Configured")
    else:
        st.info("💡 Add GEMINI_API_KEY to .env for Gemini fallback")

    st.info("✅ Local fallback: Always available")

    st.divider()

    # ── KB Status ──────────────────────────────────────────────────────────
    if _RAG_OK:
        try:
            kb = get_kb_stats()
            if kb.get("chunks", 0) > 0:
                st.success(f"📚 Knowledge Base: {kb['chunks']} chunks loaded")
            else:
                st.warning("📚 Knowledge Base: Empty — check cybercrime_kb.txt")
        except Exception:
            pass

    st.divider()

    if st.button("🗑️ Clear Chat", use_container_width=True):
        st.session_state.chat_history = []
        st.rerun()

    if st.button("🔄 Reload Knowledge Base", use_container_width=True):
        # Force KB reload
        try:
            import modules.chatbot.rag_engine as _re
            _re._kb_loaded = False
            _re._chunks = []
            _re._vectorizer = None
            _re._tfidf_matrix = None
            st.success("Knowledge base reloaded")
            st.rerun()
        except Exception as e:
            st.error(f"Reload failed: {e}")

# ── Page header ────────────────────────────────────────────────────────────
st.markdown(
    '<div class="section-header">🤖 CyberSahayak AI Assistant</div>',
    unsafe_allow_html=True,
)
st.markdown(
    "Ask me anything about cybercrime, scam identification, how to file a complaint, "
    "or Indian cyber laws (IT Act, RBI guidelines)."
)

if not _RAG_OK:
    st.error(f"⚠️ RAG engine failed to load: {_RAG_ERR if '_RAG_ERR' in dir() else 'Unknown error'}")

# ── Initialize session state ───────────────────────────────────────────────
if "chat_history" not in st.session_state:
    st.session_state.chat_history = [
        {"role": "assistant", "content": _GREETING}
    ]

# ── Display chat history ───────────────────────────────────────────────────
for msg in st.session_state.chat_history:
    avatar = "🤖" if msg["role"] == "assistant" else "👤"
    with st.chat_message(msg["role"], avatar=avatar):
        st.markdown(msg["content"])


# ── LLM call (safe, never raises) ─────────────────────────────────────────
def _call_llm(user_prompt: str, augmented_prompt: str) -> tuple[str, str]:
    """
    Returns (response_text, provider_label).
    Falls through Ollama → Gemini → local.
    """
    try:
        if _OLLAMA_OK:
            result = unified_llm_query(
                prompt=augmented_prompt,
                gemini_api_key=_GEMINI_KEY,
                original_query=user_prompt,
                model=selected_model,
            )
            return result.get("response", ""), result.get("provider", "local")
    except Exception as e:
        logger.error(f"LLM call error: {e}")

    # Ultimate fallback
    try:
        from modules.chatbot.rag_engine import _offline_response
        return _offline_response(user_prompt), "local"
    except Exception:
        return (
            "🛡️ AI unavailable. For cybercrime emergencies, call **1930** or visit cybercrime.gov.in",
            "local"
        )


def _make_rag_llm_fn(user_prompt: str):
    """Create llm_fn closure for rag_query."""
    def llm_fn(augmented: str) -> str:
        text, _ = _call_llm(user_prompt, augmented)
        return text
    return llm_fn


def _get_response(user_prompt: str) -> tuple[str, str, str]:
    """
    Full pipeline: RAG → LLM.
    Returns (response, context, provider).
    """
    context = ""
    provider = "local"

    try:
        if _RAG_OK:
            context = retrieve_context(user_prompt, k=3)

        if context:
            augmented_prompt = (
                f"Context:\n{context}\n\n"
                f"User Question:\n{user_prompt}"
            )
        else:
            augmented_prompt = user_prompt

        response, provider = _call_llm(
            user_prompt,
            augmented_prompt
        )

    except Exception as e:
        logger.error(f"RAG pipeline error: {e}")

        try:
            from modules.chatbot.rag_engine import _offline_response
            response = _offline_response(user_prompt)
            provider = "local"
        except Exception:
            response = "AI unavailable."
            provider = "local"

    return response, context, provider
# ── Chat input ─────────────────────────────────────────────────────────────
if prompt := st.chat_input("Ask about cybercrime, scams, or how to report..."):
    # Add user message
    st.session_state.chat_history.append({"role": "user", "content": prompt})
    with st.chat_message("user", avatar="👤"):
        st.markdown(prompt)

    # Generate response
    with st.chat_message("assistant", avatar="🤖"):
        with st.spinner("Thinking..."):
            response, context, provider = _get_response(prompt)

        st.markdown(response)

        # Provider badge
        badge_color = {"ollama": "green", "gemini": "blue", "local": "orange"}.get(provider, "gray")
        st.caption(f":{badge_color}[Answered by: {provider}]")

        # Show retrieved context
        if context:
            with st.expander("📚 Knowledge Base Sources"):
                st.markdown(context)

    st.session_state.chat_history.append({"role": "assistant", "content": response})


# ── Quick action buttons ───────────────────────────────────────────────────
st.divider()
st.markdown("**Quick Questions:**")
quick_cols = st.columns(3)
quick_questions = [
    "What is a digital arrest scam?",
    "How do I report UPI fraud?",
    "I received a fake CBI call, what do I do?",
    "What are the signs of OTP theft?",
    "How to file complaint on cybercrime.gov.in?",
    "What is the 1930 helpline?",
]

for i, q in enumerate(quick_questions):
    with quick_cols[i % 3]:
        if st.button(q, key=f"quick_{i}", use_container_width=True):
            st.session_state.chat_history.append({"role": "user", "content": q})
            with st.spinner("Thinking..."):
                response, _ctx, _prov = _get_response(q)
            st.session_state.chat_history.append({"role": "assistant", "content": response})
            st.rerun()
