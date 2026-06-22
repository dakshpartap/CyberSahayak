# modules/chatbot/rag_engine.py
# RAG engine using TF-IDF similarity — no langchain or FAISS required.
# Falls back gracefully when knowledge base is missing or empty.

import os
import re
import logging
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Global state (loaded once per process) ─────────────────────────────────
_lock = threading.Lock()
_chunks: list[str] = []
_tfidf_matrix = None
_vectorizer = None
_kb_loaded = False

# ── Knowledge base location ────────────────────────────────────────────────
_KB_DIR = Path("modules/chatbot/knowledge_base")
_KB_FILE = _KB_DIR / "cybercrime_kb.txt"


def _split_into_chunks(text: str, chunk_size: int = 600, overlap: int = 80) -> list[str]:
    """Split text into overlapping chunks for retrieval."""
    # Split on paragraph boundaries first
    paragraphs = [p.strip() for p in re.split(r'\n{2,}', text) if p.strip()]
    chunks = []
    current = ""
    for para in paragraphs:
        if len(current) + len(para) <= chunk_size:
            current = (current + "\n\n" + para).strip()
        else:
            if current:
                chunks.append(current)
            # If paragraph itself is too long, hard-split it
            if len(para) > chunk_size:
                words = para.split()
                buf = []
                for w in words:
                    buf.append(w)
                    if len(" ".join(buf)) >= chunk_size:
                        chunks.append(" ".join(buf))
                        # Keep overlap words
                        overlap_words = buf[-max(1, overlap // 6):]
                        buf = overlap_words
                if buf:
                    chunks.append(" ".join(buf))
            else:
                current = para
    if current:
        chunks.append(current)
    return [c for c in chunks if len(c.strip()) > 30]


def _build_tfidf(chunks: list[str]):
    """Build TF-IDF matrix from chunks."""
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        vec = TfidfVectorizer(
            ngram_range=(1, 2),
            min_df=1,
            max_df=0.95,
            sublinear_tf=True
        )
        matrix = vec.fit_transform(chunks)
        return vec, matrix
    except ImportError:
        logger.warning("scikit-learn not available — RAG will use keyword search fallback")
        return None, None


def _load_kb():
    """Load knowledge base files and build TF-IDF index (once, thread-safe)."""
    global _chunks, _tfidf_matrix, _vectorizer, _kb_loaded

    with _lock:
        if _kb_loaded:
            return

        all_text_parts = []

        # Load all .txt files from the knowledge base directory
        kb_dir = _KB_DIR if _KB_DIR.exists() else Path(".")
        txt_files = list(kb_dir.glob("*.txt"))

        for txt_file in txt_files:
            try:
                content = txt_file.read_text(encoding="utf-8", errors="replace").strip()
                if content:
                    all_text_parts.append(content)
                    logger.info(f"Loaded KB: {txt_file.name} ({len(content)} chars)")
            except Exception as e:
                logger.warning(f"Failed to read {txt_file}: {e}")

        if not all_text_parts:
            logger.warning("Knowledge base is empty — RAG will answer without context")
            _kb_loaded = True
            return

        full_text = "\n\n".join(all_text_parts)
        _chunks = _split_into_chunks(full_text)
        logger.info(f"KB split into {len(_chunks)} chunks")

        if _chunks:
            _vectorizer, _tfidf_matrix = _build_tfidf(_chunks)

        _kb_loaded = True


def _keyword_fallback(query: str, k: int) -> list[str]:
    """Simple keyword overlap retrieval when TF-IDF is unavailable."""
    if not _chunks:
        return []
    q_words = set(query.lower().split())
    scored = []
    for chunk in _chunks:
        c_lower = chunk.lower()
        score = sum(1 for w in q_words if w in c_lower)
        scored.append((score, chunk))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [c for s, c in scored[:k] if s > 0]


def retrieve_context(query: str, k: int = 4) -> str:
    """
    Retrieve top-k most relevant knowledge base chunks for a query.
    Returns empty string if knowledge base is unavailable.
    """
    try:
        _load_kb()
    except Exception as e:
        logger.error(f"KB load failed: {e}")
        return ""

    if not _chunks:
        return ""

    try:
        if _vectorizer is not None and _tfidf_matrix is not None:
            from sklearn.metrics.pairwise import cosine_similarity
            import numpy as np
            q_vec = _vectorizer.transform([query])
            sims = cosine_similarity(q_vec, _tfidf_matrix).flatten()
            top_indices = np.argsort(sims)[::-1][:k]
            top_chunks = [(sims[i], _chunks[i]) for i in top_indices if sims[i] > 0.01]
            relevant = [c for _, c in top_chunks]
        else:
            relevant = _keyword_fallback(query, k)
    except Exception as e:
        logger.warning(f"TF-IDF retrieval failed, using keyword fallback: {e}")
        relevant = _keyword_fallback(query, k)

    if not relevant:
        return ""

    parts = []
    for i, chunk in enumerate(relevant, 1):
        parts.append(f"[Source {i}]\n{chunk}")
    return "\n\n---\n\n".join(parts)


def rag_query(query: str, llm_fn=None) -> str:
    """
    Full RAG pipeline: retrieve context → augment prompt → call LLM.
    llm_fn: callable(prompt: str) -> str
    Never raises — always returns a string.
    """
    try:
        context = retrieve_context(query, k=4)
    except Exception as e:
        logger.error(f"retrieve_context error: {e}")
        context = ""

    if context:
        augmented_prompt = (
            "You are CyberSahayak, India's expert AI cybercrime prevention assistant.\n\n"
            "KNOWLEDGE BASE CONTEXT:\n"
            f"{context}\n\n"
            "USER QUESTION:\n"
            f"{query}\n\n"
            "Instructions: Answer based on the context above. If context does not fully cover "
            "the question, supplement with your knowledge but make that clear. Use simple, "
            "clear language. For active fraud victims, always recommend calling 1930 immediately. "
            "Format your response with bullet points where helpful."
        )
    else:
        augmented_prompt = (
            "You are CyberSahayak, India's expert AI cybercrime prevention assistant.\n\n"
            "USER QUESTION:\n"
            f"{query}\n\n"
            "Provide a helpful, accurate answer about Indian cybercrime, cyber laws (IT Act 2000/2008), "
            "or fraud prevention. For active fraud victims, always recommend calling 1930 immediately."
        )

    try:
        result = llm_fn(augmented_prompt)
        return result if result else _offline_response(query)
    except Exception as e:
        logger.error(f"llm_fn error in rag_query: {e}")
        return _offline_response(query)


def _offline_response(query: str) -> str:
    """
    Rule-based local fallback when all LLMs are unavailable.
    Handles the most common queries with hardcoded answers.
    """
    q = query.lower()

    if any(w in q for w in ["1930", "helpline", "emergency"]):
        return (
            "🚨 **National Cyber Crime Helpline: 1930**\n\n"
            "Available 24/7. Call immediately if you are a victim.\n\n"
            "You can also file a complaint online at **cybercrime.gov.in**"
        )

    if any(w in q for w in ["digital arrest", "video call", "arrest call", "cbi call", "police call"]):
        return (
            "🛡️ **Digital Arrest is a FRAUD — There is no such thing in Indian law.**\n\n"
            "**What is happening:** Fraudsters impersonate CBI/ED/Police/TRAI officers on video call "
            "and claim you are 'under digital arrest' until you pay money.\n\n"
            "**What to do immediately:**\n"
            "• Disconnect the call right now\n"
            "• Do NOT pay any money\n"
            "• Do NOT share bank details or OTP\n"
            "• Call **1930** immediately\n"
            "• Report at cybercrime.gov.in\n\n"
            "Real police NEVER arrest via WhatsApp or video call."
        )

    if any(w in q for w in ["upi", "gpay", "phonepe", "paytm", "payment fraud"]):
        return (
            "💳 **UPI Fraud Prevention**\n\n"
            "**Never:**\n"
            "• Share your UPI PIN with anyone — banks never ask for it\n"
            "• Approve payment requests from unknown contacts\n"
            "• Scan QR codes to 'receive' money — scanning sends money, not receives\n"
            "• Install apps on strangers' instructions (AnyDesk, TeamViewer)\n\n"
            "**If fraud happened:**\n"
            "• Call **1930** immediately\n"
            "• Contact your bank to freeze account\n"
            "• File complaint at cybercrime.gov.in\n"
            "• Report to NPCI: 1800-120-1740\n\n"
            "If reported within 3 working days, RBI guidelines entitle you to a full refund."
        )

    if any(w in q for w in ["otp", "sim swap", "sms theft"]):
        return (
            "🔐 **OTP Safety**\n\n"
            "**NEVER share your OTP with anyone — not even bank employees.**\n\n"
            "If someone asks for your OTP, it is ALWAYS a fraud. No exceptions.\n\n"
            "**If SIM stops working suddenly:** This may be SIM Swap fraud.\n"
            "• Call your telecom operator from another phone immediately\n"
            "• Inform your bank to freeze all accounts\n"
            "• Call **1930**"
        )

    if any(w in q for w in ["phishing", "fake email", "fake website", "fake link"]):
        return (
            "🌐 **Phishing Detection**\n\n"
            "**Red flags:**\n"
            "• URL contains bank name but looks different (sbi-online.in vs onlinesbi.sbi)\n"
            "• Urgency language: 'Account will be blocked in 24 hours'\n"
            "• Asks for OTP/PIN/password via email or link\n"
            "• Poor grammar and spelling\n\n"
            "**What to do:**\n"
            "• Do NOT click the link\n"
            "• Report phishing email to incident@cert-in.org.in\n"
            "• Report fake websites at cybercrime.gov.in/SafeInternet.aspx"
        )

    if any(w in q for w in ["report", "complaint", "cybercrime.gov", "how to file"]):
        return (
            "📋 **How to File a Cybercrime Complaint**\n\n"
            "**Option 1 — Online (Recommended):**\n"
            "1. Go to **cybercrime.gov.in**\n"
            "2. Click 'File a Complaint'\n"
            "3. Select category (Financial Fraud / Social Media / etc.)\n"
            "4. Fill in details and upload evidence\n"
            "5. Note your Complaint ID for follow-up\n\n"
            "**Option 2 — Helpline:**\n"
            "Call **1930** (National Cyber Crime Helpline, available 24/7)\n\n"
            "**Option 3 — Police Station:**\n"
            "Visit your nearest police station with printed evidence and request FIR "
            "under IT Act Section 66C/66D and IPC 420."
        )

    if any(w in q for w in ["it act", "law", "section 66", "legal", "punishment"]):
        return (
            "⚖️ **Key Cyber Laws in India (IT Act 2000/2008)**\n\n"
            "• **Section 66C** — Identity theft: 3 years imprisonment + Rs 1 lakh fine\n"
            "• **Section 66D** — Cheating by impersonation: 3 years + Rs 1 lakh fine\n"
            "• **Section 66E** — Privacy violation: 3 years + Rs 2 lakh fine\n"
            "• **Section 420 IPC** — Cheating: up to 7 years imprisonment\n"
            "• **Section 66F** — Cyber terrorism: life imprisonment\n\n"
            "These laws apply to all cybercrime in India, and also to offences "
            "committed from outside India targeting Indian systems."
        )

    # Generic helpful response
    return (
        "🛡️ **CyberSahayak — Offline Mode**\n\n"
        "AI assistant is currently unavailable, but here are key resources:\n\n"
        "• **Emergency:** Call **1930** (National Cyber Crime Helpline)\n"
        "• **Report:** cybercrime.gov.in\n"
        "• **Cert-In:** incident@cert-in.org.in\n\n"
        "Common scams in India:\n"
        "• Digital Arrest (fake CBI/police video calls)\n"
        "• UPI QR Code fraud\n"
        "• OTP theft\n"
        "• Phishing emails\n"
        "• Fake job/investment offers\n\n"
        f"Your question: *{query}*\n\n"
        "Please try asking again once AI service is restored, or call 1930 for immediate help."
    )


def get_kb_stats() -> dict:
    """Return knowledge base statistics for debugging."""
    _load_kb()
    return {
        "loaded": _kb_loaded,
        "chunks": len(_chunks),
        "tfidf_ready": _vectorizer is not None,
        "kb_file_exists": _KB_FILE.exists(),
        "kb_file_size": _KB_FILE.stat().st_size if _KB_FILE.exists() else 0,
    }
