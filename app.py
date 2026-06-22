# app.py — CyberSahayak v2.0 Main Entry Point
import streamlit as st

st.set_page_config(
    page_title="CyberSahayak 2.0",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://cybercrime.gov.in',
        'Report a bug': None,
        'About': 'CyberSahayak v2.0 — India\'s AI-powered Cybercrime Investigation Platform'
    }
)

from ui.styles import GLOBAL_CSS
st.markdown(GLOBAL_CSS, unsafe_allow_html=True)

from core.session_manager import InvestigationSession

# Initialize session state
if 'session' not in st.session_state:
    st.session_state.session = InvestigationSession()
if 'case_id' not in st.session_state:
    st.session_state.case_id = st.session_state.session.case_id

# Landing page
st.markdown("""
<div style="text-align:center; padding: 3rem 0 1rem 0;">
    <div style="font-size: 4rem;">🛡️</div>
    <h1 style="color: #F1F5F9; font-size: 2.8rem; font-weight: 800; margin: 0.5rem 0;">
        CyberSahayak <span style="color: #2563EB;">2.0</span>
    </h1>
    <p style="color: #94A3B8; font-size: 1.1rem; max-width: 600px; margin: 0 auto;">
        India's AI-powered Cybercrime Investigation & Fraud Detection Platform
    </p>
</div>
""", unsafe_allow_html=True)

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("""
    <div style="background: #0F1629; border: 1px solid #1E293B; border-radius: 12px; padding: 24px; text-align: center;">
        <div style="font-size: 2rem;">🚨</div>
        <h3 style="color: #EF4444;">Emergency?</h3>
        <p style="color: #94A3B8;">Call <strong style="color: #F1F5F9;">1930</strong> immediately</p>
        <p style="color: #94A3B8;">National Cyber Crime Helpline</p>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div style="background: #0F1629; border: 1px solid #1E293B; border-radius: 12px; padding: 24px; text-align: center;">
        <div style="font-size: 2rem;">🌐</div>
        <h3 style="color: #2563EB;">Report Online</h3>
        <p style="color: #94A3B8;"><strong style="color: #F1F5F9;">cybercrime.gov.in</strong></p>
        <p style="color: #94A3B8;">File your complaint 24/7</p>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div style="background: #0F1629; border: 1px solid #1E293B; border-radius: 12px; padding: 24px; text-align: center;">
        <div style="font-size: 2rem;">🔬</div>
        <h3 style="color: #10B981;">Active Case</h3>
        <p style="color: #94A3B8; font-family: monospace; font-size: 0.8rem;">{st.session_state.case_id}</p>
        <p style="color: #94A3B8;">Use sidebar to navigate</p>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

modules = [
    ("🛡️ SOC Dashboard", "Real-time threat monitoring & statistics", "01_soc_dashboard"),
    ("🌐 URL Analyzer", "Phishing & malicious URL detection", "02_url_analyzer"),
    ("📱 SMS Scanner", "Scam SMS & message analysis", "03_sms_scanner"),
    ("🖼️ Image Scanner", "QR code & image-based fraud detection", "04_image_scanner"),
    ("📄 Document Analyzer", "PDF & DOCX malware/phishing detection", "05_document_analyzer"),
    ("🤖 AI Chatbot", "CyberSahayak RAG-powered assistant", "06_chatbot"),
    ("📦 Evidence Builder", "Build & export court-ready evidence", "07_evidence_builder"),
    ("🔍 Threat Intelligence", "Live WHOIS, DNS, VT lookups", "08_threat_intelligence"),
    ("📋 Investigation Log", "Full case timeline & audit trail", "09_investigation_log"),
]

st.markdown('<div class="section-header">🗂️ Investigation Modules</div>', unsafe_allow_html=True)

cols = st.columns(3)
for i, (title, desc, _page) in enumerate(modules):
    with cols[i % 3]:
        st.markdown(f"""
        <div style="background: #131D35; border: 1px solid #1E293B; border-radius: 12px;
                    padding: 20px; margin-bottom: 16px; min-height: 100px;">
            <div style="font-size: 1.4rem;">{title.split()[0]}</div>
            <div style="color: #F1F5F9; font-weight: 600; font-size: 0.95rem;">{' '.join(title.split()[1:])}</div>
            <div style="color: #64748B; font-size: 0.8rem; margin-top: 6px;">{desc}</div>
        </div>
        """, unsafe_allow_html=True)

with st.sidebar:
    st.error("### 🚨 Emergency\nHelpline: **1930**")
    st.info("**Report:** cybercrime.gov.in")
    st.success("**Active Case:**\n" + st.session_state.case_id)
    if st.button("🆕 New Investigation", use_container_width=True):
        from core.session_manager import InvestigationSession
        st.session_state.session = InvestigationSession()
        st.session_state.case_id = st.session_state.session.case_id
        st.rerun()