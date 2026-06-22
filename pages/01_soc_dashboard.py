# pages/01_soc_dashboard.py
import streamlit as st
from datetime import datetime
from ui.styles import GLOBAL_CSS, CYBER_PALETTE
from core.audit_logger import get_recent_scans, get_stats

st.markdown(GLOBAL_CSS, unsafe_allow_html=True)
st.title("🛡️ CyberSahayak SOC Dashboard")

# === LIVE STATS ROW ===
col1, col2, col3, col4, col5 = st.columns(5)
stats = get_stats()

col1.metric("🔍 Total Scans", stats['total_scans'], 
            delta=f"+{stats['scans_today']} today")
col2.metric("🚨 Threats Detected", stats['threats_detected'])
col3.metric("🌐 URLs Scanned", stats['urls_scanned'])
col4.metric("📱 Messages Scanned", stats['sms_scanned'])
col5.metric("📂 Cases Opened", stats['cases_opened'])

st.divider()

# === THREAT TIMELINE (last 24h) ===
col_left, col_right = st.columns([2, 1])

with col_left:
    st.markdown('<div class="section-header">📈 Threat Activity (Last 24h)</div>',
                unsafe_allow_html=True)
    # Plotly chart showing scan volume + risk scores over time
    # (Implementation uses audit_logger to query SQLite)

with col_right:
    st.markdown('<div class="section-header">🗺️ Top Threat Categories</div>',
                unsafe_allow_html=True)
    # Donut chart: URL Phishing / SMS Scam / Digital Arrest / UPI Fraud

# === RECENT INVESTIGATIONS ===
st.markdown('<div class="section-header">🔬 Recent Investigations</div>',
            unsafe_allow_html=True)

recent = get_recent_scans(limit=10)
for scan in recent:
    risk = scan['risk_score']
    color = '#EF4444' if risk >= 75 else '#F59E0B' if risk >= 45 else '#10B981'
    with st.container():
        cols = st.columns([3, 1, 1, 2])
        cols[0].write(f"**{scan['type'].upper()}:** {scan['target'][:60]}...")
        cols[1].markdown(f'<span style="color:{color};font-weight:700">{risk}/100</span>',
                        unsafe_allow_html=True)
        cols[2].write(scan['verdict'])
        cols[3].write(scan['timestamp'])

# === EMERGENCY PANEL ===
with st.sidebar:
    st.error("### 🚨 Emergency\nHelpline: **1930**")
    st.info("**Report:** cybercrime.gov.in")
    st.success("**Active Case:** " + 
               st.session_state.get('case_id', 'None'))
    
    if st.button("🆕 New Investigation"):
        st.session_state.investigation = {}
        st.session_state.case_id = None
        st.rerun()