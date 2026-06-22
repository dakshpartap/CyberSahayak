# pages/09_investigation_log.py — Full investigation timeline and audit log
import streamlit as st
from ui.styles import GLOBAL_CSS
from ui.charts import risk_score_histogram
from core.audit_logger import get_recent_scans, get_stats, get_timeline_data
from core.session_manager import InvestigationSession
from modules.evidence.preservation import generate_evidence_package
import json

st.set_page_config(page_title="Investigation Log | CyberSahayak", page_icon="📋", layout="wide")
st.markdown(GLOBAL_CSS, unsafe_allow_html=True)

with st.sidebar:
    st.error("### 🚨 Emergency\nHelpline: **1930**")
    st.info("**Report:** cybercrime.gov.in")
    case_id = st.session_state.get('case_id', 'None')
    st.success(f"**Active Case:**\n{case_id}")

    st.divider()
    if st.button("🆕 New Investigation", use_container_width=True):
        st.session_state.session = InvestigationSession()
        st.session_state.case_id = st.session_state.session.case_id
        st.rerun()

st.markdown('<div class="section-header">📋 Investigation Log & Audit Trail</div>',
            unsafe_allow_html=True)

# ── Current Case Summary ───────────────────────────────────────────────
st.markdown(f"### Case: `{case_id}`")

session: InvestigationSession = st.session_state.get('session')

if session:
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Overall Risk", f"{session.overall_risk}/100")
    col2.metric("URLs Scanned", len(session.scanned_urls))
    col3.metric("Messages", len(session.scanned_messages))
    col4.metric("Images/Docs", len(session.scanned_images) + len(session.scanned_documents))

    if session.overall_risk >= 75:
        st.error("🔴 HIGH RISK case — Evidence detected. Report immediately.")
    elif session.overall_risk >= 45:
        st.warning("🟡 SUSPICIOUS activity detected in this case.")
    elif session.overall_risk > 0:
        st.info("🟠 Low-level indicators found.")
    else:
        st.info("No scans completed yet for this case.")

st.divider()

# ── Audit Log Table ────────────────────────────────────────────────────
st.markdown("### 🗃️ All Scans (Current Session Case)")

filter_col1, filter_col2 = st.columns([2, 1])
with filter_col1:
    type_filter = st.selectbox("Filter by Type", ["All", "url", "sms", "whatsapp",
                                                   "image", "document", "upi"])
with filter_col2:
    limit = st.slider("Show last N scans", min_value=5, max_value=100, value=20)

scan_type = None if type_filter == "All" else type_filter
scans = get_recent_scans(limit=limit, scan_type=scan_type, case_id=case_id)

if scans:
    # Risk histogram
    st.plotly_chart(risk_score_histogram(scans), use_container_width=True)

    # Table
    st.markdown(f"**{len(scans)} scans found:**")

    for scan in scans:
        score = scan['risk_score']
        risk_color = '#EF4444' if score >= 75 else '#F59E0B' if score >= 45 else '#10B981'
        badge_class = 'risk-badge-high' if score >= 75 else \
                      'risk-badge-medium' if score >= 45 else 'risk-badge-low'

        with st.expander(
            f"[{scan['timestamp'][:16]}] {scan['type'].upper()}: "
            f"{scan['target'][:60]}{'...' if len(scan['target']) > 60 else ''} — {score}/100"
        ):
            col_left, col_right = st.columns([2, 1])
            with col_left:
                st.markdown(f"**Target:** `{scan['target']}`")
                st.markdown(f"**Verdict:** {scan['verdict']}")
                st.markdown(f"**Timestamp:** {scan['timestamp']}")

            with col_right:
                st.markdown(
                    f'<div style="text-align:center;">'
                    f'<span class="{badge_class}">{score}/100</span></div>',
                    unsafe_allow_html=True
                )

            # Show details if available
            if scan.get('details'):
                try:
                    details = json.loads(scan['details']) if isinstance(scan['details'], str) \
                              else scan['details']
                    with st.container():
                        st.json(details)
                except Exception:
                    pass
else:
    st.info("No scans found for the current case. Use the analysis modules to start investigating.")

st.divider()

# ── Global Stats ───────────────────────────────────────────────────────
st.markdown("### 📊 Overall Statistics (All Cases)")

stats = get_stats()
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Scans", stats['total_scans'])
col2.metric("Today", stats['scans_today'])
col3.metric("Threats", stats['threats_detected'])
col4.metric("URLs", stats['urls_scanned'])
col5.metric("Cases", stats['cases_opened'])

# ── Export Case ────────────────────────────────────────────────────────
st.divider()
st.markdown("### 📤 Export This Case")
col_zip, col_json = st.columns(2)

with col_zip:
    if st.button("📦 Export Evidence ZIP", use_container_width=True):
        session_dict = session.to_dict() if session else {'case_id': case_id}
        session_dict['audit_log'] = scans

        with st.spinner("Packaging evidence..."):
            zip_bytes, zip_filename = generate_evidence_package(session_dict)

        st.download_button(
            label="⬇️ Download ZIP",
            data=zip_bytes,
            file_name=zip_filename,
            mime='application/zip',
            use_container_width=True
        )

with col_json:
    if st.button("📄 Export JSON", use_container_width=True):
        session_dict = session.to_dict() if session else {'case_id': case_id}
        session_dict['audit_log'] = scans
        json_str = json.dumps(session_dict, indent=2, default=str)

        st.download_button(
            label="⬇️ Download JSON",
            data=json_str.encode('utf-8'),
            file_name=f"CyberSahayak_Case_{case_id}.json",
            mime='application/json',
            use_container_width=True
        )