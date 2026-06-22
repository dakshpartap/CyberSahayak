# pages/07_evidence_builder.py — Evidence Package Builder
import streamlit as st
from ui.styles import GLOBAL_CSS
from modules.evidence.preservation import generate_evidence_package
from modules.evidence.pdf_report import generate_pdf_report
from core.audit_logger import get_scans_for_case
from core.session_manager import InvestigationSession
from datetime import datetime

st.set_page_config(page_title="Evidence Builder | CyberSahayak", page_icon="📦", layout="wide")
st.markdown(GLOBAL_CSS, unsafe_allow_html=True)

with st.sidebar:
    st.error("### 🚨 Emergency\nHelpline: **1930**")
    st.info("**Report:** cybercrime.gov.in")
    st.success(f"**Active Case:**\n{st.session_state.get('case_id', 'None')}")

st.markdown('<div class="section-header">📦 Evidence Package Builder</div>',
            unsafe_allow_html=True)
st.markdown(
    "Build a court-ready evidence package from your investigation. "
    "The package includes cryptographic hashes, a chain of custody record, "
    "and step-by-step complaint filing instructions."
)

# ── Case Details Form ─────────────────────────────────────────────────
st.markdown("### 📝 Case Details")

col1, col2 = st.columns(2)
with col1:
    crime_type = st.selectbox("Crime Type", [
        "Select...",
        "Digital Arrest / Impersonation",
        "UPI / Payment Fraud",
        "OTP Theft",
        "WhatsApp Scam",
        "Investment / Ponzi Fraud",
        "Phishing / Fake Website",
        "Fake Job / Task Scam",
        "Sextortion",
        "Cyber Stalking / Harassment",
        "Identity Theft",
        "KYC / Aadhaar Fraud",
        "Ransomware / Malware",
        "Other"
    ])

with col2:
    victim_desc = st.text_input("Brief Victim Description",
                                placeholder="e.g. Individual, lost ₹50,000 via UPI")

amount_lost = st.number_input("Amount Lost (₹)", min_value=0, value=0,
                               help="Enter 0 if no money was lost")
incident_date = st.date_input("Incident Date", value=datetime.today())
incident_description = st.text_area(
    "Incident Description",
    placeholder="Describe what happened in detail — the sequence of events, "
                "what was said/asked, what was transferred...",
    height=150
)

recommended_actions_input = st.text_area(
    "Notes / Recommended Actions",
    placeholder="Any additional notes or actions taken so far...",
    height=80
)

st.divider()

# ── Evidence Summary ──────────────────────────────────────────────────
st.markdown("### 🔬 Evidence in Current Session")

session: InvestigationSession = st.session_state.get('session')
case_id = st.session_state.get('case_id', 'UNKNOWN')

if session:
    col_m1, col_m2, col_m3, col_m4 = st.columns(4)
    col_m1.metric("URLs Scanned", len(session.scanned_urls))
    col_m2.metric("Messages Scanned", len(session.scanned_messages))
    col_m3.metric("Images Scanned", len(session.scanned_images))
    col_m4.metric("Documents Scanned", len(session.scanned_documents))

    if session.scanned_urls:
        with st.expander(f"🌐 URLs ({len(session.scanned_urls)})"):
            for entry in session.scanned_urls:
                score = entry['result'].get('risk_score', 0)
                color = '#EF4444' if score >= 75 else '#F59E0B' if score >= 45 else '#10B981'
                st.markdown(
                    f'• <span style="color:{color}">[{score}/100]</span> `{entry["url"][:80]}`',
                    unsafe_allow_html=True
                )

    if session.scanned_messages:
        with st.expander(f"📱 Messages ({len(session.scanned_messages)})"):
            for entry in session.scanned_messages:
                score = entry['result'].get('risk_score', 0)
                color = '#EF4444' if score >= 75 else '#F59E0B' if score >= 45 else '#10B981'
                st.markdown(
                    f'• <span style="color:{color}">[{score}/100]</span> {entry["message"][:80]}',
                    unsafe_allow_html=True
                )
else:
    st.info("No active session. Use the analysis modules to build evidence.")

st.divider()

# ── Generate Buttons ──────────────────────────────────────────────────
st.markdown("### 📤 Export Evidence")
col_zip, col_pdf = st.columns(2)

with col_zip:
    if st.button("📦 Generate Evidence ZIP", type="primary", use_container_width=True):
        # Build session dict
        session_dict = {}
        if session:
            session_dict = session.to_dict()

        # Override with form values
        session_dict['case_id'] = case_id
        session_dict['crime_type'] = crime_type if crime_type != "Select..." else ""
        session_dict['victim_description'] = victim_desc
        session_dict['amount_lost'] = amount_lost
        session_dict['incident_date'] = str(incident_date)
        session_dict['incident_description'] = incident_description
        session_dict['recommended_actions'] = [recommended_actions_input] if recommended_actions_input else []

        # Add audit log scans for this case
        audit_scans = get_scans_for_case(case_id)
        session_dict['audit_log'] = audit_scans

        with st.spinner("Generating evidence package..."):
            zip_bytes, zip_filename = generate_evidence_package(session_dict)

        st.success(f"✅ Evidence package ready: `{zip_filename}`")
        st.download_button(
            label="⬇️ Download Evidence ZIP",
            data=zip_bytes,
            file_name=zip_filename,
            mime='application/zip',
            use_container_width=True
        )

with col_pdf:
    if st.button("📄 Generate PDF Report", type="secondary", use_container_width=True):
        session_dict = {}
        if session:
            session_dict = session.to_dict()

        session_dict['case_id'] = case_id
        session_dict['crime_type'] = crime_type if crime_type != "Select..." else ""
        session_dict['victim_description'] = victim_desc
        session_dict['amount_lost'] = amount_lost
        session_dict['incident_date'] = str(incident_date)
        session_dict['incident_description'] = incident_description
        session_dict['recommended_actions'] = [
            "Call 1930 (National Cyber Crime Helpline)",
            "File complaint at cybercrime.gov.in",
            "Preserve all original messages and screenshots",
            "Contact your bank immediately if money was transferred",
        ]
        if recommended_actions_input:
            session_dict['recommended_actions'].append(recommended_actions_input)

        with st.spinner("Generating PDF report..."):
            try:
                pdf_bytes = generate_pdf_report(session_dict)
                pdf_filename = f"CyberSahayak_Report_{case_id}.pdf"
                st.success(f"✅ PDF report ready: `{pdf_filename}`")
                st.download_button(
                    label="⬇️ Download PDF Report",
                    data=pdf_bytes,
                    file_name=pdf_filename,
                    mime='application/pdf',
                    use_container_width=True
                )
            except Exception as e:
                st.error(f"PDF generation failed: {e}. Install: `pip install reportlab`")

st.divider()
st.markdown("""
<div style="background: rgba(37,99,235,0.08); border: 1px solid rgba(37,99,235,0.3);
            border-radius: 12px; padding: 20px;">
<h4 style="color: #2563EB;">📋 After Downloading Your Evidence Package</h4>
<ol style="color: #94A3B8; line-height: 2;">
<li>Call <strong style="color: #F1F5F9;">1930</strong> (National Cyber Crime Helpline) — 24/7</li>
<li>Visit <strong style="color: #F1F5F9;">cybercrime.gov.in</strong> and click "File a Complaint"</li>
<li>Upload the <code>case_summary.json</code> from the ZIP as evidence</li>
<li>Attach original screenshots (unedited) separately</li>
<li>If police refuse to register FIR, escalate to SP/Commissioner</li>
</ol>
<p style="color: #64748B; font-size: 0.85rem;">
Relevant laws: IT Act 66C (identity theft), 66D (cheating by impersonation),
IPC 420 (cheating), 406 (criminal breach of trust)
</p>
</div>
""", unsafe_allow_html=True)