# pages/05_document_analyzer.py — PDF & DOCX Forensic Analyzer
import streamlit as st
from ui.styles import GLOBAL_CSS
from ui.components import render_risk_gauge, render_finding_card
from ui.charts import risk_gauge_plotly
from modules.document_analyzer.pdf_parser import analyze_pdf
from modules.document_analyzer.docx_parser import analyze_docx
from modules.document_analyzer.malware_scanner import scan_file
from core.audit_logger import log_scan, get_recent_scans
from config import settings

st.set_page_config(page_title="Document Analyzer | CyberSahayak", page_icon="📄", layout="wide")
st.markdown(GLOBAL_CSS, unsafe_allow_html=True)

with st.sidebar:
    st.error("### 🚨 Emergency\nHelpline: **1930**")
    st.info("**Report:** cybercrime.gov.in")
    st.success(f"**Active Case:**\n{st.session_state.get('case_id', 'None')}")

st.markdown('<div class="section-header">📄 Document Forensic Analyzer</div>',
            unsafe_allow_html=True)
st.markdown("Upload a suspicious PDF or DOCX to check for malware, phishing content, and hidden threats.")

uploaded_doc = st.file_uploader(
    "Upload Document",
    type=['pdf', 'docx', 'doc'],
    help=f"Max {settings.MAX_FILE_SIZE_MB}MB. Supports PDF and DOCX/DOC"
)

if uploaded_doc:
    file_size_mb = len(uploaded_doc.getvalue()) / (1024 * 1024)
    if file_size_mb > settings.MAX_FILE_SIZE_MB:
        st.error(f"File too large ({file_size_mb:.1f}MB). Max: {settings.MAX_FILE_SIZE_MB}MB")
        st.stop()

    col_info, col_hash = st.columns(2)
    with col_info:
        st.markdown(f"**Filename:** `{uploaded_doc.name}`")
        st.markdown(f"**Size:** {file_size_mb:.2f} MB")
        st.markdown(f"**Type:** {uploaded_doc.type}")

    scan_btn = st.button("🔍 Analyze Document", type="primary", use_container_width=True)

    if scan_btn:
        doc_bytes = uploaded_doc.getvalue()
        filename = uploaded_doc.name

        with st.spinner("Running forensic analysis..."):

            # Static file scan (all file types)
            malware_result = scan_file(doc_bytes, filename)

            # Document-specific analysis
            doc_result = {}
            if filename.lower().endswith('.pdf'):
                doc_result = analyze_pdf(doc_bytes)
            elif filename.lower().endswith(('.docx', '.doc')):
                doc_result = analyze_docx(doc_bytes)

        # Composite risk
        risk_score = max(
            malware_result.get('risk_score', 0),
            doc_result.get('risk_score', 0)
        )

        if risk_score >= 75:
            verdict = '🔴 HIGH RISK — This document contains threats'
        elif risk_score >= 45:
            verdict = '🟡 SUSPICIOUS — Potentially dangerous document'
        elif risk_score >= 20:
            verdict = '🟠 CAUTION — Some suspicious elements found'
        else:
            verdict = '🟢 LIKELY SAFE — No obvious threats detected'

        all_findings = malware_result.get('findings', []) + doc_result.get('findings', [])

        log_scan(
            scan_type='document',
            target=filename,
            risk_score=risk_score,
            verdict=verdict,
            details={'malware_scan': malware_result, 'doc_analysis': doc_result},
            case_id=st.session_state.get('case_id')
        )

        if 'session' in st.session_state:
            st.session_state.session.scanned_documents.append({
                'filename': filename,
                'result': {'risk_score': risk_score, 'verdict': verdict},
                'timestamp': __import__('datetime').datetime.now().isoformat()
            })

        tabs = st.tabs(["📊 Risk Overview", "🦠 Malware Scan", "📄 Content Analysis",
                         "🔗 Links & Embeds", "🔑 Hashes"])

        with tabs[0]:
            col_g, col_d = st.columns([1, 2])
            with col_g:
                st.plotly_chart(risk_gauge_plotly(risk_score),
                                use_container_width=True, key="doc_gauge")
            with col_d:
                st.markdown(f"### {verdict}")
                for finding in all_findings[:10]:
                    st.markdown(render_finding_card(finding, risk_score >= 60),
                                unsafe_allow_html=True)

            if risk_score >= 60:
                st.error("🚨 **Do NOT open this file.** "
                         "If already opened, disconnect from internet and run a virus scan.")

        with tabs[1]:
            st.markdown(f"**Detected File Type:** `{malware_result.get('detected_type', 'Unknown')}`")
            st.markdown(f"**Extension:** `{malware_result.get('extension', 'N/A')}`")
            st.markdown(f"**Malware Risk Score:** `{malware_result.get('risk_score', 0)}/100`")

            if malware_result.get('flags'):
                st.markdown("**Flags:**")
                for flag in malware_result['flags']:
                    st.markdown(render_finding_card(flag, True), unsafe_allow_html=True)

            if malware_result.get('findings'):
                st.markdown("**Findings:**")
                for f in malware_result['findings']:
                    st.markdown(render_finding_card(f, malware_result['risk_score'] >= 60),
                                unsafe_allow_html=True)

        with tabs[2]:
            if doc_result:
                col_a, col_b = st.columns(2)
                with col_a:
                    if 'pages' in doc_result:
                        st.metric("Pages", doc_result['pages'])
                    if 'word_count' in doc_result:
                        st.metric("Word Count", doc_result['word_count'])
                    if 'has_macros' in doc_result:
                        st.metric("Has Macros", "⚠️ YES" if doc_result['has_macros'] else "✅ No")

                with col_b:
                    if doc_result.get('metadata'):
                        st.markdown("**Metadata:**")
                        meta = doc_result['metadata']
                        for k, v in meta.items():
                            if v:
                                st.markdown(f"• **{k}:** {v}")

                if doc_result.get('suspicious_keywords'):
                    st.markdown("**Suspicious Phrases Found:**")
                    for phrase in doc_result['suspicious_keywords']:
                        st.markdown(render_finding_card(phrase, True), unsafe_allow_html=True)

                if doc_result.get('javascript'):
                    st.error("🚨 JavaScript detected in this PDF — possible exploit payload")

                if doc_result.get('macro_warnings'):
                    st.markdown("**Macro Warnings:**")
                    for w in doc_result['macro_warnings']:
                        st.markdown(render_finding_card(w, True), unsafe_allow_html=True)

        with tabs[3]:
            if doc_result:
                links = doc_result.get('links', [])
                susp_links = doc_result.get('suspicious_links', [])
                embeds = doc_result.get('embedded_files', doc_result.get('images', []))

                if susp_links:
                    st.markdown(f"**⚠️ {len(susp_links)} Suspicious Link(s):**")
                    for link in susp_links:
                        st.markdown(render_finding_card(f"Suspicious URL: `{link}`", True),
                                    unsafe_allow_html=True)

                if links:
                    st.markdown(f"**All Links ({len(links)}):**")
                    for link in links[:20]:
                        st.markdown(f"• `{link}`")

                if embeds:
                    st.markdown(f"**Embedded Files/Images ({len(embeds)}):**")
                    for embed in embeds[:10]:
                        st.markdown(f"• `{embed}`")

                if not links and not embeds:
                    st.info("No links or embedded files found.")
            else:
                st.info("Detailed link extraction available for PDF and DOCX files.")

        with tabs[4]:
            col_h1, col_h2 = st.columns(2)
            with col_h1:
                st.markdown("**SHA-256:**")
                st.code(malware_result.get('hash_sha256', 'N/A'), language='text')
                st.markdown("**MD5:**")
                st.code(malware_result.get('hash_md5', 'N/A'), language='text')
            with col_h2:
                st.markdown("**SHA-1:**")
                st.code(malware_result.get('hash_sha1', 'N/A'), language='text')
                st.markdown("**File Size:**")
                st.code(f"{malware_result.get('file_size_bytes', 0):,} bytes", language='text')
            st.info("Use these hashes to look up the file on VirusTotal: https://www.virustotal.com")

st.divider()
st.markdown('<div class="section-header">🕐 Recent Document Scans</div>', unsafe_allow_html=True)
recent = get_recent_scans(limit=5, scan_type='document')
if recent:
    for scan in recent:
        risk_color = '#EF4444' if scan['risk_score'] >= 75 else \
                     '#F59E0B' if scan['risk_score'] >= 45 else '#10B981'
        cols = st.columns([3, 1, 2, 2])
        cols[0].write(scan['target'])
        cols[1].markdown(f'<span style="color:{risk_color};font-weight:700">'
                         f'{scan["risk_score"]}/100</span>', unsafe_allow_html=True)
        cols[2].write(scan['verdict'])
        cols[3].write(scan['timestamp'][:19])
else:
    st.info("No document scans yet.")