# pages/04_image_scanner.py — Image / QR Code Fraud Scanner
import streamlit as st
from ui.styles import GLOBAL_CSS
from ui.components import render_risk_gauge, render_finding_card
from ui.charts import risk_gauge_plotly
from modules.image_analyzer.vision_analyzer import analyze_image
from core.audit_logger import log_scan, get_recent_scans
from config import settings

st.set_page_config(page_title="Image Scanner | CyberSahayak", page_icon="🖼️", layout="wide")
st.markdown(GLOBAL_CSS, unsafe_allow_html=True)

with st.sidebar:
    st.error("### 🚨 Emergency\nHelpline: **1930**")
    st.info("**Report:** cybercrime.gov.in")
    st.success(f"**Active Case:**\n{st.session_state.get('case_id', 'None')}")

st.markdown('<div class="section-header">🖼️ Image & QR Code Fraud Scanner</div>',
            unsafe_allow_html=True)
st.markdown("Upload a screenshot, QR code image, or any suspicious image for analysis.")

uploaded_file = st.file_uploader(
    "Upload Image",
    type=['jpg', 'jpeg', 'png', 'webp', 'bmp', 'gif'],
    help=f"Max {settings.MAX_FILE_SIZE_MB}MB. Supports JPG, PNG, WebP, BMP, GIF"
)

if uploaded_file:
    file_size_mb = len(uploaded_file.getvalue()) / (1024 * 1024)
    if file_size_mb > settings.MAX_FILE_SIZE_MB:
        st.error(f"File too large ({file_size_mb:.1f}MB). Max allowed: {settings.MAX_FILE_SIZE_MB}MB")
        st.stop()

    col_img, col_meta = st.columns([1, 2])
    with col_img:
        st.image(uploaded_file, caption=uploaded_file.name, use_column_width=True)
    with col_meta:
        st.markdown(f"**Filename:** `{uploaded_file.name}`")
        st.markdown(f"**Size:** {file_size_mb:.2f} MB")
        st.markdown(f"**Type:** {uploaded_file.type}")

    scan_btn = st.button("🔍 Analyze Image", type="primary", use_container_width=True)

    if scan_btn:
        image_bytes = uploaded_file.getvalue()

        with st.spinner("Running QR detection, OCR, and pattern analysis..."):
            result = analyze_image(image_bytes, filename=uploaded_file.name)

        final_score = result['risk_score']
        verdict = result['verdict']

        log_scan(
            scan_type='image',
            target=uploaded_file.name,
            risk_score=final_score,
            verdict=verdict,
            details=result,
            case_id=st.session_state.get('case_id')
        )

        if 'session' in st.session_state:
            st.session_state.session.scanned_images.append({
                'filename': uploaded_file.name,
                'result': {'risk_score': final_score, 'verdict': verdict},
                'timestamp': __import__('datetime').datetime.now().isoformat()
            })

        tabs = st.tabs(["📊 Risk Overview", "📷 QR Codes", "📝 OCR Text", "🔗 URLs Found"])

        with tabs[0]:
            col_g, col_d = st.columns([1, 2])
            with col_g:
                st.plotly_chart(risk_gauge_plotly(final_score),
                                use_container_width=True, key="img_gauge")
            with col_d:
                st.markdown(f"### {verdict}")
                for finding in result.get('findings', []):
                    st.markdown(render_finding_card(finding, final_score >= 60),
                                unsafe_allow_html=True)

            if final_score >= 60:
                st.error("🚨 This image contains fraud indicators. "
                         "Do NOT scan QR codes or visit URLs from this image.")
            elif final_score >= 35:
                st.warning("⚠️ Exercise caution with links or QR codes in this image.")
            else:
                st.success("✅ No obvious fraud indicators detected in this image.")

        with tabs[1]:
            qr_codes = result.get('qr_codes', [])
            if qr_codes:
                st.markdown(f"**{len(qr_codes)} QR code(s) detected:**")
                for i, qr in enumerate(qr_codes):
                    with st.expander(f"QR Code {i+1} — {qr['type']}"):
                        st.markdown(f"**Data:** `{qr['data'][:200]}`")
                        st.markdown(f"**Is URL:** {qr.get('is_url', False)}")
                        st.markdown(f"**Is UPI:** {qr.get('is_upi', False)}")

                        if result.get('url_findings'):
                            for uf in result['url_findings']:
                                if uf.get('source') == 'qr_code':
                                    h = uf['heuristic']
                                    if h.get('findings'):
                                        st.markdown("**URL Analysis:**")
                                        for f in h['findings']:
                                            st.markdown(
                                                render_finding_card(f, h['risk_score'] >= 60),
                                                unsafe_allow_html=True
                                            )
            else:
                st.info("No QR codes detected in this image.")

        with tabs[2]:
            ocr = result.get('ocr', {})
            if ocr.get('has_text'):
                st.markdown(f"**Language:** {ocr.get('language_detected', 'unknown')}")
                st.markdown(f"**OCR Risk Score:** `{ocr.get('risk_from_ocr', 0)}/100`")
                if ocr.get('scam_patterns_found'):
                    st.markdown("**Scam Patterns in Text:**")
                    for pattern in ocr['scam_patterns_found']:
                        st.markdown(
                            render_finding_card(
                                f"{pattern['description']} (risk: {pattern['risk']})",
                                pattern['risk'] >= 75
                            ), unsafe_allow_html=True
                        )
                st.markdown("**Extracted Text:**")
                st.text_area("OCR Output", value=ocr.get('extracted_text', ''),
                             height=200, disabled=True)
            elif 'error' in ocr:
                st.warning(f"OCR failed: {ocr['error']}. Is pytesseract installed?")
            else:
                st.info("No readable text extracted from this image.")

        with tabs[3]:
            url_findings = result.get('url_findings', [])
            if url_findings:
                for uf in url_findings:
                    with st.expander(f"URL from {uf['source']}: {uf['url'][:60]}"):
                        h = uf['heuristic']
                        st.markdown(f"**Risk:** `{h['risk_score']}/100`")
                        for f in h.get('findings', []):
                            st.markdown(render_finding_card(f, h['risk_score'] >= 60),
                                        unsafe_allow_html=True)
            else:
                st.info("No URLs found in this image.")

st.divider()
st.markdown('<div class="section-header">🕐 Recent Image Scans</div>', unsafe_allow_html=True)
recent = get_recent_scans(limit=5, scan_type='image')
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
    st.info("No image scans yet.")