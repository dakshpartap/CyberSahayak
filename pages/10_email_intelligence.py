# pages/10_email_intelligence.py — CyberSahayak Email Intelligence
import logging
import streamlit as st

st.set_page_config(
    page_title="Email Intelligence | CyberSahayak",
    page_icon="📧",
    layout="wide",
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Safe styling import ─────────────────────────────────────────────────────
try:
    from ui.styles import GLOBAL_CSS
    st.markdown(GLOBAL_CSS, unsafe_allow_html=True)
except ImportError:
    pass

try:
    from ui.components import render_finding_card
    _HAS_FINDING_CARD = True
except ImportError:
    _HAS_FINDING_CARD = False

try:
    from ui.charts import risk_gauge_plotly
    _HAS_GAUGE = True
except ImportError:
    _HAS_GAUGE = False

from core.session_manager import InvestigationSession

try:
    from core.audit_logger import log_scan
    _HAS_AUDIT = True
except Exception:
    _HAS_AUDIT = False

from modules.email_analyzer.email_parser import (
    parse_eml_bytes,
    parse_raw_text,
    parse_headers_only,
    parse_msg_bytes,
    msg_parsing_available,
)
from modules.email_analyzer.email_risk_engine import analyze_email, quick_risk_summary
from modules.email_analyzer.base64_detector import scan_raw_base64_input
from modules.email_analyzer.email_report import (
    build_json_report,
    generate_pdf_report,
    build_evidence_package,
    pdf_available,
)

# ── Session bootstrap ────────────────────────────────────────────────────────
if 'session' not in st.session_state:
    st.session_state.session = InvestigationSession()
if 'case_id' not in st.session_state:
    st.session_state.case_id = st.session_state.session.case_id

# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.error("### 🚨 Emergency\nHelpline: **1930**")
    st.info("**Report:** cybercrime.gov.in")
    st.success(f"**Active Case:**\n{st.session_state.case_id}")
    st.divider()
    st.markdown("**📧 Email Intelligence**")
    st.caption("Analyzes phishing, spoofing, SPF/DKIM/DMARC, and hidden Base64 payloads.")
    if not msg_parsing_available():
        st.caption("⚠️ .msg support limited — use .eml or paste raw text for best results.")
    if not pdf_available():
        st.caption("⚠️ PDF export unavailable (reportlab not installed).")

st.markdown(
    '<div class="section-header">📧 Email Intelligence & Phishing Analysis</div>',
    unsafe_allow_html=True,
)
st.markdown(
    "Upload an email file, paste raw email text/headers, or paste suspicious Base64 "
    "content to check for phishing, spoofing, and hidden malicious payloads."
)

# ── Input mode selection ─────────────────────────────────────────────────────
input_mode = st.radio(
    "Input Method",
    [
        "📎 Upload .eml file",
        "📎 Upload .msg file",
        "📋 Paste raw email (headers + body)",
        "📋 Paste headers only",
        "🔢 Paste Base64 content",
    ],
    horizontal=False,
    key="email_input_mode",
)

raw_bytes = None
raw_text = ""
parsed_msg = None
parse_meta = {}
analysis_mode = "email"  # 'email' or 'base64_only'
source_label = ""

if input_mode == "📎 Upload .eml file":
    uploaded = st.file_uploader("Upload .eml file", type=["eml"], key="eml_uploader")
    if uploaded is not None:
        raw_bytes = uploaded.read()
        source_label = uploaded.name

elif input_mode == "📎 Upload .msg file":
    uploaded = st.file_uploader("Upload .msg file (Outlook format)", type=["msg"], key="msg_uploader")
    if uploaded is not None:
        raw_bytes = uploaded.read()
        source_label = uploaded.name

elif input_mode == "📋 Paste raw email (headers + body)":
    raw_text = st.text_area(
        "Paste the complete raw email (View Source / Show Original from your email client)",
        height=280,
        placeholder=(
            "From: \"State Bank of India\" <support@sbi-online-verify.xyz>\n"
            "To: victim@example.com\n"
            "Subject: URGENT: Your account will be blocked in 24 hours\n"
            "Date: Mon, 21 Jun 2026 10:00:00 +0530\n"
            "Authentication-Results: mx.google.com; spf=fail; dkim=none; dmarc=fail\n\n"
            "Dear Customer, your KYC has expired. Click here to verify: "
            "http://sbi-online-verify.xyz/login ..."
        ),
        key="raw_email_text",
    )
    source_label = "Pasted raw email"

elif input_mode == "📋 Paste headers only":
    raw_text = st.text_area(
        "Paste only the email headers",
        height=220,
        placeholder=(
            "From: alerts@paytm-kyc-update.tk\n"
            "Reply-To: collect@fraudster-domain.com\n"
            "Authentication-Results: spf=fail; dkim=fail; dmarc=fail\n"
            "Received-SPF: fail (client-ip=203.0.113.5)"
        ),
        key="headers_only_text",
    )
    source_label = "Pasted headers"

elif input_mode == "🔢 Paste Base64 content":
    raw_text = st.text_area(
        "Paste suspicious Base64-encoded content",
        height=180,
        placeholder="aHR0cDovL3NiaS1vbmxpbmUtdmVyaWZ5Lnh5ei9sb2dpbg==",
        key="base64_only_text",
    )
    analysis_mode = "base64_only"
    source_label = "Pasted Base64 content"

include_base64_scan = st.checkbox(
    "🔎 Scan email body for hidden Base64-encoded payloads", value=True,
    key="include_b64",
) if analysis_mode == "email" else True

analyze_btn = st.button("🔍 Analyze Email", type="primary", use_container_width=True)

# ── Validation ────────────────────────────────────────────────────────────────
has_input = bool(raw_bytes) or bool(raw_text and raw_text.strip())

if analyze_btn and not has_input:
    st.warning("Please provide email content to analyze (upload a file or paste text).")

elif analyze_btn and has_input:

    # ── Base64-only mode ──────────────────────────────────────────────────────
    if analysis_mode == "base64_only":
        with st.spinner("Decoding and analyzing Base64 content…"):
            b64_result = scan_raw_base64_input(raw_text.strip())

        st.divider()
        st.markdown('<div class="section-header">🔢 Base64 Analysis Results</div>', unsafe_allow_html=True)

        if not b64_result.get("base64_detected"):
            st.success("✅ No valid Base64-encoded payload could be decoded from this input.")
            if b64_result.get("decode_error"):
                st.caption(f"Note: {b64_result['decode_error']}")
        else:
            risk = b64_result.get("risk_delta", 0)
            col1, col2 = st.columns([1, 2])
            with col1:
                if _HAS_GAUGE:
                    st.plotly_chart(risk_gauge_plotly(risk), use_container_width=True, key="b64_gauge")
                else:
                    st.metric("Risk Score", f"{risk}/100")
            with col2:
                if b64_result.get("has_hidden_payload"):
                    st.error("🚨 **Hidden malicious payload detected in Base64 content.**")
                else:
                    st.warning("⚠️ Base64 content decoded — review findings below.")
                st.markdown(f"**Items decoded:** {b64_result.get('successfully_decoded', 0)} "
                            f"of {b64_result.get('candidates_found', 0)} candidate(s)")

            for finding in b64_result.get("findings", []):
                desc = finding.get("description", "")
                sev = finding.get("severity", "MEDIUM")
                is_crit = sev in ("CRITICAL", "HIGH")
                if _HAS_FINDING_CARD:
                    st.markdown(render_finding_card(f"[{sev}] {desc}", is_crit), unsafe_allow_html=True)
                else:
                    (st.error if is_crit else st.warning)(f"**[{sev}]** {desc}")

            for item in b64_result.get("decoded_items", []):
                with st.expander(f"📄 Decoded item — {item.get('detected_type', 'unknown')} "
                                  f"(risk: {item.get('item_risk_score', 0)}/100)"):
                    st.code(item.get("encoded_snippet", ""), language="text")
                    st.markdown("**Decoded content (preview):**")
                    st.code(item.get("decoded_text", "")[:1000] or "(binary content)", language="text")
                    if item.get("urls_found"):
                        st.markdown("**URLs found inside:**")
                        for u in item["urls_found"]:
                            st.code(u, language="text")

            if _HAS_AUDIT:
                try:
                    log_scan(
                        scan_type='email_base64',
                        target=source_label,
                        risk_score=risk,
                        verdict='SUSPICIOUS' if risk >= 25 else 'SAFE',
                        details=b64_result,
                        case_id=st.session_state.get('case_id'),
                    )
                except Exception as e:
                    logger.warning(f"Audit log failed: {e}")

    # ── Full email analysis mode ────────────────────────────────────────────
    else:
        with st.spinner("Parsing email…"):
            if raw_bytes is not None:
                if input_mode == "📎 Upload .msg file":
                    parsed_msg, parse_meta = parse_msg_bytes(raw_bytes)
                else:
                    parsed_msg, parse_meta = parse_eml_bytes(raw_bytes)
            elif input_mode == "📋 Paste headers only":
                parsed_msg, parse_meta = parse_headers_only(raw_text)
            else:
                parsed_msg, parse_meta = parse_raw_text(raw_text)

        if not parse_meta.get("parse_success", False) and parse_meta.get("error"):
            st.error(f"⚠️ Parsing issue: {parse_meta['error']}")
            if parsed_msg is None or not parsed_msg.keys():
                st.stop()

        with st.spinner("Running phishing, spoofing & authentication analysis…"):
            analysis = analyze_email(parsed_msg, include_base64=include_base64_scan)

        # Persist into session for the report download buttons below
        st.session_state["last_email_analysis"] = analysis
        st.session_state["last_email_raw_text"] = raw_text if raw_text else (
            raw_bytes.decode("utf-8", errors="replace") if raw_bytes else ""
        )
        st.session_state["last_email_source_label"] = source_label

        if analysis.get("errors"):
            with st.expander("⚠️ Non-fatal analysis warnings"):
                for err in analysis["errors"]:
                    st.caption(err)

        # Audit log
        if _HAS_AUDIT:
            try:
                log_scan(
                    scan_type='email',
                    target=analysis.get("from", {}).get("email", source_label) or source_label,
                    risk_score=analysis.get("final_score", 0),
                    verdict=analysis.get("verdict", "Unknown"),
                    details=analysis,
                    case_id=st.session_state.get('case_id'),
                )
            except Exception as e:
                logger.warning(f"Audit log failed: {e}")

        # Update investigation session
        try:
            st.session_state.session.add_message_result(
                f"Email from {analysis.get('from', {}).get('email', 'unknown')}",
                {
                    'risk_score': analysis.get("final_score", 0),
                    'verdict': analysis.get("verdict", "Unknown"),
                },
            )
        except Exception:
            pass

# ── Results display (persists across reruns via session state) ─────────────
if "last_email_analysis" in st.session_state and analysis_mode == "email":
    analysis = st.session_state["last_email_analysis"]
    score = analysis.get("final_score", 0)
    verdict = analysis.get("verdict", "Unknown")

    st.divider()

    tabs = st.tabs([
        "📊 Risk Overview", "📨 Headers", "🔐 SPF/DKIM/DMARC",
        "🎣 Phishing Analysis", "🔢 Base64 Findings",
        "📎 Attachments & URLs", "📥 Download Report",
    ])

    # ── Tab 1: Risk Overview ────────────────────────────────────────────────
    with tabs[0]:
        col_gauge, col_details = st.columns([1, 2])
        with col_gauge:
            if _HAS_GAUGE:
                st.plotly_chart(risk_gauge_plotly(score), use_container_width=True, key="email_gauge")
            else:
                st.metric("Risk Score", f"{score}/100")
        with col_details:
            st.markdown(f"### {analysis.get('verdict_full', verdict)}")
            from_info = analysis.get("from", {})
            st.markdown(f"**Sender:** `{from_info.get('email', 'Unknown')}`")
            if from_info.get("display_name"):
                st.markdown(f"**Display Name:** {from_info.get('display_name')}")
            st.markdown(f"**Subject:** {analysis.get('metadata', {}).get('subject', 'N/A')}")
            st.markdown(
                f"**Findings:** {analysis.get('total_findings', 0)} total "
                f"({analysis.get('critical_count', 0)} critical, "
                f"{analysis.get('high_count', 0)} high, "
                f"{analysis.get('medium_count', 0)} medium)"
            )

        if score >= 75:
            st.error(
                "🚨 **This email shows strong phishing indicators.** Do not click any links "
                "or download attachments. If you already did, call **1930** immediately."
            )
        elif score >= 50:
            st.warning("⚠️ **This email is likely phishing.** Verify the sender through official channels.")
        elif score >= 25:
            st.warning("🟡 This email shows some suspicious indicators. Proceed with caution.")
        else:
            st.success("✅ No strong phishing indicators detected. Always remain cautious regardless.")

        st.markdown("#### Recommendations")
        for rec in analysis.get("recommendations", []):
            st.markdown(f"- {rec}")

        st.markdown("#### All Findings")
        if analysis.get("all_findings"):
            for f in analysis["all_findings"]:
                sev = f.get("severity", "INFO")
                desc = f"**[{f.get('category', '')}]** {f.get('description', '')}"
                is_crit = sev in ("CRITICAL", "HIGH")
                if _HAS_FINDING_CARD:
                    st.markdown(render_finding_card(desc, is_crit), unsafe_allow_html=True)
                else:
                    (st.error if is_crit else st.info)(desc)
        else:
            st.success("No findings detected.")

    # ── Tab 2: Headers ──────────────────────────────────────────────────────
    with tabs[1]:
        from_info = analysis.get("from", {})
        meta = analysis.get("metadata", {})
        st.markdown("**Sender Information**")
        st.json({
            "From (display name)": from_info.get("display_name", ""),
            "From (email)": from_info.get("email", ""),
            "From (domain)": from_info.get("domain", ""),
        })
        st.markdown("**Message Metadata**")
        st.json(meta)

        header_comp = analysis.get("component_results", {}).get("header_spoofing", {})
        if header_comp.get("findings"):
            st.markdown("**Header Spoofing Indicators**")
            for f in header_comp["findings"]:
                desc = f.get("description", "") if isinstance(f, dict) else str(f)
                is_crit = isinstance(f, dict) and f.get("severity") in ("CRITICAL", "HIGH")
                if _HAS_FINDING_CARD:
                    st.markdown(render_finding_card(desc, is_crit), unsafe_allow_html=True)
                else:
                    (st.error if is_crit else st.warning)(desc)

    # ── Tab 3: Authentication ────────────────────────────────────────────────
    with tabs[2]:
        spf = analysis.get("component_results", {}).get("spf", {})
        dkim = analysis.get("component_results", {}).get("dkim", {})
        dmarc = analysis.get("component_results", {}).get("dmarc", {})

        col_spf, col_dkim, col_dmarc = st.columns(3)
        with col_spf:
            st.metric("SPF", spf.get("label", "Unknown"))
            st.caption(spf.get("recommendation", ""))
        with col_dkim:
            st.metric("DKIM", dkim.get("label", "Unknown"))
            st.caption(dkim.get("recommendation", ""))
        with col_dmarc:
            st.metric("DMARC", dmarc.get("label", "Unknown"))
            st.caption(dmarc.get("recommendation", ""))

        st.divider()
        for label, comp in [("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc)]:
            st.markdown(f"**{label} Findings**")
            findings = comp.get("findings", [])
            if findings:
                for f in findings:
                    is_crit = not comp.get("is_safe", True)
                    if _HAS_FINDING_CARD:
                        st.markdown(render_finding_card(str(f), is_crit), unsafe_allow_html=True)
                    else:
                        (st.warning if is_crit else st.info)(str(f))
            else:
                st.caption("No specific findings.")

    # ── Tab 4: Phishing Analysis ─────────────────────────────────────────────
    with tabs[3]:
        phishing = analysis.get("component_results", {}).get("phishing_content", {})
        domain_ver = analysis.get("component_results", {}).get("domain_verification", {})

        col1, col2, col3 = st.columns(3)
        col1.metric("Urgency Signals", phishing.get("urgency_count", 0))
        col2.metric("Credential Theft Patterns", phishing.get("credential_theft_count", 0))
        col3.metric("India-Specific Threats", phishing.get("india_threat_count", 0))

        st.markdown("**Domain Verification**")
        st.markdown(f"- Domain: `{domain_ver.get('domain', 'N/A')}`")
        st.markdown(f"- Classified as: {domain_ver.get('domain_type', 'Unknown')}")
        st.markdown(f"- Known legitimate: {'✅ Yes' if domain_ver.get('is_legitimate') else '❌ No'}")
        st.markdown(f"- Matches phishing pattern: {'🚨 Yes' if domain_ver.get('is_phishing_domain') else '✅ No'}")
        st.markdown(f"- Disposable domain: {'⚠️ Yes' if domain_ver.get('is_disposable') else '✅ No'}")

        st.markdown("**Content Findings**")
        content_findings = phishing.get("findings", [])
        if content_findings:
            for f in content_findings:
                desc = f.get("description", "") if isinstance(f, dict) else str(f)
                score = f.get("score", 10) if isinstance(f, dict) else 10
                is_crit = score >= 18
                if _HAS_FINDING_CARD:
                    st.markdown(render_finding_card(desc, is_crit), unsafe_allow_html=True)
                else:
                    (st.error if is_crit else st.warning)(desc)
        else:
            st.success("No phishing content patterns detected.")

    # ── Tab 5: Base64 Findings ───────────────────────────────────────────────
    with tabs[4]:
        b64 = analysis.get("component_results", {}).get("base64", {})
        if not b64.get("base64_detected"):
            st.success("✅ No hidden Base64-encoded payloads detected in the email body.")
        else:
            st.markdown(
                f"**{b64.get('successfully_decoded', 0)}** payload(s) decoded out of "
                f"**{b64.get('candidates_found', 0)}** candidate(s) found."
            )
            if b64.get("has_hidden_payload"):
                st.error("🚨 Hidden malicious payload(s) detected.")
            for f in b64.get("findings", []):
                desc = f.get("description", "") if isinstance(f, dict) else str(f)
                sev = f.get("severity", "MEDIUM") if isinstance(f, dict) else "MEDIUM"
                is_crit = sev in ("CRITICAL", "HIGH")
                if _HAS_FINDING_CARD:
                    st.markdown(render_finding_card(f"[{sev}] {desc}", is_crit), unsafe_allow_html=True)
                else:
                    (st.error if is_crit else st.warning)(desc)

            for item in b64.get("decoded_items", []):
                with st.expander(f"📄 {item.get('detected_type', 'unknown')} "
                                  f"(risk: {item.get('item_risk_score', 0)}/100)"):
                    st.code(item.get("encoded_snippet", ""), language="text")
                    st.code(item.get("decoded_text", "")[:1000] or "(binary content)", language="text")

    # ── Tab 6: Attachments & URLs ─────────────────────────────────────────────
    with tabs[5]:
        urls = analysis.get("urls", [])
        attachments = analysis.get("attachments", [])

        st.markdown(f"**URLs Found ({len(urls)})**")
        if urls:
            for u in urls:
                st.code(u, language="text")
        else:
            st.caption("No URLs found.")

        st.markdown(f"**Attachments ({len(attachments)})**")
        if attachments:
            for a in attachments:
                fname = a.get("filename", "unknown")
                ctype = a.get("content_type", "unknown")
                size = a.get("size_bytes", 0)
                st.markdown(f"- `{fname}` — {ctype} — {size:,} bytes")
        else:
            st.caption("No attachments found.")

    # ── Tab 7: Download Report ────────────────────────────────────────────────
    with tabs[6]:
        st.markdown("Generate and download a complete analysis report.")
        source_info = {
            "source_label": st.session_state.get("last_email_source_label", ""),
            "case_id": st.session_state.get("case_id", ""),
        }

        json_report = build_json_report(analysis, source_info)
        st.download_button(
            "⬇️ Download JSON Report",
            data=json_report,
            file_name=f"email_intelligence_{st.session_state.get('case_id', 'report')}.json",
            mime="application/json",
            use_container_width=True,
        )

        if pdf_available():
            try:
                pdf_bytes = generate_pdf_report(
                    analysis, source_info, case_id=st.session_state.get("case_id", "")
                )
                st.download_button(
                    "⬇️ Download PDF Report",
                    data=pdf_bytes,
                    file_name=f"email_intelligence_{st.session_state.get('case_id', 'report')}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )
            except Exception as e:
                st.error(f"PDF generation failed: {e}")
        else:
            st.info("💡 Install `reportlab` to enable PDF report export.")

        evidence_pkg = build_evidence_package(
            analysis,
            st.session_state.get("last_email_raw_text", ""),
            source_info,
        )
        import json as _json
        st.download_button(
            "⬇️ Download Evidence Package (for cybercrime.gov.in)",
            data=_json.dumps(evidence_pkg, indent=2, default=str),
            file_name=f"evidence_{st.session_state.get('case_id', 'package')}.json",
            mime="application/json",
            use_container_width=True,
        )

        st.divider()
        st.caption(quick_risk_summary(analysis))
