import urllib.parse

import streamlit as st

from ui.styles import GLOBAL_CSS
from ui.components import render_finding_card
from ui.charts import risk_gauge_plotly
from modules.url_analyzer.feature_extractor import extract_url_features
from modules.url_analyzer.heuristics import run_heuristic_checks
from modules.url_analyzer.ml_model import predict_url, model_available
from modules.reporting.report_generator import generate_pdf_report
from modules.url_analyzer.threat_intel import (
    VirusTotalClient,
    get_whois_intel,
    get_dns_intel,
)
from core.risk_engine import RiskSignal, compute_risk_score
from core.audit_logger import log_scan, get_recent_scans
from core.session_manager import InvestigationSession
from config import settings

st.set_page_config(
    page_title="URL Analyzer | CyberSahayak",
    page_icon="🌐",
    layout="wide",
)
st.markdown(GLOBAL_CSS, unsafe_allow_html=True)

# ── Always initialise session state — page can be accessed directly
if 'session' not in st.session_state:
    st.session_state.session = InvestigationSession()
if 'case_id' not in st.session_state:
    st.session_state.case_id = st.session_state.session.case_id
if 'generated_pdf' not in st.session_state:
    st.session_state.generated_pdf = None
# ── Sidebar
with st.sidebar:
    st.error("### 🚨 Emergency\nHelpline: **1930**")
    st.info("**Report:** cybercrime.gov.in")
    st.success(f"**Active Case:**\n{st.session_state.case_id}")

st.markdown(
    '<div class="section-header">🌐 URL Phishing & Threat Analyzer</div>',
    unsafe_allow_html=True,
)
st.markdown("Paste a suspicious URL to check for phishing, malware, and fraud indicators.")

url_input = st.text_input(
    "Suspicious URL",
    placeholder="https://sbi-kyc-verify.xyz/login or any suspicious link",
    help="Paste the full URL including http:// or https://",
    key="url_analyzer_input",
)

col_opt1, col_opt2, col_opt3 = st.columns(3)
with col_opt1:
    use_virustotal = st.checkbox(
        "VirusTotal Scan",
        value=bool(settings.VIRUSTOTAL_API_KEY),
        help="Requires VT API key in .env",
    )
with col_opt2:
    use_whois = st.checkbox("WHOIS Lookup", value=True)
with col_opt3:
    use_dns = st.checkbox("DNS Analysis", value=True)

analyze_btn = st.button("🔍 Analyze URL", type="primary", use_container_width=True)

if analyze_btn and not url_input.strip():
    st.warning("Please enter a URL to analyze.")

elif analyze_btn and url_input.strip():
    url = url_input.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed_input = urllib.parse.urlparse(url)
    domain = parsed_input.netloc.split(':')[0].replace('www.', '').lower()

    signals: list = []
    all_findings: list = []

    # ── Run all computation inside the spinner — NO st.tabs / st.columns here
    with st.spinner("Analyzing URL — this may take a few seconds…"):

        # Heuristic Analysis
        heuristic_result = run_heuristic_checks(url)
        if heuristic_result['risk_score'] > 0:
            signals.append(RiskSignal(
                source='rule_engine',
                score=heuristic_result['risk_score'],
                weight=1.1,
                description='; '.join(heuristic_result['findings'][:3]),
                confidence='High',
            ))
        all_findings.extend(heuristic_result['findings'])

        # ML Analysis
        ml_result: dict = {
            'ml_score': 0, 'is_phishing': False,
            'confidence': 'N/A', 'top_features': [],
        }
        if model_available():
            try:
                ml_result = predict_url(url)
                signals.append(RiskSignal(
                    source='ml_model',
                    score=int(ml_result['ml_score']),
                    weight=1.0,
                    description=f"ML phishing probability: {ml_result['ml_score']:.1f}%",
                    confidence=ml_result['confidence'],
                ))
            except Exception as exc:
                ml_result['error'] = str(exc)

        # VirusTotal
        vt_result: dict = {}
        if use_virustotal and settings.VIRUSTOTAL_API_KEY:
            try:
                vt = VirusTotalClient()
                vt_result = vt.scan_url(url)
                if 'vt_risk_score' in vt_result:
                    signals.append(RiskSignal(
                        source='virustotal',
                        score=vt_result['vt_risk_score'],
                        weight=1.5,
                        description=(
                            f"VT: {vt_result.get('malicious', 0)} engines flagged malicious"
                        ),
                        confidence='High',
                    ))
            except Exception as exc:
                vt_result = {'error': str(exc)}

        # WHOIS
        whois_result: dict = {}
        if use_whois and domain:
            try:
                whois_result = get_whois_intel(domain)
                if whois_result.get('risk_from_whois', 0) > 0:
                    signals.append(RiskSignal(
                        source='whois',
                        score=whois_result['risk_from_whois'],
                        weight=0.8,
                        description=(
                            f"Domain age: {whois_result.get('age_days', 'Unknown')} days — "
                            "very new domain"
                        ),
                        confidence='Medium',
                    ))
            except Exception as exc:
                whois_result = {'error': str(exc)}

        # DNS
        dns_result: dict = {}
        if use_dns and domain:
            try:
                dns_result = get_dns_intel(domain)
                if dns_result.get('risk_score', 0) > 0:
                    signals.append(RiskSignal(
                        source='dns',
                        score=dns_result['risk_score'],
                        weight=0.7,
                        description='; '.join(dns_result.get('findings', [])[:2]),
                        confidence='Medium',
                    ))
            except Exception as exc:
                dns_result = {'error': str(exc)}

        # Compute Final Risk
        risk = compute_risk_score(signals)
        final_score = risk['score']
        verdict = risk['verdict']
        pdf_file = generate_pdf_report(
    "url_investigation_report.pdf",
    "CyberSahayak Investigation Report",
    [
    "=== SUMMARY ===",

    f"URL: {url}",
    f"Verdict: {verdict}",
    f"Risk Score: {final_score}",

    "",

    "=== ML ANALYSIS ===",

    f"ML Score: {ml_result.get('ml_score', 0)}",
    f"Confidence: {ml_result.get('confidence', 'N/A')}",

    "",

    "=== VIRUSTOTAL ===",

    f"Malicious Engines: {vt_result.get('malicious', 0)}",
    f"Suspicious Engines: {vt_result.get('suspicious', 0)}",

    "",

    "=== WHOIS ===",

    f"Domain Age: {whois_result.get('age_days', 'Unknown')} days",

    "",

    "=== HEURISTIC FINDINGS ===",

    *heuristic_result.get('findings', []),

    "",

    "=== RECOMMENDATION ===",

    "Do not visit this URL if risk score is above 60."
]
)

        # Audit log — always persisted regardless of UI state
        log_scan(
            scan_type='url',
            target=url,
            risk_score=final_score,
            verdict=verdict,
            details={
                'heuristic': heuristic_result,
                'ml': ml_result,
                'vt': vt_result,
                'whois': whois_result,
                'dns': dns_result,
                'signals': risk.get('explanation', []),
            },
            case_id=st.session_state.get('case_id'),
        )

        # Update investigation session — non-fatal if missing
        try:
            st.session_state.session.add_url_result(url, {
                'risk_score': final_score,
                'verdict': verdict,
                'findings': all_findings,
            })
        except Exception:
            pass

    # ── Create tabs OUTSIDE spinner — this is required for Streamlit to bind them
    tabs = st.tabs([
        "📊 Risk Overview", "🔬 Heuristics", "🧠 ML Analysis",
        "🌐 Threat Intel", "📋 Raw Features",
    ])

    # Tab 1: Risk Overview
    with tabs[0]:
        col_gauge, col_details = st.columns([1, 2])
        with col_gauge:
            st.plotly_chart(
                risk_gauge_plotly(final_score),
                use_container_width=True,
                key="url_gauge",
            )
        with col_details:
            st.markdown(f"### {verdict}")
            try:
                with open("url_investigation_report.pdf", "rb") as f:
                    st.download_button(
                        "📥 Download Investigation Report",
                        data=f.read(),
                        file_name="CyberSahayak_Report.pdf",
                        mime="application/pdf"
                    )
            except Exception as e:
                st.error(f"Report Error: {e}")
            st.markdown(
                f"**URL:** `{url[:80]}{'...' if len(url) > 80 else ''}`"
            )
            if risk.get('explanation'):
                st.markdown("**Signal Breakdown:**")
                for expl in risk['explanation']:
                    is_crit = any(
                        w in expl.lower()
                        for w in ['virustotal', 'phishing', 'malicious']
                    )
                    st.markdown(
                        render_finding_card(expl, is_crit),
                        unsafe_allow_html=True,
                    )
            if final_score >= 60:
                st.error(
                    "⚠️ **Do NOT visit this URL.** If you already clicked it, "
                    "change your passwords immediately and call **1930**."
                )
            elif final_score >= 35:
                st.warning(
                    "⚠️ Exercise caution. Verify this URL from an official source "
                    "before proceeding."
                )

    # Tab 2: Heuristics
    with tabs[1]:
        st.markdown(f"**Heuristic Risk Score:** `{heuristic_result['risk_score']}/100`")
        if heuristic_result.get('flags'):
            st.markdown(
                "**Flags:** " + " • ".join(
                    f"`{f}`" for f in heuristic_result['flags']
                )
            )
        if heuristic_result.get('findings'):
            for finding in heuristic_result['findings']:
                st.markdown(
                    render_finding_card(
                        finding, heuristic_result['risk_score'] >= 60
                    ),
                    unsafe_allow_html=True,
                )
        else:
            st.success("No heuristic flags triggered.")
        st.markdown(
            f"**Detected Domain:** `{heuristic_result.get('domain', 'N/A')}`"
        )

    # Tab 3: ML Analysis
    with tabs[2]:
        if not model_available():
            st.info(
                "ML model not trained yet.\n\n"
                "Run:  `python training/train_url_model.py`"
            )
        elif 'error' in ml_result:
            st.warning(
                f"ML model error: {ml_result['error']}\n\n"
                "Re-run `python training/train_url_model.py` to rebuild the model."
            )
        else:
            col_m1, col_m2 = st.columns(2)
            col_m1.metric(
                "ML Phishing Probability",
                f"{ml_result.get('ml_score', 0):.1f}%",
            )
            col_m2.metric("Confidence", ml_result.get('confidence', 'N/A'))
            if ml_result.get('top_features'):
                st.markdown("**Top Contributing Features:**")
                for feat in ml_result['top_features']:
                    st.markdown(f"• `{feat}`")

    # Tab 4: Threat Intel
    with tabs[3]:
        intel_col1, intel_col2 = st.columns(2)

        with intel_col1:
            st.markdown("**WHOIS Information**")
            if whois_result and 'error' not in whois_result:
                st.json({
                    'Registrar': whois_result.get('registrar', 'N/A'),
                    'Created': whois_result.get('creation_date', 'N/A'),
                    'Age (days)': whois_result.get('age_days', 'N/A'),
                    'Country': whois_result.get('registrant_country', 'N/A'),
                    'New Domain': whois_result.get('is_new_domain', False),
                })
            elif whois_result.get('error'):
                st.warning(f"WHOIS: {whois_result['error']}")
            else:
                st.info("WHOIS lookup disabled.")

            if vt_result:
                st.markdown("**VirusTotal Results**")
                if 'error' in vt_result:
                    st.warning(f"VT Error: {vt_result['error']}")
                else:
                    st.json({
                        'Malicious Engines': vt_result.get('malicious', 0),
                        'Suspicious': vt_result.get('suspicious', 0),
                        'Harmless': vt_result.get('harmless', 0),
                        'VT Risk Score': vt_result.get('vt_risk_score', 0),
                    })

        with intel_col2:
            st.markdown("**DNS Analysis**")
            if dns_result and 'error' not in dns_result:
                st.json({
                    'A Records': dns_result.get('records', {}).get('A', []),
                    'MX Records': dns_result.get('records', {}).get('MX', []),
                    'Has SPF': dns_result.get('has_spf', False),
                    'Has DMARC': dns_result.get('has_dmarc', False),
                    'DNS Findings': dns_result.get('findings', []),
                })
            elif dns_result.get('error'):
                st.warning(f"DNS: {dns_result['error']}")
            else:
                st.info("DNS lookup disabled.")

    # Tab 5: Raw Features
    with tabs[4]:
        st.markdown("**Extracted URL Features (used by ML model):**")
        features = extract_url_features(url)
        feature_cols = st.columns(3)
        items = list(features.items())
        chunk = max(1, len(items) // 3 + 1)
        for i, col in enumerate(feature_cols):
            with col:
                for k, v in items[i * chunk:(i + 1) * chunk]:
                    st.markdown(f"`{k}`: **{v}**")

# ── Recent URL Scans
st.divider()
st.markdown(
    '<div class="section-header">🕐 Recent URL Scans</div>',
    unsafe_allow_html=True,
)
recent = get_recent_scans(limit=5, scan_type='url')
if recent:
    for scan in recent:
        risk_color = (
            '#EF4444' if scan['risk_score'] >= 75
            else '#F59E0B' if scan['risk_score'] >= 45
            else '#10B981'
        )
        cols = st.columns([4, 1, 2, 2])
        target = scan['target']
        cols[0].markdown(
            f"`{target[:70]}...`" if len(target) > 70 else f"`{target}`"
        )
        cols[1].markdown(
            f'<span style="color:{risk_color};font-weight:700">'
            f'{scan["risk_score"]}/100</span>',
            unsafe_allow_html=True,
        )
        cols[2].write(scan['verdict'])
        cols[3].write(scan['timestamp'][:19])
else:
    st.info("No URL scans yet. Analyze a URL above to get started.")