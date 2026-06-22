# pages/03_sms_scanner.py — SMS / Message Scam Scanner
import streamlit as st
from ui.styles import GLOBAL_CSS
from ui.components import render_risk_gauge, render_finding_card
from ui.charts import risk_gauge_plotly
from modules.sms_analyzer.keyword_engine import run_keyword_scan
from modules.sms_analyzer.local_classifier import analyze_sms_local
from modules.sms_analyzer.llm_analyzer import analyze_with_llm
from modules.fraud_detectors.digital_arrest import analyze_for_digital_arrest
from modules.fraud_detectors.whatsapp_scam import analyze_whatsapp_message
from core.audit_logger import log_scan, get_recent_scans
from core.risk_engine import RiskSignal, compute_risk_score
from config import settings
from pathlib import Path

st.set_page_config(page_title="SMS Scanner | CyberSahayak", page_icon="📱", layout="wide")
st.markdown(GLOBAL_CSS, unsafe_allow_html=True)

with st.sidebar:
    st.error("### 🚨 Emergency\nHelpline: **1930**")
    st.info("**Report:** cybercrime.gov.in")
    st.success(f"**Active Case:**\n{st.session_state.get('case_id', 'None')}")

st.markdown('<div class="section-header">📱 SMS & Message Scam Scanner</div>',
            unsafe_allow_html=True)
st.markdown("Paste a suspicious SMS, WhatsApp message, or any text to analyze for fraud.")

msg_source = st.radio("Message Source", ["SMS", "WhatsApp", "Email", "Other"],
                      horizontal=True)
message_input = st.text_area(
    "Paste the suspicious message",
    placeholder="e.g. Your KYC is expiring. Click here to update: bit.ly/kyc-sbi",
    height=140,
    help="Paste the complete message. More context = better analysis."
)

col1, col2 = st.columns(2)
with col1:
    use_llm = st.checkbox("AI Deep Analysis (LLM)", value=True,
                          help="Uses local Ollama or Gemini API for deeper analysis")
with col2:
    use_digital_arrest = st.checkbox("Digital Arrest Check", value=True)

scan_btn = st.button("🔍 Scan Message", type="primary", use_container_width=True)

if scan_btn and message_input.strip():
    text = message_input.strip()
    signals = []

    with st.spinner("Analyzing message..."):

        # ── Stage 1: Keyword Engine (instant) ────────────────────────
        kw_result = run_keyword_scan(text)

        # ── Stage 2: ML Classifier (fast) ────────────────────────────
        local_result = {'risk_score': 0, 'method': 'unavailable', 'flags': [], 'needs_llm': True}
        try:
            if Path('models/sms_pipeline.pkl').exists():
                local_result = analyze_sms_local(text)
        except Exception as e:
            local_result['error'] = str(e)

        # ── Stage 3: WhatsApp-specific detector ──────────────────────
        wa_result = {}
        if msg_source == "WhatsApp":
            wa_result = analyze_whatsapp_message(text)
            if wa_result.get('risk_score', 0) > 0:
                signals.append(RiskSignal(
                    source='rule_engine',
                    score=wa_result['risk_score'],
                    weight=1.1,
                    description='WhatsApp scam pattern detected',
                    confidence='High'
                ))

        # ── Stage 4: Digital Arrest check ────────────────────────────
        da_result = {}
        if use_digital_arrest:
            da_result = analyze_for_digital_arrest(text)
            if da_result.get('risk_score', 0) > 0:
                signals.append(RiskSignal(
                    source='rule_engine',
                    score=da_result['risk_score'],
                    weight=1.3,
                    description='Digital arrest scam indicators',
                    confidence='High'
                ))

        # ── Build signals from keyword + ML ──────────────────────────
        if kw_result['keyword_risk_score'] > 0:
            signals.append(RiskSignal(
                source='rule_engine',
                score=kw_result['keyword_risk_score'],
                weight=1.1,
                description='; '.join(
                    [m['description'] for m in kw_result['top_matches'][:2]]
                ),
                confidence='High'
            ))

        if local_result.get('risk_score', 0) > 0 and local_result['method'] != 'unavailable':
            signals.append(RiskSignal(
                source='ml_model',
                score=local_result['risk_score'],
                weight=1.0,
                description=f"ML classifier ({local_result['method']})",
                confidence=local_result.get('confidence', 'Medium')
            ))

        # ── Stage 5: LLM escalation ───────────────────────────────────
        llm_result = {}
        needs_llm = (
            use_llm and
            (local_result.get('needs_llm', False) or
             kw_result['keyword_risk_score'] == 0 or
             not signals)
        )
        if needs_llm:
            with st.spinner("Running AI deep analysis..."):
                llm_result = analyze_with_llm(text)
            if llm_result.get('risk_score', 0) > 0:
                signals.append(RiskSignal(
                    source='llm',
                    score=llm_result['risk_score'],
                    weight=0.5,
                    description=f"AI: {llm_result.get('scam_type', 'Unknown')}",
                    confidence=llm_result.get('confidence', 'Low')
                ))

        # ── Compute Final Risk ────────────────────────────────────────
        risk = compute_risk_score(signals) if signals else {
            'score': 0, 'verdict': '🟢 LIKELY SAFE', 'explanation': []}
        final_score = risk['score']
        verdict = risk['verdict']

        log_scan(
            scan_type='sms' if msg_source != 'WhatsApp' else 'whatsapp',
            target=text[:200],
            risk_score=final_score,
            verdict=verdict,
            details={
                'keywords': kw_result,
                'ml': local_result,
                'digital_arrest': da_result,
                'whatsapp': wa_result,
                'llm': llm_result
            },
            case_id=st.session_state.get('case_id')
        )

        if 'session' in st.session_state:
            st.session_state.session.add_message_result(text, {
                'risk_score': final_score,
                'verdict': verdict,
                'flags': kw_result.get('matched_categories', [])
            })

        # ── Display Results ───────────────────────────────────────────
        tabs = st.tabs(["📊 Risk Overview", "🔑 Keywords", "🤖 AI Analysis",
                         "🚨 Digital Arrest", "📱 WhatsApp"])

        with tabs[0]:
            col_g, col_d = st.columns([1, 2])
            with col_g:
                st.plotly_chart(risk_gauge_plotly(final_score),
                                use_container_width=True, key="sms_gauge")
            with col_d:
                st.markdown(f"### {verdict}")
                for expl in risk.get('explanation', []):
                    st.markdown(render_finding_card(expl, final_score >= 60),
                                unsafe_allow_html=True)

            if da_result.get('is_digital_arrest'):
                st.error(f"🚨 {da_result.get('immediate_action', '')}")
            elif final_score >= 60:
                st.error("⚠️ **Do NOT respond or click any links.** "
                         "Call **1930** if you've already sent money.")
            elif final_score >= 35:
                st.warning("⚠️ Be cautious. Do not share OTP, UPI PIN, or personal details.")

        with tabs[1]:
            if kw_result['has_keywords']:
                st.metric("Keyword Risk", f"{kw_result['keyword_risk_score']}/100")
                st.markdown(f"**Categories Matched:** {', '.join(kw_result['matched_categories'])}")
                for match in kw_result['top_matches']:
                    st.markdown(render_finding_card(
                        f"{match['description']} (risk: {match['risk']}) — context: `{match['context']}`",
                        match['risk'] >= 75
                    ), unsafe_allow_html=True)
            else:
                st.success("No high-risk keyword patterns detected.")

        with tabs[2]:
            if llm_result:
                st.metric("AI Risk Score", f"{llm_result.get('risk_score', 0)}/100")
                st.markdown(f"**Scam Type:** {llm_result.get('scam_type', 'N/A')}")
                st.markdown(f"**Confidence:** {llm_result.get('confidence', 'N/A')}")
                if llm_result.get('key_indicators'):
                    st.markdown("**Key Indicators:**")
                    for ind in llm_result['key_indicators']:
                        st.markdown(f"• {ind}")
                if llm_result.get('recommended_action'):
                    st.info(f"💡 {llm_result['recommended_action']}")
                st.caption(f"Provider: {llm_result.get('provider', 'N/A')}")
            else:
                st.info("LLM analysis was not triggered (high-confidence result from rule engine).")

        with tabs[3]:
            if da_result and da_result.get('signals'):
                st.metric("Digital Arrest Risk", f"{da_result.get('risk_score', 0)}/100")
                for sig in da_result['signals']:
                    st.markdown(render_finding_card(
                        f"**{sig['name']}** — {sig['explanation']}", True
                    ), unsafe_allow_html=True)
            else:
                st.success("No digital arrest scam indicators found.")

        with tabs[4]:
            if msg_source == "WhatsApp" and wa_result:
                st.metric("WhatsApp Scam Risk", f"{wa_result.get('risk_score', 0)}/100")
                if wa_result.get('signals'):
                    for sig in wa_result['signals']:
                        st.markdown(render_finding_card(sig['pattern'], sig['score'] >= 75),
                                    unsafe_allow_html=True)
                if wa_result.get('shortened_urls'):
                    st.warning(f"Shortened URLs found: {wa_result['shortened_urls']}")
            elif msg_source != "WhatsApp":
                st.info("WhatsApp-specific checks only run for WhatsApp messages.")
            else:
                st.success("No WhatsApp scam patterns detected.")

elif scan_btn and not message_input.strip():
    st.warning("Please paste a message to scan.")

st.divider()
st.markdown('<div class="section-header">🕐 Recent Message Scans</div>', unsafe_allow_html=True)
recent = get_recent_scans(limit=5, scan_type='sms')
if recent:
    for scan in recent:
        risk_color = '#EF4444' if scan['risk_score'] >= 75 else \
                     '#F59E0B' if scan['risk_score'] >= 45 else '#10B981'
        cols = st.columns([4, 1, 2, 2])
        cols[0].write(scan['target'][:70] + '...' if len(scan['target']) > 70 else scan['target'])
        cols[1].markdown(f'<span style="color:{risk_color};font-weight:700">'
                         f'{scan["risk_score"]}/100</span>', unsafe_allow_html=True)
        cols[2].write(scan['verdict'])
        cols[3].write(scan['timestamp'][:19])
else:
    st.info("No message scans yet.")