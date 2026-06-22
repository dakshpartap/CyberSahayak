# pages/08_threat_intelligence.py — Live Threat Intelligence Lookups
import streamlit as st
from ui.styles import GLOBAL_CSS
from ui.components import render_finding_card
from modules.url_analyzer.threat_intel import (
    VirusTotalClient, get_whois_intel, get_dns_intel, get_geoip_intel
)
from modules.fraud_detectors.upi_fraud import analyze_upi
from config import settings
import re

st.set_page_config(page_title="Threat Intel | CyberSahayak", page_icon="🔍", layout="wide")
st.markdown(GLOBAL_CSS, unsafe_allow_html=True)

with st.sidebar:
    st.error("### 🚨 Emergency\nHelpline: **1930**")
    st.info("**Report:** cybercrime.gov.in")
    st.success(f"**Active Case:**\n{st.session_state.get('case_id', 'None')}")

    st.divider()
    st.markdown("**API Status**")
    if settings.VIRUSTOTAL_API_KEY:
        st.success("✅ VirusTotal: Configured")
    else:
        st.warning("⚠️ VirusTotal: No key")
    if settings.ABUSEIPDB_API_KEY:
        st.success("✅ AbuseIPDB: Configured")
    else:
        st.warning("⚠️ AbuseIPDB: No key")

st.markdown('<div class="section-header">🔍 Threat Intelligence Center</div>',
            unsafe_allow_html=True)
st.markdown("Look up domains, IPs, URLs, and UPI IDs against live threat intelligence feeds.")

intel_type = st.radio("Lookup Type", ["URL / Domain", "IP Address", "WHOIS", "DNS", "UPI ID"],
                      horizontal=True)

query_input = st.text_input(
    "Enter target",
    placeholder={
        "URL / Domain": "https://suspicious-sbi.xyz or sbi-kyc.in",
        "IP Address": "192.168.1.1",
        "WHOIS": "suspicious-domain.xyz",
        "DNS": "suspicious-domain.xyz",
        "UPI ID": "scammer@paytm"
    }.get(intel_type, "Enter target...")
)

lookup_btn = st.button("🔍 Run Lookup", type="primary", use_container_width=True)

if lookup_btn and query_input.strip():
    target = query_input.strip()

    with st.spinner(f"Running {intel_type} lookup..."):

        if intel_type == "URL / Domain":
            col1, col2 = st.columns(2)

            # VirusTotal
            with col1:
                st.markdown("**VirusTotal URL Scan**")
                if settings.VIRUSTOTAL_API_KEY:
                    try:
                        vt = VirusTotalClient()
                        vt_result = vt.scan_url(target)
                        if 'error' in vt_result:
                            st.error(f"VT Error: {vt_result['error']}")
                        else:
                            malicious = vt_result.get('malicious', 0)
                            color = '#EF4444' if malicious > 5 else \
                                    '#F59E0B' if malicious > 0 else '#10B981'
                            st.markdown(
                                f'<span style="color:{color};font-size:2rem;font-weight:800">'
                                f'{malicious}</span> engines flagged malicious',
                                unsafe_allow_html=True
                            )
                            st.json({
                                'Malicious': vt_result.get('malicious', 0),
                                'Suspicious': vt_result.get('suspicious', 0),
                                'Harmless': vt_result.get('harmless', 0),
                                'Risk Score': vt_result.get('vt_risk_score', 0)
                            })
                    except Exception as e:
                        st.error(f"VT scan error: {e}")
                else:
                    st.info("Add VIRUSTOTAL_API_KEY to .env to enable VT scanning.")

            with col2:
                st.markdown("**GeoIP Information**")
                try:
                    parsed_domain = target
                    if '://' in target:
                        import urllib.parse
                        parsed_domain = urllib.parse.urlparse(target).netloc.replace('www.', '')

                    geo_result = get_geoip_intel(parsed_domain)
                    if 'error' in geo_result:
                        st.info(f"GeoIP: {geo_result['error']}")
                    else:
                        st.json({
                            'IP': geo_result.get('ip', 'N/A'),
                            'Country': geo_result.get('country', 'Unknown'),
                            'High Risk Country': geo_result.get('is_high_risk_country', False),
                            'Risk from Geo': geo_result.get('risk_from_geo', 0)
                        })
                        if geo_result.get('is_high_risk_country'):
                            st.warning("⚠️ This domain is hosted in a high-risk country")
                except Exception as e:
                    st.info(f"GeoIP lookup requires GeoLite2 database. Error: {e}")

        elif intel_type == "IP Address":
            from modules.url_analyzer.threat_intel import AbuseIPDBClient
            col1, col2 = st.columns(2)

            with col1:
                st.markdown("**AbuseIPDB Check**")
                if settings.ABUSEIPDB_API_KEY:
                    try:
                        aipdb = AbuseIPDBClient()
                        abuse_result = aipdb.check_ip(target)
                        if 'error' in abuse_result:
                            st.error(f"AbuseIPDB Error: {abuse_result['error']}")
                        else:
                            score = abuse_result.get('abuse_score', 0)
                            color = '#EF4444' if score >= 50 else \
                                    '#F59E0B' if score >= 20 else '#10B981'
                            st.markdown(
                                f'<span style="color:{color};font-size:2rem;font-weight:800">'
                                f'{score}%</span> abuse confidence',
                                unsafe_allow_html=True
                            )
                            st.json(abuse_result)
                    except Exception as e:
                        st.error(f"AbuseIPDB error: {e}")
                else:
                    st.info("Add ABUSEIPDB_API_KEY to .env to enable abuse checking.")

            with col2:
                st.markdown("**GeoIP Lookup**")
                try:
                    geo = get_geoip_intel(target)
                    if 'error' not in geo:
                        st.json(geo)
                    else:
                        st.info(f"GeoIP unavailable: {geo['error']}")
                except Exception as e:
                    st.info(f"GeoIP error: {e}")

        elif intel_type == "WHOIS":
            st.markdown("**WHOIS Lookup**")
            try:
                domain = target.replace('http://', '').replace('https://', '').split('/')[0]
                result = get_whois_intel(domain)
                if 'error' in result:
                    st.error(f"WHOIS Error: {result['error']}")
                else:
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Domain Age", f"{result.get('age_days', 'N/A')} days")
                        st.metric("Is New Domain", "⚠️ YES" if result.get('is_new_domain') else "✅ No")
                    with col2:
                        st.metric("Registrar", result.get('registrar', 'Unknown')[:30])
                        st.metric("Country", result.get('registrant_country', 'Unknown'))

                    st.json(result)

                    if result.get('is_new_domain'):
                        st.warning("⚠️ Very new domain (< 30 days) — commonly used in phishing campaigns")
            except Exception as e:
                st.error(f"WHOIS lookup failed: {e}")

        elif intel_type == "DNS":
            st.markdown("**DNS Analysis**")
            try:
                domain = target.replace('http://', '').replace('https://', '').split('/')[0]
                result = get_dns_intel(domain)

                if 'error' in result:
                    st.error(f"DNS Error: {result['error']}")
                else:
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("A Records", len(result.get('records', {}).get('A', [])))
                    with col2:
                        st.metric("Has SPF", "✅" if result.get('has_spf') else "⚠️ No")
                    with col3:
                        st.metric("Has DMARC", "✅" if result.get('has_dmarc') else "⚠️ No")

                    if result.get('findings'):
                        st.markdown("**Findings:**")
                        for f in result['findings']:
                            st.markdown(render_finding_card(f, result['risk_score'] >= 30),
                                        unsafe_allow_html=True)

                    st.json(result.get('records', {}))
            except Exception as e:
                st.error(f"DNS lookup failed: {e}")

        elif intel_type == "UPI ID":
            st.markdown("**UPI ID Analysis**")
            result = analyze_upi(upi_id=target)

            score = result['risk_score']
            color = '#EF4444' if score >= 60 else '#F59E0B' if score >= 30 else '#10B981'
            st.markdown(
                f'<span style="color:{color};font-size:1.5rem;font-weight:800">'
                f'{result["verdict"]}</span>',
                unsafe_allow_html=True
            )
            st.metric("Risk Score", f"{score}/100")

            if result['findings']:
                for f in result['findings']:
                    st.markdown(render_finding_card(f, score >= 60), unsafe_allow_html=True)
            else:
                st.success("No suspicious indicators in this UPI ID.")

elif lookup_btn and not query_input.strip():
    st.warning("Please enter a target to look up.")