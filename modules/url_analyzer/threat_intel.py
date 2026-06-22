import socket
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

try:
    import whois as _whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver as _dns_resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import geoip2.database as _geoip2_db
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

from config import settings


class VirusTotalClient:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self):
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.headers = {"x-apikey": self.api_key}

    def scan_url(self, url: str) -> dict:
        if not self.api_key:
            return {'error': 'VirusTotal API key not configured'}
        try:
            resp = requests.post(
                f"{self.BASE}/urls",
                headers=self.headers,
                data={"url": url},
                timeout=15,
            )
            if resp.status_code != 200:
                return {'error': f'VT submission failed: {resp.status_code}'}

            analysis_id = resp.json()['data']['id']
            time.sleep(3)

            result_resp = requests.get(
                f"{self.BASE}/analyses/{analysis_id}",
                headers=self.headers,
                timeout=15,
            )
            result_resp.raise_for_status()
            stats = (
                result_resp.json()
                .get('data', {})
                .get('attributes', {})
                .get('stats', {})
            )
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            
            vt_risk_score = min(
                100,
                malicious * 15 + suspicious * 5
            )
            
            return {
                'malicious': malicious,
                'suspicious': suspicious,
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'vt_risk_score': vt_risk_score,
            }
        except requests.exceptions.Timeout:
            return {'error': 'VirusTotal request timed out'}
        except Exception as exc:
            return {'error': str(exc)}


class AbuseIPDBClient:
    BASE = "https://api.abuseipdb.com/api/v2"

    def __init__(self):
        self.api_key = settings.ABUSEIPDB_API_KEY

    def check_ip(self, ip: str) -> dict:
        if not self.api_key:
            return {'error': 'AbuseIPDB key not configured'}
        try:
            resp = requests.get(
                f"{self.BASE}/check",
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json().get('data', {})
            return {
                'abuse_score': data.get('abuseConfidenceScore', 0),
                'total_reports': data.get('totalReports', 0),
                'country': data.get('countryCode', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'domain': data.get('domain', ''),
                'last_reported': data.get('lastReportedAt', ''),
            }
        except Exception as exc:
            return {'error': str(exc)}


def get_whois_intel(domain: str) -> dict:
    if not WHOIS_AVAILABLE:
        return {
            'error': 'python-whois not installed (pip install python-whois)',
            'risk_from_whois': 0,
        }
    try:
        w = _whois_lib.whois(domain)

        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]

        age_days = None
        if creation:
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation).days

        return {
            'registrar': str(w.registrar or 'Unknown'),
            'creation_date': str(creation or 'Unknown'),
            'expiration_date': str(expiration or 'Unknown'),
            'age_days': age_days,
            'registrant_country': str(w.country or 'Unknown'),
            'is_new_domain': age_days is not None and age_days < 30,
            'risk_from_whois': 40 if (age_days is not None and age_days < 30) else 0,
        }
    except Exception as exc:
        return {'error': str(exc), 'risk_from_whois': 0}


def get_dns_intel(domain: str) -> dict:
    if not DNS_AVAILABLE:
        return {
            'error': 'dnspython not installed (pip install dnspython)',
            'risk_score': 0,
            'records': {},
            'findings': [],
        }
    result: dict = {'records': {}, 'findings': [], 'risk_score': 0}

    for record_type in ['A', 'MX', 'TXT', 'NS']:
        try:
            answers = _dns_resolver.resolve(domain, record_type, lifetime=5)
            result['records'][record_type] = [str(r) for r in answers]
        except Exception:
            result['records'][record_type] = []

    txt_records = ' '.join(result['records'].get('TXT', []))
    result['has_spf'] = 'v=spf1' in txt_records
    result['has_dmarc'] = 'v=DMARC1' in txt_records

    if not result['has_spf']:
        result['findings'].append('No SPF record — domain can be easily spoofed')
        result['risk_score'] += 20

    a_records = result['records'].get('A', [])
    if a_records:
        ip = a_records[0]
        reversed_ip = '.'.join(reversed(ip.split('.')))
        for dnsbl in ['zen.spamhaus.org', 'bl.spamcop.net']:
            try:
                _dns_resolver.resolve(f"{reversed_ip}.{dnsbl}", 'A', lifetime=3)
                result['findings'].append(f'Listed in DNSBL: {dnsbl}')
                result['risk_score'] += 30
            except Exception:
                pass

    return result


def get_geoip_intel(domain: str) -> dict:
    if not GEOIP_AVAILABLE:
        return {
            'error': 'geoip2 not installed (pip install geoip2)',
            'risk_from_geo': 0,
        }
    geoip_db_path = Path(settings.GEOIP_DB)
    if not geoip_db_path.exists():
        return {
            'error': f'GeoIP DB not found at {geoip_db_path}. '
                     'Download GeoLite2-Country.mmdb from maxmind.com.',
            'risk_from_geo': 0,
        }
    try:
        ip = socket.gethostbyname(domain)
        with _geoip2_db.Reader(str(geoip_db_path)) as reader:
            resp = reader.country(ip)
            country = resp.country.iso_code or 'Unknown'

        HIGH_RISK_COUNTRIES = {'RU', 'CN', 'NG', 'UA', 'KP', 'BR'}
        return {
            'ip': ip,
            'country': country,
            'is_high_risk_country': country in HIGH_RISK_COUNTRIES,
            'risk_from_geo': 25 if country in HIGH_RISK_COUNTRIES else 0,
        }
    except Exception as exc:
        return {'error': str(exc), 'risk_from_geo': 0}