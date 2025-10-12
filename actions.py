# actions.py

import subprocess
import os
import json
import re
from datetime import datetime
from database import db, Incident, Observable
import requests
from config import VT_API_KEY, EMAIL_RECIPIENT

# --- AKSİYON FONKSİYONLARI ---

def enrich_ip_with_virustotal(params):
    ip_address = params.get('ip_address')
    if not ip_address:
        print("  -> ⚠️  IP address not provided for VirusTotal enrichment.")
        return None

    # Simülasyon kontrolü
    if ip_address == '127.0.0.100':
        print("  -> 📈 [SIMULATED] High-score test IP detected. Returning mock data.")
        report = {"count": 15, "link": "#mock-report"}
        return {"virustotal_report": report}

    if not VT_API_KEY or VT_API_KEY.startswith("BURAYA"):
        print("  -> ⚠️  VirusTotal API Key not configured in config.py. Skipping enrichment.")
        return None
        
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        malicious_count = stats.get('malicious', 0)
        report_link = f"https://www.virustotal.com/gui/ip-address/{ip_address}/detection"
        print(f"  -> 📈 VirusTotal Enrichment: IP {ip_address} flagged as malicious by {malicious_count} vendors.")
        report = {"count": malicious_count, "link": report_link}
        return {"virustotal_report": report}
    except requests.exceptions.RequestException as e:
        print(f"  -> 🛑 ERROR: Failed to get VirusTotal report. Error: {e}")
        return None

def create_incident(params):
    try:
        vt_report = params.get('virustotal_report') or {}
        mitre_mapping = params.get('mitre_mapping') or {}
        
        new_incident = Incident(
            event_type=params.get('event_type', 'unknown'),
            severity=params.get('severity', 'low'),
            details=params.get('details', 'No details provided.'),
            vt_malicious_count=vt_report.get('count'),
            vt_report_link=vt_report.get('link'),
            mitre_technique_id=mitre_mapping.get('technique_id'),
            mitre_technique_name=mitre_mapping.get('technique_name')
        )
        
        # Context'ten gelen zenginleştirilmiş observable listesini al
        observables_data = params.get('extracted_observables', [])
        if observables_data:
            for obs_data in observables_data:
                new_observable = Observable(
                    type=obs_data['type'],
                    value=obs_data['value'],
                    vt_score=obs_data['vt_score'],
                    vt_link=obs_data['vt_link'],
                    incident=new_incident # Otomatik olarak incident'a bağla
                )
                db.session.add(new_observable)
                
        db.session.add(new_incident)
        db.session.commit()
        print(f"  -> ✅ Incident Action: Successfully created incident with ID: {new_incident.id} in the database.")
        return {"incident_id": new_incident.id}
    except Exception as e:
        db.session.rollback()
        print(f"  -> 🛑 ERROR: Failed to create incident in database. Error: {e}")
        return None

def add_firewall_rule(params):
    ip_address = params.get('ip_address')
    print(f"  -> 🛡️  [SIMULATED] Firewall Action: Block rule for IP {ip_address} would be added.")

def send_notification(params, incident_obj=None):
    channel = params.get('channel', 'soc_alerts')
    message = params.get('message', 'No message content.')
    print(f"  -> 📧 [SIMULATED NOTIFICATION] Channel: {channel}, Recipient: {EMAIL_RECIPIENT}, Message: \"{message}\"")

def isolate_host(params):
    hostname = params.get('hostname')
    print(f"  -> 🚨 [SIMULATED] Critical Action: Isolating host '{hostname}' from the network.")

# --- YARDIMCI VT FONKSİYONLARI ---

def _get_virustotal_ip_report(ip_address):
    """Verilen IP adresi için VirusTotal'dan rapor çeker."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        malicious_count = stats.get('malicious', 0)
        report_link = f"https://www.virustotal.com/gui/ip-address/{ip_address}/detection"
        return {"count": malicious_count, "link": report_link}
    except requests.exceptions.RequestException as e:
        print(f"  -> 🛑 ERROR getting VT report for IP {ip_address}: {e}")
        return None

def _get_virustotal_domain_report(domain):
    """Verilen domain için VirusTotal'dan rapor çeker."""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        malicious_count = stats.get('malicious', 0)
        report_link = f"https://www.virustotal.com/gui/domain/{domain}/detection"
        return {"count": malicious_count, "link": report_link}
    except requests.exceptions.RequestException as e:
        print(f"  -> 🛑 ERROR getting VT report for domain {domain}: {e}")
        return None

def _get_virustotal_hash_report(file_hash):
    """Verilen dosya hash'i için VirusTotal'dan rapor çeker."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        malicious_count = stats.get('malicious', 0)
        report_link = f"https://www.virustotal.com/gui/file/{file_hash}/detection"
        return {"count": malicious_count, "link": report_link}
    except requests.exceptions.RequestException as e:
        print(f"  -> 🛑 ERROR getting VT report for hash {file_hash}: {e}")
        return None
       
# ---  ZENGİNLEŞTİRME AKSİYONU ---

def extract_and_enrich_observables(params):
    text_to_scan = params.get('text_block', '')
    if not text_to_scan: return None

    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    domain_pattern = r'\b(?:[a-zA-Z0-9-]{2,}\.)+[a-zA-Z]{2,}\b'
    hash_pattern = r'\b[A-Fa-f0-9]{64}\b' # Sadece SHA256 için

    found_ips = re.findall(ip_pattern, text_to_scan)
    found_domains = re.findall(domain_pattern, text_to_scan)
    found_hashes = re.findall(hash_pattern, text_to_scan)

    all_observables = {
        "ip": list(set(found_ips)),
        "domain": list(set(found_domains)),
        "hash": list(set(found_hashes))
    }
    print(f"  -> 🔎 Found observables: {all_observables}")

    enrichment_results = []

    if not VT_API_KEY or VT_API_KEY.startswith("BURAYA"):
        print("  -> ⚠️  VirusTotal API Key not configured. Skipping all enrichments.")
        return None

    # IP'leri zenginleştir
    for ip in all_observables['ip']:
        report = _get_virustotal_ip_report(ip)
        if report:
            print(f"  -> 📈 VT Enrichment (IP): {ip} -> {report.get('count', 0)} vendors.")
            enrichment_results.append({"type": "ip", "value": ip, "vt_score": report.get('count', 0), "vt_link": report.get('link')})
    
    # Domain'leri zenginleştir
    for domain in all_observables['domain']:
        report = _get_virustotal_domain_report(domain)
        if report:
            print(f"  -> 📈 VT Enrichment (Domain): {domain} -> {report.get('count', 0)} vendors.")
            enrichment_results.append({"type": "domain", "value": domain, "vt_score": report.get('count', 0), "vt_link": report.get('link')})
            
    # Hash'leri zenginleştir
    for file_hash in all_observables['hash']:
        report = _get_virustotal_hash_report(file_hash)
        if report:
            print(f"  -> 📈 VT Enrichment (Hash): {file_hash} -> {report.get('count', 0)} vendors.")
            enrichment_results.append({"type": "hash", "value": file_hash, "vt_score": report.get('count', 0), "vt_link": report.get('link')})
            
    return {"extracted_observables": enrichment_results}

# ---  USER MANAGEMENT AKSİYONU ---
def lock_user_account(params):
    """Bir kullanıcı hesabını kimlik yönetim sisteminde kilitler (simülasyon)."""
    username = params.get('username', 'N/A')
    print(f"  -> 🔐 Identity Action: Locking account for user '{username}' in Active Directory.")
    # Gerçek hayatta burada bir AD veya IAM API'sine komut gönderilirdi.
    return {"account_lock_status": "success"}

def query_edr_for_processes(params):
    """Bir sunucudaki çalışan proses listesini EDR'dan ister (simülasyon)."""
    hostname = params.get('hostname', 'N/A')
    print(f"  -> 💻 EDR Action: Querying process list from host '{hostname}'.")
    # Gerçek hayatta burada bir EDR (CrowdStrike, SentinelOne) API'sine komut gönderilirdi.
    return {"edr_query_status": "pending"}

def submit_hash_to_sandbox(params):
    """Bir dosya hash'ini analiz için sandbox'a gönderir (simülasyon)."""
    file_hash = params.get('hash', 'N/A')
    print(f"  -> 🔬 Sandbox Action: Submitting hash '{file_hash[:10]}...' to Sandbox for deep analysis.")
    # Gerçek hayatta burada bir Sandbox (Cuckoo, JoeSandbox) API'sine komut gönderilirdi.
    return {"sandbox_submission_id": "sb-12345"}


# ---  USER MANAGEMENT AKSİYONU ---