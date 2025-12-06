# actions.py

import subprocess
import os
import whois
import dns.resolver
import json
import re
import shodan
from datetime import datetime
from database import db, Incident, Observable, Enrichment
import requests
from config import (
    VT_API_KEY, EMAIL_RECIPIENT, ABUSEIPDB_API_KEY, 
    SHODAN_API_KEY, URLSCAN_API_KEY, HYBRID_ANALYSIS_API_KEY
)

# --- AKSİYON FONKSİYONLARI ---

def create_incident(params):
    """
    1. Olayı ve Observable'ları oluşturur (KRİTİK AŞAMA).
    2. Veritabanına kaydeder.
    3. Kaydedilmiş Observable'lar üzerinden zenginleştirme fonksiyonlarını
       "hata toleranslı" (best-effort) bir şekilde tetikler.
    """
    
    new_incident = None
    
    # --- AŞAMA 1: OLAY VE OBSERVABLE YARATMA (KRİTİK BLOK) ---
    try:
        mitre_mapping = params.get('mitre_mapping') or {}
        
        new_incident = Incident(
            event_type=params.get('event_type', 'unknown'),
            severity=params.get('severity', 'low'),
            details=params.get('details', 'No details provided.'),
            mitre_technique_id=mitre_mapping.get('technique_id'),
            mitre_technique_name=mitre_mapping.get('technique_name'),
            # Playbook'tan gelen 'suggested_firewall_rule' verisini kaydet
            suggested_firewall_rule=params.get('suggested_firewall_rule')
        )
        
        observables_to_create = []
        observables_data = params.get('extracted_observables', [])
        if observables_data:
            for obs_data in observables_data:
                new_observable = Observable(
                    type=obs_data['type'],
                    value=obs_data['value']
                )
                observables_to_create.append(new_observable)
        
        new_incident.observables = observables_to_create
        
        db.session.add(new_incident)
        db.session.commit()
        
        print(f"   -> ✅ Incident Action: Successfully created incident with ID: {new_incident.id}.")

    except Exception as e:
        db.session.rollback()
        print(f"   -> 🛑 ERROR: Failed to create incident in database (Critical Path). Error: {e}")
        return None # Olay yaratılamadıysa fonksiyondan çık
    
    
    # --- AŞAMA 2: ZENGİNLEŞTİRMELER (HATA TOLERANSLI BLOK) ---
    # Bu blok, Aşama 1'deki try...except'in DIŞINDADIR.
    # Olayımız artık güvende.
    
    print(f"   -> 🚀 Starting enrichment for {len(new_incident.observables)} observables...")
    for obs in new_incident.observables:
        # Her zenginleştirme kendi try...except bloğu içinde
        try:
            enrich_observable_with_virustotal(obs)
        except Exception as e:
            print(f"   -> 🛑 ERROR during VirusTotal enrichment for {obs.value}: {e}")

        try:
            enrich_observable_with_whois(obs)
        except Exception as e:
            print(f"   -> 🛑 ERROR during WHOIS enrichment for {obs.value}: {e}")
            
        # Tipe özel olanlar
        if obs.type == 'ip':
            try:
                enrich_observable_with_abuseipdb(obs)
            except Exception as e:
                print(f"   -> 🛑 ERROR during AbuseIPDB enrichment for {obs.value}: {e}")
            
            try:
                enrich_observable_with_shodan(obs)
            except Exception as e:
                print(f"   -> 🛑 ERROR during Shodan enrichment for {obs.value}: {e}")
                
        elif obs.type == 'domain':
            try:
                enrich_observable_with_dns(obs)
            except Exception as e:
                print(f"   -> 🛑 ERROR during DNS enrichment for {obs.value}: {e}")
            try:
                submit_to_hybrid_analysis(obs) 
            except Exception as e:
                print(f"   -> 🛑 ERROR during Hybrid Analysis submission for {obs.value}: {e}")

        elif obs.type == 'hash':
            try:
                submit_to_hybrid_analysis(obs) 
            except Exception as e:
                print(f"   -> 🛑 ERROR during Hybrid Analysis submission for {obs.value}: {e}")
            
        
    # Zenginleştirme sonuçlarını (başarılı olanları) veritabanına işle
    try:
        db.session.commit()
        print(f"   -> ✨ Enrichment complete (best-effort).")
    except Exception as e:
        db.session.rollback()
        print(f"   -> 🛑 ERROR committing enrichment results: {e}")
    
    return {"incident_id": new_incident.id}

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
       
# ---  PARÇALAMA AKSİYONU ---
# actions.py içindeki extract_observables fonksiyonu

def extract_observables(params):
    text_to_scan = params.get('text_block', '')
    if not text_to_scan: return {"extracted_observables": []}

    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    domain_pattern = r'\b(?:[a-zA-Z0-9-]{2,}\.)+[a-zA-Z]{2,}\b'
    hash_pattern = r'\b[A-Fa-f0-9]{64}\b' 

    found_ips = re.findall(ip_pattern, text_to_scan)
    found_domains = re.findall(domain_pattern, text_to_scan)
    found_hashes = re.findall(hash_pattern, text_to_scan)

    # Özel IP'leri (localhost, broadcast vb.) filtreleyelim
    private_ips = r'^(127\.)|(192\.168\.)|(10\.)|(172\.(1[6-9]|2[0-9]|3[0-1])\.)'
    filtered_ips = [ip for ip in found_ips if not re.match(private_ips, ip)]
    observables_list = []
    
    # Tekrarları önlemek için set kullanalım
    for ip in set(found_ips):
        observables_list.append({"type": "ip", "value": ip})
    for domain in set(found_domains):
        observables_list.append({"type": "domain", "value": domain})
    for h in set(found_hashes):
        observables_list.append({"type": "hash", "value": h})

    print(f"   -> 🔎 Extracted observables: {observables_list}")
    
    # KRİTİK NOKTA: Veriyi sözlük olarak döndür ki engine context'e yazabilsin
    return {"extracted_observables": observables_list}


# ---  ZENGİNLEŞTİRME AKSİYONU ---
def enrich_observable_with_virustotal(observable):
    """
    Bir Observable nesnesini VirusTotal ile zenginleştirir ve
    sonucu Enrichment tablosuna kaydeder.
    """
    report = None
    if observable.type == 'ip':
        report = _get_virustotal_ip_report(observable.value)
    elif observable.type == 'domain':
        report = _get_virustotal_domain_report(observable.value)
    elif observable.type == 'hash':
        report = _get_virustotal_hash_report(observable.value)

    if report:
        new_enrichment = Enrichment(
            observable_id=observable.id,
            source="VirusTotal",
            status="Success",
            raw_data=json.dumps(report), # Raporun tamamını JSON olarak kaydet
            summary=f"Malicious Count: {report.get('count', 0)}"
        )
        db.session.add(new_enrichment)
        
        # vt_score'u da Observable'a hızlı erişim için hala ekleyebiliriz
        observable.vt_score = report.get('count', 0)
        observable.vt_link = report.get('link')

def enrich_observable_with_abuseipdb(observable):
    """
    Bir IP Observable'ını AbuseIPDB ile zenginleştirir ve
    sonucu Enrichment tablosuna kaydeder.
    """
    if observable.type != 'ip':
        return # Bu zenginleştirme sadece IP'ler için

    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY.startswith("BURAYA"):
        print("   -> ⚠️  AbuseIPDB API Key not configured. Skipping.")
        return

    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': observable.value, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json().get('data', {})
        
        new_enrichment = Enrichment(
            observable_id=observable.id,
            source="AbuseIPDB",
            status="Success",
            raw_data=json.dumps(data),
            summary=f"Abuse Score: {data.get('abuseConfidenceScore', 0)}%"
        )
        db.session.add(new_enrichment)
    except requests.exceptions.RequestException as e:
        print(f"   -> 🛑 ERROR getting AbuseIPDB report: {e}")
            
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


# ---  SHODAN ZENGİNLEŞİRME AKSİYONU ---
def enrich_observable_with_shodan(observable):
    """
    Bir IP Observable'ını Shodan ile zenginleştirir ve
    sonucu Enrichment tablosuna kaydeder.
    """
    if observable.type != 'ip':
        return # Bu zenginleştirme sadece IP'ler için

    if not SHODAN_API_KEY or SHODAN_API_KEY.startswith("BURAYA"):
        print("   -> ⚠️  Shodan API Key not configured. Skipping.")
        return

    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        # API'yi sorgula
        result = api.host(observable.value)
        
        # Arayüzde göstermek için özeti hazırla
        open_ports = result.get('ports', [])
        summary_text = f"Open Ports: {', '.join(map(str, open_ports))}"
        if not open_ports:
            summary_text = "No open ports found."

        new_enrichment = Enrichment(
            observable_id=observable.id,
            source="Shodan",
            status="Success",
            raw_data=json.dumps(result, indent=2), # Raporun tamamını formatlı kaydet
            summary=summary_text
        )
        db.session.add(new_enrichment)
        
    except shodan.APIError as e:
        # Shodan'ın kendi API hatalarını yakala (örn: IP bulunamadı)
        print(f"   -> 🛑 ERROR getting Shodan report: {e}")
        new_enrichment = Enrichment(
            observable_id=observable.id,
            source="Shodan",
            status="Failed",
            raw_data=json.dumps({"error": str(e)}, indent=2),
            summary="Error: IP not found or API error"
        )
        db.session.add(new_enrichment)
    except Exception as e:
        # Diğer genel hatalar
        print(f"   -> 🛑 CRITICAL ERROR in Shodan enrichment: {e}")
        
# ---  WHOIS ZENGİNLEŞİRME AKSİYONU ---
def enrich_observable_with_whois(observable):
    """
    Bir IP veya Domain Observable'ını WHOIS bilgisi ile zenginleştirir.
    """
    if observable.type not in ['ip', 'domain']:
        return # Bu zenginleştirme sadece IP ve domainler için

    try:
        w = whois.whois(observable.value)
        
        # WHOIS sonucu bazen karmaşık nesneler dönebilir,
        # bunları JSON'a dökülebilir basit bir dict'e çevirelim.
        result = {}
        if w.registrar:
            result['registrar'] = w.registrar
            result['creation_date'] = str(w.creation_date)
            result['expiration_date'] = str(w.expiration_date)
            result['last_updated'] = str(w.last_updated)
            result['name_servers'] = list(w.name_servers)
            result['emails'] = list(w.emails)
        else:
            # IP adresleri için genellikle daha az bilgi döner
            result['name'] = w.name
            result['country'] = w.country
            result['address'] = w.address

        summary_text = f"Registrar: {result.get('registrar', 'N/A')}"
        if observable.type == 'ip':
            summary_text = f"Name: {result.get('name', 'N/A')}, Country: {result.get('country', 'N/A')}"

        new_enrichment = Enrichment(
            observable_id=observable.id,
            source="WHOIS",
            status="Success",
            raw_data=json.dumps(result, indent=2),
            summary=summary_text
        )
        db.session.add(new_enrichment)

    except Exception as e:
        print(f"   -> 🛑 ERROR getting WHOIS report: {e}")
        new_enrichment = Enrichment(
            observable_id=observable.id,
            source="WHOIS",
            status="Failed",
            raw_data=json.dumps({"error": str(e)}, indent=2),
            summary="Error: Failed to get WHOIS data"
        )
        db.session.add(new_enrichment)
        
# ---  DNS ZENGİNLEŞİRME AKSİYONU ---        
def enrich_observable_with_dns(observable):
    """
    Bir Domain Observable'ını DNS kayıtları (A, MX, TXT) ile zenginleştirir.
    """
    if observable.type != 'domain':
        return # Bu zenginleştirme sadece domainler için

    try:
        result = {}
        resolver = dns.resolver.Resolver()
        
        # A Kayıtları (IP Adresleri)
        try:
            a_records = resolver.resolve(observable.value, 'A')
            result['A'] = [ip.to_text() for ip in a_records]
        except Exception as e:
            result['A'] = f"Error: {e}"

        # MX Kayıtları (Mail Sunucuları)
        try:
            mx_records = resolver.resolve(observable.value, 'MX')
            result['MX'] = [f"{mx.preference} {mx.exchange.to_text()}" for mx in mx_records]
        except Exception as e:
            result['MX'] = f"Error: {e}"
            
        # TXT Kayıtları (SPF, DKIM vb.)
        try:
            txt_records = resolver.resolve(observable.value, 'TXT')
            result['TXT'] = [txt.to_text().strip('"') for txt in txt_records]
        except Exception as e:
            result['TXT'] = f"Error: {e}"

        summary_text = f"A: {len(result.get('A',[]))}, MX: {len(result.get('MX',[]))}, TXT: {len(result.get('TXT',[]))}"

        new_enrichment = Enrichment(
            observable_id=observable.id,
            source="DNS Query",
            status="Success",
            raw_data=json.dumps(result, indent=2),
            summary=summary_text
        )
        db.session.add(new_enrichment)

    except Exception as e:
        print(f"   -> 🛑 CRITICAL ERROR in DNS enrichment: {e}")
        
# ---  Hybrid Analysis ZENGİNLEŞİRME AKSİYONU ---  
def submit_to_hybrid_analysis(observable):
    """
    Bir Hash veya URL Observable'ını Hybrid Analysis Sandbox'a
    analiz için gönderir (requests kullanarak).
    """
    print(f"   -> [DEBUG] submit_to_hybrid_analysis called for {observable.type}: {observable.value}")
    
    if observable.type not in ['hash', 'domain', 'url']: # URL'i de ekleyelim
        print(f"   -> [DEBUG] Observable type '{observable.type}' is not supported. Skipping.")
        return

    if not HYBRID_ANALYSIS_API_KEY or HYBRID_ANALYSIS_API_KEY.startswith("BURAYA"):
        print("   -> ⚠️  Hybrid Analysis API Key not configured. Skipping.")
        return

    # API Endpoint'leri
    base_url = "https://www.hybrid-analysis.com/api/v2"
    headers = {
        'accept': 'application/json',
        'User-Agent': 'Falcon Sandbox', # API dokümantasyonu bunu öneriyor
        'api-key': HYBRID_ANALYSIS_API_KEY
    }
    
    summary_text = ""
    raw_result = {}
    status_code = None

    try:
        if observable.type == 'hash':
            print(f"   -> 🔬 Searching hash {observable.value[:10]}... in Hybrid Analysis...")
            search_url = f"{base_url}/search/hash"
            params = {'hash': observable.value}
            response = requests.post(search_url, headers=headers, data=params)
            status_code = response.status_code
            response.raise_for_status() # Hata varsa exception fırlat
            results = response.json()
            if results:
                print("   -> ✨ Found existing report(s) in Hybrid Analysis.")
                raw_result = results[0] # İlk raporu al
                summary_text = f"Existing Report Found. Verdict: {raw_result.get('verdict', 'N/A')}"
            else:
                summary_text = "Hash not found in Hybrid Analysis DB."
                raw_result = {"message": summary_text}
        
        elif observable.type in ['domain', 'url']:
            print(f"   -> 🔬 Submitting URL/Domain {observable.value} to Hybrid Analysis...")
            submit_url = f"{base_url}/submit/url"
            params = {'url': observable.value, 'environment_id': 160} # 160 = Linux Ubuntu 20.04 (64 bit) - Dokümantasyondan
            response = requests.post(submit_url, headers=headers, data=params)
            status_code = response.status_code
            response.raise_for_status()
            raw_result = response.json()
            summary_text = f"Scan submitted. Job ID: {raw_result.get('job_id', 'N/A')}"

        new_enrichment = Enrichment(
            observable_id=observable.id,
            source="Hybrid Analysis",
            # API yanıt koduna ve içeriğe göre durumu belirle
            status="Success" if status_code == 200 and 'verdict' in raw_result else \
                   "Pending" if status_code == 200 and 'job_id' in raw_result else \
                   "Info" if status_code == 200 else \
                   "Failed",
            raw_data=json.dumps(raw_result, indent=2),
            summary=summary_text
        )
        db.session.add(new_enrichment)

    except requests.exceptions.RequestException as e:
        print(f"   -> 🛑 ERROR during Hybrid Analysis request: {e}")
        # Hata durumunda API yanıtını da kaydetmeye çalışalım
        error_data = {"error": str(e)}
        if 'response' in locals() and response is not None:
             try:
                 error_data["api_response"] = response.json()
             except:
                 error_data["api_response_text"] = response.text

        new_enrichment = Enrichment(
            observable_id=observable.id,
            source="Hybrid Analysis",
            status="Failed",
            raw_data=json.dumps(error_data, indent=2),
            summary="Error: API or submission error"
        )
        db.session.add(new_enrichment)
    except Exception as e:
        # Kod içindeki diğer olası hatalar
        print(f"   -> 🛑 CRITICAL ERROR in Hybrid Analysis submission: {e}")
        
        
def generate_firewall_rule(params):
    """
    Olayın türüne ve içeriğine göre otomatik bir firewall kuralı önerir.
    Dönen kural, Incident tablosundaki 'suggested_firewall_rule' alanına kaydedilir.
    """
    event_type = params.get('event_type')
    rule = None
    
    # Senaryo 1: Malicious IP (Kaynak IP'yi engelle)
    if event_type == 'malicious_ip_detected':
        # Olayın içindeki IP'yi bulmaya çalışalım (params'dan veya observable'lardan)
        ip = params.get('ip') or params.get('source_ip')
        if not ip:
            # Eğer direkt parametre olarak gelmediyse, extracted_observables içinden IP'yi bul
            observables = params.get('extracted_observables', [])
            for obs in observables:
                if obs.get('type') == 'ip':
                    ip = obs.get('value')
                    break
        
        if ip:
            # Linux iptables formatında kural üret
            rule = f"iptables -A INPUT -s {ip} -j DROP # Block Malicious IP"

    # Senaryo 2: Brute Force (SSH/RDP gibi servisleri koru)
    elif event_type == 'brute_force_detected':
        ip = params.get('source_ip')
        # Varsayılan olarak SSH (22) portunu koruyalım
        if ip:
            rule = f"iptables -A INPUT -p tcp --dport 22 -s {ip} -j DROP # Block SSH Brute Force"

    # Senaryo 3: Phishing (Zararlı IP'ye çıkışı engelle)
    elif event_type == 'phishing_email_detected':
        # Phishing'de genellikle içeriden dışarıya (C2 sunucusuna) bağlantı engellenir
        source_ip = params.get('source_ip')
        if source_ip:
             rule = f"iptables -A OUTPUT -d {source_ip} -j DROP # Block C2 Connection"

    # Senaryo 4: Ransomware (Cihazı izole et - Firewall seviyesinde tüm trafiği kes)
    elif event_type == 'ransomware_activity_detected':
        hostname = params.get('hostname')
        # Bu biraz daha sembolik, çünkü hostname ile iptables kuralı yazılmaz, IP lazım.
        # Ama simülasyon için mantığı göstermek yeterli.
        rule = f"# ISOLATION RULE\niptables -A INPUT -s {hostname} -j DROP\niptables -A OUTPUT -d {hostname} -j DROP"

    if rule:
        print(f"   -> 🛡️  Generated Firewall Rule: {rule}")
        return {"suggested_firewall_rule": rule}
    
    print("   -> ℹ️  No suitable firewall rule generated for this event type.")
    return None

        
        
    