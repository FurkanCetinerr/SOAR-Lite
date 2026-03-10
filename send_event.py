# send_event.py

import requests
import json
import sys

# Sunucumuzun adresi
SOAR_API_URL = "https://soar-lite-app.onrender.com/api/v1/event"

# Senaryo 1: Malicious IP Tespiti Olayı
malicious_ip_event = {
    "event_type": "malicious_ip_detected",
    "source": "suricata",
    # Eski IP yerine, AbuseIPDB'de sıkça raporlanan bir IP (Örnek: Kötüye kullanılan bir VPN/Proxy IP'si)
    "ip": "123.249.100.226", 
    "confidence": 0.95,
    "details": "Suricata sig ET MALWARE Known Malvertising IP" 
}

# Senaryo 2: Phishing E-posta Tespiti Olayı
phishing_mail_event = {
    "event_type": "phishing_email_detected",
    "source": "mail_gateway",
    "mail_id": "phish-002",
    "recipient": "kurban.kullanici@sirket.com",
    "sender": "noreply@baddomain-example.com", # Daha jenerik bir sahte domain
    "subject": "Fatura Guncellemesi Gerekli",
    # Eski IP yerine, bilinen kötü amaçlı IP (Örn: PhishTank'ten alınmış)
    "source_ip": "39.107.242.130", 
    
    "email_body_text": (
        # Eski domain yerine, WHOIS/DNS sorgusunda sonuç verecek aktif ama test amaçlı domain
        "Lutfen faturanizi odemek icin https://google.com adresine tiklayin. " 
        # Hash, WannaCry iyi bir test örneği
        "Ekli dosya SHA256: 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c" 
    )
}

# Senaryo 3: Bilgilendirme Olayı (Low Severity)
informational_event = {
    "event_type": "informational_event_detected",
    "source": "network_monitor",
    # Özel IP yerine, Google'ın DNS sunucusu (WHOIS/Shodan sorgulanabilir)
    "device_ip": "8.8.8.8", 
    "mac_address": "AA:BB:CC:01:02:03", # MAC adresi jenerik kalabilir
    "details": "New device registered on network."
}

# Senaryo 4: Şüpheli Giriş (Medium Severity)
suspicious_login_event = {
    "event_type": "suspicious_login_detected",
    "source": "Azure_AD_Identity_Protection",
    "username": "test.user", # Daha jenerik
    # Eski IP yerine, farklı bir ülkeden bilinen bir IP (Örn: Tor exit node)
    "source_ip": "185.220.101.43", 
    "country": "Germany", # IP'ye uygun ülke
    "details": "Successful login from a Tor exit node."
}

# Senaryo 5: Olası Fidye Yazılımı (High Severity)
ransomware_activity_event = {
    "event_type": "ransomware_activity_detected",
    "source": "CrowdStrike_EDR",
    "hostname": "FINANCE-PC01", # Daha jenerik
    "file_count": 850,
    "details": "High volume of file modifications detected matching known ransomware patterns (.crypt extension)."
}

# Senaryo 6: Başarısız Login (Low Severity)
failed_login_event = {
    "event_type": "failed_login",
    "source": "Firewall_Logs",
    "username": "administrator",
    # Localhost yerine, dışarıdan gelen bir IP (Shodan/AbuseIPDB sorgulanabilir)
    "source_ip": "1.1.1.1", # Cloudflare DNS
    "details": "Multiple failed SSH login attempts for user 'administrator'."
}

# Olayları kolayca seçebilmek için bir sözlük (dictionary) oluşturalım
EVENT_MAP = {
    "malicious_ip": malicious_ip_event,
    "phishing": phishing_mail_event,
    "info": informational_event,
    "login": suspicious_login_event,
    "ransomware": ransomware_activity_event,
    "failed_login": failed_login_event
}

def send_event(event_payload):
    """Belirtilen olayı SOAR API'sine gönderir."""
    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(SOAR_API_URL, data=json.dumps(event_payload), headers=headers)
        
        print(f"Status Code: {response.status_code}")
        response.raise_for_status() # 500 veya 400 gibi hatalarda programı durdur
        print(f"Response JSON: {response.json()}")

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        print(f"Response Content: {response.text}")
    except requests.exceptions.ConnectionError as e:
        print(f"Error: Connection to the SOAR engine failed. Is the server running?")
    except requests.exceptions.JSONDecodeError as e:
        print(f"Error: Failed to decode JSON response from server. Server may have crashed.")
        print(f"Response Content: {response.text}")

# --- YENİ: AKILLI BAŞLATMA KISMI ---
if __name__ == "__main__":
    # Komut satırından bir argüman verilmiş mi diye kontrol et
    # sys.argv[0] her zaman dosya adıdır (send_event.py)
    # sys.argv[1] ise bizim verdiğimiz ilk argümandır (örn: "phishing")
    
    if len(sys.argv) < 2:
        # Argüman verilmemişse, kullanıcıya nasıl kullanacağını söyle
        print("Hata: Lütfen göndermek istediğiniz olayın adını belirtin.")
        print("Kullanım: python send_event.py <olay_adi>")
        print("\nKullanılabilir olay adları:")
        for key in EVENT_MAP.keys():
            print(f"  - {key}")
        sys.exit(1) # Hata koduyla çık

    # Verilen argümanı al (örn: "phishing")
    event_key = sys.argv[1]
    
    # Argümanın EVENT_MAP içinde olup olmadığını kontrol et
    if event_key not in EVENT_MAP:
        print(f"Hata: '{event_key}' adında bir olay bulunamadı.")
        print("\nKullanılabilir olay adları:")
        for key in EVENT_MAP.keys():
            print(f"  - {key}")
        sys.exit(1)

    # Argümana karşılık gelen olayı sözlükten al
    event_to_send = EVENT_MAP[event_key]
    
    print(f"--- Sending '{event_key}' Event ---")
    send_event(event_to_send)