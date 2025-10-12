# send_event.py

import requests
import json

# Sunucumuzun adresi
SOAR_API_URL = "http://127.0.0.1:5000/api/v1/event"

# Senaryo 1: Malicious IP Tespiti Olayı [cite: 37]
malicious_ip_event = {
    "event_type": "malicious_ip_detected", # [cite: 39]
    "source": "suricata", # [cite: 40]
    "ip": "92.118.39.95", # IP adresini değiştirebilirsin (Bilinen bir Cobalt Strike sunucusu)
    "confidence": 0.95, # [cite: 42]
    "first_seen": "2025-09-14T12:00:00Z", # [cite: 43]
    "details": "Suricata sig 201234 matched" # [cite: 44]
}

# Senaryo 2: Phishing E-posta Tespiti Olayı [cite: 54]
phishing_mail_event = {
    "event_type": "phishing_email_detected", # [cite: 56]
    "source": "mail_gateway", # [cite: 57]
    "mail_id": "phish-001", # [cite: 58]
    "recipient": "kurban.kullanici@sirket.com", # [cite: 59]
    "sender": "destek@bilgigncillemesi.com", # [cite: 60]
    "subject": "Acil: Hesabinizi dogrulayin", # [cite: 61]
    "source_ip": "45.146.164.110", # Test için bilinen zararlı bir IP
    
    "email_body_text": (
        "Sayin kullanici, lutfen bilgilerinizi guncellemek icin http://cijoint-my-account-part-fr.com adresine tiklayin. "
        "Guvenlik taramasi icin ekteki programi calistirin. "
        "Dosya SHA256: 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c" # WannaCry hash'i
    )
}

# Senaryo 3: Bilgilendirme Olayı (Low Severity) ---
informational_event = {
    "event_type": "informational_event_detected",
    "source": "network_monitor",
    "device_ip": "192.168.1.201",
    "mac_address": "B8:27:EB:01:02:03",
    "details": "New device connected to the Guest WiFi network."
}

# --- Senaryo 4: Şüpheli Giriş (Medium Severity) ---
suspicious_login_event = {
    "event_type": "suspicious_login_detected",
    "source": "Azure_AD_Identity_Protection",
    "username": "furkan.kaya",
    "source_ip": "203.0.113.55",
    "country": "Netherlands",
    "details": "Successful login from a new and infrequent location."
}

# --- Senaryo 5: Olası Fidye Yazılımı (High Severity) ---
ransomware_activity_event = {
    "event_type": "ransomware_activity_detected",
    "source": "CrowdStrike_EDR",
    "hostname": "WEBSRV01",
    "file_count": 742,
    "details": "Rapid file encryption detected in C:\\shares\\. Affected extension: .locked"
}

# --- Senaryo 6: Başarısız Login (Low Severity) ---
failed_login_event = {
    "event_type": "failed_login",
    "source": "Firewall_Logs",
    "username": "admin",
    "source_ip": "127.0.0.1", # Test için kendi IP'miz
    "details": "Failed password attempt for user 'admin'."
}

def send_event(event_payload):
    """Belirtilen olayı SOAR API'sine gönderir."""
    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(SOAR_API_URL, data=json.dumps(event_payload), headers=headers)
        
        # Sunucudan gelen yanıtı yazdır
        print(f"Status Code: {response.status_code}")
        print(f"Response JSON: {response.json()}")

    except requests.exceptions.ConnectionError as e:
        print(f"Error: Connection to the SOAR engine failed. Is the server running?")
        print(e)

if __name__ == "__main__":
    #import time
    # 1 dakika içinde 6 kez başarısız login olayı gönder
    #for i in range(6):
        #print(f"--- Sending Failed Login Event #{i+1} ---")
        #send_event(failed_login_event)
        #time.sleep(1) # Her olay arasında 1 saniye bekle
        
    # print("--- Sending Malicious IP Event ---")
    # send_event(malicious_ip_event)

    # Aşağıdaki bölümleri test etmek için üsttekini yorum satırı yapıp bunu aktif edebilirsin
    # print("\n--- Sending Phishing Mail Event ---")
    # send_event(phishing_mail_event)
    
     print("\n--- Sending Informational Event (Low) ---")
     send_event(informational_event)
    
    # print("\n--- Sending Suspicious Login Event (Medium) ---")
    # send_event(suspicious_login_event)

    # print("\n--- Sending Ransomware Activity Event (High) ---")
    # send_event(ransomware_activity_event)