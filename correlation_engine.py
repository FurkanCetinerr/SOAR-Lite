# correlation_engine.py

import time

class CorrelationEngine:
    def __init__(self, playbook_engine):
        self.playbook_engine = playbook_engine

    def process(self, new_event, event_cache):
        """
        Yeni bir olay geldiğinde korelasyon kurallarını çalıştırır.
        """
        # --- KURAL 1: Brute-Force Tespiti ---
        brute_force_detected = self.check_brute_force(new_event, event_cache)
        
        if brute_force_detected:
            # DÜZELTME: new_event'ten veri alırken ['data'] katmanını kaldırdık
            correlated_event = {
                "event_type": "brute_force_detected",
                "source": "correlation_engine",
                "username": new_event.get('username'),
                "source_ip": new_event.get('source_ip'),
                "failed_login_count": brute_force_detected['count'],
                "details": f"{brute_force_detected['count']} failed logins from IP {new_event.get('source_ip')} for user {new_event.get('username')} within 60 seconds."
            }
            print(f"🔥 CORRELATION MATCH: Brute-force attack detected!")
            self.playbook_engine.run(correlated_event)
        
        # DÜZELTME: new_event'ten veri alırken ['data'] katmanını kaldırdık
        elif new_event.get('event_type') != 'failed_login':
            self.playbook_engine.run(new_event)
        else:
            print(f"-> Suppressing low-severity event: {new_event.get('event_type')}")


    def check_brute_force(self, new_event, event_cache):
        """
        Önbellekteki olayları tarayarak brute-force saldırısı olup olmadığını kontrol eder.
        """
        # DÜZELTME: new_event'ten veri alırken ['data'] katmanını kaldırdık
        if new_event.get('event_type') != 'failed_login':
            return None
            
        target_ip = new_event.get('source_ip')
        target_user = new_event.get('username')
        
        count = 0
        # Önbelleği tararken ['data'] katmanını kullanmaya devam ediyoruz, çünkü orası doğru.
        for event in event_cache:
            if (event['data'].get('event_type') == 'failed_login' and
                event['data'].get('source_ip') == target_ip and
                event['data'].get('username') == target_user):
                count += 1
        
        if count >= 5:
            return {"count": count}
            
        return None