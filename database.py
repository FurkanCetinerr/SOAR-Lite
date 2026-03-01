# database.py

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin

# SQLAlchemy nesnesini oluştur
db = SQLAlchemy()

# Incident (Olay Kaydı) veritabanı modelini tanımla
class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    event_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default='New')
    # YENİ: Incident'ın notlarını kolayca çekmek için ilişki
    # backref='incident', bir notun hangi incident'a ait olduğunu note.incident ile verir.
    notes = db.relationship('Note', backref='incident', lazy=True, cascade="all, delete-orphan")
    
    closed_at = db.Column(db.DateTime, nullable=True) # Olay kapatıldığında doldurulacak
    
    # VirusTotal
    vt_malicious_count = db.Column(db.Integer, nullable=True)
    vt_report_link = db.Column(db.String(255), nullable=True)
    
    # MITRE
    mitre_technique_id = db.Column(db.String(20), nullable=True)
    mitre_technique_name = db.Column(db.String(100), nullable=True)
    
    # Firewall kural
    suggested_firewall_rule = db.Column(db.Text, nullable=True) # Otomatik üretilen kural burada saklanacak
        
        # --- İlişkiler (Relationships) ---
    # Atanan Kullanıcı (Assignee)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    assignee = db.relationship('User', backref='incidents') # backref eklendi

    # Bağlı Notlar
    notes = db.relationship('Note', backref='incident', lazy=True, cascade="all, delete-orphan")
    
    # Bağlı Gözlemlenebilirler (Observables)
    observables = db.relationship('Observable', backref='incident', lazy=True, cascade="all, delete-orphan")
    
    # Bağlı Aksiyon Kayıtları (Action Logs)
    action_logs = db.relationship('ActionLog', backref='incident', lazy=True, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Incident {self.id} - {self.event_type} ({self.status})>"
    
#  Note (Analist Notu) Modeli
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Her notun hangi Incident'a ait olduğunu belirten Foreign Key
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=False)
    #Her otun kime ait olduğu bilgisi
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='notes')
    
    def __repr__(self):
        return f"<Note {self.id} for Incident {self.incident_id}>"

# --- KULLANICI MODELİ ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    role = db.Column(db.String(50), nullable=False, default='Analyst')
    
    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Observable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False) # 'ip', 'domain', 'hash'
    value = db.Column(db.String(255), nullable=False)
    vt_score = db.Column(db.Integer, nullable=True)
    vt_link = db.Column(db.String(255), nullable=True)
    
    # Her observable'ın hangi Incident'a ait olduğunu belirten Foreign Key
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=False)
    #Enrichment ile bağlantı
    enrichments = db.relationship('Enrichment', backref='observable', lazy=True, cascade="all, delete-orphan")
# --- AKSİYON KAYIT MODELİ ---
class ActionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    action_type = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), nullable=False) # örn: Success, Skipped, Failure
    details = db.Column(db.Text, nullable=True)
    
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=False)

# --- BİLFİRİM MODELİ ---
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Bildirimi alan kullanıcıya referans
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='notifications')
    
    # Bildirim içeriği ve linki
    message = db.Column(db.String(255), nullable=False)
    link = db.Column(db.String(255), nullable=True) # Tıklanınca gidilecek URL
    
    # Bildirim durumu ve zamanı
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Notification for User {self.user_id}>'

# --- UserAcitivity Logs Modeli ---
class UserActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='activity_logs')
    
    action = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text, nullable=True)
    
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=True)
    # Bu ilişki, bir log'dan olaya kolayca erişmemizi sağlar.
    incident = db.relationship('Incident', backref='activity_logs')

    def __repr__(self):
        return f'<UserActivityLog {self.id} by User {self.user.username}>'
    
# --- Enrichment Modeli ---
class Enrichment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Bu zenginleştirme hangi Observable'a ait? (IP, domain, hash)
    observable_id = db.Column(db.Integer, db.ForeignKey('observable.id'), nullable=False)
    
    source = db.Column(db.String(100), nullable=False) # Örn: "VirusTotal", "AbuseIPDB", "Shodan"
    status = db.Column(db.String(50), default='Success') # Örn: "Success", "Pending", "Failed"
    
    # API'den dönen tüm JSON yanıtını burada saklayacağız
    raw_data = db.Column(db.Text, nullable=True)
    
    # Arayüzde hızlıca göstermek için özet bilgi
    summary = db.Column(db.String(255), nullable=True) # Örn: "Skor: 100/100", "Açık Portlar: 80, 443"

    def __repr__(self):
        return f'<Enrichment {self.id} for Obs {self.observable_id} from {self.source}>'
    
    