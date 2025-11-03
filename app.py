# app.py
import time
import re

from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, abort
from engine import PlaybookEngine
from database import db, Incident, Note, User, Notification, UserActivityLog, Observable
from datetime import datetime, timedelta, timezone
from correlation_engine import CorrelationEngine
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from functools import wraps 
from sqlalchemy import func, cast, Interval, or_

# Geçici olayları ve zaman damgalarını saklamak için basit bir önbellek
EVENT_CACHE = []
CACHE_LIFETIME_SECONDS = 60 # Olayları 60 saniye (1 dakika) boyunca sakla

def create_app():
    
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///soar.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # WTF-Forms ve Flash mesajları için Secret Key GEREKLİDİR
    app.config['SECRET_KEY'] = 'bunu-mutlaka-guvenli-ve-rastgele-bir-degerle-degistir'

    db.init_app(app)

    # --- Flask-Login Yapılandırması ---
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    @login_manager.user_loader
    def load_user(user_id):
        # Eski User.query.get() yerine yeni standart olan db.session.get() kullanıyoruz
        return db.session.get(User, int(user_id))

    with app.app_context():
        db.create_all()
        print("🗄️ Database tables created or already exist.")

    return app

#Admin ve Managerlara özel sayfa kontrolü
def role_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

app = create_app()
engine = PlaybookEngine()
correlation_engine = CorrelationEngine(playbook_engine=engine)

# --- OTURUM YÖNETİMİ ROTALARI ---
#login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and user.check_password(request.form.get('password')):
            login_user(user, remember=True)
            log_activity(user=user, action="User Login")
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists.', 'warning')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    log_activity(user=current_user, action="User Logout")
    logout_user()
    return redirect(url_for('login'))

# --- YENİ: ANALİSTE ÖZEL OLAY LİSTESİ ROTASI ---
@app.route('/my_incidents')
@login_required
def my_incidents():
    # Sadece o an giriş yapmış kullanıcıya (current_user) atanmış olayları,
    # en yeniden eskiye doğru sıralayarak çek.
    incidents = Incident.query.filter_by(assignee_id=current_user.id).order_by(Incident.created_at.desc()).all()
    
    # Bu veriyi yeni bir HTML şablonuna gönder
    return render_template('my_incidents.html', incidents=incidents)


# --- KORUMA ALTINA ALINMIŞ ANA ROTALAR ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

def format_timedelta(seconds):
    """Toplam saniyeyi 'X gün Y saat Z dk' formatına çevirir."""
    if seconds == 0: return "N/A"
    delta = timedelta(seconds=seconds)
    days = delta.days
    hours, remainder = divmod(delta.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    parts = []
    if days > 0: parts.append(f"{days} day")
    if hours > 0: parts.append(f"{hours} hour")
    if minutes > 0: parts.append(f"{minutes} min")
    return " ".join(parts) if parts else "< 1 min"

@app.route('/dashboard')
@login_required
def dashboard():
    # 1. ZAMAN FİLTRESİNİ AL VE HESAPLA (Aynı)
    current_range = request.args.get('range', '30d') 
    now_utc = datetime.now(timezone.utc)
    start_time = None
    
    if current_range == '24h':
        start_time = now_utc - timedelta(hours=24)
    elif current_range == '7d':
        start_time = now_utc - timedelta(days=7)
    elif current_range == 'all':
        start_time = None 
    else:
        current_range = '30d' 
        start_time = now_utc - timedelta(days=30)
    
    # 2. FİLTRELENMİŞ TEMEL SORGU (BASE QUERY) (Aynı)
    base_query = Incident.query
    if start_time:
        base_query = base_query.filter(Incident.created_at >= start_time)

    # --- KPI Kartları (Filtreli) (Aynı) ---
    total_incidents = base_query.count()
    new_incidents = base_query.filter_by(status='New').count()
    
    # --- DÜZELTİLMİŞ SORGULAR (select_from yerine with_entities kullanarak) ---
    
    # Severities (SAWarning Düzeltildi)
    severities_data = base_query.with_entities(
        Incident.severity, func.count(Incident.severity)
    ).filter(Incident.severity.isnot(None)).group_by(Incident.severity).all()
    severities = {s: c for s, c in severities_data}

    # --- Çizgi Grafik (Son 7 Gün - Değişiklik yok) ---
    today = datetime.utcnow().date()
    # ... (Geri kalanı aynı, burayı kısaltıyorum) ...
    daily_counts = db.session.query(
        func.date(Incident.created_at), func.count(Incident.id)
    ).filter(Incident.created_at >= (today - timedelta(days=6))).group_by(
        func.date(Incident.created_at)
    ).all()
    chart_data = {}
    for i in range(7):
        day = today - timedelta(days=i)
        chart_data[day.strftime('%Y-%m-%d')] = 0
    for day_str, count in daily_counts:
        if str(day_str) in chart_data:
             chart_data[str(day_str)] = count
    sorted_chart_data = sorted(chart_data.items())
    line_chart_labels = [item[0] for item in sorted_chart_data]
    line_chart_values = [item[1] for item in sorted_chart_data]

    # --- Diğer Grafikler (SAWarning Düzeltildi) ---
    event_type_data = base_query.with_entities(
        Incident.event_type, func.count(Incident.event_type)
    ).group_by(Incident.event_type).all()
    pie_event_type_labels = [item[0] for item in event_type_data]
    pie_event_type_values = [item[1] for item in event_type_data]

    status_data = base_query.with_entities(
        Incident.status, func.count(Incident.status)
    ).group_by(Incident.status).all()
    pie_status_labels = [item[0] for item in status_data]
    pie_status_values = [item[1] for item in status_data]
    
    top_alerts_data = base_query.with_entities(
        Incident.details, func.count(Incident.details)
    ).group_by(Incident.details).order_by(
        func.count(Incident.details).desc()
    ).limit(5).all()
    bar_top_alerts_labels = [item[0] for item in top_alerts_data]
    bar_top_alerts_values = [item[1] for item in top_alerts_data]
    
    mitre_data = base_query.with_entities(
        Incident.mitre_technique_name, func.count(Incident.mitre_technique_name)
    ).filter(Incident.mitre_technique_name.isnot(None)).group_by(
        Incident.mitre_technique_name
    ).order_by(func.count(Incident.mitre_technique_name).desc()).all()
    pie_mitre_labels = [item[0] for item in mitre_data]
    pie_mitre_values = [item[1] for item in mitre_data]

    # --- Analist Performans (InvalidRequestError DÜZELTİLDİ) ---
    
    # 1. Önce açık olaylar için temel sorguyu oluştur (filtreli)
    open_incidents_query = Incident.query.filter(Incident.status != 'Closed')
    if start_time:
        open_incidents_query = open_incidents_query.filter(Incident.created_at >= start_time)
        
    # 2. BU SORGUDAN BAŞLAYARAK JOIN VE GROUP BY YAP
    open_incidents_by_assignee = open_incidents_query.join(
            User, Incident.assignee_id == User.id # .join(Incident.assignee) yerine açıkça yazalım
        ).with_entities(
            User.username, 
            func.count(Incident.id)
        ).group_by(User.username).all()
    
    assignee_labels = [item[0] for item in open_incidents_by_assignee]
    assignee_values = [item[1] for item in open_incidents_by_assignee]

    # MTTR (Zaman Filtreli - Değişiklik yok)
    closed_incidents = base_query.filter(Incident.status == 'Closed', Incident.closed_at.isnot(None)).all()
    total_resolution_time = timedelta(0)
    resolved_count = 0
    if closed_incidents:
        for incident in closed_incidents:
            created = incident.created_at.replace(tzinfo=timezone.utc)
            closed = incident.closed_at.replace(tzinfo=timezone.utc)
            total_resolution_time += (closed - created)
            resolved_count += 1
    average_resolution_time_seconds = 0
    if resolved_count > 0:
        average_resolution_time_seconds = total_resolution_time.total_seconds() / resolved_count
    mttr_formatted = format_timedelta(average_resolution_time_seconds)

    # Son Kapatılanlar (Filtresiz - Değişiklik yok)
    recently_closed = Incident.query.filter(
            Incident.status == 'Closed', 
            Incident.closed_at.isnot(None)
        ).order_by(Incident.closed_at.desc()).limit(5).all()
    
    # --- YENİ SORGULAR: FAZ 2 - TEHDİT MANZARASI ---

    # 1. En Çok Görülen MITRE Teknikleri (Bar Grafik)
    # base_query'miz zaten zaman filtresini içeriyor.
    mitre_data = base_query.with_entities(
        Incident.mitre_technique_name, func.count(Incident.mitre_technique_name)
    ).filter(Incident.mitre_technique_name.isnot(None)).group_by(
        Incident.mitre_technique_name
    ).order_by(func.count(Incident.mitre_technique_name).desc()).limit(5).all()

    # Not: Bu sorgu, bir önceki adımdaki pie_mitre_labels ile aynı olabilir,
    # ama bariz olması için yeni değişken adları kullanalım:
    mitre_bar_labels = [item[0] for item in mitre_data]
    mitre_bar_values = [item[1] for item in mitre_data]

    # 2. En Çok Görülen Zararlı IP/Domain'ler (vt_score > 5 olanlar)
    # Bu yeni bir sorgu, Incident ve Observable tablolarını join etmeliyiz.
    top_obs_query = db.session.query(
            Observable.value, 
            func.count(Observable.value)
        ).join(Incident, Observable.incident_id == Incident.id).filter(
         Observable.type.in_(['ip', 'domain']),
            Observable.vt_score > 5  # Sadece skoru 5'ten yüksek olanları "zararlı" sayalım
        )

    # Zaman filtresini bu sorguya da uygula
    if start_time:
        top_obs_query = top_obs_query.filter(Incident.created_at >= start_time)

    top_obs_data = top_obs_query.group_by(Observable.value).order_by(
        func.count(Observable.value).desc()
    ).limit(5).all()

    top_obs_labels = [item[0] for item in top_obs_data]
    top_obs_values = [item[1] for item in top_obs_data]

# ------------------------------------------------
    
    
    # --- RENDER TEMPLATE (Değişiklik yok) ---
    return render_template('dashboard.html',
                           current_range=current_range,
                           total_incidents=total_incidents,
                           new_incidents=new_incidents,
                           severities=severities,
                           line_chart_labels=line_chart_labels,
                           line_chart_values=line_chart_values,
                           pie_event_type_labels=pie_event_type_labels,
                           pie_event_type_values=pie_event_type_values,
                           pie_status_labels=pie_status_labels,
                           pie_status_values=pie_status_values,
                           bar_top_alerts_labels=bar_top_alerts_labels,
                           bar_top_alerts_values=bar_top_alerts_values,
                           pie_mitre_labels=pie_mitre_labels,
                           pie_mitre_values=pie_mitre_values,
                           assignee_labels=assignee_labels,
                           assignee_values=assignee_values,
                           mttr_formatted=mttr_formatted,
                           recently_closed=recently_closed,
                           # --- YENİ EKLENEN TEHDİT MANZARASI VERİLERİ ---
                           mitre_bar_labels=mitre_bar_labels,
                           mitre_bar_values=mitre_bar_values,
                           top_obs_labels=top_obs_labels,
                           top_obs_values=top_obs_values
                           )

@app.route('/incidents')
@login_required
def incidents_list():
    severity_filter = request.args.get('severity', None)
    status_filter = request.args.get('status', None)
    query = Incident.query
    if severity_filter and severity_filter != 'all':
        query = query.filter_by(severity=severity_filter)
    if status_filter and status_filter != 'all':
        query = query.filter_by(status=status_filter)
    incidents = query.order_by(Incident.created_at.desc()).all()
    return render_template('incidents.html',
                           incidents=incidents,
                           current_severity=severity_filter,
                           current_status=status_filter)

# Assign + kullanıcı ilişkilendirme
@app.route('/incident/<int:incident_id>')
@login_required
def incident_detail(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    all_users = User.query.all() 
    return render_template('incident_detail.html', 
                           incident=incident, 
                           all_users=all_users) # all_users'ı şablona gönder

# Escalated için route
@app.route('/incident/<int:incident_id>/escalate', methods=['POST'])
@login_required
def escalate_incident(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    
    # Sadece olaya atalı kişi veya bir yönetici/admin eskale edebilsin (opsiyonel kural)
    if incident.assignee == current_user or current_user.role in ['Manager', 'Admin']:
        # Olayın durumunu 'Escalated' yap
        incident.status = 'Escalated'
        # Atamayı temizle ki yönetici/kıdemli analist havuzuna düşsün
        incident.assignee = None
        #log
        log_activity(
            user=current_user, 
            action="Incident Escalated", 
            details=f"Incident #{incident.id} was escalated.",
            incident=incident
        )
        
        db.session.commit()
        flash(f'Incident #{incident.id} başarıyla eskale edildi ve atama havuzuna gönderildi.', 'warning')
    else:
        flash('Bu olayı eskale etme yetkiniz yok.', 'danger')
        
    return redirect(url_for('incident_detail', incident_id=incident.id))

@app.route('/incident/<int:incident_id>/update_status', methods=['POST'])
@login_required
def update_status(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    old_status = incident.status
    new_status = request.form.get('status')
    
    if new_status and new_status != old_status: # Sadece durum değişmişse işlem yap
        incident.status = new_status
        
        # --- YENİ MANTIK ---
        # Eğer yeni durum 'Closed' ise, closed_at zamanını ayarla
        if new_status == 'Closed':
            incident.closed_at = datetime.utcnow() # VEYA datetime.now(datetime.UTC) Python 3.12+
        # Eğer olay 'Closed' durumundan çıkarılıyorsa, closed_at zamanını temizle
        elif old_status == 'Closed' and new_status != 'Closed':
            incident.closed_at = None
        # --------------------

        # Aktiviteyi logla
        log_activity(user=current_user, 
                     action="Status Change", 
                     details=f"Changed status from '{old_status}' to '{new_status}'.",
                     incident=incident)
            
        db.session.commit()
        flash(f"Incident #{incident.id} status updated to '{new_status}'.", 'success')
        
    # Yönlendirmeyi, isteğin geldiği yere göre yapalım (liste veya detay sayfası)
    # Bu kısmı eklemek kullanıcı deneyimini iyileştirir
    # referrer = request.referrer
    # if referrer and 'incident/' in referrer:
    #     return redirect(url_for('incident_detail', incident_id=incident.id))
    # else:
    #     return redirect(url_for('incidents_list'))
    
    # Şimdilik basit tutalım:
    return redirect(request.referrer or url_for('incidents_list')) # Geldiği sayfaya geri dön

#Not fonksiyonu route 
@app.route('/incident/<int:incident_id>/add_note', methods=['POST'])
@login_required
def add_note(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    note_content = request.form.get('note_content')
    if note_content:
        new_note = Note(
            content=note_content,
            incident_id=incident.id,
            user_id=current_user.id
        )
        db.session.add(new_note)
        db.session.commit()
        flash('Not başarıyla eklendi.', 'success')

        # --- @MENTION VE BİLDİRİM OLUŞTURMA MANTIĞI ---
        # Not içeriğinde @kullaniciadi formatında ifadeler ara
        mentioned_usernames = re.findall(r'@(\w+)', note_content)
        if mentioned_usernames:
            # Tekrarlanan isimleri engelle
            for username in set(mentioned_usernames):
                # Kullanıcıyı veritabanında bul
                mentioned_user = User.query.filter_by(username=username).first()
                # Eğer kullanıcı varsa ve notu yazan kişi kendisi değilse
                if mentioned_user and mentioned_user.id != current_user.id:
                    # Bildirim oluştur
                    notification = Notification(
                        user_id=mentioned_user.id,
                        message=f"<b>{current_user.username}</b>, Olay <b>#{incident.id}</b>'de sizden bahsetti.",
                        link=url_for('incident_detail', incident_id=incident.id)
                    )
                    db.session.add(notification)
            db.session.commit()
        # --- BİLDİRİM MANTIĞI SONU ---
            
    return redirect(url_for('incident_detail', incident_id=incident.id))

# --- OLAY ATAMA/SİLME ROTASI ---
@app.route('/incident/<int:incident_id>/assign', methods=['POST'])
@login_required
def assign_incident(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    assignee_value = request.form.get('assignee_id') # Adını 'assignee_value' olarak değiştirelim
    
    # Seçenek 1: Kullanıcı olayı sahiplenmek istedi
    if assignee_value == 'claim_for_myself':
        if incident.assignee is None:
            incident.assignee = current_user
            incident.status = 'In Progress'
            flash(f'Incident #{incident.id} başarıyla tarafınıza atandı.', 'success')
            log_activity(current_user, "Incident Claimed", f"Claimed Incident #{incident.id}", incident)
        else:
            flash(f'Incident #{incident.id} zaten başka birine atanmış.', 'warning')
    
    # Seçenek 2: Olayın ataması kaldırılmak istendi
    elif assignee_value == 'unassign':
        incident.assignee = None
        # Olay sahipsiz kalınca durumunu "New" yapabiliriz
        if incident.status == 'In Progress':
             incident.status = 'New'
        flash(f'Incident #{incident.id} ataması kaldırıldı.', 'info')
        log_activity(current_user, "Incident Unassigned", f"Unassigned Incident #{incident.id}", incident)
    
    # Seçenek 3: Olay belirli bir kullanıcıya atandı
    else:
        user = User.query.get(assignee_value)
        if user:
            incident.assignee = user
            # Birine atanınca otomatik "In Progress" yapalım
            if incident.status == 'New':
                incident.status = 'In Progress'
            flash(f'Incident #{incident.id} başarıyla {user.username} kullanıcısına atandı.', 'success')
        log_activity(current_user, "Incident Assigned", f"Assigned Incident #{incident.id} to {user.username}", incident)
        
    db.session.commit()
    return redirect(url_for('incident_detail', incident_id=incident.id))

# --- API ve PUBLIC ROTALAR ---
@app.route('/api/v1/event', methods=['POST'])
def handle_event():
    event_data = request.get_json()
    if not event_data:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400
    
    # DÜZELTME: global ifadesini, değişken kullanılmadan önce en başa taşıdık
    global EVENT_CACHE
    
    current_time = time.time()
    
    # Önbelleğe yeni olayı ekle
    EVENT_CACHE.append({'timestamp': current_time, 'data': event_data})
    
    # Önbellekte süresi dolmuş eski olayları temizle
    EVENT_CACHE = [
        event for event in EVENT_CACHE 
        if current_time - event['timestamp'] < CACHE_LIFETIME_SECONDS
    ]
    
    # Gelen olayı ve tüm önbelleği korelasyon motoruna gönder
    with app.app_context():
        correlation_engine.process(event_data, EVENT_CACHE)
    
    return jsonify({"status": "success", "message": "Event received for correlation"}), 200

@app.route('/api/v1/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok", "system": "SOAR-lite"})

#Admin kullacı paneli 
@app.route('/admin/users')
@login_required
@role_required('Admin')
def user_management():
    # Tüm kullanıcıları ID'ye göre sıralayarak çek
    users = User.query.order_by(User.id).all()
    return render_template('admin_panel.html', users=users)

#Admin kullacılarının rolünü değiştirmesi
@app.route('/admin/user/<int:user_id>/change_role', methods=['POST'])
@login_required
@role_required('Admin')
def change_user_role(user_id):
    # Rolü değiştirilecek kullanıcıyı veritabanından bul
    user_to_update = User.query.get_or_404(user_id)
    
    # Formdan gelen yeni rolü al
    new_role = request.form.get('role')
    
    # --- Güvenlik Kontrolleri ---
    # 1. Adminin kendi rolünü değiştirmesini engelle (kendini kilitlemesin)
    if user_to_update.id == current_user.id:
        flash('Kendi rolünüzü değiştiremezsiniz.', 'danger')
        return redirect(url_for('user_management'))
        
    # 2. Geçerli bir rol mü seçildiğini kontrol et
    available_roles = ['Analyst', 'Senior_Analyst', 'Manager', 'Admin']
    if new_role not in available_roles:
        flash('Geçersiz rol seçimi.', 'danger')
        return redirect(url_for('user_management'))

    # Rolü güncelle ve veritabanına kaydet
    user_to_update.role = new_role
    db.session.commit()
    
    flash(f"'{user_to_update.username}' kullanıcısının rolü başarıyla '{new_role}' olarak güncellendi.", 'success')
    return redirect(url_for('user_management'))

#bildirimler için okunmamış yada okunmuş
@app.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        # Okunmamış bildirim sayısını veritabanından say
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        return dict(unread_notifications=unread_count)
    return dict(unread_notifications=0)

#Bildirim ilgili kişi mention edilmiş ise
@app.route('/notifications')
@login_required
def notifications():
    # Kullanıcının tüm bildirimlerini en yeniden eskiye doğru sırala
    user_notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=user_notifications)

@app.route('/notifications/read/<int:notification_id>')
@login_required
def read_notification(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    # Bildirimin bu kullanıcıya ait olup olmadığını kontrol et
    if notification.user_id == current_user.id:
        notification.is_read = True
        db.session.commit()
        # Kullanıcıyı bildirimin linkine yönlendir
        return redirect(notification.link or url_for('notifications'))
    else:
        abort(403) # Yetkisi yok

#Loglar 
def log_activity(user, action, details="", incident=None):
    log_entry = UserActivityLog(
        user_id=user.id,
        action=action,
        details=details,
        incident_id=incident.id if incident else None
    )
    db.session.add(log_entry)
    db.session.commit()
    
#Loglar Sayfa routerı    
@app.route('/activity-log')
@login_required
@role_required('Admin', 'Manager') # Sadece Admin ve Manager görebilir
def activity_log():
    # Logları en yeniden eskiye doğru sırala
    logs = UserActivityLog.query.order_by(UserActivityLog.timestamp.desc()).all()
    return render_template('activity_log.html', logs=logs)    

if __name__ == '__main__':
    app.run(debug=True, port=5000)