# app.py
import time
import re
from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, abort
from engine import PlaybookEngine
from database import db, Incident, Note, User, Notification, UserActivityLog
from datetime import datetime, timedelta
from correlation_engine import CorrelationEngine
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from functools import wraps 

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

@app.route('/dashboard')
@login_required
def dashboard():
    # KPI Kartları
    total_incidents = Incident.query.count()
    new_incidents = Incident.query.filter_by(status='New').count()
    severities_data = db.session.query(Incident.severity, db.func.count(Incident.severity)).group_by(Incident.severity).all()
    severities = {s: c for s, c in severities_data}

    # Çizgi Grafik (Son 7 Gün)
    chart_data = {}
    today = datetime.utcnow().date()
    for i in range(7):
        day = today - timedelta(days=i)
        chart_data[day.strftime('%Y-%m-%d')] = 0
    seven_days_ago = today - timedelta(days=6)
    daily_counts = db.session.query(
        db.func.date(Incident.created_at), db.func.count(Incident.id)
    ).filter(Incident.created_at >= seven_days_ago).group_by(
        db.func.date(Incident.created_at)
    ).all()
    for day_str, count in daily_counts:
        chart_data[str(day_str)] = count
    sorted_chart_data = sorted(chart_data.items())
    line_chart_labels = [item[0] for item in sorted_chart_data]
    line_chart_values = [item[1] for item in sorted_chart_data]

    # Pasta Grafik (Olay Tipine Göre)
    event_type_data = db.session.query(Incident.event_type, db.func.count(Incident.event_type)).group_by(Incident.event_type).all()
    pie_event_type_labels = [item[0] for item in event_type_data]
    pie_event_type_values = [item[1] for item in event_type_data]

    # Pasta Grafik (Duruma Göre)
    status_data = db.session.query(Incident.status, db.func.count(Incident.status)).group_by(Incident.status).all()
    pie_status_labels = [item[0] for item in status_data]
    pie_status_values = [item[1] for item in status_data]
    
        # --- YENİ: ÇUBUK GRAFİK İÇİN VERİ HAZIRLAMA (EN SIK GÖRÜLEN 5 ALARM) ---
    top_alerts_data = db.session.query(
        Incident.details, 
        db.func.count(Incident.details)
    ).group_by(Incident.details).order_by(
        db.func.count(Incident.details).desc()
    ).limit(5).all()
    
    bar_top_alerts_labels = [item[0] for item in top_alerts_data]
    bar_top_alerts_values = [item[1] for item in top_alerts_data]
    
    # Çubuk Grafik (En Sık Görülen 5 Alarm)
    top_alerts_data = db.session.query(
        Incident.details, db.func.count(Incident.details)
    ).group_by(Incident.details).order_by(
        db.func.count(Incident.details).desc()
    ).limit(5).all()
    bar_top_alerts_labels = [item[0] for item in top_alerts_data]
    bar_top_alerts_values = [item[1] for item in top_alerts_data]
    
        # --- YENİ: MITRE GRAFİĞİ İÇİN VERİ HAZIRLAMA ---
    mitre_data = db.session.query(
        Incident.mitre_technique_name, 
        db.func.count(Incident.mitre_technique_name)
    ).filter(Incident.mitre_technique_name.isnot(None)).group_by(
        Incident.mitre_technique_name
    ).order_by(
        db.func.count(Incident.mitre_technique_name).desc()
    ).all()
    
    pie_mitre_labels = [item[0] for item in mitre_data]
    pie_mitre_values = [item[1] for item in mitre_data]

    return render_template('dashboard.html',
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
                           pie_mitre_values=pie_mitre_values)

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
    new_status = request.form.get('status')
    if new_status:
        incident.status = new_status
        db.session.commit()
    return redirect(url_for('incidents_list'))

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