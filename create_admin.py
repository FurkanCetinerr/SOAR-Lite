# create_admin.py

from app import create_app
from database import db, User

# Flask uygulamasını ve context'ini oluştur
app = create_app()
with app.app_context():
    # Admin kullanıcısının olup olmadığını kontrol et
    if User.query.filter_by(username='admin').first():
        print("ℹ️  'admin' kullanıcısı zaten mevcut.")
    else:
        # Yeni admin kullanıcısını oluştur
        admin_user = User(
            username='admin',
            email='admin@soar.local',
            role='Admin'  # Rolü manuel olarak 'Admin' yapıyoruz
        )
        # Şifresini ayarla (güvenli bir şifre seç)
        admin_user.set_password('Admin')
        
        # Veritabanına ekle
        db.session.add(admin_user)
        db.session.commit()
        print("✅ 'admin' kullanıcısı başarıyla oluşturuldu.")