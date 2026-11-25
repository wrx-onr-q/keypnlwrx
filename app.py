import os, time, sqlite3, hashlib, secrets, string, re, json, random
from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, g, Response
from flask_cors import CORS
import bcrypt, jwt

# =====================================================================
# WROX ULTIMATE VIP PANEL - BACKEND
# =====================================================================

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

DATA_DIR = '/data' if os.path.isdir('/data') else os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DATA_DIR, 'wrox_ultimate.db')

JWT_SECRET = os.environ.get('JWT_SECRET', 'WROX_SECRET_ULTIMATE_2025_X')
AUTH_SECRET = 'Vm8Lk7Uj2JmsjCPVPVjrLa7zgfx3uz9E'  # C++ İLE AYNI
ADMIN_USER = 'WROX'            
ADMIN_PASS = 'Wroxtanrıgibi'   

UNITS = {'dakika':60,'saat':3600,'günlük':86400,'haftalık':604800,'aylık':2592000,'sınırsız':0}
CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=15)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA journal_mode=WAL')
        g.db.execute('PRAGMA foreign_keys=ON')
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db: db.close()

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.execute('PRAGMA journal_mode=WAL')
    db.executescript('''
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL, is_admin INTEGER DEFAULT 0, is_banned INTEGER DEFAULT 0,
      ban_reason TEXT, invite_used TEXT, created_at INTEGER DEFAULT (strftime('%s','now')), last_login INTEGER
    );
    CREATE TABLE IF NOT EXISTS keys(
      id INTEGER PRIMARY KEY AUTOINCREMENT, key_value TEXT UNIQUE NOT NULL,
      duration_seconds INTEGER NOT NULL, max_devices INTEGER DEFAULT 5,
      created_at INTEGER DEFAULT (strftime('%s','now')), expires_at INTEGER,
      activated_at INTEGER, created_by TEXT, note TEXT, is_banned INTEGER DEFAULT 0, ban_reason TEXT
    );
    CREATE TABLE IF NOT EXISTS key_devices(
      id INTEGER PRIMARY KEY AUTOINCREMENT, key_id INTEGER NOT NULL, hwid TEXT NOT NULL, ip TEXT,
      first_seen INTEGER DEFAULT (strftime('%s','now')), last_seen INTEGER DEFAULT (strftime('%s','now')),
      UNIQUE(key_id, hwid), FOREIGN KEY(key_id) REFERENCES keys(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS invite_codes(
      code TEXT PRIMARY KEY, max_uses INTEGER DEFAULT 1, used INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS logs(
      id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, detail TEXT, ip TEXT, created_at INTEGER DEFAULT (strftime('%s','now'))
    );
    ''')
    db.execute("INSERT OR IGNORE INTO invite_codes(code,max_uses) VALUES(?,999999)",('Wroxtanrıgibi',))
    if not db.execute("SELECT id FROM users WHERE is_admin=1").fetchone():
        h = bcrypt.hashpw(ADMIN_PASS.encode(), bcrypt.gensalt()).decode()
        db.execute("INSERT INTO users(username,password,is_admin) VALUES(?,?,1)",(ADMIN_USER,h))
        print(f'> WROX Admin: {ADMIN_USER} / {ADMIN_PASS}')
    db.commit(); db.close()

def log_action(db, action, detail, ip):
    try:
        db.execute("INSERT INTO logs(action,detail,ip) VALUES(?,?,?)",(action,detail,ip))
        db.commit()
    except: pass

def random_key(prefix='WROX'):
    seg = lambda n: ''.join(secrets.choice(CHARS) for _ in range(n))
    return f"{prefix}-{seg(6)}-{seg(6)}-{seg(6)}-{seg(6)}"

def custom_key(p):
    return re.sub(r'\{random(\d+)?\}', lambda m: ''.join(secrets.choice(CHARS) for _ in range(int(m.group(1)) if m.group(1) else 6)), p)

def auth_required(f):
    @wraps(f)
    def w(*a,**k):
        t = (request.headers.get('Authorization') or '').replace('Bearer ','')
        try: request.user = jwt.decode(t, JWT_SECRET, algorithms=['HS256'])
        except: return jsonify({'status':False,'reason':'WROX: Yetkisiz erişim'}),401
        return f(*a,**k)
    return w

def admin_required(f):
    @wraps(f)
    @auth_required
    def w(*a,**k):
        if not request.user.get('is_admin'): return jsonify({'status':False,'reason':'WROX: Admin yetkisi gerekli'}),403
        return f(*a,**k)
    return w

# ----------------- API: AUTH -----------------

@app.route('/api/register',methods=['POST'])
def register():
    d = request.json or {}; u,p,inv = d.get('username'),d.get('password'),d.get('invite')
    if not u or not p or not inv: return jsonify({'status':False,'reason':'Lütfen tüm alanları doldurun.'})
    db = get_db(); r = db.execute("SELECT * FROM invite_codes WHERE code=?",(inv,)).fetchone()
    if not r or r['used']>=r['max_uses']: return jsonify({'status':False,'reason':'Bu davet kodu geçersiz veya süresi dolmuş.'})
    try:
        h = bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()
        db.execute("INSERT INTO users(username,password,invite_used) VALUES(?,?,?)",(u,h,inv))
        db.execute("UPDATE invite_codes SET used=used+1 WHERE code=?",(inv,))
        db.commit()
        log_action(db, 'REGISTER', f'{u} kayıt oldu.', request.remote_addr)
        return jsonify({'status':True,'reason':'Kayıt başarılı! Giriş yapabilirsiniz.'})
    except: return jsonify({'status':False,'reason':'Bu kullanıcı adı zaten alınmış.'})

@app.route('/api/login',methods=['POST'])
def login():
    d = request.json or {}; db = get_db()
    u = db.execute("SELECT * FROM users WHERE username=?",(d.get('username'),)).fetchone()
    if not u or not bcrypt.checkpw((d.get('password') or '').encode(),u['password'].encode()): 
        return jsonify({'status':False,'reason':'Kullanıcı adı veya şifre yanlış.'})
    if u['is_banned']: return jsonify({'status':False,'reason':f"Hesabınız askıya alındı. Sebep: {u['ban_reason']}"})
    db.execute("UPDATE users SET last_login=? WHERE id=?", (int(time.time()), u['id'])); db.commit()
    tok = jwt.encode({'id':u['id'],'username':u['username'],'is_admin':bool(u['is_admin']),'exp':int(time.time())+7*86400},JWT_SECRET,algorithm='HS256')
    log_action(db, 'LOGIN', f'{u["username"]} giriş yaptı.', request.remote_addr)
    return jsonify({'status':True,'token':tok,'username':u['username'],'is_admin':bool(u['is_admin'])})

# ----------------- API: KEY MANAGEMENT -----------------

@app.route('/api/key/create',methods=['POST'])
@auth_required
def create_key():
    d = request.json or {}; t = d.get('type')
    cnt = min(max(int(d.get('count') or 1),1),100)
    md = int(d.get('max_devices') or 0) # 0 = SINIRSIZ
    pat, note = d.get('pattern'), d.get('note')
    if t=='özel':
        dur = int(d.get('days') or 0)*86400+int(d.get('hours') or 0)*3600+int(d.get('minutes') or 0)*60
        if dur<=0: return jsonify({'status':False,'reason':'Özel süre en az 1 dakika olmalıdır.'})
    elif t in UNITS: dur = UNITS[t]
    else: return jsonify({'status':False,'reason':'Geçersiz süre tipi.'})
    db = get_db(); created = []
    for _ in range(cnt):
        kv = custom_key(pat) if pat else random_key()
        try:
            db.execute("INSERT INTO keys(key_value,duration_seconds,max_devices,created_by,note) VALUES(?,?,?,?,?)",(kv,dur,md,request.user['username'],note))
            created.append(kv)
        except: pass
    db.commit()
    log_action(db, 'KEY_GEN', f'{len(created)} adet key üretildi.', request.remote_addr)
    return jsonify({'status':True,'keys':created})

@app.route('/api/key/list',methods=['GET'])
@auth_required
def list_keys():
    db = get_db()
    rows = db.execute("SELECT * FROM keys ORDER BY id DESC").fetchall() if request.user.get('is_admin') else db.execute("SELECT * FROM keys WHERE created_by=? ORDER BY id DESC",(request.user['username'],)).fetchall()
    now = int(time.time()); out = []
    for k in rows:
        devs = db.execute("SELECT hwid,ip,first_seen,last_seen FROM key_devices WHERE key_id=?",(k['id'],)).fetchall()
        if k['is_banned']: durum,kalan = 'BANLI', 0
        elif k['activated_at']:
            if k['expires_at'] is None: durum,kalan = 'SINIRSIZ', '∞'
            elif k['expires_at']<now: durum,kalan = 'DOLDU', 0
            else: durum,kalan = 'AKTİF', k['expires_at']-now
        else: durum, kalan = 'BEKLEMEDE', ('∞' if k['duration_seconds']==0 else k['duration_seconds'])
        out.append({**dict(k),'durum':durum,'kalan':kalan,'devices':[dict(x) for x in devs]})
    return jsonify({'status':True,'keys':out})

@app.route('/api/key/<int:kid>',methods=['DELETE'])
@auth_required
def delete_key(kid):
    db = get_db(); k = db.execute("SELECT * FROM keys WHERE id=?",(kid,)).fetchone()
    if not k: return jsonify({'status':False,'reason':'Key bulunamadı.'})
    if not request.user.get('is_admin') and k['created_by']!=request.user['username']: return jsonify({'status':False,'reason':'Bu keyi silme yetkiniz yok.'})
    db.execute("DELETE FROM key_devices WHERE key_id=?",(kid,)); db.execute("DELETE FROM keys WHERE id=?",(kid,)); db.commit()
    log_action(db, 'KEY_DEL', f'{k["key_value"]} silindi.', request.remote_addr)
    return jsonify({'status':True})

@app.route('/api/key/<int:kid>/reset-devices',methods=['POST'])
@auth_required
def reset_devices(kid):
    db = get_db(); k = db.execute("SELECT * FROM keys WHERE id=?",(kid,)).fetchone()
    if not k: return jsonify({'status':False,'reason':'Key yok.'})
    db.execute("DELETE FROM key_devices WHERE key_id=?",(kid,)); db.commit()
    log_action(db, 'KEY_RESET', f'{k["key_value"]} cihazları sıfırlandı.', request.remote_addr)
    return jsonify({'status':True,'reason':'Cihazlar başarıyla sıfırlandı.'})

@app.route('/api/key/<int:kid>/extend',methods=['POST'])
@auth_required
def extend_key(kid):
    sec = int((request.json or {}).get('seconds') or 0); db = get_db()
    k = db.execute("SELECT * FROM keys WHERE id=?",(kid,)).fetchone()
    if not k or k['duration_seconds']==0: return jsonify({'status':False,'reason':'Sınırsız keyler uzatılamaz.'})
    now = int(time.time()); base = k['expires_at'] if (k['expires_at'] and k['expires_at']>now) else now
    db.execute("UPDATE keys SET expires_at=? WHERE id=?",(base+sec,kid)); db.commit()
    log_action(db, 'KEY_EXT', f'{k["key_value"]} süresi uzatıldı.', request.remote_addr)
    return jsonify({'status':True,'reason':'Süre başarıyla uzatıldı.'})

@app.route('/api/key/<int:kid>/ban',methods=['POST'])
@admin_required
def key_ban(kid):
    reason = (request.json or {}).get('reason','Kural ihlali'); db = get_db()
    db.execute("UPDATE keys SET is_banned=1, ban_reason=? WHERE id=?",(reason,kid)); db.commit()
    log_action(db, 'KEY_BAN', f'Key ID {kid} banlandı.', request.remote_addr)
    return jsonify({'status':True,'reason':'Key başarıyla banlandı.'})

@app.route('/api/key/<int:kid>/unban',methods=['POST'])
@admin_required
def key_unban(kid):
    db = get_db(); db.execute("UPDATE keys SET is_banned=0, ban_reason=NULL WHERE id=?",(kid,)); db.commit()
    log_action(db, 'KEY_UNBAN', f'Key ID {kid} banı açıldı.', request.remote_addr)
    return jsonify({'status':True,'reason':'Key banı açıldı.'})

@app.route('/api/key/<int:kid>/devices',methods=['GET'])
@auth_required
def key_devices(kid):
    db = get_db(); k = db.execute("SELECT * FROM keys WHERE id=?",(kid,)).fetchone()
    devs = db.execute("SELECT * FROM key_devices WHERE key_id=? ORDER BY last_seen DESC",(kid,)).fetchall()
    return jsonify({'status':True,'devices':[dict(d) for d in devs],'max':k['max_devices']})

# ----------------- API: ADMIN MANAGEMENT -----------------

@app.route('/api/admin/users',methods=['GET'])
@admin_required
def admin_users():
    db = get_db()
    rows = db.execute("SELECT u.*, (SELECT COUNT(*) FROM keys WHERE created_by=u.username) as key_count FROM users u ORDER BY u.id DESC").fetchall()
    return jsonify({'status':True,'users':[dict(r) for r in rows]})

@app.route('/api/admin/user/<int:uid>/<action>',methods=['POST'])
@admin_required
def admin_user_action(uid, action):
    db = get_db(); u = db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
    if not u: return jsonify({'status':False,'reason':'Kullanıcı yok.'})
    if action=='ban':
        if u['is_admin']: return jsonify({'status':False,'reason':'Adminler banlanamaz.'})
        db.execute("UPDATE users SET is_banned=1, ban_reason=? WHERE id=?",((request.json or {}).get('reason','Kural ihlali'), uid))
    elif action=='unban': db.execute("UPDATE users SET is_banned=0 WHERE id=?",(uid,))
    elif action=='make-admin': db.execute("UPDATE users SET is_admin=1 WHERE id=?",(uid,))
    elif action=='remove-admin': db.execute("UPDATE users SET is_admin=0 WHERE id=?",(uid,))
    elif action=='delete':
        if u['is_admin']: return jsonify({'status':False,'reason':'Adminler silinemez.'})
        db.execute("DELETE FROM users WHERE id=?",(uid,))
    db.commit()
    log_action(db, f'USER_{action.upper()}', f'Kullanıcı ID {uid} üzerinde işlem yapıldı.', request.remote_addr)
    return jsonify({'status':True,'reason':'İşlem başarılı.'})

@app.route('/api/admin/stats',methods=['GET'])
@admin_required
def admin_stats():
    db = get_db(); now = int(time.time())
    return jsonify({'status':True,
        'users':db.execute("SELECT COUNT(*) c FROM users").fetchone()['c'],
        'keys':db.execute("SELECT COUNT(*) c FROM keys").fetchone()['c'],
        'active':db.execute("SELECT COUNT(*) c FROM keys WHERE activated_at IS NOT NULL AND (expires_at IS NULL OR expires_at>?) AND is_banned=0",(now,)).fetchone()['c']})

@app.route('/api/admin/invites',methods=['GET'])
@admin_required
def admin_invites():
    db = get_db(); return jsonify({'status':True,'invites':[dict(r) for r in db.execute("SELECT * FROM invite_codes").fetchall()]})

@app.route('/api/admin/invite',methods=['POST'])
@admin_required
def admin_add_invite():
    d = request.json or {}; db = get_db()
    try:
        db.execute("INSERT INTO invite_codes(code,max_uses) VALUES(?,?)",(d.get('code'),int(d.get('max_uses') or 10))); db.commit()
        log_action(db, 'INVITE_ADD', f'{d.get("code")} davet kodu eklendi.', request.remote_addr)
        return jsonify({'status':True,'reason':'Davet kodu başarıyla eklendi.'})
    except: return jsonify({'status':False,'reason':'Bu davet kodu zaten mevcut.'})

@app.route('/api/admin/logs',methods=['GET'])
@admin_required
def admin_logs():
    db = get_db()
    return jsonify({'status':True,'logs':[dict(r) for r in db.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 100").fetchall()]})

# ----------------- API: CONNECT (C++ & Browser Uyumlu) -----------------

@app.route('/connect',methods=['POST', 'GET'])
def connect():
    # Hem form (C++) hem de GET parametresi (?=KEY) altyapısını destekler
    user_key = request.form.get('user_key') or request.args.get('user_key') or request.args.get('')
    if not user_key:
        for k,v in request.args.items():
            if k == '': user_key = v; break
            
    serial = request.form.get('serial') or request.args.get('serial') or 'unknown'
    game = request.form.get('game') or request.args.get('game') or 'PUBG'
    ip = request.remote_addr or ''
    
    if not user_key: return jsonify({'status':False,'reason':'Lütfen bir key girin (?=KEY)'})
    
    db = get_db(); k = db.execute("SELECT * FROM keys WHERE key_value=?",(user_key,)).fetchone()
    if not k: return jsonify({'status':False,'reason':'Key veritabanında bulunamadı.'})
    if k['is_banned']: return jsonify({'status':False,'reason':'Bu key kural ihlalinden dolayı banlanmış.'})
    
    now = int(time.time())
    
    # Cihaz Kontrolü
    if k['max_devices'] > 0:
        dev = db.execute("SELECT * FROM key_devices WHERE key_id=? AND hwid=?",(k['id'],serial)).fetchone()
        if not dev:
            c = db.execute("SELECT COUNT(*) c FROM key_devices WHERE key_id=?",(k['id'],)).fetchone()['c']
            if c >= k['max_devices']: return jsonify({'status':False,'reason':f'Cihaz limiti aşıldı ({c}/{k["max_devices"]})'})
            db.execute("INSERT INTO key_devices(key_id,hwid,ip) VALUES(?,?,?)",(k['id'],serial,ip))
        else: db.execute("UPDATE key_devices SET last_seen=?, ip=? WHERE id=?",(now,ip,dev['id']))
    
    # Aktivasyon
    if not k['activated_at']:
        exp = None if k['duration_seconds']==0 else now+k['duration_seconds']
        db.execute("UPDATE keys SET activated_at=?, expires_at=? WHERE id=?",(now,exp,k['id']))
        k = dict(k); k['expires_at']=exp
    
    # Süre Kontrolü
    if k['expires_at'] is not None and now > k['expires_at']: return jsonify({'status':False,'reason':'Key süresi dolmuş.'})
    
    # MD5 TOKEN (C++ için)
    token = hashlib.md5(f'{game}-{user_key}-{serial}-{AUTH_SECRET}'.encode()).hexdigest()
    db.commit()
    
    # Tarayıcıdan GET atıldıysa görsel HTML sayfası dön
    if request.method == 'GET':
        return Response(f"""
        <html><head><meta charset='utf-8'><title>WROX | Key Onay</title>
        <style>
        body{{background:#050505;color:#fff;text-align:center;padding:50px;font-family:'Segoe UI',sans-serif}}
        .box{{background:rgba(20,20,20,0.9);border:1px solid #dc2626;border-radius:16px;padding:40px;max-width:500px;margin:auto;box-shadow:0 0 30px rgba(220,38,38,0.3)}}
        h1{{color:#dc2626;letter-spacing:3px;margin-bottom:20px}} 
        .token{{background:#000;padding:15px;border-radius:8px;font-family:monospace;color:#86efac;word-break:break-all;margin-top:20px;border:1px solid #333}}
        </style></head>
        <body><div class='box'><h1>KEY AKTİF</h1>
        <p>Key: <b>{user_key}</b></p>
        <p>Süre: <b>{'Sınırsız' if k['duration_seconds']==0 else str(k['duration_seconds'])+' sn'}</b></p>
        <p>Durum: <b style="color:#86efac">Başarıyla doğrulandı.</b></p>
        <div class='token'>Token: {token}</div></div></body></html>""", mimetype='text/html')
    
    return jsonify({'status':True,'data':{'token':token,'rng':now}})

# =====================================================================
# WROX ULTIMATE VIP PANEL - FRONTEND (HTML/CSS/JS)
# =====================================================================

HTML = r"""<!DOCTYPE html>
<html lang="tr"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>WROX VIP PANEL</title>
<style>
/* TEMA RENKLERİ VE TEMEL AYARLAR */
:root {
    --bg: #050505;
    --panel-bg: rgba(15, 15, 15, 0.75);
    --primary: #dc2626;
    --primary-glow: rgba(220, 38, 38, 0.6);
    --text: #ffffff;
    --text-dim: #9ca3af;
    --success: #16a34a;
    --warning: #d97706;
}

* { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', sans-serif; -webkit-tap-highlight-color: transparent; }

body { 
    min-height: 100vh; 
    background: var(--bg); 
    color: var(--text); 
    overflow-x: hidden; 
    padding-bottom: 80px; 
    background-image: radial-gradient(circle at 50% -20%, rgba(220, 38, 38, 0.15), transparent 50%);
}

/* ARKA PLAN KAR EFEKTİ */
#fx { position: fixed; inset: 0; pointer-events: none; z-index: 0; }

/* YÜKLEME EKRANI (LOADER) */
#loader {
    position: fixed; inset: 0; background: var(--bg); z-index: 9999;
    display: flex; justify-content: center; align-items: center; flex-direction: column;
    transition: opacity 0.5s ease;
}
.loader-text {
    font-size: 40px; font-weight: 900; letter-spacing: 10px; color: var(--primary);
    text-shadow: 0 0 20px var(--primary-glow); animation: pulse 1.5s infinite;
}
@keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.5; transform: scale(0.95); } }

/* ÜST BAR */
.topbar {
    position: sticky; top: 0; z-index: 10; background: rgba(5, 5, 5, 0.85); backdrop-filter: blur(15px);
    padding: 16px 20px; display: flex; justify-content: space-between; align-items: center;
    border-bottom: 1px solid rgba(220, 38, 38, 0.3); box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
}
.topbar h1 { font-size: 22px; font-weight: 900; letter-spacing: 4px; color: var(--primary); text-shadow: 0 0 15px var(--primary-glow); }
.user-pill { font-size: 12px; background: rgba(220, 38, 38, 0.15); padding: 6px 14px; border-radius: 20px; border: 1px solid rgba(220, 38, 38, 0.4); color: #fca5a5; font-weight: 700; }

/* KONTEYNER */
.container { max-width: 600px; margin: 0 auto; padding: 20px 16px; position: relative; z-index: 1; }

/* KART TASARIMI */
.card {
    background: var(--panel-bg); backdrop-filter: blur(20px); border: 1px solid rgba(255, 255, 255, 0.05);
    border-radius: 16px; padding: 20px; margin-bottom: 20px; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.8);
    transition: transform 0.2s, box-shadow 0.2s;
}
.card:hover { border-color: rgba(220, 38, 38, 0.3); box-shadow: 0 10px 40px rgba(220, 38, 38, 0.1); }
.card h2 { font-size: 14px; color: #fca5a5; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 1.5px; font-weight: 800; border-left: 3px solid var(--primary); padding-left: 10px; }

/* FORMLAR */
input, select, textarea {
    width: 100%; padding: 14px; border-radius: 12px; border: 1px solid rgba(255, 255, 255, 0.1);
    background: rgba(0, 0, 0, 0.6); color: #fff; font-size: 15px; margin-bottom: 12px; outline: none; transition: 0.3s;
}
input:focus, select:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(220, 38, 38, 0.2); background: rgba(0, 0, 0, 0.8); }
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; }

/* BUTONLAR */
button {
    width: 100%; padding: 16px; border-radius: 12px; border: none; font-weight: 800; font-size: 15px;
    cursor: pointer; transition: 0.2s; display: flex; align-items: center; justify-content: center; gap: 8px; letter-spacing: 0.5px;
}
.btn-main { background: linear-gradient(135deg, var(--primary), #7f1d1d); color: #fff; box-shadow: 0 4px 15px rgba(220, 38, 38, 0.4); }
.btn-main:active { transform: scale(0.97); }
.btn-ghost { background: rgba(255, 255, 255, 0.05); color: #fca5a5; border: 1px solid rgba(220, 38, 38, 0.3); }
.btn-ghost:hover { background: rgba(220, 38, 38, 0.1); }
.btn-mini { width: auto; padding: 10px 14px; font-size: 12px; border-radius: 8px; font-weight: 700; }

/* KEY KARTLARI */
.key-item { background: rgba(0, 0, 0, 0.5); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 14px; padding: 16px; margin-bottom: 12px; position: relative; overflow: hidden; transition: 0.2s; }
.key-item:hover { border-color: rgba(220, 38, 38, 0.4); transform: translateY(-2px); }
.key-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.key-val { font-family: monospace; color: #fca5a5; font-size: 14px; font-weight: 800; letter-spacing: 1px; word-break: break-all; }

/* BADGE (ETİKETLER) */
.badge { font-size: 11px; padding: 5px 10px; border-radius: 6px; font-weight: 900; text-transform: uppercase; letter-spacing: 0.5px; }
.b-aktif { background: #14532d; color: #86efac; border: 1px solid var(--success); }
.b-beklemede { background: #422006; color: #fbbf24; border: 1px solid var(--warning); }
.b-doldu { background: #1f2937; color: #9ca3af; border: 1px solid #4b5563; }
.b-banli { background: #7f1d1d; color: #fecaca; border: 1px solid #ef4444; box-shadow: 0 0 10px rgba(239, 68, 68, 0.4); }

.key-info { display: flex; gap: 16px; font-size: 12px; color: var(--text-dim); margin-bottom: 14px; font-weight: 600; }
.key-actions { display: flex; gap: 8px; flex-wrap: wrap; }
.key-actions button { flex: 1; padding: 10px; font-size: 11px; }

/* ALT MENÜ (BOTTOM NAV) */
.bottom-nav {
    position: fixed; bottom: 0; left: 0; right: 0; z-index: 50; background: rgba(5, 5, 5, 0.95); backdrop-filter: blur(20px);
    border-top: 1px solid rgba(255, 255, 255, 0.05); display: flex; justify-content: space-around; padding: 12px 0 24px 0;
}
.nav-item { display: flex; flex-direction: column; align-items: center; gap: 6px; color: #6b7280; font-size: 11px; font-weight: 800; cursor: pointer; transition: 0.3s; flex: 1; }
.nav-item.active { color: var(--primary); text-shadow: 0 0 10px var(--primary-glow); transform: translateY(-2px); }
.nav-item i { font-size: 24px; font-style: normal; }

/* MODAL (AÇILIR PENCERE) */
.modal-bg { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.85); backdrop-filter: blur(8px); z-index: 100; display: flex; align-items: flex-end; justify-content: center; }
.modal-content { background: #0f0f0f; width: 100%; max-width: 600px; border-radius: 24px 24px 0 0; padding: 24px; max-height: 85vh; overflow-y: auto; border-top: 2px solid var(--primary); animation: slideUp 0.3s ease-out; }
@keyframes slideUp { from { transform: translateY(100%); } to { transform: translateY(0); } }
.modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 16px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); }
.modal-header h3 { font-size: 18px; color: #fca5a5; }
.close-btn { background: rgba(255, 255, 255, 0.1); width: 36px; height: 36px; border-radius: 50%; display: flex; align-items: center; justify-content: center; cursor: pointer; color: #fff; font-size: 18px; transition: 0.2s; }
.close-btn:hover { background: rgba(220, 38, 38, 0.5); }

/* SEKMELER */
.tab-content { display: none; animation: fadeIn 0.3s ease-out; }
.tab-content.active { display: block; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

/* TOAST BİLDİRİM SİSTEMİ */
.toast-container { position: fixed; top: 20px; right: 20px; z-index: 10000; display: flex; flex-direction: column; gap: 10px; }
.toast { background: rgba(15, 15, 15, 0.95); border-left: 4px solid var(--primary); padding: 15px 20px; border-radius: 8px; color: #fff; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.8); display: flex; align-items: center; gap: 10px; animation: slideIn 0.3s ease-out; min-width: 250px; font-weight: 600; font-size: 14px; backdrop-filter: blur(10px); }
.toast.success { border-color: var(--success); }
.toast.error { border-color: var(--primary); }
@keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

.hidden { display: none !important; }
.footer { text-align: center; font-size: 11px; color: #374151; margin-top: 40px; letter-spacing: 4px; font-weight: 900; }

/* KULLANICI KARTLARI */
.user-item { background: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 14px; padding: 16px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; transition: 0.2s; }
.user-item:hover { background: rgba(255, 255, 255, 0.05); }
.user-info h3 { font-size: 15px; margin-bottom: 6px; color: #fff; font-weight: 700; }
.user-info p { font-size: 12px; color: var(--text-dim); font-weight: 600; }
.user-actions { display: flex; flex-direction: column; gap: 8px; }
.user-actions button { padding: 8px 12px; font-size: 11px; width: auto; }

/* MOBİL UYUMLULUK */
@media(max-width: 450px) {
    .grid-3 { grid-template-columns: 1fr; }
    .grid-2 { grid-template-columns: 1fr; }
    .key-actions { flex-direction: column; }
}
</style>
</head>
<body>

<!-- YÜKLEME EKRANI -->
<div id="loader"><div class="loader-text">WROX</div></div>

<canvas id="fx"></canvas>
<div class="toast-container" id="toastBox"></div>

<!-- ÜST BAR -->
<div class="topbar">
    <h1>WROX VIP</h1>
    <div id="userBar" class="hidden"><span id="uname" class="user-pill"></span></div>
</div>

<div class="container">
    <!-- GİRİŞ / KAYIT SEKMESİ -->
    <div id="authTab">
        <div class="card">
            <h2>Sisteme Giriş</h2>
            <input id="l_u" placeholder="Kullanıcı Adı">
            <input id="l_p" type="password" placeholder="Şifre">
            <button class="btn-main" onclick="login()">🚀 GİRİŞ YAP</button>
        </div>
        <div class="card">
            <h2>Kayıt Ol</h2>
            <input id="r_u" placeholder="Kullanıcı Adı">
            <input id="r_p" type="password" placeholder="Şifre">
            <input id="r_i" placeholder="Davet Kodu (Wroxtanrıgibi)">
            <button class="btn-ghost" onclick="register()">📝 KAYIT OL</button>
        </div>
    </div>

    <!-- ANA PANEL -->
    <div id="mainPanel" class="hidden">
        
        <!-- KEY SEKMESİ -->
        <div id="tab-keys" class="tab-content active">
            <div class="card">
                <h2>Key Üret</h2>
                <div class="grid-2">
                    <select id="k_type" onchange="toggleCustom()">
                        <option value="dakika">Dakikalık</option>
                        <option value="saat">Saatlik</option>
                        <option value="günlük">Günlük</option>
                        <option value="haftalık">Haftalık</option>
                        <option value="aylık">Aylık</option>
                        <option value="sınırsız">Sınırsız</option>
                        <option value="özel">Özel Süre</option>
                    </select>
                    <input id="k_count" type="number" value="1" min="1" placeholder="Adet">
                </div>
                <div id="customTime" class="grid-3 hidden">
                    <input id="k_d" type="number" placeholder="Gün" min="0" value="0">
                    <input id="k_h" type="number" placeholder="Saat" min="0" value="0">
                    <input id="k_m" type="number" placeholder="Dakika" min="0" value="0">
                </div>
                <div class="grid-2">
                    <input id="k_dev" type="number" value="0" min="0" placeholder="Cihaz Sınırı (0=∞)">
                    <input id="k_note" placeholder="Not (İsteğe bağlı)">
                </div>
                <input id="k_pattern" placeholder="Özel Format (WROX-{random8})">
                <button class="btn-main" onclick="createKey()">🔑 KEY OLUŞTUR</button>
            </div>
            <div id="kList"></div>
        </div>

        <!-- ADMİN SEKMESİ -->
        <div id="tab-admin" class="tab-content">
            <div class="grid-3" style="margin-bottom:16px">
                <div class="card" style="text-align:center;padding:16px"><h2 style="margin:0;font-size:24px;color:var(--primary);border:none;padding:0" id="s_users">-</h2><span style="font-size:11px;color:var(--text-dim);font-weight:700">KULLANICI</span></div>
                <div class="card" style="text-align:center;padding:16px"><h2 style="margin:0;font-size:24px;color:var(--primary);border:none;padding:0" id="s_keys">-</h2><span style="font-size:11px;color:var(--text-dim);font-weight:700">KEY</span></div>
                <div class="card" style="text-align:center;padding:16px"><h2 style="margin:0;font-size:24px;color:var(--success);border:none;padding:0" id="s_active">-</h2><span style="font-size:11px;color:var(--text-dim);font-weight:700">AKTİF</span></div>
            </div>
            
            <div class="card">
                <h2>Sistem Logları (Son 100)</h2>
                <div id="logList" style="max-height:200px;overflow-y:auto;font-size:12px;color:#aaa;"></div>
            </div>

            <div class="card">
                <h2>Davet Kodu Ekle</h2>
                <div class="grid-2">
                    <input id="i_code" placeholder="Kod (Örn: VIP50)">
                    <input id="i_max" type="number" value="10" placeholder="Maks Kullanım">
                </div>
                <button class="btn-ghost" onclick="addInvite()">➕ KOD EKLE</button>
            </div>

            <h2 style="font-size:14px;color:#fca5a5;margin:20px 0 12px;text-transform:uppercase;letter-spacing:1.5px;border-left:3px solid var(--primary);padding-left:10px;font-weight:800">KULLANICILAR</h2>
            <div id="usrList"></div>
        </div>

    </div>
    <div class="footer">WROX VIP PANEL</div>
</div>

<!-- ALT MENÜ -->
<div id="bottomNav" class="bottom-nav hidden">
    <div class="nav-item active" id="nav-keys" onclick="switchTab('keys')"><i>🔑</i><span>KEYLER</span></div>
    <div class="nav-item hidden" id="nav-admin" onclick="switchTab('admin')"><i>🛡️</i><span>ADMİN</span></div>
    <div class="nav-item" onclick="logout()"><i>🚪</i><span>ÇIKIŞ</span></div>
</div>

<script>
// =====================================================================
// WROX ULTIMATE VIP PANEL - JAVASCRIPT
// =====================================================================

const API = location.origin;
let token = localStorage.getItem('wrox_token');
let isAdmin = false;

// --- TOAST BİLDİRİM SİSTEMİ ---
function toast(msg, type='success') {
    const box = document.getElementById('toastBox');
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.innerHTML = `<span>${type==='success'?'✅':'❌'}</span> ${msg}`;
    box.appendChild(t);
    setTimeout(() => { t.style.opacity = '0'; setTimeout(()=>t.remove(), 300); }, 3000);
}

// --- KAR EFEKTİ (3D Canvas) ---
const cv = document.getElementById('fx'), ctx = cv.getContext('2d');
let W, H, ps = [];
function rs() { W = cv.width = innerWidth; H = cv.height = innerHeight; init(); }
function init() {
    ps = [];
    const n = Math.floor(W / 15); // Yoğunluk
    for (let i = 0; i < n; i++) {
        const isSnow = Math.random() > 0.3;
        ps.push({
            x: Math.random() * W, y: Math.random() * H,
            r: isSnow ? Math.random() * 2.5 + 1 : Math.random() * 1.5 + 0.5,
            vy: isSnow ? Math.random() * 1.5 + 0.5 : Math.random() * 8 + 8,
            vx: isSnow ? Math.random() * 1 - 0.5 : -1.5,
            s: isSnow
        });
    }
}
function draw() {
    ctx.clearRect(0, 0, W, H);
    for (const p of ps) {
        if (p.s) {
            ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
            ctx.shadowBlur = 10; ctx.shadowColor = 'white';
            ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, 7); ctx.fill();
        } else {
            ctx.strokeStyle = 'rgba(220, 38, 38, 0.6)';
            ctx.lineWidth = 1.5; ctx.shadowBlur = 5; ctx.shadowColor = '#dc2626';
            ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(p.x - 2, p.y + 15); ctx.stroke();
        }
        p.x += p.vx; p.y += p.vy;
        if (p.y > H) { p.y = -10; p.x = Math.random() * W; }
        if (p.x < 0) p.x = W;
    }
    ctx.shadowBlur = 0; // Reset
    requestAnimationFrame(draw);
}
addEventListener('resize', rs); rs(); draw();

// --- API FETCH ---
async function api(path, opts = {}) {
    opts.headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
    if (token) opts.headers.Authorization = 'Bearer ' + token;
    try {
        const r = await fetch(API + path, opts);
        return await r.json();
    } catch (e) {
        toast('Sunucuya bağlanılamadı!', 'error');
        return { status: false, reason: 'Bağlantı hatası' };
    }
}

// --- GİRİŞ / KAYIT ---
async function login() {
    const btn = event.target; btn.innerHTML = '⏳ BEKLENİYOR...'; btn.disabled = true;
    const d = await api('/api/login', { method: 'POST', body: JSON.stringify({ username: l_u.value, password: l_p.value }) });
    btn.innerHTML = '🚀 GİRİŞ YAP'; btn.disabled = false;
    if (d.status) {
        token = d.token; isAdmin = d.is_admin;
        localStorage.setItem('wrox_token', token);
        toast('Giriş başarılı. Hoş geldin!');
        showPanel();
    } else toast(d.reason, 'error');
}

async function register() {
    const btn = event.target; btn.innerHTML = '⏳ KAYIT OLUNUYOR...'; btn.disabled = true;
    const d = await api('/api/register', { method: 'POST', body: JSON.stringify({ username: r_u.value, password: r_p.value, invite: r_i.value }) });
    btn.innerHTML = '📝 KAYIT OL'; btn.disabled = false;
    if (d.status) {
        toast(d.reason);
        r_u.value = ''; r_p.value = ''; r_i.value = '';
    } else toast(d.reason, 'error');
}

function logout() { token = null; localStorage.removeItem('wrox_token'); location.reload(); }

// --- PANEL YÜKLEME ---
function showPanel() {
    document.getElementById('authTab').classList.add('hidden');
    document.getElementById('mainPanel').classList.remove('hidden');
    document.getElementById('bottomNav').classList.remove('hidden');
    document.getElementById('userBar').classList.remove('hidden');
    
    const p = JSON.parse(atob(token.split('.')[1]));
    document.getElementById('uname').textContent = '👤 ' + p.username;
    if (p.is_admin) {
        isAdmin = true;
        document.getElementById('nav-admin').classList.remove('hidden');
    }
    loadKeys();
}

// --- YÜKLEME EKRANINI GİZLE ---
setTimeout(() => {
    const l = document.getElementById('loader');
    l.style.opacity = '0';
    setTimeout(() => l.remove(), 500);
}, 1500);

// --- KEY İŞLEMLERİ ---
function toggleCustom() { document.getElementById('customTime').classList.toggle('hidden', k_type.value !== 'özel'); }

async function createKey() {
    const btn = event.target; btn.innerHTML = '⏳ ÜRETİLİYOR...'; btn.disabled = true;
    const body = {
        type: k_type.value, count: k_count.value, max_devices: k_dev.value,
        pattern: k_pattern.value || undefined, note: k_note.value || undefined
    };
    if (k_type.value === 'özel') { body.days = k_d.value; body.hours = k_h.value; body.minutes = k_m.value; }
    
    const d = await api('/api/key/create', { method: 'POST', body: JSON.stringify(body) });
    btn.innerHTML = '🔑 KEY OLUŞTUR'; btn.disabled = false;
    
    if (d.status) {
        toast(`${d.keys.length} adet key başarıyla oluşturuldu!`);
        d.keys.forEach(k => console.log('Üretilen Key:', k));
        loadKeys();
    } else toast(d.reason, 'error');
}

function fmtSec(s) { if (s === '∞') return '∞'; s = +s; if (s < 60) return s + 's'; if (s < 3600) return Math.floor(s / 60) + 'dk'; if (s < 86400) return Math.floor(s / 3600) + 'sa'; return Math.floor(s / 86400) + 'g'; }
function fmtDur(s) { if (s === 0) return '∞'; return fmtSec(s); }
function fmtTime(t) { if (!t) return '-'; const d = new Date(t * 1000); return d.toLocaleDateString('tr-TR') + ' ' + d.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' }); }
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

async function loadKeys() {
    const d = await api('/api/key/list'); if (!d.status) return;
    kList.innerHTML = d.keys.map(k => {
        let bc = 'b-beklemede', extra = '';
        if (k.is_banned) { bc = 'b-banli'; extra = ' ' + esc(k.ban_reason || ''); }
        else if (k.durum === 'AKTİF' || k.durum === 'SINIRSIZ') bc = 'b-aktif';
        else if (k.durum === 'DOLDU') bc = 'b-doldu';
        
        let btns = `<button class="btn-ghost btn-mini" onclick="viewDevices(${k.id})">📱 Cihazlar</button>
                    <button class="btn-ghost btn-mini" onclick="extendKey(${k.id})">⏱️ Uzat</button>`;
        if (isAdmin) {
            btns += k.is_banned 
                ? `<button class="btn-main btn-mini" style="background:#16a34a" onclick="keyAction(${k.id},'unban')">✅ Ban Aç</button>`
                : `<button class="btn-main btn-mini" style="background:#7f1d1d" onclick="keyAction(${k.id},'ban')">🚫 Banla</button>`;
        }
        btns += `<button class="btn-main btn-mini" style="background:#dc2626" onclick="delKey(${k.id})">🗑️ Sil</button>`;
        
        let devTxt = k.max_devices > 0 ? `${k.devices.length}/${k.max_devices}` : `${k.devices.length}/∞`;
        
        return `<div class="key-item">
            <div class="key-top">
                <span class="key-val">${esc(k.key_value)}</span>
                <span class="badge ${bc}">${k.durum}${extra}</span>
            </div>
            <div class="key-info">
                <span>⏳ ${fmtDur(k.duration_seconds)}</span>
                <span>⌛ ${fmtSec(k.kalan)}</span>
                <span>💻 ${devTxt}</span>
            </div>
            <div class="key-actions">${btns}</div>
        </div>`;
    }).join('');
}

async function delKey(id) { if (!confirm('Key silinsin mi?')) return; const d = await api('/api/key/' + id, { method: 'DELETE' }); if (d.status) toast('Key silindi.'); else toast(d.reason, 'error'); loadKeys(); }
async function extendKey(id) { const v = prompt('Kaç saat uzatılsın?', '24'); if (!v) return; const d = await api('/api/key/' + id + '/extend', { method: 'POST', body: JSON.stringify({ seconds: parseInt(v) * 3600 }) }); if (d.status) toast(d.reason); else toast(d.reason, 'error'); loadKeys(); }
async function keyAction(id, act) {
    if (act === 'ban') {
        const r = prompt('Ban sebebi:', 'Kural ihlali'); if (r === null) return;
        const d = await api('/api/key/' + id + '/ban', { method: 'POST', body: JSON.stringify({ reason: r }) });
        if (d.status) toast(d.reason); else toast(d.reason, 'error');
    } else {
        const d = await api('/api/key/' + id + '/unban', { method: 'POST' });
        if (d.status) toast(d.reason); else toast(d.reason, 'error');
    }
    loadKeys();
}

async function viewDevices(id) {
    const d = await api('/api/key/' + id + '/devices'); if (!d.status) { toast(d.reason, 'error'); return; }
    let maxTxt = d.max > 0 ? `${d.devices.length}/${d.max}` : `${d.devices.length}/∞`;
    let html = `<div class="modal-header"><h3>💻 Cihazlar (${maxTxt})</h3><div class="close-btn" onclick="closeModal()">✕</div></div>`;
    
    if (d.devices.length === 0) html += '<p style="color:#888;text-align:center;padding:20px">Henüz cihaz yok.</p>';
    else {
        html += '<div style="display:flex;flex-direction:column;gap:10px">';
        html += d.devices.map(x => `
            <div style="background:rgba(255,255,255,.05);padding:10px;border-radius:8px;border:1px solid rgba(220,38,38,.2)">
                <div style="font-family:monospace;color:#fca5a5;font-size:12px;word-break:break-all">${esc(x.hwid)}</div>
                <div style="font-size:11px;color:#9ca3af;margin-top:4px">IP: ${esc(x.ip || '-')} | Son: ${fmtTime(x.last_seen)}</div>
            </div>
        `).join('');
        html += '</div><button class="btn-main" style="margin-top:16px;background:#dc2626" onclick="resetDev(' + id + ')">🚨 Tüm Cihazları Sıfırla</button>';
    }
    showModal(html);
}

async function resetDev(id) {
    if (!confirm('Tüm cihazlar sıfırlansın mı?')) return;
    const d = await api('/api/key/' + id + '/reset-devices', { method: 'POST' });
    if (d.status) { toast(d.reason); closeModal(); loadKeys(); } else toast(d.reason, 'error');
}

// --- ADMİN İŞLEMLERİ ---
async function loadAdmin() {
    const s = await api('/api/admin/stats');
    if (s.status) { s_users.textContent = s.users; s_keys.textContent = s.keys; s_active.textContent = s.active; }
    
    const u = await api('/api/admin/users');
    if (u.status) {
        usrList.innerHTML = u.users.map(x => {
            let role = x.is_admin ? '<span class="badge b-aktif">ADMIN</span>' : '<span style="font-size:10px;color:#888">USER</span>';
            let st = x.is_banned ? '<span class="badge b-banli">BAN</span>' : '<span class="badge" style="background:#14532d;color:#86efac">AKTİF</span>';
            let btns = '';
            if (x.is_admin) { btns += `<button class="btn-ghost btn-mini" onclick="userAction(${x.id},'remove-admin')">Admin Kaldır</button>`; }
            else {
                btns += x.is_banned
                    ? `<button class="btn-main btn-mini" style="background:#16a34a" onclick="userAction(${x.id},'unban')">Ban Aç</button>`
                    : `<button class="btn-main btn-mini" style="background:#7f1d1d" onclick="userAction(${x.id},'ban')">Banla</button>`;
                btns += `<button class="btn-ghost btn-mini" onclick="userAction(${x.id},'make-admin')">Admin Yap</button>`;
                btns += `<button class="btn-main btn-mini" style="background:#dc2626" onclick="userAction(${x.id},'delete')">Sil</button>`;
            }
            return `<div class="user-item">
                <div class="user-info"><h3>${esc(x.username)} ${role}</h3><p>${st} • ${x.key_count} Key</p></div>
                <div class="user-actions">${btns}</div>
            </div>`;
        }).join('');
    }
    
    const l = await api('/api/admin/logs');
    if (l.status) logList.innerHTML = l.logs.map(x => `<div style="padding:4px 0;border-bottom:1px solid #222">[${fmtTime(x.created_at)}] <b style="color:#fca5a5">${esc(x.action)}</b> - ${esc(x.detail)}</div>`).join('');
}

async function userAction(id, act) {
    if (act === 'ban') {
        const r = prompt('Ban sebebi:'); if (r === null) return;
        const d = await api('/api/admin/user/' + id + '/ban', { method: 'POST', body: JSON.stringify({ reason: r }) });
        if (d.status) toast(d.reason); else toast(d.reason, 'error');
    } else if (act === 'delete') {
        if (!confirm('Kullanıcı silinsin mi?')) return;
        const d = await api('/api/admin/user/' + id + '/delete', { method: 'DELETE' });
        if (d.status) toast('Kullanıcı silindi.'); else toast(d.reason, 'error');
    } else {
        const d = await api('/api/admin/user/' + id + '/' + act, { method: 'POST' });
        if (d.status) toast('İşlem başarılı.'); else toast(d.reason, 'error');
    }
    loadAdmin();
}

async function addInvite() {
    const d = await api('/api/admin/invite', { method: 'POST', body: JSON.stringify({ code: i_code.value, max_uses: i_max.value }) });
    if (d.status) { i_code.value = ''; toast(d.reason); } else toast(d.reason, 'error');
}

// --- UI ARAÇLARI ---
function switchTab(t) {
    document.querySelectorAll('.tab-content').forEach(x => x.classList.remove('active'));
    document.getElementById('tab-' + t).classList.add('active');
    document.querySelectorAll('.nav-item').forEach(x => x.classList.remove('active'));
    document.getElementById('nav-' + t).classList.add('active');
    if (t === 'admin') loadAdmin(); else loadKeys();
}

function showModal(html) {
    const bg = document.createElement('div'); bg.className = 'modal-bg'; bg.id = 'modalBg';
    bg.onclick = (e) => { if (e.target === bg) closeModal(); };
    bg.innerHTML = '<div class="modal-content">' + html + '</div>';
    document.body.appendChild(bg);
}

function closeModal() { const m = document.getElementById('modalBg'); if (m) m.remove(); }

// --- BAŞLATMA ---
if (token) {
    showPanel();
}
</script>
</body></html>"""

@app.route('/')
def index():
    return Response(HTML, mimetype='text/html')

init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port)
