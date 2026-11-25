import os, time, sqlite3, hashlib, secrets, string, re
from functools import wraps
from flask import Flask, request, jsonify, g, Response
from flask_cors import CORS
import bcrypt, jwt

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

DATA_DIR = '/data' if os.path.isdir('/data') else os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DATA_DIR, 'wrox_final.db')

JWT_SECRET = os.environ.get('JWT_SECRET', 'WROX_SECRET_2025')
AUTH_SECRET = 'Vm8Lk7Uj2JmsjCPVPVjrLa7zgfx3uz9E'  # C++ İLE BİREBİR AYNI!
ADMIN_USER = 'WROX'            # 🔥 İSTEDİĞİN ADMİN KULLANICI ADI
ADMIN_PASS = 'Wroxtanrıgibi'   # 🔥 İSTEDİĞİN ADMİN ŞİFRESİ

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
      duration_seconds INTEGER NOT NULL, max_devices INTEGER DEFAULT 9999,
      created_at INTEGER DEFAULT (strftime('%s','now')), expires_at INTEGER,
      activated_at INTEGER, created_by TEXT, note TEXT, is_banned INTEGER DEFAULT 0, ban_reason TEXT
    );
    CREATE TABLE IF NOT EXISTS key_devices(
      id INTEGER PRIMARY KEY AUTOINCREMENT, key_id INTEGER NOT NULL, hwid TEXT NOT NULL, ip TEXT,
      first_seen INTEGER DEFAULT (strftime('%s','now')), last_seen INTEGER DEFAULT (strftime('%s','now')),
      UNIQUE(key_id, hwid), FOREIGN KEY(key_id) REFERENCES keys(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS invite_codes(code TEXT PRIMARY KEY, max_uses INTEGER DEFAULT 1, used INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, detail TEXT, ip TEXT, created_at INTEGER DEFAULT (strftime('%s','now')));
    ''')
    db.execute("INSERT OR IGNORE INTO invite_codes(code,max_uses) VALUES(?,999999)",('Wroxtanrıgibi',))
    if not db.execute("SELECT id FROM users WHERE is_admin=1").fetchone():
        h = bcrypt.hashpw(ADMIN_PASS.encode(), bcrypt.gensalt()).decode()
        db.execute("INSERT INTO users(username,password,is_admin) VALUES(?,?,1)",(ADMIN_USER,h))
    db.commit(); db.close()

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
        except: return jsonify({'status':False,'reason':'Yetkisiz'}),401
        return f(*a,**k)
    return w

def admin_required(f):
    @wraps(f)
    @auth_required
    def w(*a,**k):
        if not request.user.get('is_admin'): return jsonify({'status':False,'reason':'Admin değil'}),403
        return f(*a,**k)
    return w

@app.route('/api/register',methods=['POST'])
def register():
    d = request.json or {}; u,p,inv = d.get('username'),d.get('password'),d.get('invite')
    if not u or not p or not inv: return jsonify({'status':False,'reason':'Eksik alan'})
    db = get_db(); r = db.execute("SELECT * FROM invite_codes WHERE code=?",(inv,)).fetchone()
    if not r or r['used']>=r['max_uses']: return jsonify({'status':False,'reason':'Geçersiz davet kodu'})
    try:
        h = bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()
        db.execute("INSERT INTO users(username,password,invite_used) VALUES(?,?,?)",(u,h,inv))
        db.execute("UPDATE invite_codes SET used=used+1 WHERE code=?",(inv,))
        db.commit(); return jsonify({'status':True,'reason':'Kayıt başarılı'})
    except: return jsonify({'status':False,'reason':'Bu kullanıcı adı zaten alınmış'})

@app.route('/api/login',methods=['POST'])
def login():
    d = request.json or {}; db = get_db()
    u = db.execute("SELECT * FROM users WHERE username=?",(d.get('username'),)).fetchone()
    if not u or not bcrypt.checkpw((d.get('password') or '').encode(),u['password'].encode()): 
        return jsonify({'status':False,'reason':'Hatalı kullanıcı adı veya şifre'})
    if u['is_banned']: return jsonify({'status':False,'reason':f"Banlısınız: {u['ban_reason']}"})
    db.execute("UPDATE users SET last_login=? WHERE id=?", (int(time.time()), u['id'])); db.commit()
    tok = jwt.encode({'id':u['id'],'username':u['username'],'is_admin':bool(u['is_admin']),'exp':int(time.time())+7*86400},JWT_SECRET,algorithm='HS256')
    return jsonify({'status':True,'token':tok,'username':u['username'],'is_admin':bool(u['is_admin'])})

@app.route('/api/key/create',methods=['POST'])
@auth_required
def create_key():
    d = request.json or {}; t = d.get('type')
    cnt = min(max(int(d.get('count') or 1),1),200)
    md = 9999 # 🔥 CİHAZ LİMİTİ KALDIRILDI, C++ HATA VERMEZ
    pat, note = d.get('pattern'), d.get('note')
    if t=='özel':
        dur = int(d.get('days') or 0)*86400+int(d.get('hours') or 0)*3600+int(d.get('minutes') or 0)*60
        if dur<=0: return jsonify({'status':False,'reason':'Süre girin'})
    elif t in UNITS: dur = UNITS[t]
    else: return jsonify({'status':False,'reason':'Geçersiz tür'})
    db = get_db(); created = []
    for _ in range(cnt):
        kv = custom_key(pat) if pat else random_key()
        try:
            db.execute("INSERT INTO keys(key_value,duration_seconds,max_devices,created_by,note) VALUES(?,?,?,?,?)",(kv,dur,md,request.user['username'],note))
            created.append(kv)
        except: pass
    db.commit(); return jsonify({'status':True,'keys':created})

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
    if not k: return jsonify({'status':False,'reason':'Key yok'})
    db.execute("DELETE FROM key_devices WHERE key_id=?",(kid,)); db.execute("DELETE FROM keys WHERE id=?",(kid,)); db.commit()
    return jsonify({'status':True})

@app.route('/api/key/<int:kid>/reset-devices',methods=['POST'])
@auth_required
def reset_devices(kid):
    db = get_db(); db.execute("DELETE FROM key_devices WHERE key_id=?",(kid,)); db.commit()
    return jsonify({'status':True,'reason':'Cihazlar sıfırlandı'})

@app.route('/api/key/<int:kid>/extend',methods=['POST'])
@auth_required
def extend_key(kid):
    sec = int((request.json or {}).get('seconds') or 0); db = get_db()
    k = db.execute("SELECT * FROM keys WHERE id=?",(kid,)).fetchone()
    if not k or k['duration_seconds']==0: return jsonify({'status':False,'reason':'İşlem yapılamaz'})
    now = int(time.time()); base = k['expires_at'] if (k['expires_at'] and k['expires_at']>now) else now
    db.execute("UPDATE keys SET expires_at=? WHERE id=?",(base+sec,kid)); db.commit()
    return jsonify({'status':True,'reason':'Süre uzatıldı'})

@app.route('/api/key/<int:kid>/ban',methods=['POST'])
@admin_required
def key_ban(kid):
    reason = (request.json or {}).get('reason','Kural ihlali'); db = get_db()
    db.execute("UPDATE keys SET is_banned=1, ban_reason=? WHERE id=?",(reason,kid)); db.commit()
    return jsonify({'status':True,'reason':'Key banlandı'})

@app.route('/api/key/<int:kid>/unban',methods=['POST'])
@admin_required
def key_unban(kid):
    db = get_db(); db.execute("UPDATE keys SET is_banned=0, ban_reason=NULL WHERE id=?",(kid,)); db.commit()
    return jsonify({'status':True,'reason':'Ban açıldı'})

@app.route('/api/key/<int:kid>/devices',methods=['GET'])
@auth_required
def key_devices(kid):
    db = get_db(); k = db.execute("SELECT * FROM keys WHERE id=?",(kid,)).fetchone()
    devs = db.execute("SELECT * FROM key_devices WHERE key_id=? ORDER BY last_seen DESC",(kid,)).fetchall()
    return jsonify({'status':True,'devices':[dict(d) for d in devs]})

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
    if not u: return jsonify({'status':False,'reason':'Kullanıcı yok'})
    if action=='ban':
        if u['is_admin']: return jsonify({'status':False,'reason':'Admin banlanamaz'})
        db.execute("UPDATE users SET is_banned=1, ban_reason=? WHERE id=?",((request.json or {}).get('reason',''), uid))
    elif action=='unban': db.execute("UPDATE users SET is_banned=0 WHERE id=?",(uid,))
    elif action=='make-admin': db.execute("UPDATE users SET is_admin=1 WHERE id=?",(uid,))
    elif action=='remove-admin': db.execute("UPDATE users SET is_admin=0 WHERE id=?",(uid,))
    elif action=='delete':
        if u['is_admin']: return jsonify({'status':False,'reason':'Admin silinemez'})
        db.execute("DELETE FROM users WHERE id=?",(uid,))
    db.commit(); return jsonify({'status':True,'reason':'İşlem başarılı'})

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
        return jsonify({'status':True,'reason':'Eklendi'})
    except: return jsonify({'status':False,'reason':'Zaten var'})

# 🔥 C++ İLE %100 UYUMLU /connect
@app.route('/connect',methods=['POST', 'GET'])
def connect():
    if request.method == 'GET': return jsonify({'status':False, 'reason':'WROX: Sadece POST kabul edilir.'})
    user_key = request.form.get('user_key') or (request.json or {}).get('user_key')
    serial = request.form.get('serial') or (request.json or {}).get('serial') or 'unknown'
    game = request.form.get('game') or (request.json or {}).get('game') or 'PUBG'
    ip = request.remote_addr or ''
    if not user_key: return jsonify({'status':False,'reason':'Eksik user_key'})
    db = get_db(); k = db.execute("SELECT * FROM keys WHERE key_value=?",(user_key,)).fetchone()
    if not k: return jsonify({'status':False,'reason':'Key bulunamadı'})
    if k['is_banned']: return jsonify({'status':False,'reason':'Key banlı'})
    now = int(time.time())
    dev = db.execute("SELECT * FROM key_devices WHERE key_id=? AND hwid=?",(k['id'],serial)).fetchone()
    if not dev: db.execute("INSERT INTO key_devices(key_id,hwid,ip) VALUES(?,?,?)",(k['id'],serial,ip))
    else: db.execute("UPDATE key_devices SET last_seen=?, ip=? WHERE id=?",(now,ip,dev['id']))
    if not k['activated_at']:
        exp = None if k['duration_seconds']==0 else now+k['duration_seconds']
        db.execute("UPDATE keys SET activated_at=?, expires_at=? WHERE id=?",(now,exp,k['id']))
        k = dict(k); k['expires_at']=exp
    if k['expires_at'] is not None and now > k['expires_at']: return jsonify({'status':False,'reason':'Süre doldu'})
    token = hashlib.md5(f'{game}-{user_key}-{serial}-{AUTH_SECRET}'.encode()).hexdigest()
    db.commit(); return jsonify({'status':True,'data':{'token':token,'rng':now}})

# ---------- KUSURSUZ VENOM VIP TASARIMI ----------
HTML = r"""<!DOCTYPE html>
<html lang="tr"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>WROX VIP PANEL</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;font-family:'Segoe UI',sans-serif;-webkit-tap-highlight-color:transparent}
body{min-height:100vh;background:#050505;color:#fff;overflow-x:hidden;padding-bottom:80px}
#fx{position:fixed;inset:0;pointer-events:none;z-index:0}
.topbar{position:sticky;top:0;z-index:10;background:rgba(5,5,5,.95);backdrop-filter:blur(10px);padding:16px 20px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(220,38,38,.3);box-shadow:0 4px 20px rgba(220,38,38,0.15)}
.topbar h1{font-size:22px;font-weight:900;letter-spacing:4px;color:#dc2626;text-shadow:0 0 15px rgba(220,38,38,0.8);margin:0}
.user-pill{font-size:12px;background:rgba(220,38,38,.2);padding:6px 12px;border-radius:20px;border:1px solid rgba(220,38,38,.4);color:#fca5a5;font-weight:600}
.container{max-width:600px;margin:0 auto;padding:20px 16px;position:relative;z-index:1}
.card{background:rgba(15,15,15,.8);backdrop-filter:blur(12px);border:1px solid rgba(220,38,38,.2);border-radius:16px;padding:20px;margin-bottom:20px;box-shadow:0 8px 30px rgba(0,0,0,.8)}
.card h2{font-size:14px;color:#fca5a5;margin-bottom:16px;text-transform:uppercase;letter-spacing:1.5px;font-weight:800;border-left:3px solid #dc2626;padding-left:10px}
input,select,textarea{width:100%;padding:14px;border-radius:12px;border:1px solid rgba(220,38,38,.3);background:rgba(0,0,0,.7);color:#fff;font-size:15px;margin-bottom:12px;outline:none;transition:0.2s}
input:focus,select:focus{border-color:#dc2626;box-shadow:0 0 0 3px rgba(220,38,38,.2)}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
button{width:100%;padding:16px;border-radius:12px;border:none;font-weight:800;font-size:15px;cursor:pointer;transition:0.2s;display:flex;align-items:center;justify-content:center;gap:8px;letter-spacing:0.5px}
.btn-main{background:linear-gradient(135deg,#dc2626,#7f1d1d);color:#fff;box-shadow:0 6px 20px rgba(220,38,38,0.4)}
.btn-main:active{transform:scale(0.97)}
.btn-ghost{background:rgba(220,38,38,.1);color:#fca5a5;border:1px solid rgba(220,38,38,.4)}
.btn-mini{width:auto;padding:10px 14px;font-size:12px;border-radius:8px;font-weight:700}
.key-item{background:rgba(0,0,0,.6);border:1px solid rgba(220,38,38,.2);border-radius:14px;padding:16px;margin-bottom:12px;position:relative;overflow:hidden}
.key-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.key-val{font-family:monospace;color:#fca5a5;font-size:14px;font-weight:800;letter-spacing:1px;word-break:break-all}
.badge{font-size:11px;padding:5px 10px;border-radius:6px;font-weight:900;text-transform:uppercase;letter-spacing:0.5px}
.b-aktif{background:#450a0a;color:#fca5a5;border:1px solid #dc2626;box-shadow:0 0 10px rgba(220,38,38,0.6)}
.b-beklemede{background:#422006;color:#fbbf24;border:1px solid #d97706}
.b-doldu{background:#1f2937;color:#9ca3af;border:1px solid #4b5563}
.b-banli{background:#7f1d1d;color:#fecaca;border:1px solid #ef4444}
.key-info{display:flex;gap:16px;font-size:12px;color:#9ca3af;margin-bottom:14px;font-weight:600}
.key-actions{display:flex;gap:8px;flex-wrap:wrap}
.key-actions button{flex:1;padding:10px;font-size:11px}
.bottom-nav{position:fixed;bottom:0;left:0;right:0;z-index:50;background:rgba(5,5,5,.98);backdrop-filter:blur(20px);border-top:1px solid rgba(220,38,38,.4);display:flex;justify-content:space-around;padding:12px 0 24px 0}
.nav-item{display:flex;flex-direction:column;align-items:center;gap:6px;color:#6b7280;font-size:11px;font-weight:800;cursor:pointer;transition:0.2s;flex:1}
.nav-item.active{color:#dc2626;text-shadow:0 0 12px rgba(220,38,38,0.9)}
.nav-item i{font-size:24px;font-style:normal}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.95);backdrop-filter:blur(6px);z-index:100;display:flex;align-items:flex-end;justify-content:center}
.modal-content{background:#0f0f0f;width:100%;max-width:600px;border-radius:24px 24px 0 0;padding:24px;max-height:85vh;overflow-y:auto;border-top:3px solid #dc2626;animation:slideUp 0.3s ease-out}
@keyframes slideUp{from{transform:translateY(100%)}to{transform:translateY(0)}}
.modal-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;padding-bottom:16px;border-bottom:1px solid rgba(220,38,38,.3)}
.modal-header h3{font-size:18px;color:#fca5a5;text-shadow:0 0 8px rgba(220,38,38,0.6)}
.close-btn{background:rgba(255,255,255,.1);width:36px;height:36px;border-radius:50%;display:flex;align-items:center;justify-content:center;cursor:pointer;color:#fff;font-size:18px}
.tab-content{display:none;animation:fadeIn 0.3s}
.tab-content.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.hidden{display:none!important}
.msg{font-size:13px;margin-top:10px;color:#fca5a5;text-align:center;font-weight:700}
.msg.ok{color:#86efac}
.footer{text-align:center;font-size:11px;color:#374151;margin-top:40px;letter-spacing:5px;font-weight:900}
.user-item{background:rgba(0,0,0,.6);border:1px solid rgba(220,38,38,.2);border-radius:14px;padding:16px;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center}
.user-info h3{font-size:15px;margin-bottom:6px;color:#fff;font-weight:700}
.user-info p{font-size:12px;color:#9ca3af;font-weight:600}
.user-actions{display:flex;flex-direction:column;gap:8px}
.user-actions button{padding:8px 12px;font-size:11px;width:auto}
@media(max-width:400px){.grid-3{grid-template-columns:1fr}}
</style></head>
<body><canvas id="fx"></canvas>
<div class="topbar"><h1>WROX VIP</h1><div id="userBar" class="hidden"><span id="uname" class="user-pill"></span></div></div>
<div class="container">
  <div id="authTab">
    <div class="card"><h2>Giriş Yap</h2>
      <input id="l_u" placeholder="Kullanıcı Adı"><input id="l_p" type="password" placeholder="Şifre">
      <button class="btn-main" onclick="login()">🚀 GİRİŞ YAP</button><div id="authMsg" class="msg"></div>
    </div>
    <div class="card"><h2>Kayıt Ol</h2>
      <input id="r_u" placeholder="Kullanıcı Adı"><input id="r_p" type="password" placeholder="Şifre">
      <input id="r_i" placeholder="Davet Kodu (Wroxtanrıgibi)">
      <button class="btn-ghost" onclick="register()">📝 KAYIT OL</button>
    </div>
  </div>
  <div id="mainPanel" class="hidden">
    <div id="tab-keys" class="tab-content active">
      <div class="card"><h2>Key Oluştur</h2>
        <div class="grid-2">
          <select id="k_type" onchange="toggleCustom()">
            <option value="dakika">Dakikalık</option><option value="saat">Saatlik</option>
            <option value="günlük">Günlük</option><option value="haftalık">Haftalık</option>
            <option value="aylık">Aylık</option><option value="sınırsız">Sınırsız</option>
            <option value="özel">Özel Süre</option>
          </select>
          <input id="k_count" type="number" value="1" min="1" placeholder="Adet">
        </div>
        <div id="customTime" class="grid-3 hidden">
          <input id="k_d" type="number" placeholder="Gün" min="0" value="0">
          <input id="k_h" type="number" placeholder="Saat" min="0" value="0">
          <input id="k_m" type="number" placeholder="Dakika" min="0" value="0">
        </div>
        <input id="k_pattern" placeholder="Özel Format (WROX-{random8})">
        <input id="k_note" placeholder="Not (opsiyonel)">
        <button class="btn-main" onclick="createKey()">🔑 KEY ÜRET</button><div id="newKeys" class="msg ok"></div>
      </div>
      <div id="kList"></div>
    </div>
    <div id="tab-admin" class="tab-content">
      <div class="grid-3" style="margin-bottom:16px">
        <div class="card" style="text-align:center;padding:16px"><h2 style="margin:0;font-size:24px;color:#dc2626;border:none;padding:0" id="s_users">-</h2><span style="font-size:11px;color:#9ca3af;font-weight:700">KULLANICI</span></div>
        <div class="card" style="text-align:center;padding:16px"><h2 style="margin:0;font-size:24px;color:#dc2626;border:none;padding:0" id="s_keys">-</h2><span style="font-size:11px;color:#9ca3af;font-weight:700">KEY</span></div>
        <div class="card" style="text-align:center;padding:16px"><h2 style="margin:0;font-size:24px;color:#dc2626;border:none;padding:0" id="s_active">-</h2><span style="font-size:11px;color:#9ca3af;font-weight:700">AKTİF</span></div>
      </div>
      <div class="card"><h2>Davet Kodu Ekle</h2>
        <div class="grid-2"><input id="i_code" placeholder="Kod"><input id="i_max" type="number" value="10" placeholder="Max"></div>
        <button class="btn-ghost" onclick="addInvite()">➕ EKLE</button>
      </div>
      <h2 style="font-size:14px;color:#fca5a5;margin:20px 0 12px;text-transform:uppercase;letter-spacing:1.5px;border-left:3px solid #dc2626;padding-left:10px;font-weight:800">Kullanıcılar</h2>
      <div id="usrList"></div>
    </div>
  </div>
  <div class="footer">WROX VIP PANEL</div>
</div>
<div id="bottomNav" class="bottom-nav hidden">
  <div class="nav-item active" id="nav-keys" onclick="switchTab('keys')"><i>🔑</i><span>KEYLER</span></div>
  <div class="nav-item hidden" id="nav-admin" onclick="switchTab('admin')"><i>🛡️</i><span>ADMİN</span></div>
  <div class="nav-item" onclick="logout()"><i>🚪</i><span>ÇIKIŞ</span></div>
</div>
<script>
const API=location.origin;
let token=localStorage.getItem('wrox_token'), isAdmin=false;
const cv=document.getElementById('fx'),ctx=cv.getContext('2d');
let W,H,ps=[];
function rs(){W=cv.width=innerWidth;H=cv.height=innerHeight;init();}
function init(){ps=[];const n=Math.floor(W/18);for(let i=0;i<n;i++){const s=Math.random()>.5;ps.push({x:Math.random()*W,y:Math.random()*H,r:s?Math.random()*2+1:Math.random()*1.5+.5,vy:s?Math.random()*1+.5:Math.random()*6+6,vx:s?Math.random()*.6-.3:-1,s});}}
function draw(){ctx.clearRect(0,0,W,H);for(const p of ps){if(p.s){ctx.fillStyle='rgba(220,235,255,.6)';ctx.beginPath();ctx.arc(p.x,p.y,p.r,0,7);ctx.fill();}else{ctx.strokeStyle='rgba(220,38,38,.6)';ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(p.x,p.y);ctx.lineTo(p.x-2,p.y+12);ctx.stroke();}p.x+=p.vx;p.y+=p.vy;if(p.y>H){p.y=-10;p.x=Math.random()*W;}if(p.x<0)p.x=W;}requestAnimationFrame(draw);}
addEventListener('resize',rs);rs();draw();
async function api(p,o={}){o.headers=Object.assign({'Content-Type':'application/json'},o.headers||{});if(token)o.headers.Authorization='Bearer '+token;try{const r=await fetch(API+p,o);return await r.json();}catch(e){return {status:false,reason:'Bağlantı hatası'};}}
function showMsg(el,m,ok){el.textContent=m;el.className='msg'+(ok?' ok':'');}
function toggleCustom(){document.getElementById('customTime').classList.toggle('hidden',k_type.value!=='özel');}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
async function login(){showMsg(authMsg,'Bağlanıyor...',true);const d=await api('/api/login',{method:'POST',body:JSON.stringify({username:l_u.value,password:l_p.value})});if(d.status){token=d.token;isAdmin=d.is_admin;localStorage.setItem('wrox_token',token);showPanel();}else showMsg(authMsg,d.reason);}
async function register(){showMsg(authMsg,'Kayıt olunuyor...',true);const d=await api('/api/register',{method:'POST',body:JSON.stringify({username:r_u.value,password:r_p.value,invite:r_i.value})});showMsg(authMsg,d.reason,d.status);}
function logout(){token=null;localStorage.removeItem('wrox_token');location.reload();}
async function createKey(){showMsg(newKeys,'Oluşturuluyor...',true);const body={type:k_type.value,count:k_count.value,pattern:k_pattern.value||undefined,note:k_note.value||undefined};if(k_type.value==='özel'){body.days=k_d.value;body.hours=k_h.value;body.minutes=k_m.value;}const d=await api('/api/key/create',{method:'POST',body:JSON.stringify(body)});if(d.status){newKeys.innerHTML=d.keys.map(k=>'<div style="font-family:monospace;color:#fca5a5;padding:4px 0;font-size:14px">'+k+'</div>').join('');loadKeys();}else showMsg(newKeys,d.reason);}
function fmtSec(s){if(s==='∞')return'∞';s=+s;if(s<60)return s+'s';if(s<3600)return Math.floor(s/60)+'dk';if(s<86400)return Math.floor(s/3600)+'sa';return Math.floor(s/86400)+'g';}
function fmtDur(s){if(s===0)return'∞';return fmtSec(s);}
function fmtTime(t){if(!t)return'-';const d=new Date(t*1000);return d.toLocaleDateString('tr-TR')+' '+d.toLocaleTimeString('tr-TR',{hour:'2-digit',minute:'2-digit'});}
async function loadKeys(){const d=await api('/api/key/list');if(!d.status)return;kList.innerHTML=d.keys.map(k=>{let bc='b-beklemede', extra='';if(k.is_banned){bc='b-banli';extra=' '+esc(k.ban_reason||'');}else if(k.durum==='AKTİF'||k.durum==='SINIRSIZ')bc='b-aktif';else if(k.durum==='DOLDU')bc='b-doldu';let btns=`<button class="btn-ghost btn-mini" onclick="viewDevices(${k.id})">📱 Cihazlar</button><button class="btn-ghost btn-mini" onclick="extendKey(${k.id})">⏱️ Uzat</button>`;if(isAdmin){btns+=k.is_banned?`<button class="btn-main btn-mini" style="background:#16a34a" onclick="keyAction(${k.id},'unban')">✅ Ban Aç</button>`:`<button class="btn-main btn-mini" style="background:#7f1d1d" onclick="keyAction(${k.id},'ban')">🚫 Banla</button>`;}btns+=`<button class="btn-main btn-mini" style="background:#dc2626" onclick="delKey(${k.id})">🗑️ Sil</button>`;return `<div class="key-item"><div class="key-top"><span class="key-val">${esc(k.key_value)}</span><span class="badge ${bc}">${k.durum}${extra}</span></div><div class="key-info"><span>⏳ ${fmtDur(k.duration_seconds)}</span><span>⌛ ${fmtSec(k.kalan)}</span><span>💻 ${k.devices.length}</span></div><div class="key-actions">${btns}</div></div>`;}).join('');}
async function delKey(id){if(!confirm('Key silinsin mi?'))return;const d=await api('/api/key/'+id,{method:'DELETE'});if(!d.status)alert(d.reason);loadKeys();}
async function extendKey(id){const v=prompt('Kaç saat uzatılsın?','24');if(!v)return;const d=await api('/api/key/'+id+'/extend',{method:'POST',body:JSON.stringify({seconds:parseInt(v)*3600})});alert(d.reason||'OK');loadKeys();}
async function keyAction(id, act){if(act==='ban'){const r=prompt('Ban sebebi:','Kural ihlali');if(r===null)return;await api('/api/key/'+id+'/ban',{method:'POST',body:JSON.stringify({reason:r})});}else{await api('/api/key/'+id+'/unban',{method:'POST'});}loadKeys();}
async function viewDevices(id){const d=await api('/api/key/'+id+'/devices');if(!d.status){alert(d.reason);return;}let html=`<div class="modal-header"><h3>💻 Cihazlar</h3><div class="close-btn" onclick="closeModal()">✕</div></div>`;if(d.devices.length===0)html+='<p style="color:#888;text-align:center;padding:20px">Henüz cihaz yok.</p>';else{html+='<div style="display:flex;flex-direction:column;gap:10px">';html+=d.devices.map(x=>`<div style="background:rgba(255,255,255,.05);padding:10px;border-radius:8px;border:1px solid rgba(220,38,38,.2)"><div style="font-family:monospace;color:#fca5a5;font-size:12px;word-break:break-all">${esc(x.hwid)}</div><div style="font-size:11px;color:#9ca3af;margin-top:4px">IP: ${esc(x.ip||'-')} | Son: ${fmtTime(x.last_seen)}</div></div>`).join('');html+='</div><button class="btn-main" style="margin-top:16px;background:#dc2626" onclick="resetDev('+id+')">🚨 Tüm Cihazları Sıfırla</button>';}showModal(html);}
async function resetDev(id){if(!confirm('Tüm cihazlar sıfırlansın mı?'))return;const d=await api('/api/key/'+id+'/reset-devices',{method:'POST'});alert(d.reason||'OK');closeModal();loadKeys();}
async function loadAdmin(){const s=await api('/api/admin/stats');if(s.status){s_users.textContent=s.users;s_keys.textContent=s.keys;s_active.textContent=s.active;}const u=await api('/api/admin/users');if(u.status){usrList.innerHTML=u.users.map(x=>{let role=x.is_admin?'<span class="badge b-aktif">ADMIN</span>':'<span style="font-size:10px;color:#888">USER</span>';let st=x.is_banned?'<span class="badge b-banli">BAN</span>':'<span class="badge" style="background:#14532d;color:#86efac">AKTİF</span>';let btns='';if(x.is_admin){btns+=`<button class="btn-ghost btn-mini" onclick="userAction(${x.id},'remove-admin')">Admin Kaldır</button>`;}else{btns+=x.is_banned?`<button class="btn-main btn-mini" style="background:#16a34a" onclick="userAction(${x.id},'unban')">Ban Aç</button>`:`<button class="btn-main btn-mini" style="background:#7f1d1d" onclick="userAction(${x.id},'ban')">Banla</button>`;btns+=`<button class="btn-ghost btn-mini" onclick="userAction(${x.id},'make-admin')">Admin Yap</button>`;btns+=`<button class="btn-main btn-mini" style="background:#dc2626" onclick="userAction(${x.id},'delete')">Sil</button>`;}return `<div class="user-item"><div class="user-info"><h3>${esc(x.username)} ${role}</h3><p>${st} • ${x.key_count} Key</p></div><div class="user-actions">${btns}</div></div>`;}).join('');}}
async function userAction(id, act){if(act==='ban'){const r=prompt('Ban sebebi:');if(r===null)return;await api('/api/admin/user/'+id+'/ban',{method:'POST',body:JSON.stringify({reason:r})});}else if(act==='delete'){if(!confirm('Kullanıcı silinsin mi?'))return;await api('/api/admin/user/'+id+'/delete',{method:'DELETE'});}else{await api('/api/admin/user/'+id+'/'+act,{method:'POST'});}loadAdmin();}
async function addInvite(){const d=await api('/api/admin/invite',{method:'POST',body:JSON.stringify({code:i_code.value,max_uses:i_max.value})});if(d.status){i_code.value='';alert('Eklendi');}else alert(d.reason);}
function switchTab(t){document.querySelectorAll('.tab-content').forEach(x=>x.classList.remove('active'));document.getElementById('tab-'+t).classList.add('active');document.querySelectorAll('.nav-item').forEach(x=>x.classList.remove('active'));document.getElementById('nav-'+t).classList.add('active');if(t==='admin')loadAdmin();else loadKeys();}
function showModal(html){const bg=document.createElement('div');bg.className='modal-bg';bg.id='modalBg';bg.onclick=(e)=>{if(e.target===bg)closeModal();};bg.innerHTML='<div class="modal-content">'+html+'</div>';document.body.appendChild(bg);}
function closeModal(){const m=document.getElementById('modalBg');if(m)m.remove();}
function showPanel(){document.getElementById('authTab').classList.add('hidden');document.getElementById('mainPanel').classList.remove('hidden');document.getElementById('bottomNav').classList.remove('hidden');document.getElementById('userBar').classList.remove('hidden');const p=JSON.parse(atob(token.split('.')[1]));uname.textContent=p.username;if(p.is_admin){isAdmin=true;document.getElementById('nav-admin').classList.remove('hidden');}loadKeys();}
if(token)showPanel();
</script></body></html>"""

@app.route('/')
def index():
    return Response(HTML, mimetype='text/html')

init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port)
