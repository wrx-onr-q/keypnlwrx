import os, time, sqlite3, hashlib, secrets, string, re
from functools import wraps
from flask import Flask, request, jsonify, g, Response
from flask_cors import CORS
import bcrypt, jwt

app = Flask(__name__)
CORS(app)

DATA_DIR = '/data' if os.path.isdir('/data') else os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DATA_DIR, 'wrox.db')

JWT_SECRET = os.environ.get('JWT_SECRET', 'WROX_SECRET_DEGISTIR_2025')
AUTH_SECRET = 'Vm8Lk7Uj2JmsjCPVPVjrLa7zgfx3uz9E'  # C++ ile AYNI, DEĞİŞTİRME
ADMIN_USER = os.environ.get('ADMIN_USER', 'WROX')
ADMIN_PASS = os.environ.get('ADMIN_PASS', 'Wroxtanrıgibi')

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
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password TEXT NOT NULL,is_admin INTEGER DEFAULT 0,invite_used TEXT,created_at INTEGER DEFAULT (strftime('%s','now')));
    CREATE TABLE IF NOT EXISTS keys(id INTEGER PRIMARY KEY AUTOINCREMENT,key_value TEXT UNIQUE NOT NULL,duration_seconds INTEGER NOT NULL,max_devices INTEGER DEFAULT 1,created_at INTEGER DEFAULT (strftime('%s','now')),expires_at INTEGER,activated_at INTEGER,created_by TEXT,note TEXT);
    CREATE TABLE IF NOT EXISTS key_devices(id INTEGER PRIMARY KEY AUTOINCREMENT,key_id INTEGER NOT NULL,hwid TEXT NOT NULL,first_seen INTEGER DEFAULT (strftime('%s','now')),last_seen INTEGER DEFAULT (strftime('%s','now')),UNIQUE(key_id,hwid),FOREIGN KEY(key_id) REFERENCES keys(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS invite_codes(code TEXT PRIMARY KEY,max_uses INTEGER DEFAULT 1,used INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY AUTOINCREMENT,action TEXT,detail TEXT,ip TEXT,created_at INTEGER DEFAULT (strftime('%s','now')));
    ''')
    db.execute("INSERT OR IGNORE INTO invite_codes(code,max_uses) VALUES(?,999999)",('Wroxtanrıgibi',))
    if not db.execute("SELECT id FROM users WHERE is_admin=1").fetchone():
        h = bcrypt.hashpw(ADMIN_PASS.encode(), bcrypt.gensalt()).decode()
        db.execute("INSERT INTO users(username,password,is_admin) VALUES(?,?,1)",(ADMIN_USER,h))
        print(f'> WROX Admin: {ADMIN_USER} / {ADMIN_PASS}')
    db.commit(); db.close()

def random_key(prefix='WROX'):
    seg = lambda n: ''.join(secrets.choice(CHARS) for _ in range(n))
    return f"{prefix}-{seg(6)}-{seg(6)}-{seg(6)}-{seg(6)}"

def custom_key(p):
    return re.sub(r'\{random(\d+)?\}', lambda m: ''.join(secrets.choice(CHARS) for _ in range(int(m.group(1)) if m.group(1) else 6)), p)

def log_action(db, a, d='', ip=''):
    try: db.execute("INSERT INTO logs(action,detail,ip) VALUES(?,?,?)",(a,d or '',ip or ''))
    except: pass

def auth_required(f):
    @wraps(f)
    def w(*a,**k):
        t = (request.headers.get('Authorization') or '').replace('Bearer ','')
        try: request.user = jwt.decode(t, JWT_SECRET, algorithms=['HS256'])
        except: return jsonify({'status':False,'reason':'WROX: Yetkisiz'}),401
        return f(*a,**k)
    return w

def admin_required(f):
    @wraps(f)
    @auth_required
    def w(*a,**k):
        if not request.user.get('is_admin'): return jsonify({'status':False,'reason':'WROX: Admin değil'}),403
        return f(*a,**k)
    return w

# ---------- AUTH ----------
@app.route('/api/register',methods=['POST'])
def register():
    d = request.json or {}
    u,p,inv = d.get('username'),d.get('password'),d.get('invite')
    if not u or not p or not inv: return jsonify({'status':False,'reason':'WROX: Eksik alan'})
    db = get_db()
    r = db.execute("SELECT * FROM invite_codes WHERE code=?",(inv,)).fetchone()
    if not r or r['used']>=r['max_uses']: return jsonify({'status':False,'reason':'WROX: Geçersiz davet kodu'})
    try:
        h = bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()
        db.execute("INSERT INTO users(username,password,invite_used) VALUES(?,?,?)",(u,h,inv))
        db.execute("UPDATE invite_codes SET used=used+1 WHERE code=?",(inv,))
        log_action(db,'WROX_register',u,request.remote_addr); db.commit()
        return jsonify({'status':True,'reason':'WROX: Kayıt başarılı'})
    except sqlite3.IntegrityError: return jsonify({'status':False,'reason':'WROX: Kullanıcı zaten var'})

@app.route('/api/login',methods=['POST'])
def login():
    d = request.json or {}
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE username=?",(d.get('username'),)).fetchone()
    if not u or not bcrypt.checkpw((d.get('password') or '').encode(),u['password'].encode()):
        return jsonify({'status':False,'reason':'WROX: Hatalı bilgi'})
    tok = jwt.encode({'id':u['id'],'username':u['username'],'is_admin':bool(u['is_admin']),'exp':int(time.time())+7*86400},JWT_SECRET,algorithm='HS256')
    log_action(db,'WROX_login',u['username'],request.remote_addr); db.commit()
    return jsonify({'status':True,'token':tok,'username':u['username'],'is_admin':bool(u['is_admin'])})

# ---------- KEY ----------
@app.route('/api/key/create',methods=['POST'])
@auth_required
def create_key():
    d = request.json or {}
    t = d.get('type')
    cnt = min(max(int(d.get('count') or 1),1),200)
    md = min(max(int(d.get('max_devices') or 1),1),50)
    pat = d.get('pattern'); note = d.get('note') or None
    if t=='özel':
        dur = int(d.get('days') or 0)*86400+int(d.get('hours') or 0)*3600+int(d.get('minutes') or 0)*60
        if dur<=0: return jsonify({'status':False,'reason':'WROX: Süre girin'})
    elif t in UNITS: dur = UNITS[t]
    else: return jsonify({'status':False,'reason':'WROX: Geçersiz tür'})
    db = get_db(); created = []
    for _ in range(cnt):
        kv = custom_key(pat) if pat else random_key()
        try:
            db.execute("INSERT INTO keys(key_value,duration_seconds,max_devices,created_by,note) VALUES(?,?,?,?,?)",(kv,dur,md,request.user['username'],note))
            created.append(kv)
        except sqlite3.IntegrityError: pass
    log_action(db,'WROX_key_create',f"{len(created)} adet ({t})",request.remote_addr); db.commit()
    return jsonify({'status':True,'keys':created,'duration':dur,'max_devices':md})

@app.route('/api/key/list',methods=['GET'])
@auth_required
def list_keys():
    db = get_db()
    rows = db.execute("SELECT * FROM keys ORDER BY id DESC").fetchall() if request.user.get('is_admin') else db.execute("SELECT * FROM keys WHERE created_by=? ORDER BY id DESC",(request.user['username'],)).fetchall()
    now = int(time.time()); out = []
    for k in rows:
        devs = db.execute("SELECT hwid,first_seen,last_seen FROM key_devices WHERE key_id=?",(k['id'],)).fetchall()
        if k['activated_at']:
            if k['expires_at'] is None: durum,kalan = 'sınırsız','∞'
            elif k['expires_at']<now: durum,kalan = 'doldu',0
            else: durum,kalan = 'aktif',k['expires_at']-now
        else:
            durum = 'beklemede'
            kalan = '∞' if k['duration_seconds']==0 else k['duration_seconds']
        out.append({**dict(k),'durum':durum,'kalan':kalan,'devices':[dict(x) for x in devs]})
    return jsonify({'status':True,'keys':out})

@app.route('/api/key/<int:kid>',methods=['DELETE'])
@auth_required
def delete_key(kid):
    db = get_db()
    k = db.execute("SELECT * FROM keys WHERE id=?",(kid,)).fetchone()
    if not k: return jsonify({'status':False,'reason':'WROX: Key yok'})
    if not request.user.get('is_admin') and k['created_by']!=request.user['username']: return jsonify({'status':False,'reason':'WROX: Yetkisiz'})
    db.execute("DELETE FROM key_devices WHERE key_id=?",(kid,))
    db.execute("DELETE FROM keys WHERE id=?",(kid,)); db.commit()
    return jsonify({'status':True,'reason':'WROX: Key silindi'})

@app.route('/api/key/<int:kid>/reset-devices',methods=['POST'])
@auth_required
def reset_devices(kid):
    db = get_db()
    k = db.execute("SELECT * FROM keys WHERE id=?",(kid,)).fetchone()
    if not k: return jsonify({'status':False,'reason':'WROX: Key yok'})
    if not request.user.get('is_admin') and k['created_by']!=request.user['username']: return jsonify({'status':False,'reason':'WROX: Yetkisiz'})
    db.execute("DELETE FROM key_devices WHERE key_id=?",(kid,)); db.commit()
    return jsonify({'status':True,'reason':'WROX: Cihazlar sıfırlandı'})

@app.route('/api/key/<int:kid>/extend',methods=['POST'])
@auth_required
def extend_key(kid):
    d = request.json or {}
    sec = int(d.get('seconds') or 0)
    db = get_db()
    k = db.execute("SELECT * FROM keys WHERE id=?",(kid,)).fetchone()
    if not k: return jsonify({'status':False,'reason':'WROX: Key yok'})
    if not request.user.get('is_admin') and k['created_by']!=request.user['username']: return jsonify({'status':False,'reason':'WROX: Yetkisiz'})
    if k['duration_seconds']==0: return jsonify({'status':False,'reason':'WROX: Sınırsız key uzatılamaz'})
    now = int(time.time()); base = k['expires_at'] if (k['expires_at'] and k['expires_at']>now) else now
    new_exp = base+sec
    db.execute("UPDATE keys SET expires_at=? WHERE id=?",(new_exp,kid)); db.commit()
    return jsonify({'status':True,'expires_at':new_exp})

# ---------- ADMIN ----------
@app.route('/api/admin/users',methods=['GET'])
@admin_required
def admin_users():
    db = get_db()
    rows = db.execute("SELECT id,username,is_admin,created_at,invite_used FROM users ORDER BY id DESC").fetchall()
    return jsonify({'status':True,'users':[dict(r) for r in rows]})

@app.route('/api/admin/invites',methods=['GET'])
@admin_required
def admin_invites():
    db = get_db()
    return jsonify({'status':True,'invites':[dict(r) for r in db.execute("SELECT * FROM invite_codes").fetchall()]})

@app.route('/api/admin/invite',methods=['POST'])
@admin_required
def admin_add_invite():
    d = request.json or {}
    code, mx = d.get('code'), int(d.get('max_uses') or 10)
    if not code: return jsonify({'status':False,'reason':'WROX: Kod boş'})
    db = get_db()
    try:
        db.execute("INSERT INTO invite_codes(code,max_uses) VALUES(?,?)",(code,mx)); db.commit()
        return jsonify({'status':True,'reason':'WROX: Davet eklendi'})
    except sqlite3.IntegrityError: return jsonify({'status':False,'reason':'WROX: Kod zaten var'})

@app.route('/api/admin/logs',methods=['GET'])
@admin_required
def admin_logs():
    db = get_db()
    return jsonify({'status':True,'logs':[dict(r) for r in db.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 200").fetchall()]})

@app.route('/api/admin/stats',methods=['GET'])
@admin_required
def admin_stats():
    db = get_db()
    return jsonify({'status':True,
        'users':db.execute("SELECT COUNT(*) c FROM users").fetchone()['c'],
        'keys':db.execute("SELECT COUNT(*) c FROM keys").fetchone()['c'],
        'active':db.execute("SELECT COUNT(*) c FROM keys WHERE activated_at IS NOT NULL AND (expires_at IS NULL OR expires_at>?)",(int(time.time()),)).fetchone()['c'],
        'devices':db.execute("SELECT COUNT(*) c FROM key_devices").fetchone()['c']})

# ---------- WROX /connect (C++ UYUMLU) ----------
@app.route('/connect',methods=['POST'])
def connect():
    user_key = request.form.get('user_key') or (request.json or {}).get('user_key')
    serial = request.form.get('serial') or (request.json or {}).get('serial') or 'unknown'
    game = request.form.get('game') or (request.json or {}).get('game') or 'PUBG'
    ip = request.remote_addr or ''
    if not user_key: return jsonify({'status':False,'reason':'WROX: Eksik user_key'})
    db = get_db()
    k = db.execute("SELECT * FROM keys WHERE key_value=?",(user_key,)).fetchone()
    if not k:
        log_action(db,'WROX_connect_fail',f'{user_key} (bulunamadı)',ip); db.commit()
        return jsonify({'status':False,'reason':'WROX: Key bulunamadı'})
    now = int(time.time())
    dev = db.execute("SELECT * FROM key_devices WHERE key_id=? AND hwid=?",(k['id'],serial)).fetchone()
    if not dev:
        c = db.execute("SELECT COUNT(*) c FROM key_devices WHERE key_id=?",(k['id'],)).fetchone()['c']
        if c >= k['max_devices']:
            log_action(db,'WROX_connect_fail',f'{user_key} (limit {c}/{k["max_devices"]})',ip); db.commit()
            return jsonify({'status':False,'reason':f'WROX: Cihaz limiti dolu ({c}/{k["max_devices"]})'})
        db.execute("INSERT INTO key_devices(key_id,hwid) VALUES(?,?)",(k['id'],serial))
    else:
        db.execute("UPDATE key_devices SET last_seen=? WHERE id=?",(now,dev['id']))
    if not k['activated_at']:
        exp = None if k['duration_seconds']==0 else now+k['duration_seconds']
        db.execute("UPDATE keys SET activated_at=?, expires_at=? WHERE id=?",(now,exp,k['id']))
        k = dict(k); k['activated_at']=now; k['expires_at']=exp
        log_action(db,'WROX_activate',f'{user_key} ({k["duration_seconds"]}sn)',ip)
    if k['expires_at'] is not None and now > k['expires_at']:
        log_action(db,'WROX_connect_fail',f'{user_key} (süre doldu)',ip); db.commit()
        return jsonify({'status':False,'reason':'WROX: Key süresi dolmuş'})
    token = hashlib.md5(f'{game}-{user_key}-{serial}-{AUTH_SECRET}'.encode()).hexdigest()
    log_action(db,'WROX_connect_ok',f'{user_key} @{serial[:12]}',ip); db.commit()
    return jsonify({'status':True,'data':{'token':token,'rng':now}})

# ---------- WROX FRONTEND ----------
HTML = r"""<!DOCTYPE html>
<html lang="tr"><head><meta charset="UTF-8"><title>WROX Key Panel</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;font-family:'Segoe UI',sans-serif}
body{min-height:100vh;background:#0b0f1a;color:#e8eefc;overflow-x:hidden}
#fx{position:fixed;inset:0;pointer-events:none;z-index:0}
.wrap{position:relative;z-index:2;max-width:1100px;margin:0 auto;padding:24px 16px}
header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;flex-wrap:wrap;gap:10px}
h1{font-size:26px;letter-spacing:2px;background:linear-gradient(90deg,#7dd3fc,#a78bfa);-webkit-background-clip:text;color:transparent;font-weight:900}
h2{font-size:18px;margin-bottom:12px;color:#a5b4fc}
.card{background:rgba(20,28,45,.78);backdrop-filter:blur(14px);border:1px solid rgba(120,160,255,.15);border-radius:14px;padding:18px;margin-bottom:16px;box-shadow:0 8px 30px rgba(0,0,0,.4)}
input,select,button{width:100%;padding:10px 12px;border-radius:9px;border:1px solid rgba(120,160,255,.25);background:rgba(10,15,28,.9);color:#e8eefc;font-size:14px;margin:5px 0;outline:none}
input:focus,select:focus{border-color:#7dd3fc}
button{background:linear-gradient(90deg,#2563eb,#7c3aed);border:none;cursor:pointer;font-weight:600;transition:.2s}
button:hover{filter:brightness(1.15)}
button.danger{background:linear-gradient(90deg,#dc2626,#b91c1c)}
button.mini{width:auto;padding:5px 10px;font-size:11px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{padding:7px;border-bottom:1px solid rgba(120,160,255,.1);text-align:left}
th{color:#9fb3d9;font-weight:500}
.key{font-family:monospace;color:#7dd3fc;word-break:break-all;font-size:11px}
.badge{display:inline-block;padding:2px 7px;border-radius:6px;font-size:10px;background:#1e293b}
.badge.ok{background:#14532d;color:#86efac}
.badge.dead{background:#450a0a;color:#fca5a5}
.badge.wait{background:#422006;color:#fbbf24}
.hidden{display:none!important}
.msg{font-size:13px;margin-top:8px;color:#fca5a5}
.msg.ok{color:#86efac}
.tabs{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
.tabs button{width:auto;padding:8px 16px;background:rgba(20,28,45,.7);border:1px solid rgba(120,160,255,.2)}
.tabs button.active{background:linear-gradient(90deg,#2563eb,#7c3aed);border:none}
.stat{background:rgba(20,28,45,.8);padding:14px;border-radius:10px;text-align:center;border:1px solid rgba(120,160,255,.15)}
.stat b{display:block;font-size:22px;color:#7dd3fc}
.stat span{font-size:11px;color:#9fb3d9}
.watermark{position:fixed;bottom:10px;right:14px;font-size:11px;color:#3b4b6b;z-index:3;letter-spacing:3px;font-weight:900}
.footer{text-align:center;font-size:11px;color:#3b4b6b;margin-top:20px;letter-spacing:3px;font-weight:900}
@media(max-width:700px){.grid,.grid3{grid-template-columns:1fr}}
</style></head>
<body><canvas id="fx"></canvas>
<div class="wrap">
<header><h1>❄️ WROX KEY PANEL ❄️</h1>
<div id="userBar" class="hidden">
<span id="uname" style="margin-right:10px"></span>
<button class="mini" onclick="logout()">Çıkış</button></div></header>

<div id="auth">
<div class="card"><div class="grid">
<div><h2>WROX Giriş</h2>
<input id="l_u" placeholder="Kullanıcı adı">
<input id="l_p" type="password" placeholder="Şifre">
<button onclick="login()">WROX Giriş Yap</button></div>
<div><h2>WROX Kayıt (davet kodu)</h2>
<input id="r_u" placeholder="Kullanıcı adı">
<input id="r_p" type="password" placeholder="Şifre">
<input id="r_i" placeholder="Davet kodu (Wroxtanrıgibi)">
<button onclick="register()">WROX Kayıt Ol</button></div>
</div><div id="authMsg" class="msg"></div></div></div>

<div id="panel" class="hidden">
<div class="tabs">
<button id="tabKeys" class="active" onclick="tab('keys')">🔑 WROX Keylerim</button>
<button id="tabAdmin" class="hidden" onclick="tab('admin')">🛡️ WROX Admin</button>
</div>

<div id="vKeys">
<div class="card"><h2>WROX Key Oluştur</h2>
<div class="grid">
<select id="k_type" onchange="toggleCustom()">
<option value="dakika">Dakikalık</option><option value="saat">Saatlik</option>
<option value="günlük">Günlük</option><option value="haftalık">Haftalık</option>
<option value="aylık">Aylık</option><option value="sınırsız">Sınırsız</option>
<option value="özel">Özel Süre</option>
</select>
<input id="k_count" type="number" value="1" min="1" max="200" placeholder="Adet">
</div>
<div id="customTime" class="grid3 hidden" style="margin-top:8px">
<input id="k_d" type="number" placeholder="Gün" min="0" value="0">
<input id="k_h" type="number" placeholder="Saat" min="0" value="0">
<input id="k_m" type="number" placeholder="Dakika" min="0" value="0">
</div>
<div class="grid">
<input id="k_dev" type="number" value="1" min="1" max="50" placeholder="Cihaz Sınırı">
<input id="k_note" placeholder="Not (opsiyonel)">
</div>
<input id="k_pattern" placeholder="Özel format: WROX-{random8}-KEY (boş = rastgele)">
<button onclick="createKey()">WROX Key Üret</button>
<div id="newKeys" class="msg ok"></div></div>

<div class="card"><h2>WROX Keylerim</h2>
<div style="overflow-x:auto"><table>
<thead><tr><th>Key</th><th>Süre</th><th>Kalan</th><th>Cihaz</th><th>Durum</th><th>İşlem</th></tr></thead>
<tbody id="kList"></tbody></table></div></div>
</div>

<div id="vAdmin" class="hidden">
<div class="grid" style="margin-bottom:16px">
<div class="stat"><b id="s_users">-</b><span>WROX Kullanıcı</span></div>
<div class="stat"><b id="s_keys">-</b><span>WROX Toplam Key</span></div>
<div class="stat"><b id="s_active">-</b><span>WROX Aktif Key</span></div>
<div class="stat"><b id="s_dev">-</b><span>WROX Cihaz Kaydı</span></div>
</div>
<div class="card"><h2>WROX Davet Kodu Ekle</h2>
<div class="grid">
<input id="i_code" placeholder="Kod">
<input id="i_max" type="number" value="10" min="1" placeholder="Maks kullanım">
</div>
<button onclick="addInvite()">WROX Ekle</button>
<div id="invMsg" class="msg"></div></div>
<div class="card"><h2>WROX Davet Kodları</h2>
<div style="overflow-x:auto"><table><thead><tr><th>Kod</th><th>Kullanım</th><th>Max</th></tr></thead><tbody id="invList"></tbody></table></div></div>
<div class="card"><h2>WROX Kullanıcılar</h2>
<div style="overflow-x:auto"><table><thead><tr><th>ID</th><th>Kullanıcı</th><th>Admin</th><th>Davet</th></tr></thead><tbody id="usrList"></tbody></table></div></div>
<div class="card"><h2>WROX Son Loglar</h2>
<div style="overflow-x:auto"><table><thead><tr><th>Aksiyon</th><th>Detay</th><th>IP</th></tr></thead><tbody id="logList"></tbody></table></div></div>
</div>
</div>
<div class="footer">WROX KEY PANEL</div>
</div>
<div class="watermark">WROX</div>

<script>
const API=location.origin;
let token=localStorage.getItem('wrox_token'), isAdmin=false;
const cv=document.getElementById('fx'),ctx=cv.getContext('2d');
let W,H,ps=[];
function rs(){W=cv.width=innerWidth;H=cv.height=innerHeight;init();}
function init(){ps=[];const n=Math.floor(W/14);for(let i=0;i<n;i++){const s=Math.random()>.5;ps.push({x:Math.random()*W,y:Math.random()*H,r:s?Math.random()*2+1:Math.random()*1.5+.5,vy:s?Math.random()*1+.5:Math.random()*6+6,vx:s?Math.random()*.6-.3:-1,s});}}
function draw(){ctx.clearRect(0,0,W,H);for(const p of ps){if(p.s){ctx.fillStyle='rgba(220,235,255,.85)';ctx.beginPath();ctx.arc(p.x,p.y,p.r,0,7);ctx.fill();}else{ctx.strokeStyle='rgba(120,180,255,.45)';ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(p.x,p.y);ctx.lineTo(p.x-2,p.y+12);ctx.stroke();}p.x+=p.vx;p.y+=p.vy;if(p.y>H){p.y=-10;p.x=Math.random()*W;}if(p.x<0)p.x=W;}requestAnimationFrame(draw);}
addEventListener('resize',rs);rs();draw();
async function api(p,o={}){o.headers=Object.assign({'Content-Type':'application/json'},o.headers||{});if(token)o.headers.Authorization='Bearer '+token;const r=await fetch(API+p,o);return r.json();}
function showMsg(el,m,ok){el.textContent=m;el.className='msg'+(ok?' ok':'');}
function toggleCustom(){document.getElementById('customTime').classList.toggle('hidden',k_type.value!=='özel');}
async function login(){const d=await api('/api/login',{method:'POST',body:JSON.stringify({username:l_u.value,password:l_p.value})});if(d.status){token=d.token;isAdmin=d.is_admin;localStorage.setItem('wrox_token',token);showPanel();}else showMsg(authMsg,d.reason);}
async function register(){const d=await api('/api/register',{method:'POST',body:JSON.stringify({username:r_u.value,password:r_p.value,invite:r_i.value})});showMsg(authMsg,d.reason,d.status);}
function logout(){token=null;localStorage.removeItem('wrox_token');location.reload();}
async function createKey(){
  const body={type:k_type.value,count:k_count.value,pattern:k_pattern.value||undefined,note:k_note.value||undefined,max_devices:k_dev.value};
  if(k_type.value==='özel'){body.days=k_d.value;body.hours=k_h.value;body.minutes=k_m.value;}
  const d=await api('/api/key/create',{method:'POST',body:JSON.stringify(body)});
  if(d.status){newKeys.innerHTML=d.keys.map(k=>'<div class="key">'+k+'</div>').join('');loadKeys();}
  else showMsg(newKeys,d.reason);
}
function fmtSec(s){if(s==='∞')return'∞';s=+s;if(s<60)return s+'s';if(s<3600)return Math.floor(s/60)+'dk';if(s<86400)return Math.floor(s/3600)+'sa';return Math.floor(s/86400)+'g';}
function fmtDur(s){if(s===0)return'∞';return fmtSec(s);}
async function loadKeys(){
  const d=await api('/api/key/list');if(!d.status)return;
  kList.innerHTML=d.keys.map(k=>{
    const bc=k.durum==='aktif'||k.durum==='sınırsız'?'ok':k.durum==='doldu'?'dead':'wait';
    return '<tr><td class="key">'+k.key_value+'</td><td>'+fmtDur(k.duration_seconds)+'</td><td>'+fmtSec(k.kalan)+'</td><td>'+k.devices.length+'/'+k.max_devices+'</td><td><span class="badge '+bc+'">'+k.durum+'</span></td><td>'+
    '<button class="mini" onclick="resetDev('+k.id+')">Cihaz Sıfırla</button> '+
    '<button class="mini danger" onclick="delKey('+k.id+')">Sil</button></td></tr>';
  }).join('');
}
async function delKey(id){if(!confirm('WROX: Key silinsin mi?'))return;await api('/api/key/'+id,{method:'DELETE'});loadKeys();}
async function resetDev(id){if(!confirm('WROX: Cihazlar sıfırlansın mı?'))return;const d=await api('/api/key/'+id+'/reset-devices',{method:'POST'});alert(d.reason||'WROX: OK');loadKeys();}
function tab(t){tabKeys.classList.toggle('active',t==='keys');tabAdmin.classList.toggle('active',t==='admin');vKeys.classList.toggle('hidden',t!=='keys');vAdmin.classList.toggle('hidden',t!=='admin');if(t==='admin')loadAdmin();}
async function loadAdmin(){
  const s=await api('/api/admin/stats');
  if(s.status){s_users.textContent=s.users;s_keys.textContent=s.keys;s_active.textContent=s.active;s_dev.textContent=s.devices;}
  const i=await api('/api/admin/invites');
  if(i.status)invList.innerHTML=i.invites.map(x=>'<tr><td class="key">'+x.code+'</td><td>'+x.used+'</td><td>'+x.max_uses+'</td></tr>').join('');
  const u=await api('/api/admin/users');
  if(u.status)usrList.innerHTML=u.users.map(x=>'<tr><td>'+x.id+'</td><td>'+x.username+'</td><td>'+(x.is_admin?'✅':'')+'</td><td>'+x.invite_used+'</td></tr>').join('');
  const l=await api('/api/admin/logs');
  if(l.status)logList.innerHTML=l.logs.map(x=>'<tr><td>'+x.action+'</td><td style="font-size:11px">'+(x.detail||'')+'</td><td style="font-size:10px">'+(x.ip||'')+'</td></tr>').join('');
}
async function addInvite(){const d=await api('/api/admin/invite',{method:'POST',body:JSON.stringify({code:i_code.value,max_uses:i_max.value})});showMsg(invMsg,d.status?'WROX: Eklendi':d.reason,d.status);if(d.status)loadAdmin();}
function showPanel(){
  auth.classList.add('hidden');panel.classList.remove('hidden');userBar.classList.remove('hidden');
  const p=JSON.parse(atob(token.split('.')[1]));
  uname.textContent='👤 '+p.username+(p.is_admin?' (WROX Admin)':'');
  if(p.is_admin)tabAdmin.classList.remove('hidden');
  loadKeys();
}
if(token)showPanel();
</script></body></html>"""

@app.route('/')
def index():
    return Response(HTML, mimetype='text/html')

init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port)
