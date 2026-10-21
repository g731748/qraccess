#!/usr/bin/env node
/*
 * QR Access — מערכת בקרת כניסה (גרסה 3)
 * =========================================
 * עצמאית, 100% בבעלותך. ללא תלות בספק.
 *
 * חדש בגרסה 3 — היררכיית הרשאות מלאה + קודים:
 *   • 3 רמות: Super Admin (אתה) → Admin לקוח (ועד בית/אחזקה) → משתמשי קצה
 *   • אתה מחליט לכל Admin לקוח אילו יכולות יש לו (הרשאות גרנולריות)
 *   • Admin לקוח מנהל רק את האתר שלו ואת המשתמשים שלו
 *   • אמצעי כניסה: QR מתחלף, קוד מספרי (קבוע/זמני/חד-פעמי), NFC/כרטיס (מוכן לחומרה)
 *   • חלונות זמן למשתמש, יומן כניסות, מצב גרסה
 *
 * מתוכנן לפי דפוסים מקובלים בתעשייה (Kisi, Brivo וכו'):
 *   דשבורד ענן, ניהול מהנייד, קבוצות/תפקידים, access schedules,
 *   self-expiring passes (קוד חד-פעמי/זמני), audit log.
 *
 * Node בלבד, ללא תלויות.  node server.js
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const VERSION = '3.0';
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data', 'db.json');
const STEP_SECONDS = 30, TOLERANCE = 1;

// Super Admin (אתה) — שנה ב-Render ע"י משתני סביבה
const SUPER_USER = process.env.SUPER_USER || 'michael';
const SUPER_PASSWORD = process.env.SUPER_PASSWORD || 'michael2026';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(16).toString('hex');

// רשימת כל ההרשאות שניתן לתת ל-Admin לקוח
const PERMS = {
  manage_users:   'הוספה/עריכה/מחיקה של משתמשים',
  issue_qr:       'הנפקת QR מתחלף',
  issue_code:     'הנפקת קוד מספרי',
  code_permanent: 'קוד קבוע',
  code_temporary: 'קוד זמני',
  code_onetime:   'קוד חד-פעמי',
  use_nfc:        'כרטיס/צ׳יפ NFC',
  time_windows:   'חלונות זמן',
  view_log:       'צפייה ביומן כניסות',
};

// ---------- אחסון ----------
function freshDB() {
  return {
    // לקוחות (אתרים). כל לקוח = ארגון עם Admin משלו
    tenants: {},      // id -> {id,name,createdAt}
    admins: {},       // id -> {id,tenantId,user,passHash,salt,name,perms:{},maxUsers,active}
    users: {},        // id -> {id,tenantId,name,secret,code,codeType,codeExp,nfcId,active,window,createdAt}
    doors: {},        // id -> {id,tenantId,name}
    log: [],          // {ts,tenantId,userId,userName,method,result,reason}
  };
}
function loadDB() { try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch { return freshDB(); } }
function saveDB() { fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true }); fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); }
let db = loadDB();

// ---------- הצפנת סיסמאות ----------
function hashPass(pw, salt) { return crypto.pbkdf2Sync(pw, salt, 60000, 32, 'sha256').toString('hex'); }
function makePass(pw) { const salt = crypto.randomBytes(12).toString('hex'); return { salt, passHash: hashPass(pw, salt) }; }
function checkPass(pw, salt, hash) { return hashPass(pw, salt) === hash; }

// ---------- TOTP ----------
function totp(secret, t = Date.now()) {
  const counter = Math.floor(t / 1000 / STEP_SECONDS);
  const buf = Buffer.alloc(8); buf.writeBigInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', Buffer.from(secret, 'hex')).update(buf).digest();
  const o = h[h.length - 1] & 0x0f;
  const bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return (bin % 1000000).toString().padStart(6, '0');
}
function verifyTotp(secret, code, t = Date.now()) {
  for (let w = -TOLERANCE; w <= TOLERANCE; w++) if (totp(secret, t + w * STEP_SECONDS * 1000) === code) return true;
  return false;
}
const newSecret = () => crypto.randomBytes(20).toString('hex');
const genCode = () => Math.floor(100000 + Math.random() * 900000).toString(); // 6 ספרות

// ---------- Sessions (role מוצפן בטוקן) ----------
function signToken(obj) {
  const payload = Buffer.from(JSON.stringify(obj)).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  return payload + '.' + sig;
}
function readToken(tok) {
  if (!tok) return null;
  const i = tok.lastIndexOf('.'); if (i < 0) return null;
  const payload = tok.slice(0, i), sig = tok.slice(i + 1);
  if (crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex') !== sig) return null;
  try { return JSON.parse(Buffer.from(payload, 'base64url').toString()); } catch { return null; }
}
function getCookie(req, n) { const m = (req.headers.cookie || '').match(new RegExp('(?:^|; )' + n + '=([^;]+)')); return m ? decodeURIComponent(m[1]) : null; }
function sessionOf(req) { return readToken(getCookie(req, 'qrsess')); }

// ---------- HTTP helpers ----------
function send(res, code, body, type = 'application/json', headers = {}) {
  res.writeHead(code, { 'Content-Type': type + '; charset=utf-8', ...headers });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}
function readBody(req) { return new Promise(r => { let d = ''; req.on('data', c => d += c); req.on('end', () => { try { r(JSON.parse(d || '{}')); } catch { r({}); } }); }); }
function cookieHeader(tok, maxAge = 2592000) { return { 'Set-Cookie': `qrsess=${encodeURIComponent(tok)}; HttpOnly; Path=/; Max-Age=${maxAge}; SameSite=Lax` }; }

function withinWindow(u, now = new Date()) {
  if (!u.window) return true;
  const w = u.window;
  if (w.days && w.days.length && !w.days.includes(now.getDay())) return false;
  if (w.from && w.to) {
    const cur = now.getHours() * 60 + now.getMinutes();
    const [fh, fm] = w.from.split(':').map(Number), [th, tm] = w.to.split(':').map(Number);
    if (cur < fh * 60 + fm || cur > th * 60 + tm) return false;
  }
  return true;
}

// ---------- Server ----------
const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://${req.headers.host}`);
  const p = u.pathname, m = req.method;
  const S = sessionOf(req); // null | {role:'super'} | {role:'admin',adminId,tenantId}

  // ===== התחברות =====
  if (p === '/api/login' && m === 'POST') {
    const b = await readBody(req);
    // super
    if (b.user === SUPER_USER && b.password === SUPER_PASSWORD)
      return send(res, 200, { ok: true, role: 'super' }, 'application/json', cookieHeader(signToken({ role: 'super' })));
    // admin לקוח
    const admin = Object.values(db.admins).find(a => a.user === b.user && a.active);
    if (admin && checkPass(b.password, admin.salt, admin.passHash))
      return send(res, 200, { ok: true, role: 'admin' }, 'application/json', cookieHeader(signToken({ role: 'admin', adminId: admin.id, tenantId: admin.tenantId })));
    return send(res, 401, { ok: false, error: 'שם משתמש או סיסמה שגויים' });
  }
  if (p === '/api/logout') return send(res, 200, { ok: true }, 'application/json', { 'Set-Cookie': 'qrsess=; Path=/; Max-Age=0' });

  // ===== דף QR לעובד (ציבורי) =====
  if (p.startsWith('/q/')) { const user = db.users[p.split('/')[2]]; if (!user) return send(res, 404, 'לא נמצא', 'text/plain'); return send(res, 200, qrPage(user), 'text/html'); }
  if (p.startsWith('/api/qr/')) {
    const user = db.users[p.split('/')[3]];
    if (!user || !user.active) return send(res, 403, { ok: false });
    const payload = `${user.id}.${totp(user.secret)}`;
    const msLeft = STEP_SECONDS * 1000 - (Date.now() % (STEP_SECONDS * 1000));
    return send(res, 200, { ok: true, payload, secondsLeft: Math.ceil(msLeft / 1000), name: user.name });
  }

  // ===== אימות כניסה (ציבורי — הקורא קורא לזה) =====
  // תומך ב: QR ("userId.code"), קוד מספרי ("CODE:123456"), NFC ("NFC:<uid>")
  if (p === '/api/verify' && m === 'POST') {
    const b = await readBody(req);
    const raw = (b.payload || '').trim();
    let user = null, method = 'qr', result = 'denied', reason = 'לא מזוהה';

    if (raw.startsWith('CODE:')) {
      method = 'code'; const code = raw.slice(5);
      user = Object.values(db.users).find(x => x.code && x.code === code);
      if (user) {
        if (!user.active) reason = 'מושבת';
        else if (user.codeType === 'temporary' && user.codeExp && Date.now() > user.codeExp) reason = 'קוד פג תוקף';
        else if (!withinWindow(user)) reason = 'מחוץ לחלון זמן';
        else { result = 'granted'; reason = ''; if (user.codeType === 'onetime') { user.code = null; user.codeType = null; } }
      }
    } else if (raw.startsWith('NFC:')) {
      method = 'nfc'; const nfc = raw.slice(4);
      user = Object.values(db.users).find(x => x.nfcId && x.nfcId === nfc);
      if (user) {
        if (!user.active) reason = 'מושבת';
        else if (!withinWindow(user)) reason = 'מחוץ לחלון זמן';
        else { result = 'granted'; reason = ''; }
      }
    } else {
      method = 'qr'; const [uid, code] = raw.split('.'); user = db.users[uid];
      if (user) {
        if (!user.active) reason = 'מושבת';
        else if (!withinWindow(user)) reason = 'מחוץ לחלון זמן';
        else if (!code || !verifyTotp(user.secret, code)) reason = 'קוד לא תקף';
        else { result = 'granted'; reason = ''; }
      }
    }
    db.log.unshift({ ts: Date.now(), tenantId: user ? user.tenantId : null, userId: user ? user.id : null, userName: user ? user.name : 'לא ידוע', method, result, reason, doorId: b.doorId || null });
    db.log = db.log.slice(0, 2000); saveDB();
    return send(res, 200, { result, open: result === 'granted', reason, method });
  }

  // ===== מכאן דורש התחברות =====
  if (!S) {
    if (p.startsWith('/api/')) return send(res, 401, { ok: false, error: 'לא מחובר' });
    return send(res, 200, loginPage(), 'text/html');
  }

  // מידע על המשתמש המחובר
  if (p === '/api/me') {
    if (S.role === 'super') return send(res, 200, { role: 'super', version: VERSION, user: SUPER_USER, perms: Object.keys(PERMS) });
    const a = db.admins[S.adminId];
    return send(res, 200, { role: 'admin', version: VERSION, name: a ? a.name : '', tenantName: db.tenants[S.tenantId] ? db.tenants[S.tenantId].name : '', perms: a ? Object.keys(a.perms).filter(k => a.perms[k]) : [], maxUsers: a ? a.maxUsers : 0, permDefs: PERMS });
  }

  // ===================== SUPER ADMIN =====================
  if (S.role === 'super') {
    // רשימת לקוחות + האדמינים שלהם
    if (p === '/api/tenants' && m === 'GET') {
      const list = Object.values(db.tenants).map(t => ({
        ...t,
        admins: Object.values(db.admins).filter(a => a.tenantId === t.id).map(a => ({ id: a.id, user: a.user, name: a.name, active: a.active, perms: a.perms, maxUsers: a.maxUsers })),
        userCount: Object.values(db.users).filter(x => x.tenantId === t.id).length,
      }));
      return send(res, 200, list);
    }
    // יצירת לקוח + אדמין ראשון
    if (p === '/api/tenants' && m === 'POST') {
      const b = await readBody(req);
      const tid = 't' + crypto.randomBytes(3).toString('hex');
      db.tenants[tid] = { id: tid, name: b.name || 'לקוח חדש', createdAt: Date.now() };
      db.doors['d' + crypto.randomBytes(2).toString('hex')] = { id: 'd', tenantId: tid, name: 'כניסה ראשית' };
      // אדמין
      const aid = 'a' + crypto.randomBytes(3).toString('hex');
      const { salt, passHash } = makePass(b.adminPassword || 'changeme');
      const perms = {}; (b.perms || ['manage_users', 'issue_qr', 'view_log']).forEach(k => { if (PERMS[k]) perms[k] = true; });
      db.admins[aid] = { id: aid, tenantId: tid, user: b.adminUser || ('admin_' + tid), name: b.adminName || 'מנהל', salt, passHash, perms, maxUsers: b.maxUsers || 50, active: true };
      saveDB();
      return send(res, 200, { tenant: db.tenants[tid], adminUser: db.admins[aid].user });
    }
    // עדכון הרשאות/פרטי אדמין
    if (p.startsWith('/api/admins/') && m === 'POST') {
      const id = p.split('/')[3]; const b = await readBody(req); const a = db.admins[id];
      if (!a) return send(res, 404, { error: 'not found' });
      if (b.perms) { a.perms = {}; b.perms.forEach(k => { if (PERMS[k]) a.perms[k] = true; }); }
      if (typeof b.active === 'boolean') a.active = b.active;
      if (typeof b.maxUsers === 'number') a.maxUsers = b.maxUsers;
      if (b.newPassword) { const x = makePass(b.newPassword); a.salt = x.salt; a.passHash = x.passHash; }
      if (typeof b.name === 'string' && b.name.trim()) a.name = b.name.trim();
      saveDB(); return send(res, 200, { ok: true });
    }
    if (p.startsWith('/api/tenants/') && m === 'DELETE') {
      const id = p.split('/')[3];
      delete db.tenants[id];
      Object.values(db.admins).filter(a => a.tenantId === id).forEach(a => delete db.admins[a.id]);
      Object.values(db.users).filter(x => x.tenantId === id).forEach(x => delete db.users[x.id]);
      saveDB(); return send(res, 200, { ok: true });
    }
    if (p === '/api/log') return send(res, 200, db.log.slice(0, 150));
    if (p === '/' || p === '/admin') return send(res, 200, superPage(), 'text/html');
  }

  // ===================== ADMIN לקוח =====================
  if (S.role === 'admin') {
    const a = db.admins[S.adminId];
    if (!a || !a.active) return send(res, 200, loginPage(), 'text/html');
    const has = k => !!a.perms[k];
    const tid = S.tenantId;

    if (p === '/api/users' && m === 'GET') {
      return send(res, 200, Object.values(db.users).filter(x => x.tenantId === tid));
    }
    if (p === '/api/users' && m === 'POST') {
      if (!has('manage_users')) return send(res, 403, { error: 'אין הרשאה' });
      const count = Object.values(db.users).filter(x => x.tenantId === tid).length;
      if (count >= a.maxUsers) return send(res, 403, { error: `הגעת למכסה (${a.maxUsers} משתמשים)` });
      const b = await readBody(req);
      const id = 'u' + crypto.randomBytes(3).toString('hex');
      db.users[id] = { id, tenantId: tid, name: b.name || 'משתמש', secret: newSecret(), code: null, codeType: null, codeExp: null, nfcId: null, active: true, window: null, createdAt: Date.now() };
      saveDB(); return send(res, 200, db.users[id]);
    }
    if (p.startsWith('/api/users/') && p.endsWith('/code') && m === 'POST') {
      if (!has('issue_code')) return send(res, 403, { error: 'אין הרשאה להנפיק קוד' });
      const id = p.split('/')[3]; const user = db.users[id];
      if (!user || user.tenantId !== tid) return send(res, 404, { error: 'not found' });
      const b = await readBody(req); const type = b.type || 'permanent';
      const permMap = { permanent: 'code_permanent', temporary: 'code_temporary', onetime: 'code_onetime' };
      if (!has(permMap[type])) return send(res, 403, { error: 'אין הרשאה לסוג קוד זה' });
      user.code = genCode(); user.codeType = type;
      user.codeExp = type === 'temporary' ? (Date.now() + (b.hours || 24) * 3600000) : null;
      saveDB(); return send(res, 200, { code: user.code, type, exp: user.codeExp });
    }
    if (p.startsWith('/api/users/') && m === 'POST') {
      if (!has('manage_users')) return send(res, 403, { error: 'אין הרשאה' });
      const id = p.split('/')[3]; const user = db.users[id];
      if (!user || user.tenantId !== tid) return send(res, 404, { error: 'not found' });
      const b = await readBody(req);
      if (typeof b.active === 'boolean') user.active = b.active;
      if (typeof b.name === 'string' && b.name.trim()) user.name = b.name.trim();
      if ('window' in b && has('time_windows')) user.window = b.window;
      if ('nfcId' in b && has('use_nfc')) user.nfcId = b.nfcId || null;
      saveDB(); return send(res, 200, user);
    }
    if (p.startsWith('/api/users/') && m === 'DELETE') {
      if (!has('manage_users')) return send(res, 403, { error: 'אין הרשאה' });
      const id = p.split('/')[3]; const user = db.users[id];
      if (user && user.tenantId === tid) delete db.users[id];
      saveDB(); return send(res, 200, { ok: true });
    }
    if (p === '/api/log') {
      if (!has('view_log')) return send(res, 403, { error: 'אין הרשאה' });
      return send(res, 200, db.log.filter(l => l.tenantId === tid).slice(0, 100));
    }
    if (p === '/' || p === '/admin') return send(res, 200, adminPage(), 'text/html');
  }

  send(res, 404, 'not found', 'text/plain');
});

server.listen(PORT, () => console.log(`\n  QR Access v${VERSION} — פועל על פורט ${PORT}\n  Super: ${SUPER_USER} ${SUPER_PASSWORD === 'michael2026' ? '(סיסמת ברירת מחדל — שנה!)' : ''}\n`));

// ================= HTML =================
function shell(title, body, head = '') {
  return `<!doctype html><html dir="rtl" lang="he"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<meta name="theme-color" content="#1f3a5f"><title>${title}</title>
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>${head}
<style>
  :root{--bg:#f4f6f9;--card:#fff;--ink:#1a2b3c;--muted:#64748b;--brand:#1f3a5f;--brand2:#2c5282;--ok:#1b8a4b;--bad:#c0392b;--warn:#b7791f;--line:#e2e8f0}
  *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
  body{font-family:Arial,system-ui,sans-serif;background:var(--bg);color:var(--ink);margin:0;padding:14px;font-size:16px}
  .wrap{max-width:820px;margin:0 auto}
  h1{color:var(--brand);font-size:21px;margin:6px 0 2px}h3{margin:0 0 10px}
  .sub{color:var(--muted);font-size:13px;margin:0 0 14px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:15px;margin-bottom:13px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
  button{font-family:inherit;font-size:16px;border:0;border-radius:11px;padding:13px 18px;cursor:pointer;min-height:48px}
  .primary{background:var(--brand);color:#fff;width:100%}.ghost{background:#eef3f8;color:var(--brand)}
  .danger{background:#fdeaea;color:var(--bad)}.ok{background:#e6f6ec;color:var(--ok)}
  .sm{padding:9px 13px;font-size:14px;min-height:40px;width:auto}
  input,select{font-family:inherit;font-size:16px;padding:12px;border:1px solid var(--line);border-radius:11px;width:100%;min-height:48px;background:#fff}
  .row{display:flex;gap:9px;align-items:center}.wrap2{flex-wrap:wrap}
  .item{border:1px solid var(--line);border-radius:12px;padding:12px;margin-bottom:10px}
  .item .top{display:flex;justify-content:space-between;align-items:center;gap:8px}
  .item .name{font-weight:bold;font-size:17px}
  .btns{display:flex;gap:7px;flex-wrap:wrap;margin-top:10px}
  .pill{display:inline-block;padding:3px 11px;border-radius:999px;font-size:12px}
  .on{background:#e6f6ec;color:var(--ok)}.off{background:#f1f5f9;color:var(--muted)}
  .g{color:var(--ok);font-weight:bold}.r{color:var(--bad);font-weight:bold}
  a.link{color:var(--brand2);text-decoration:none;font-size:14px;font-weight:bold}
  .nav{display:flex;gap:9px;margin-bottom:13px;flex-wrap:wrap;align-items:center}
  .nav a,.nav span.badge{background:#fff;border:1px solid var(--line);border-radius:10px;padding:9px 13px;color:var(--brand);text-decoration:none;font-size:14px}
  .nav .ver{margin-right:auto;color:var(--muted);font-size:12px}
  .muted{color:var(--muted);font-size:12px}
  .perm{display:flex;align-items:center;gap:8px;padding:6px 0;font-size:14px}
  .perm input{width:auto;min-height:auto}
  .logline{display:flex;justify-content:space-between;padding:9px 2px;border-bottom:1px solid var(--line);font-size:14px;gap:8px}
  .codebox{font-size:30px;font-weight:bold;letter-spacing:4px;text-align:center;color:var(--brand);background:#eef3f8;border-radius:12px;padding:16px;margin:10px 0}
  label{font-size:14px;color:var(--muted)}
</style></head><body><div class="wrap">${body}</div></body></html>`;
}

function loginPage() {
  return shell('התחברות', `
<div style="height:40px"></div>
<div class="card" style="max-width:380px;margin:0 auto">
  <h1 style="text-align:center">בקרת כניסה</h1><p class="sub" style="text-align:center">התחברות</p>
  <div style="display:flex;flex-direction:column;gap:11px">
    <input id="user" placeholder="שם משתמש" autocomplete="username">
    <input id="pass" type="password" placeholder="סיסמה" autocomplete="current-password">
    <button class="primary" onclick="login()">התחבר</button>
    <div id="err" class="r" style="text-align:center;font-size:14px"></div>
  </div>
</div>
<script>
async function login(){const user=user_.value.trim(),password=pass.value;
  const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user,password})});
  const d=await r.json(); if(d.ok)location.href='/admin'; else err.textContent=d.error||'שגיאה';}
const user_=document.getElementById('user'),pass=document.getElementById('pass'),err=document.getElementById('err');
pass.addEventListener('keydown',e=>{if(e.key==='Enter')login();});
</script>`);
}

// ---- Super Admin page ----
function superPage() {
  return shell('ניהול-על', `
<div class="nav"><span class="badge">👑 ניהול-על</span><a href="#" onclick="logout();return false;">התנתק</a><span class="ver">גרסה <span id="ver">…</span></span></div>
<h1>לקוחות (אתרים)</h1><p class="sub">כל לקוח = אתר עם מנהל משלו. אתה מחליט אילו הרשאות יש לכל מנהל.</p>

<div class="card">
  <h3>הוספת לקוח חדש</h3>
  <div style="display:flex;flex-direction:column;gap:9px">
    <input id="tname" placeholder="שם הלקוח/אתר (למשל: בניין רוטשילד 5)">
    <div class="row wrap2"><input id="auser" placeholder="שם משתמש למנהל" style="flex:1"><input id="aname" placeholder="שם המנהל" style="flex:1"></div>
    <input id="apass" placeholder="סיסמה למנהל">
    <label>מכסת משתמשים: <input id="amax" type="number" value="50" style="width:100px;display:inline-block"></label>
    <div><label>הרשאות למנהל הלקוח:</label><div id="permbox" style="margin-top:6px"></div></div>
    <button class="primary" onclick="addTenant()">צור לקוח + מנהל</button>
    <div id="msg" class="muted"></div>
  </div>
</div>

<div id="tenants"></div>

<div class="card"><h3>יומן כניסות (כל הלקוחות)</h3><div id="log"></div></div>

<script>
let PERMS={};
async function logout(){await fetch('/api/logout');location.href='/admin';}
async function init(){
  const me=await (await fetch('/api/me')).json(); ver.textContent=me.version;
  // משיכת שמות הרשאות מתוך admin permDefs דרך נתון קבוע:
  PERMS=${JSON.stringify(PERMS_DEFS())};
  const pb=document.getElementById('permbox'); pb.innerHTML='';
  Object.entries(PERMS).forEach(([k,label])=>{
    const d=document.createElement('label'); d.className='perm';
    const def=['manage_users','issue_qr','view_log'].includes(k);
    d.innerHTML='<input type="checkbox" value="'+k+'" '+(def?'checked':'')+'> '+label;
    pb.appendChild(d);
  });
  load();
}
const ver=document.getElementById('ver');
function checkedPerms(scope){return[...document.querySelectorAll(scope+' input[type=checkbox]:checked')].map(c=>c.value);}
async function addTenant(){
  const body={name:tname.value.trim(),adminUser:auser.value.trim(),adminName:aname.value.trim(),adminPassword:apass.value,maxUsers:parseInt(amax.value)||50,perms:checkedPerms('#permbox')};
  if(!body.name||!body.adminUser||!body.adminPassword){msg.textContent='מלא שם לקוח, שם משתמש וסיסמה';return;}
  const r=await (await fetch('/api/tenants',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})).json();
  msg.textContent='נוצר! מנהל: '+r.adminUser; tname.value=auser.value=aname.value=apass.value=''; load();
}
const tname=document.getElementById('tname'),auser=document.getElementById('auser'),aname=document.getElementById('aname'),apass=document.getElementById('apass'),amax=document.getElementById('amax'),msg=document.getElementById('msg');
async function load(){
  const ts=await (await fetch('/api/tenants')).json();
  const box=document.getElementById('tenants'); box.innerHTML=ts.length?'':'<div class="card muted">אין עדיין לקוחות.</div>';
  ts.forEach(t=>{
    const c=document.createElement('div'); c.className='card';
    let adminsHtml=t.admins.map(a=>{
      const permList=Object.keys(a.perms).filter(k=>a.perms[k]).map(k=>PERMS[k]).join(', ')||'ללא';
      return '<div class="item"><div class="top"><span class="name">👤 '+a.name+' ('+a.user+')</span><span class="pill '+(a.active?'on':'off')+'">'+(a.active?'פעיל':'מושבת')+'</span></div>'+
        '<div class="muted" style="margin-top:4px">הרשאות: '+permList+' | מכסה: '+a.maxUsers+'</div>'+
        '<div class="btns"><button class="ghost sm" onclick="editPerms(\\''+a.id+'\\')">ערוך הרשאות</button>'+
        '<button class="'+(a.active?'danger':'ghost')+' sm" onclick="toggleAdmin(\\''+a.id+'\\','+(!a.active)+')">'+(a.active?'השבת':'הפעל')+'</button></div></div>';
    }).join('');
    c.innerHTML='<div class="top"><span class="name">🏢 '+t.name+'</span><span class="muted">'+t.userCount+' משתמשים</span></div>'+adminsHtml+
      '<div class="btns"><button class="danger sm" onclick="delTenant(\\''+t.id+'\\',\\''+t.name.replace(/\\x27/g,"")+'\\')">מחק לקוח</button></div>';
    box.appendChild(c);
  });
  const log=await (await fetch('/api/log')).json();
  const lb=document.getElementById('log'); lb.innerHTML=log.length?'':'<div class="muted">אין כניסות.</div>';
  log.forEach(l=>{const d=document.createElement('div');d.className='logline';const t=new Date(l.ts).toLocaleString('he-IL');const mth={qr:'QR',code:'קוד',nfc:'NFC'}[l.method]||l.method;
    d.innerHTML='<span>'+l.userName+' <span class="muted">('+mth+')</span></span><span class="'+(l.result==='granted'?'g':'r')+'">'+(l.result==='granted'?'✓':'✕'+(l.reason?' '+l.reason:''))+'</span><span class="muted">'+t+'</span>';lb.appendChild(d);});
}
async function editPerms(id){
  const picks=Object.entries(PERMS).map(([k,v])=>k+'='+v).join('\\n');
  const cur=prompt('הזן הרשאות מופרדות בפסיק מתוך הרשימה:\\n'+Object.keys(PERMS).join(', ')+'\\n\\nלדוגמה: manage_users,issue_code,code_temporary,view_log','manage_users,issue_qr,view_log');
  if(cur===null)return;
  const perms=cur.split(',').map(s=>s.trim()).filter(Boolean);
  await fetch('/api/admins/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({perms})}); load();
}
async function toggleAdmin(id,active){await fetch('/api/admins/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({active})});load();}
async function delTenant(id,name){if(confirm('למחוק את '+name+' וכל המשתמשים שלו?')){await fetch('/api/tenants/'+id,{method:'DELETE'});load();}}
init();
</script>`);
}

// ---- Admin לקוח page ----
function adminPage() {
  return shell('ניהול אתר', `
<div class="nav"><span class="badge">🏢 <span id="tname">…</span></span><a href="#" onclick="logout();return false;">התנתק</a><span class="ver">גרסה <span id="ver">…</span></span></div>
<h1 id="title">ניהול כניסה</h1><p class="sub" id="whoami"></p>

<div class="card" id="addcard" style="display:none">
  <div class="row"><input id="name" placeholder="שם משתמש חדש (דייר/מורה)"><button class="primary sm" onclick="addUser()">הוסף</button></div>
  <div id="quota" class="muted" style="margin-top:6px"></div>
</div>

<div class="card"><h3>משתמשים</h3><div id="users"></div></div>
<div class="card" id="logcard" style="display:none"><h3>יומן כניסות</h3><div id="log"></div></div>

<script>
let ME={perms:[]};
async function logout(){await fetch('/api/logout');location.href='/admin';}
function can(k){return ME.perms.includes(k);}
async function init(){
  ME=await (await fetch('/api/me')).json();
  ver.textContent=ME.version; document.getElementById('tname').textContent=ME.tenantName||'אתר';
  whoami.textContent='מחובר: '+(ME.name||'')+' | הרשאות: '+(ME.perms.map(k=>ME.permDefs[k]).join(', ')||'צפייה בלבד');
  if(can('manage_users'))addcard.style.display='block';
  if(can('view_log'))logcard.style.display='block';
  load();
}
const ver=document.getElementById('ver'),whoami=document.getElementById('whoami'),addcard=document.getElementById('addcard'),logcard=document.getElementById('logcard');
async function load(){
  const users=await (await fetch('/api/users')).json();
  if(can('manage_users'))document.getElementById('quota').textContent='משתמשים: '+users.length+' / '+ME.maxUsers;
  const box=document.getElementById('users'); box.innerHTML=users.length?'':'<div class="muted">אין עדיין משתמשים.</div>';
  users.forEach(u=>{
    const div=document.createElement('div'); div.className='item';
    let codeInfo=''; if(u.code){const ct={permanent:'קבוע',temporary:'זמני',onetime:'חד-פעמי'}[u.codeType]||'';codeInfo='<div class="muted">קוד '+ct+': <b>'+u.code+'</b></div>';}
    let nfcInfo=u.nfcId?'<div class="muted">NFC: '+u.nfcId+'</div>':'';
    let btns='<a class="link" href="/q/'+u.id+'" target="_blank">QR ↗</a>';
    if(can('issue_code'))btns+='<button class="ghost sm" onclick="issueCode(\\''+u.id+'\\')">הנפק קוד</button>';
    if(can('use_nfc'))btns+='<button class="ghost sm" onclick="setNfc(\\''+u.id+'\\')">NFC</button>';
    if(can('time_windows'))btns+='<button class="ghost sm" onclick="setWindow(\\''+u.id+'\\')">חלון זמן</button>';
    if(can('manage_users')){btns+='<button class="ghost sm" onclick="rename(\\''+u.id+'\\',\\''+u.name.replace(/\\x27/g,"")+'\\')">שם</button>';
      btns+='<button class="'+(u.active?'danger':'ghost')+' sm" onclick="toggle(\\''+u.id+'\\','+(!u.active)+')">'+(u.active?'השבת':'הפעל')+'</button>';
      btns+='<button class="danger sm" onclick="del(\\''+u.id+'\\',\\''+u.name.replace(/\\x27/g,"")+'\\')">מחק</button>';}
    div.innerHTML='<div class="top"><span class="name">'+u.name+'</span><span class="pill '+(u.active?'on':'off')+'">'+(u.active?'פעיל':'מושבת')+'</span></div>'+codeInfo+nfcInfo+'<div class="btns">'+btns+'</div>';
    box.appendChild(div);
  });
  if(can('view_log')){
    const log=await (await fetch('/api/log')).json(); const lb=document.getElementById('log');
    lb.innerHTML=log.length?'':'<div class="muted">אין כניסות.</div>';
    log.forEach(l=>{const d=document.createElement('div');d.className='logline';const t=new Date(l.ts).toLocaleString('he-IL');const mth={qr:'QR',code:'קוד',nfc:'NFC'}[l.method]||l.method;
      d.innerHTML='<span>'+l.userName+' <span class="muted">('+mth+')</span></span><span class="'+(l.result==='granted'?'g':'r')+'">'+(l.result==='granted'?'✓':'✕'+(l.reason?' '+l.reason:''))+'</span><span class="muted">'+t+'</span>';lb.appendChild(d);});
  }
}
async function addUser(){const name=document.getElementById('name').value.trim()||'משתמש';
  const r=await fetch('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});
  if(!r.ok){const e=await r.json();alert(e.error||'שגיאה');return;} document.getElementById('name').value=''; load();}
async function toggle(id,active){await fetch('/api/users/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({active})});load();}
async function rename(id,cur){const name=prompt('שם חדש:',cur);if(name&&name.trim()){await fetch('/api/users/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name.trim()})});load();}}
async function del(id,name){if(confirm('למחוק את '+name+'?')){await fetch('/api/users/'+id,{method:'DELETE'});load();}}
async function setNfc(id){const nfcId=prompt('הזן מזהה כרטיס/צ׳יפ NFC (UID). ריק = הסרה:','');if(nfcId===null)return;await fetch('/api/users/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({nfcId:nfcId.trim()})});load();}
async function setWindow(id){const ans=prompt('חלון זמן. "תמיד" לגישה חופשית.\\nדוגמה: 0,1,2,3,4 08:00 18:00','תמיד');if(ans===null)return;let win=null;if(ans.trim()!=='תמיד'){const pr=ans.trim().split(/\\s+/);win={days:(pr[0]||'').split(',').map(x=>parseInt(x)).filter(x=>!isNaN(x)),from:pr[1]||'00:00',to:pr[2]||'23:59'};}await fetch('/api/users/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({window:win})});load();}
async function issueCode(id){
  let types=[]; if(can('code_permanent'))types.push('permanent'); if(can('code_temporary'))types.push('temporary'); if(can('code_onetime'))types.push('onetime');
  if(!types.length){alert('אין לך הרשאה לסוג קוד כלשהו');return;}
  const names={permanent:'קבוע',temporary:'זמני (24ש)',onetime:'חד-פעמי'};
  const choice=prompt('סוג קוד — הקלד אחד מ:\\n'+types.map(t=>t+' = '+names[t]).join('\\n'),types[0]);
  if(choice===null||!types.includes(choice.trim()))return;
  const r=await (await fetch('/api/users/'+id+'/code',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:choice.trim(),hours:24})})).json();
  if(r.code)alert('קוד חדש: '+r.code+'\\nשלח אותו למשתמש.'); else alert(r.error||'שגיאה'); load();
}
init();
</script>`);
}

function PERMS_DEFS() { return PERMS; }

function qrPage(user) {
  return shell('כניסה — ' + user.name, `
<div style="height:16px"></div><h1 style="text-align:center">${user.name}</h1>
<p class="sub" style="text-align:center">הצג לקורא. מתחדש כל ${STEP_SECONDS} שניות.</p>
<div class="card" style="text-align:center;max-width:320px;margin:0 auto">
  <div id="qr" style="display:inline-block;padding:14px;background:#fff;border-radius:12px"></div>
  <div style="margin-top:12px;color:var(--muted)">מתחדש בעוד <b id="sec">--</b> ש׳</div>
  <div style="margin-top:6px;height:7px;background:#eef3f8;border-radius:4px;overflow:hidden"><div id="bar" style="height:100%;background:var(--brand);width:100%;transition:width 1s linear"></div></div>
</div>
<script>
let qr=new QRCode(document.getElementById('qr'),{width:230,height:230,correctLevel:QRCode.CorrectLevel.M});
async function tick(){try{const r=await (await fetch('/api/qr/${user.id}')).json();
  if(!r.ok){document.getElementById('qr').innerHTML='<b style="color:#c0392b">הגישה הושבתה</b>';return;}
  qr.clear();qr.makeCode(r.payload);document.getElementById('sec').textContent=r.secondsLeft;document.getElementById('bar').style.width=(r.secondsLeft/${STEP_SECONDS}*100)+'%';}catch(e){}}
tick();setInterval(tick,1000);
</script>`);
                 }
