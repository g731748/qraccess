#!/usr/bin/env node
/*
 * QR Access — מערכת בקרת כניסה (גרסה 6)
 * =========================================
 * עצמאית, 100% בבעלותך. ללא תלות בספק.
 *
 * חדש בגרסה 7:
 *   • קליטת תגי NFC בשתי דרכים:
 *     1) ידנית/מהנייד — מזינים את ה-UID שקראת עם הנייד
 *     2) אוטומטית מהקורא — הקורא שולח סריקה, והתג האחרון שנקרא
 *        מופיע לשיוך בלחיצה (כשתג לא מוכר נסרק, הוא נשמר ל-60 שניות)
 *
 * גרסה 6: מסד נתונים קבוע (PostgreSQL) — הלקוחות נשמרים לתמיד.
 *
 * גרסאות קודמות: היררכיית הרשאות, קודים, NFC, חלונות זמן,
 *   דשבורד, חיפוש, וואטסאפ, ניהול סיסמאות ואיפוס.
 *
 * רמות: Super Admin (אתה) → Admin לקוח → משתמשי קצה
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const VERSION = '8.0';
// סוגי תגי NFC/RFID נתמכים
const TAG_TYPES = { '125khz': 'תג 125kHz (EM/קירבה)', '13.56mhz': 'תג 13.56MHz (Mifare/NFC)' };

// זיכרון קצר של התג האחרון שנסרק ולא זוהה — לקליטה אוטומטית מהקורא
// לכל לקוח (tenant) נשמר התג האחרון, לתקופה קצרה
const lastUnknownTag = {}; // tenantId -> { uid, ts }
const TAG_ENROLL_WINDOW = 60 * 1000; // 60 שניות
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data', 'db.json');
const DATABASE_URL = process.env.DATABASE_URL || '';
const STEP_SECONDS = 30, TOLERANCE = 1;

const SUPER_USER = process.env.SUPER_USER || 'michael';
const SUPER_PASSWORD = process.env.SUPER_PASSWORD || 'michael2026';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(16).toString('hex');

const PERMS = {
  manage_users:   'ניהול משתמשים (הוספה/עריכה/מחיקה)',
  issue_qr:       'הנפקת QR מתחלף',
  issue_code:     'הנפקת קוד מספרי',
  code_permanent: 'קוד קבוע',
  code_temporary: 'קוד זמני',
  code_onetime:   'קוד חד-פעמי',
  use_nfc:        'כרטיס/צ׳יפ NFC',
  time_windows:   'חלונות זמן',
  view_log:       'צפייה ביומן כניסות',
};

function freshDB() { return { tenants: {}, admins: {}, users: {}, doors: {}, log: [] }; }

/* ========= שכבת אחסון ========= *
 * db נשמר בזיכרון כמקור האמת. בהפעלה טוענים אותו ממסד הנתונים (או מקובץ).
 * כל שמירה כותבת את כל האובייקט בחזרה. עם Postgres — שורה אחת עם JSON.
 */
let db = freshDB();
let pgPool = null;           // מאותחל ב-initStorage אם יש DATABASE_URL
let saveTimer = null;        // דחיית כתיבות כדי לא להציף את ה-DB

async function initStorage() {
  if (DATABASE_URL) {
    const { Pool } = require('pg');
    pgPool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
    await pgPool.query('CREATE TABLE IF NOT EXISTS store (id INT PRIMARY KEY, data JSONB)');
    const r = await pgPool.query('SELECT data FROM store WHERE id=1');
    if (r.rows.length) { db = r.rows[0].data; console.log('  אחסון: Postgres (נטען מסד קיים)'); }
    else { db = freshDB(); await pgPool.query('INSERT INTO store (id,data) VALUES (1,$1)', [JSON.stringify(db)]); console.log('  אחסון: Postgres (מסד חדש נוצר)'); }
  } else {
    try { db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch { db = freshDB(); }
    console.log('  אחסון: קובץ מקומי (פיתוח)');
  }
}

async function persist() {
  if (pgPool) { try { await pgPool.query('UPDATE store SET data=$1 WHERE id=1', [JSON.stringify(db)]); } catch (e) { console.error('persist DB error:', e.message); } }
  else { try { fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true }); fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); } catch (e) { console.error('persist file error:', e.message); } }
}

// saveDB נשאר סינכרוני לקריאה מהקוד הקיים — מתזמן כתיבה ברקע (debounce קצר)
function saveDB() {
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(() => { saveTimer = null; persist(); }, 150);
}

function hashPass(pw, salt) { return crypto.pbkdf2Sync(pw, salt, 60000, 32, 'sha256').toString('hex'); }
function makePass(pw) { const salt = crypto.randomBytes(12).toString('hex'); return { salt, passHash: hashPass(pw, salt) }; }
function checkPass(pw, salt, hash) { return hashPass(pw, salt) === hash; }

function totp(secret, t = Date.now()) {
  const counter = Math.floor(t / 1000 / STEP_SECONDS);
  const buf = Buffer.alloc(8); buf.writeBigInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', Buffer.from(secret, 'hex')).update(buf).digest();
  const o = h[h.length - 1] & 0x0f;
  const bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return (bin % 1000000).toString().padStart(6, '0');
}
function verifyTotp(secret, code, t = Date.now()) { for (let w = -TOLERANCE; w <= TOLERANCE; w++) if (totp(secret, t + w * STEP_SECONDS * 1000) === code) return true; return false; }
const newSecret = () => crypto.randomBytes(20).toString('hex');
const genCode = () => Math.floor(100000 + Math.random() * 900000).toString();

function signToken(obj) { const payload = Buffer.from(JSON.stringify(obj)).toString('base64url'); const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex'); return payload + '.' + sig; }
function readToken(tok) { if (!tok) return null; const i = tok.lastIndexOf('.'); if (i < 0) return null; const payload = tok.slice(0, i), sig = tok.slice(i + 1); if (crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex') !== sig) return null; try { return JSON.parse(Buffer.from(payload, 'base64url').toString()); } catch { return null; } }
function getCookie(req, n) { const m = (req.headers.cookie || '').match(new RegExp('(?:^|; )' + n + '=([^;]+)')); return m ? decodeURIComponent(m[1]) : null; }
function sessionOf(req) { return readToken(getCookie(req, 'qrsess')); }

function send(res, code, body, type = 'application/json', headers = {}) { res.writeHead(code, { 'Content-Type': type + '; charset=utf-8', ...headers }); res.end(typeof body === 'string' ? body : JSON.stringify(body)); }
function readBody(req) { return new Promise(r => { let d = ''; req.on('data', c => d += c); req.on('end', () => { try { r(JSON.parse(d || '{}')); } catch { r({}); } }); }); }
function cookieHeader(tok, maxAge = 2592000) { return { 'Set-Cookie': `qrsess=${encodeURIComponent(tok)}; HttpOnly; Path=/; Max-Age=${maxAge}; SameSite=Lax` }; }

function withinWindow(u, now = new Date()) {
  if (!u.window) return true; const w = u.window;
  if (w.days && w.days.length && !w.days.includes(now.getDay())) return false;
  if (w.from && w.to) { const cur = now.getHours() * 60 + now.getMinutes(); const [fh, fm] = w.from.split(':').map(Number), [th, tm] = w.to.split(':').map(Number); if (cur < fh * 60 + fm || cur > th * 60 + tm) return false; }
  return true;
}
function todayStats(tenantId) {
  const start = new Date(); start.setHours(0, 0, 0, 0);
  const t0 = start.getTime();
  const rows = db.log.filter(l => l.ts >= t0 && (!tenantId || l.tenantId === tenantId));
  return { today: rows.length, granted: rows.filter(r => r.result === 'granted').length, denied: rows.filter(r => r.result !== 'granted').length };
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://${req.headers.host}`);
  const p = u.pathname, m = req.method;
  const S = sessionOf(req);

  // ===== התחברות =====
  if (p === '/api/login' && m === 'POST') {
    const b = await readBody(req);
    if (b.user === SUPER_USER && b.password === SUPER_PASSWORD)
      return send(res, 200, { ok: true, role: 'super' }, 'application/json', cookieHeader(signToken({ role: 'super' })));
    const admin = Object.values(db.admins).find(a => a.user === b.user && a.active);
    if (admin && checkPass(b.password, admin.salt, admin.passHash))
      return send(res, 200, { ok: true, role: 'admin' }, 'application/json', cookieHeader(signToken({ role: 'admin', adminId: admin.id, tenantId: admin.tenantId })));
    return send(res, 401, { ok: false, error: 'שם משתמש או סיסמה שגויים' });
  }
  if (p === '/api/logout') return send(res, 200, { ok: true }, 'application/json', { 'Set-Cookie': 'qrsess=; Path=/; Max-Age=0' });

  // ===== QR עובד (ציבורי) =====
  if (p.startsWith('/q/')) { const user = db.users[p.split('/')[2]]; if (!user) return send(res, 404, 'לא נמצא', 'text/plain'); return send(res, 200, qrPage(user), 'text/html'); }
  if (p.startsWith('/api/qr/')) {
    const user = db.users[p.split('/')[3]]; if (!user || !user.active) return send(res, 403, { ok: false });
    const payload = `${user.id}.${totp(user.secret)}`; const msLeft = STEP_SECONDS * 1000 - (Date.now() % (STEP_SECONDS * 1000));
    return send(res, 200, { ok: true, payload, secondsLeft: Math.ceil(msLeft / 1000), name: user.name });
  }

  // ===== אימות (ציבורי) =====
  if (p === '/api/verify' && m === 'POST') {
    const b = await readBody(req); const raw = (b.payload || '').trim();
    let user = null, method = 'qr', result = 'denied', reason = 'לא מזוהה';
    if (raw.startsWith('CODE:')) {
      method = 'code'; const code = raw.slice(5); user = Object.values(db.users).find(x => x.code && x.code === code);
      if (user) { if (!user.active) reason = 'מושבת'; else if (user.codeType === 'temporary' && user.codeExp && Date.now() > user.codeExp) reason = 'קוד פג'; else if (!withinWindow(user)) reason = 'מחוץ לחלון זמן'; else { result = 'granted'; reason = ''; if (user.codeType === 'onetime') { user.code = null; user.codeType = null; } } }
    } else if (raw.startsWith('NFC:')) {
      method = 'nfc'; const nfc = raw.slice(4); user = Object.values(db.users).find(x => x.nfcId && x.nfcId === nfc);
      // סוג התג שהקורא מדווח (125khz / 13.56mhz) — אם נשלח
      var tagType = (b.tagType && TAG_TYPES[b.tagType]) ? b.tagType : null;
      if (user) { if (!user.active) reason = 'מושבת'; else if (!withinWindow(user)) reason = 'מחוץ לחלון זמן'; else { result = 'granted'; reason = ''; } }
      else {
        // תג לא מוכר — נשמור אותו לקליטה אוטומטית. הקורא שולח tenantId/doorId + סוג
        let tid = b.tenantId || null;
        if (!tid && b.doorId && db.doors[b.doorId]) tid = db.doors[b.doorId].tenantId;
        if (tid) { lastUnknownTag[tid] = { uid: nfc, type: tagType, ts: Date.now() }; reason = 'תג לא רשום (זמין לשיוך)'; }
      }
    } else {
      method = 'qr'; const [uid, code] = raw.split('.'); user = db.users[uid];
      if (user) { if (!user.active) reason = 'מושבת'; else if (!withinWindow(user)) reason = 'מחוץ לחלון זמן'; else if (!code || !verifyTotp(user.secret, code)) reason = 'קוד לא תקף'; else { result = 'granted'; reason = ''; } }
    }
    db.log.unshift({ ts: Date.now(), tenantId: user ? user.tenantId : null, userId: user ? user.id : null, userName: user ? user.name : 'לא ידוע', method, result, reason, tagType: (method === 'nfc' ? (user && user.nfcType ? user.nfcType : (typeof tagType !== 'undefined' ? tagType : null)) : null), doorId: b.doorId || null });
    db.log = db.log.slice(0, 2000); saveDB();
    return send(res, 200, { result, open: result === 'granted', reason, method });
  }

  if (!S) { if (p.startsWith('/api/')) return send(res, 401, { ok: false, error: 'לא מחובר' }); return send(res, 200, loginPage(), 'text/html'); }

  if (p === '/api/me') {
    if (S.role === 'super') return send(res, 200, { role: 'super', version: VERSION, user: SUPER_USER, permDefs: PERMS, stats: todayStats(null), tenantCount: Object.keys(db.tenants).length });
    const a = db.admins[S.adminId]; if (!a) return send(res, 401, { error: 'לא מחובר' });
    return send(res, 200, { role: 'admin', version: VERSION, name: a.name, tenantName: db.tenants[S.tenantId] ? db.tenants[S.tenantId].name : '', perms: Object.keys(a.perms).filter(k => a.perms[k]), maxUsers: a.maxUsers, permDefs: PERMS, stats: todayStats(S.tenantId) });
  }

  // ========== SUPER ==========
  if (S.role === 'super') {
    if (p === '/api/permdefs') return send(res, 200, PERMS);
    if (p === '/api/tenants' && m === 'GET') {
      return send(res, 200, Object.values(db.tenants).map(t => ({ ...t, admins: Object.values(db.admins).filter(a => a.tenantId === t.id).map(a => ({ id: a.id, user: a.user, name: a.name, active: a.active, perms: a.perms, maxUsers: a.maxUsers })), userCount: Object.values(db.users).filter(x => x.tenantId === t.id).length })));
    }
    if (p === '/api/tenants' && m === 'POST') {
      const b = await readBody(req); const tid = 't' + crypto.randomBytes(3).toString('hex');
      db.tenants[tid] = { id: tid, name: b.name || 'לקוח חדש', createdAt: Date.now() };
      const aid = 'a' + crypto.randomBytes(3).toString('hex'); const { salt, passHash } = makePass(b.adminPassword || 'changeme');
      const perms = {}; (b.perms || ['manage_users', 'issue_qr', 'view_log']).forEach(k => { if (PERMS[k]) perms[k] = true; });
      db.admins[aid] = { id: aid, tenantId: tid, user: b.adminUser || ('admin_' + tid), name: b.adminName || 'מנהל', phone: b.phone || '', email: b.email || '', salt, passHash, perms, maxUsers: b.maxUsers || 50, active: true };
      saveDB(); return send(res, 200, { tenant: db.tenants[tid], adminUser: db.admins[aid].user });
    }
    // איפוס סיסמה מהיר למנהל — מחזיר סיסמה זמנית (לפני המטפל הכללי!)
    if (p.startsWith('/api/admins/') && p.endsWith('/reset') && m === 'POST') {
      const id = p.split('/')[3]; const a = db.admins[id]; if (!a) return send(res, 404, { error: 'not found' });
      const temp = 'tmp' + Math.floor(1000 + Math.random() * 9000);
      const x = makePass(temp); a.salt = x.salt; a.passHash = x.passHash; saveDB();
      return send(res, 200, { ok: true, tempPassword: temp, user: a.user, phone: a.phone || '' });
    }
    if (p.startsWith('/api/admins/') && m === 'POST') {
      const id = p.split('/')[3]; const b = await readBody(req); const a = db.admins[id]; if (!a) return send(res, 404, { error: 'not found' });
      if (b.perms) { a.perms = {}; b.perms.forEach(k => { if (PERMS[k]) a.perms[k] = true; }); }
      if (typeof b.active === 'boolean') a.active = b.active;
      if (typeof b.maxUsers === 'number' && b.maxUsers > 0) a.maxUsers = b.maxUsers;
      if (b.newPassword) { const x = makePass(b.newPassword); a.salt = x.salt; a.passHash = x.passHash; }
      if (typeof b.name === 'string' && b.name.trim()) a.name = b.name.trim();
      if (typeof b.phone === 'string') a.phone = b.phone.trim();
      if (typeof b.email === 'string') a.email = b.email.trim();
      saveDB(); return send(res, 200, { ok: true });
    }
    // שינוי סיסמת על-מנהל עצמו — דורש הגדרה ב-Render (לא ניתן לשנות ENV מהקוד)
    if (p === '/api/self/password' && m === 'POST') {
      return send(res, 200, { ok: false, note: 'super' });
    }
    if (p.startsWith('/api/tenants/') && m === 'DELETE') {
      const id = p.split('/')[3]; delete db.tenants[id];
      Object.values(db.admins).filter(a => a.tenantId === id).forEach(a => delete db.admins[a.id]);
      Object.values(db.users).filter(x => x.tenantId === id).forEach(x => delete db.users[x.id]);
      saveDB(); return send(res, 200, { ok: true });
    }
    if (p === '/api/log') return send(res, 200, db.log.slice(0, 150));
    if (p === '/' || p === '/admin') return send(res, 200, superPage(), 'text/html');
  }

  // ========== ADMIN ==========
  if (S.role === 'admin') {
    const a = db.admins[S.adminId]; if (!a || !a.active) return send(res, 200, loginPage(), 'text/html');
    const has = k => !!a.perms[k]; const tid = S.tenantId;
    // קליטת תג אוטומטית: מחזיר את התג האחרון שנסרק בקורא ולא זוהה (לשיוך)
    if (p === '/api/last-tag' && m === 'GET') {
      const t = lastUnknownTag[tid];
      if (t && Date.now() - t.ts < TAG_ENROLL_WINDOW) return send(res, 200, { uid: t.uid, type: t.type || null, ageSec: Math.floor((Date.now() - t.ts) / 1000) });
      return send(res, 200, { uid: null });
    }
    // מנהל משנה את הסיסמה של עצמו
    if (p === '/api/self/password' && m === 'POST') {
      const b = await readBody(req);
      if (!b.current || !checkPass(b.current, a.salt, a.passHash)) return send(res, 403, { ok: false, error: 'סיסמה נוכחית שגויה' });
      if (!b.newPassword || b.newPassword.length < 4) return send(res, 400, { ok: false, error: 'סיסמה חדשה קצרה מדי' });
      const x = makePass(b.newPassword); a.salt = x.salt; a.passHash = x.passHash; saveDB();
      return send(res, 200, { ok: true });
    }
    if (p === '/api/users' && m === 'GET') return send(res, 200, Object.values(db.users).filter(x => x.tenantId === tid));
    if (p === '/api/users' && m === 'POST') {
      if (!has('manage_users')) return send(res, 403, { error: 'אין הרשאה' });
      const count = Object.values(db.users).filter(x => x.tenantId === tid).length;
      if (count >= a.maxUsers) return send(res, 403, { error: `הגעת למכסה (${a.maxUsers})` });
      const b = await readBody(req); const id = 'u' + crypto.randomBytes(3).toString('hex');
      db.users[id] = { id, tenantId: tid, name: b.name || 'משתמש', phone: b.phone || '', secret: newSecret(), code: null, codeType: null, codeExp: null, nfcId: null, nfcType: null, active: true, window: null, createdAt: Date.now() };
      saveDB(); return send(res, 200, db.users[id]);
    }
    if (p.startsWith('/api/users/') && p.endsWith('/code') && m === 'POST') {
      if (!has('issue_code')) return send(res, 403, { error: 'אין הרשאה' });
      const id = p.split('/')[3]; const user = db.users[id]; if (!user || user.tenantId !== tid) return send(res, 404, { error: 'not found' });
      const b = await readBody(req); const type = b.type || 'permanent';
      const pm = { permanent: 'code_permanent', temporary: 'code_temporary', onetime: 'code_onetime' };
      if (!has(pm[type])) return send(res, 403, { error: 'אין הרשאה לסוג זה' });
      user.code = genCode(); user.codeType = type; user.codeExp = type === 'temporary' ? (Date.now() + (b.hours || 24) * 3600000) : null;
      saveDB(); return send(res, 200, { code: user.code, type, exp: user.codeExp });
    }
    if (p.startsWith('/api/users/') && m === 'POST') {
      if (!has('manage_users')) return send(res, 403, { error: 'אין הרשאה' });
      const id = p.split('/')[3]; const user = db.users[id]; if (!user || user.tenantId !== tid) return send(res, 404, { error: 'not found' });
      const b = await readBody(req);
      if (typeof b.active === 'boolean') user.active = b.active;
      if (typeof b.name === 'string' && b.name.trim()) user.name = b.name.trim();
      if ('window' in b && has('time_windows')) user.window = b.window;
      if ('nfcId' in b && has('use_nfc')) { user.nfcId = b.nfcId || null; if ('nfcType' in b) user.nfcType = b.nfcType || null; if (!user.nfcId) user.nfcType = null; }
      if (typeof b.phone === 'string') user.phone = b.phone.trim();
      if (b.resetAccess) { user.secret = newSecret(); user.code = null; user.codeType = null; } // איפוס: QR חדש, מבטל קוד ישן
      saveDB(); return send(res, 200, user);
    }
    if (p.startsWith('/api/users/') && m === 'DELETE') {
      if (!has('manage_users')) return send(res, 403, { error: 'אין הרשאה' });
      const id = p.split('/')[3]; const user = db.users[id]; if (user && user.tenantId === tid) delete db.users[id];
      saveDB(); return send(res, 200, { ok: true });
    }
    if (p === '/api/log') { if (!has('view_log')) return send(res, 403, { error: 'אין הרשאה' }); return send(res, 200, db.log.filter(l => l.tenantId === tid).slice(0, 100)); }
    if (p === '/' || p === '/admin') return send(res, 200, adminPage(), 'text/html');
  }

  send(res, 404, 'not found', 'text/plain');
});

// מפעילים את השרת רק אחרי שהאחסון מוכן (טעינת הנתונים הקיימים)
initStorage().then(() => {
  server.listen(PORT, () => console.log(`\n  QR Access v${VERSION} — פורט ${PORT}\n  Super: ${SUPER_USER} ${SUPER_PASSWORD === 'michael2026' ? '(ברירת מחדל — שנה!)' : ''}\n`));
}).catch(e => { console.error('שגיאת אתחול אחסון:', e.message); process.exit(1); });

// ================= HTML =================
function shell(title, body, head = '') {
  return `<!doctype html><html dir="rtl" lang="he"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<meta name="theme-color" content="#1f3a5f"><title>${title}</title>
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>${head}
<style>
  :root{--bg:#f4f6f9;--card:#fff;--ink:#1a2b3c;--muted:#64748b;--brand:#1f3a5f;--brand2:#2c5282;--ok:#1b8a4b;--bad:#c0392b;--line:#e2e8f0}
  *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
  body{font-family:Arial,system-ui,sans-serif;background:var(--bg);color:var(--ink);margin:0;padding:14px;font-size:16px}
  .wrap{max-width:820px;margin:0 auto}
  h1{color:var(--brand);font-size:21px;margin:6px 0 2px}h3{margin:0 0 10px}
  .sub{color:var(--muted);font-size:13px;margin:0 0 14px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:15px;margin-bottom:13px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
  button{font-family:inherit;font-size:16px;border:0;border-radius:11px;padding:13px 18px;cursor:pointer;min-height:48px}
  .primary{background:var(--brand);color:#fff;width:100%}.ghost{background:#eef3f8;color:var(--brand)}
  .danger{background:#fdeaea;color:var(--bad)}.wa{background:#25d366;color:#fff}
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
  .perm{display:flex;align-items:center;gap:8px;padding:7px 0;font-size:15px;cursor:pointer}
  .perm input{width:auto;min-height:auto;transform:scale(1.3);margin-left:4px}
  .logline{display:flex;justify-content:space-between;padding:9px 2px;border-bottom:1px solid var(--line);font-size:14px;gap:8px}
  label{font-size:14px;color:var(--muted)}
  /* stats */
  .stats{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:13px}
  .stat{flex:1;min-width:95px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:13px;text-align:center}
  .stat .n{font-size:26px;font-weight:bold;color:var(--brand)}
  .stat .l{font-size:12px;color:var(--muted);margin-top:3px}
  /* modal */
  .modal{position:fixed;inset:0;background:rgba(0,0,0,.45);display:none;align-items:center;justify-content:center;padding:16px;z-index:50}
  .modal.show{display:flex}
  .modal .box{background:#fff;border-radius:16px;padding:18px;max-width:420px;width:100%;max-height:85vh;overflow:auto}
  .modal h3{margin:0 0 12px}
</style></head><body><div class="wrap">${body}</div>
<div class="modal" id="modal"><div class="box" id="modalBox"></div></div>
<script>
function openModal(html){document.getElementById('modalBox').innerHTML=html;document.getElementById('modal').classList.add('show');}
function closeModal(){document.getElementById('modal').classList.remove('show');}
document.getElementById('modal').addEventListener('click',e=>{if(e.target.id==='modal')closeModal();});
function waLink(text){return 'https://wa.me/?text='+encodeURIComponent(text);}
</script></body></html>`;
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
async function login(){const user=document.getElementById('user').value.trim(),password=document.getElementById('pass').value;
  const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user,password})});
  const d=await r.json(); if(d.ok)location.href='/admin'; else document.getElementById('err').textContent=d.error||'שגיאה';}
document.getElementById('pass').addEventListener('keydown',e=>{if(e.key==='Enter')login();});
</script>`);
}

function superPage() {
  return shell('ניהול-על', `
<div class="nav"><span class="badge">👑 ניהול-על</span><a href="#" onclick="myPassword();return false;">🔑 הסיסמה שלי</a><a href="#" onclick="logout();return false;">התנתק</a><span class="ver">גרסה <span id="ver">…</span></span></div>
<h1>לוח בקרה</h1><p class="sub">סקירה של כל הלקוחות והכניסות היום.</p>
<div class="stats" id="stats"></div>

<div class="card">
  <h3>הוספת לקוח חדש</h3>
  <div style="display:flex;flex-direction:column;gap:9px">
    <input id="tname" placeholder="שם הלקוח/אתר (למשל: בניין רוטשילד 5)">
    <div class="row wrap2"><input id="auser" placeholder="שם משתמש למנהל" style="flex:1"><input id="aname" placeholder="שם המנהל" style="flex:1"></div>
    <input id="apass" placeholder="סיסמה למנהל">
    <div class="row wrap2"><input id="aphone" placeholder="נייד המנהל (לשחזור)" style="flex:1"><input id="aemail" placeholder="מייל (לא חובה)" style="flex:1"></div>
    <label>מכסת משתמשים: <input id="amax" type="number" value="50" style="width:100px;display:inline-block"></label>
    <div><label>הרשאות למנהל:</label><div id="permbox" style="margin-top:6px"></div></div>
    <button class="primary" onclick="addTenant()">צור לקוח + מנהל</button>
    <div id="msg" class="muted"></div>
  </div>
</div>

<div id="tenants"></div>
<div class="card"><h3>יומן כניסות (כל הלקוחות)</h3><div id="log"></div></div>

<script>
const PERMS=${JSON.stringify(PERMS)};
async function logout(){await fetch('/api/logout');location.href='/admin';}
function myPassword(){
  openModal('<h3>🔑 הסיסמה שלך (על-מנהל)</h3>'+
    '<p class="muted">מטעמי אבטחה, סיסמת העל-מנהל נשמרת מחוץ לקוד ומשתנה דרך Render (לא מהממשק):</p>'+
    '<ol style="font-size:14px;line-height:1.8;padding-right:18px">'+
    '<li>היכנס ל-Render → השירות qraccess</li>'+
    '<li>פתח <b>Environment</b></li>'+
    '<li>ערוך את <b>SUPER_PASSWORD</b> (והוסף אם חסר)</li>'+
    '<li>שמור — השרת יתעדכן תוך דקה</li></ol>'+
    '<p class="muted">כך אף אחד שנכנס למערכת לא יכול לשנות את סיסמת-העל שלך — רק מי שיש לו גישה ל-Render (אתה).</p>'+
    '<button class="ghost sm" onclick="closeModal()">הבנתי</button>');
}
function permCheckboxes(containerId, selected){
  const box=document.getElementById(containerId); box.innerHTML='';
  Object.entries(PERMS).forEach(([k,label])=>{
    const l=document.createElement('label'); l.className='perm';
    l.innerHTML='<input type="checkbox" value="'+k+'" '+(selected.includes(k)?'checked':'')+'> '+label;
    box.appendChild(l);
  });
}
function checkedIn(id){return[...document.querySelectorAll('#'+id+' input:checked')].map(c=>c.value);}
async function init(){
  const me=await (await fetch('/api/me')).json(); document.getElementById('ver').textContent=me.version;
  document.getElementById('stats').innerHTML=
    '<div class="stat"><div class="n">'+me.tenantCount+'</div><div class="l">לקוחות</div></div>'+
    '<div class="stat"><div class="n">'+me.stats.today+'</div><div class="l">כניסות היום</div></div>'+
    '<div class="stat"><div class="n" style="color:#1b8a4b">'+me.stats.granted+'</div><div class="l">אושרו</div></div>'+
    '<div class="stat"><div class="n" style="color:#c0392b">'+me.stats.denied+'</div><div class="l">נדחו</div></div>';
  permCheckboxes('permbox',['manage_users','issue_qr','view_log']); load();
}
async function addTenant(){
  const body={name:tname.value.trim(),adminUser:auser.value.trim(),adminName:aname.value.trim(),adminPassword:apass.value,phone:document.getElementById('aphone').value.trim(),email:document.getElementById('aemail').value.trim(),maxUsers:parseInt(amax.value)||50,perms:checkedIn('permbox')};
  if(!body.name||!body.adminUser||!body.adminPassword){msg.textContent='מלא שם לקוח, שם משתמש וסיסמה';return;}
  const r=await (await fetch('/api/tenants',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})).json();
  msg.textContent='✓ נוצר! מנהל: '+r.adminUser; tname.value=auser.value=aname.value=apass.value=document.getElementById('aphone').value=document.getElementById('aemail').value=''; init();
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
        '<div class="btns"><button class="ghost sm" onclick=\\'editAdmin('+JSON.stringify(JSON.stringify({id:a.id,name:a.name,perms:Object.keys(a.perms).filter(k=>a.perms[k]),maxUsers:a.maxUsers,active:a.active}))+')\\'>ערוך</button>'+
        '<button class="'+(a.active?'danger':'ghost')+' sm" onclick="toggleAdmin(\\''+a.id+'\\','+(!a.active)+')">'+(a.active?'השבת':'הפעל')+'</button></div></div>';
    }).join('');
    c.innerHTML='<div class="top"><span class="name">🏢 '+t.name+'</span><span class="muted">'+t.userCount+' משתמשים</span></div>'+adminsHtml+
      '<div class="btns"><button class="danger sm" onclick="delTenant(\\''+t.id+'\\',\\''+t.name.replace(/\\x27/g,"")+'\\')">מחק לקוח</button></div>';
    box.appendChild(c);
  });
  const log=await (await fetch('/api/log')).json(); renderLog(log,'log');
}
function renderLog(log,elId){
  const lb=document.getElementById(elId); lb.innerHTML=log.length?'':'<div class="muted">אין כניסות.</div>';
  log.forEach(l=>{const d=document.createElement('div');d.className='logline';const t=new Date(l.ts).toLocaleString('he-IL');const mth=({qr:'QR',code:'קוד',nfc:'NFC'}[l.method]||l.method)+(l.method==='nfc'&&l.tagType?' '+({'125khz':'125kHz','13.56mhz':'13.56MHz'}[l.tagType]||''):'');
    d.innerHTML='<span>'+l.userName+' <span class="muted">('+mth+')</span></span><span class="'+(l.result==='granted'?'g':'r')+'">'+(l.result==='granted'?'✓':'✕'+(l.reason?' '+l.reason:''))+'</span><span class="muted">'+t+'</span>';lb.appendChild(d);});
}
function editAdmin(json){
  const a=JSON.parse(json);
  let html='<h3>עריכת מנהל: '+a.name+'</h3>';
  html+='<label>שם המנהל</label><input id="eName" value="'+a.name+'" style="margin-bottom:10px">';
  html+='<label>נייד (לשחזור)</label><input id="ePhone" value="'+(a.phone||'')+'" placeholder="05X-XXXXXXX" style="margin-bottom:10px">';
  html+='<label>מכסת משתמשים</label><input id="eMax" type="number" value="'+a.maxUsers+'" style="margin-bottom:10px">';
  html+='<label>סיסמה חדשה (ריק = ללא שינוי)</label><input id="ePass" placeholder="סיסמה חדשה" style="margin-bottom:10px">';
  html+='<button class="ghost sm" style="width:100%;margin-bottom:12px" onclick="resetAdmin(\\''+a.id+'\\')">🔄 איפוס מהיר — צור סיסמה זמנית</button>';
  html+='<label>הרשאות</label><div id="ePerms"></div>';
  html+='<div class="btns" style="margin-top:14px"><button class="primary sm" style="flex:1" onclick="saveAdmin(\\''+a.id+'\\')">שמור</button><button class="ghost sm" onclick="closeModal()">ביטול</button></div>';
  openModal(html);
  permCheckboxes('ePerms',a.perms);
}
async function saveAdmin(id){
  const body={name:document.getElementById('eName').value.trim(),phone:document.getElementById('ePhone').value.trim(),maxUsers:parseInt(document.getElementById('eMax').value)||50,perms:checkedIn('ePerms')};
  const np=document.getElementById('ePass').value; if(np)body.newPassword=np;
  await fetch('/api/admins/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  closeModal(); load();
}
async function resetAdmin(id){
  if(!confirm('לאפס סיסמה? תיווצר סיסמה זמנית שתוכל לשלוח למנהל.'))return;
  const r=await (await fetch('/api/admins/'+id+'/reset',{method:'POST'})).json();
  if(r.ok){const msg='הסיסמה החדשה שלך למערכת: '+r.tempPassword+' (מומלץ להחליף אחרי הכניסה)';
    let h='<h3>סיסמה זמנית נוצרה ✓</h3><p class="muted">משתמש: '+r.user+'</p><div style="font-size:28px;font-weight:bold;text-align:center;color:#1f3a5f;background:#eef3f8;border-radius:12px;padding:16px;margin:10px 0">'+r.tempPassword+'</div>';
    h+='<a href="'+waLink(msg)+'" target="_blank"><button class="wa" style="margin-bottom:8px">שלח בוואטסאפ</button></a>';
    h+='<button class="ghost sm" onclick="closeModal();load()">סגור</button>';
    openModal(h);
  } else alert(r.error||'שגיאה');
}
async function toggleAdmin(id,active){await fetch('/api/admins/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({active})});load();}
async function delTenant(id,name){if(confirm('למחוק את '+name+' וכל המשתמשים שלו?')){await fetch('/api/tenants/'+id,{method:'DELETE'});init();}}
init();
</script>`);
}

function adminPage() {
  return shell('ניהול אתר', `
<div class="nav"><span class="badge">🏢 <span id="tname">…</span></span><a href="#" onclick="changeMyPass();return false;">🔑 שנה סיסמה</a><a href="#" onclick="logout();return false;">התנתק</a><span class="ver">גרסה <span id="ver">…</span></span></div>
<h1 id="title">ניהול כניסה</h1><p class="sub" id="whoami"></p>
<div class="stats" id="stats"></div>

<div class="card" id="addcard" style="display:none">
  <div class="row"><input id="name" placeholder="שם משתמש חדש (דייר/מורה)"><button class="primary sm" onclick="addUser()">הוסף</button></div>
  <div id="quota" class="muted" style="margin-top:6px"></div>
  <div id="guestWrap" style="margin-top:10px;display:none"><button class="ghost sm" onclick="quickGuest()">⚡ קוד אורח מהיר (חד-פעמי)</button></div>
</div>

<div class="card">
  <div class="row" style="margin-bottom:10px"><input id="search" placeholder="🔍 חיפוש משתמש…" oninput="render()"></div>
  <div id="users"></div>
</div>
<div class="card" id="logcard" style="display:none"><h3>יומן כניסות</h3><div id="log"></div></div>

<script>
let ME={perms:[]}, USERS=[];
async function logout(){await fetch('/api/logout');location.href='/admin';}
function can(k){return ME.perms.includes(k);}
function changeMyPass(){
  openModal('<h3>🔑 שינוי הסיסמה שלי</h3>'+
    '<label>סיסמה נוכחית</label><input id="cpCur" type="password" style="margin-bottom:10px">'+
    '<label>סיסמה חדשה</label><input id="cpNew" type="password" style="margin-bottom:10px">'+
    '<div id="cpErr" class="r" style="font-size:13px;margin-bottom:8px"></div>'+
    '<div class="btns"><button class="primary sm" style="flex:1" onclick="doChangePass()">שמור</button><button class="ghost sm" onclick="closeModal()">ביטול</button></div>');
}
async function doChangePass(){
  const current=document.getElementById('cpCur').value,newPassword=document.getElementById('cpNew').value;
  const r=await (await fetch('/api/self/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current,newPassword})})).json();
  if(r.ok){closeModal();alert('הסיסמה שונתה ✓');}else document.getElementById('cpErr').textContent=r.error||'שגיאה';
}
async function init(){
  ME=await (await fetch('/api/me')).json();
  document.getElementById('ver').textContent=ME.version; document.getElementById('tname').textContent=ME.tenantName||'אתר';
  document.getElementById('whoami').textContent='מחובר: '+(ME.name||'')+' | הרשאות: '+(ME.perms.map(k=>ME.permDefs[k]).join(', ')||'צפייה בלבד');
  document.getElementById('stats').innerHTML=
    '<div class="stat"><div class="n">'+ME.stats.today+'</div><div class="l">כניסות היום</div></div>'+
    '<div class="stat"><div class="n" style="color:#1b8a4b">'+ME.stats.granted+'</div><div class="l">אושרו</div></div>'+
    '<div class="stat"><div class="n" style="color:#c0392b">'+ME.stats.denied+'</div><div class="l">נדחו</div></div>';
  if(can('manage_users'))document.getElementById('addcard').style.display='block';
  if(can('issue_code'))document.getElementById('guestWrap').style.display='block';
  if(can('view_log'))document.getElementById('logcard').style.display='block';
  await loadUsers(); if(can('view_log'))loadLog();
}
async function loadUsers(){USERS=await (await fetch('/api/users')).json(); if(can('manage_users'))document.getElementById('quota').textContent='משתמשים: '+USERS.length+' / '+ME.maxUsers; render();}
function render(){
  const q=(document.getElementById('search').value||'').trim();
  const list=q?USERS.filter(u=>u.name.includes(q)):USERS;
  const box=document.getElementById('users'); box.innerHTML=list.length?'':'<div class="muted">'+(USERS.length?'לא נמצא.':'אין עדיין משתמשים.')+'</div>';
  list.forEach(u=>{
    const div=document.createElement('div'); div.className='item';
    let codeInfo=''; if(u.code){const ct={permanent:'קבוע',temporary:'זמני',onetime:'חד-פעמי'}[u.codeType]||'';codeInfo='<div class="muted">קוד '+ct+': <b style="font-size:16px;color:#1f3a5f">'+u.code+'</b></div>';}
    let tagTypeName={'125khz':'125kHz','13.56mhz':'13.56MHz'}[u.nfcType]||'';
    let nfcInfo=u.nfcId?'<div class="muted">תג'+(tagTypeName?' '+tagTypeName:'')+': '+u.nfcId+'</div>':'';
    let btns='<a class="link" href="/q/'+u.id+'" target="_blank">QR ↗</a>';
    btns+='<button class="wa sm" onclick="shareWa(\\''+u.id+'\\')">וואטסאפ</button>';
    if(can('issue_code'))btns+='<button class="ghost sm" onclick="issueCode(\\''+u.id+'\\')">הנפק קוד</button>';
    if(can('use_nfc'))btns+='<button class="ghost sm" onclick="setNfc(\\''+u.id+'\\')">NFC</button>';
    if(can('time_windows'))btns+='<button class="ghost sm" onclick="setWindow(\\''+u.id+'\\')">חלון זמן</button>';
    if(can('manage_users')){btns+='<button class="ghost sm" onclick="rename(\\''+u.id+'\\',\\''+u.name.replace(/\\x27/g,"")+'\\')">שם</button>';
      btns+='<button class="ghost sm" onclick="resetAccess(\\''+u.id+'\\',\\''+u.name.replace(/\\x27/g,"")+'\\')">🔄 איפוס גישה</button>';
      btns+='<button class="'+(u.active?'danger':'ghost')+' sm" onclick="toggle(\\''+u.id+'\\','+(!u.active)+')">'+(u.active?'השבת':'הפעל')+'</button>';
      btns+='<button class="danger sm" onclick="del(\\''+u.id+'\\',\\''+u.name.replace(/\\x27/g,"")+'\\')">מחק</button>';}
    div.innerHTML='<div class="top"><span class="name">'+u.name+'</span><span class="pill '+(u.active?'on':'off')+'">'+(u.active?'פעיל':'מושבת')+'</span></div>'+codeInfo+nfcInfo+'<div class="btns">'+btns+'</div>';
    box.appendChild(div);
  });
}
async function loadLog(){const log=await (await fetch('/api/log')).json();const lb=document.getElementById('log');lb.innerHTML=log.length?'':'<div class="muted">אין כניסות.</div>';
  log.forEach(l=>{const d=document.createElement('div');d.className='logline';const t=new Date(l.ts).toLocaleString('he-IL');const mth=({qr:'QR',code:'קוד',nfc:'NFC'}[l.method]||l.method)+(l.method==='nfc'&&l.tagType?' '+({'125khz':'125kHz','13.56mhz':'13.56MHz'}[l.tagType]||''):'');
    d.innerHTML='<span>'+l.userName+' <span class="muted">('+mth+')</span></span><span class="'+(l.result==='granted'?'g':'r')+'">'+(l.result==='granted'?'✓':'✕'+(l.reason?' '+l.reason:''))+'</span><span class="muted">'+t+'</span>';lb.appendChild(d);});}
async function addUser(){const name=document.getElementById('name').value.trim()||'משתמש';
  const r=await fetch('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});
  if(!r.ok){alert((await r.json()).error||'שגיאה');return;} document.getElementById('name').value=''; loadUsers();}
async function toggle(id,active){await fetch('/api/users/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({active})});loadUsers();}
async function rename(id,cur){const name=prompt('שם חדש:',cur);if(name&&name.trim()){await fetch('/api/users/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name.trim()})});loadUsers();}}
async function del(id,name){if(confirm('למחוק את '+name+'?')){await fetch('/api/users/'+id,{method:'DELETE'});loadUsers();}}
async function resetAccess(id,name){if(confirm('לאפס גישה ל'+name+'?\\nה-QR הישן וכל קוד ישן יפסיקו לעבוד, וייווצר QR חדש.')){await fetch('/api/users/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({resetAccess:true})});loadUsers();alert('הגישה אופסה ✓ שלח למשתמש את ה-QR החדש (כפתור QR/וואטסאפ).');}}
let tagPollTimer=null;
function setNfc(id){
  const u=USERS.find(x=>x.id===id);
  let html='<h3>שיוך תג/כרטיס NFC — '+(u?u.name:'')+'</h3>';
  html+='<p class="muted">שתי דרכים לקלוט את מספר התג (UID):</p>';
  html+='<div style="border:1px solid #e2e8f0;border-radius:12px;padding:12px;margin-bottom:12px">';
  html+='<b>1. קליטה מהקורא (אוטומטי)</b><div class="muted" style="margin:4px 0 8px">הצמד את התג לקורא בדלת, והמספר יופיע כאן.</div>';
  html+='<button class="ghost sm" style="width:100%" onclick="startTagListen()">🔄 התחל להאזין לקורא</button>';
  html+='<div id="tagStatus" class="muted" style="margin-top:8px"></div></div>';
  html+='<div style="border:1px solid #e2e8f0;border-radius:12px;padding:12px;margin-bottom:12px">';
  html+='<b>2. הזנה ידנית / מהנייד</b><div class="muted" style="margin:4px 0 8px">קרא עם אפליקציית NFC בנייד והקלד כאן:</div>';
  html+='<input id="nfcManual" placeholder="UID (למשל 04A3B2C1)" value="'+(u&&u.nfcId?u.nfcId:'')+'"></div>';
  const curType=(u&&u.nfcType)?u.nfcType:'13.56mhz';
  html+='<label>סוג התג</label><select id="nfcType" style="margin-bottom:12px">';
  html+='<option value="13.56mhz"'+(curType==='13.56mhz'?' selected':'')+'>תג 13.56MHz (Mifare/NFC)</option>';
  html+='<option value="125khz"'+(curType==='125khz'?' selected':'')+'>תג 125kHz (EM/קירבה)</option></select>';
  html+='<div class="btns"><button class="primary sm" style="flex:1" onclick="saveNfc(\\''+id+'\\')">שמור תג</button>';
  if(u&&u.nfcId)html+='<button class="danger sm" onclick="clearNfc(\\''+id+'\\')">הסר תג</button>';
  html+='<button class="ghost sm" onclick="stopTagListen();closeModal()">סגור</button></div>';
  openModal(html);
}
function startTagListen(){
  const st=document.getElementById('tagStatus'); st.textContent='⏳ ממתין לתג... הצמד עכשיו לקורא.';
  if(tagPollTimer)clearInterval(tagPollTimer);
  tagPollTimer=setInterval(async()=>{
    try{const r=await (await fetch('/api/last-tag')).json();
      if(r.uid){document.getElementById('nfcManual').value=r.uid;
        if(r.type){document.getElementById('nfcType').value=r.type;}
        const tn={'125khz':'125kHz','13.56mhz':'13.56MHz'}[r.type]||'';
        st.innerHTML='✓ זוהה תג'+(tn?' ('+tn+')':'')+': <b>'+r.uid+'</b> — לחץ "שמור תג".';stopTagListen();}
    }catch(e){}
  },1500);
}
function stopTagListen(){if(tagPollTimer){clearInterval(tagPollTimer);tagPollTimer=null;}}
async function saveNfc(id){const nfcId=document.getElementById('nfcManual').value.trim();if(!nfcId){alert('אין UID');return;}const nfcType=document.getElementById('nfcType').value;stopTagListen();await fetch('/api/users/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({nfcId,nfcType})});closeModal();loadUsers();}
async function clearNfc(id){stopTagListen();await fetch('/api/users/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({nfcId:''})});closeModal();loadUsers();}
async function setWindow(id){const ans=prompt('חלון זמן. "תמיד" לגישה חופשית.\\nדוגמה: 0,1,2,3,4 08:00 18:00','תמיד');if(ans===null)return;let win=null;if(ans.trim()!=='תמיד'){const pr=ans.trim().split(/\\s+/);win={days:(pr[0]||'').split(',').map(x=>parseInt(x)).filter(x=>!isNaN(x)),from:pr[1]||'00:00',to:pr[2]||'23:59'};}await fetch('/api/users/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({window:win})});loadUsers();}
async function issueCode(id){
  let types=[]; if(can('code_permanent'))types.push(['permanent','קבוע']); if(can('code_temporary'))types.push(['temporary','זמני 24ש']); if(can('code_onetime'))types.push(['onetime','חד-פעמי']);
  if(!types.length){alert('אין לך הרשאה לסוג קוד');return;}
  let html='<h3>הנפקת קוד</h3><p class="muted">בחר סוג:</p>';
  types.forEach(([t,n])=>html+='<button class="primary" style="margin-bottom:8px" onclick="doIssue(\\''+id+'\\',\\''+t+'\\')">'+n+'</button>');
  html+='<button class="ghost sm" onclick="closeModal()">ביטול</button>';
  openModal(html);
}
async function doIssue(id,type){
  const r=await (await fetch('/api/users/'+id+'/code',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type,hours:24})})).json();
  if(r.code){const u=USERS.find(x=>x.id===id);const msg='קוד כניסה ל'+(u?u.name:'')+': '+r.code;
    openModal('<h3>הקוד נוצר ✓</h3><div style="font-size:34px;font-weight:bold;text-align:center;letter-spacing:5px;color:#1f3a5f;background:#eef3f8;border-radius:12px;padding:18px;margin:10px 0">'+r.code+'</div><a href="'+waLink(msg)+'" target="_blank"><button class="wa" style="margin-bottom:8px">שלח בוואטסאפ</button></a><button class="ghost sm" onclick="closeModal();loadUsers()">סגור</button>');
  } else alert(r.error||'שגיאה');
}
async function quickGuest(){
  // יוצר משתמש אורח זמני ומנפיק לו קוד חד-פעמי
  const name='אורח '+new Date().toLocaleDateString('he-IL');
  const u=await (await fetch('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})})).json();
  if(u.error){alert(u.error);return;}
  await loadUsers(); doIssue(u.id,'onetime');
}
function shareWa(id){
  const u=USERS.find(x=>x.id===id);
  const url=location.origin+'/q/'+id;
  const msg='קישור כניסה אישי ל'+u.name+' ('+u.name+'):\\n'+url+'\\n(הצג את ה-QR לקורא בכניסה)';
  window.open(waLink(msg),'_blank');
}
init();
</script>`);
}

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
