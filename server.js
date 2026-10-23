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

const VERSION = '13.0';
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

// הרשאות שאתה (על-מנהל) נותן למנהל-לקוח. מנהל יכול לתת למשתמשים רק ממה שיש לו.
const PERMS = {
  manage_users:   'ניהול משתמשים (הוספה/עריכה/מחיקה)',
  issue_qr:       'הנפקת QR מתחלף',
  issue_code:     'הנפקת קוד מספרי',
  code_permanent: 'קוד קבוע',
  code_temporary: 'קוד זמני',
  code_onetime:   'קוד חד-פעמי',
  use_nfc:        'כרטיס/צ׳יפ NFC',
  remote_open:    'פתיחה מרחוק',
  time_windows:   'חלונות זמן',
  view_log:       'צפייה ביומן כניסות',
};

// אמצעי כניסה שמנהל-לקוח מקצה לכל משתמש קצה. כל אחד דורש שלמנהל יש את ההרשאה המתאימה.
// access flag בצד המשתמש  ->  הרשאת מנהל שנדרשת כדי לתת אותו
const ACCESS_METHODS = {
  allow_qr:     { label: 'כניסה ב-QR',        needs: 'issue_qr'    },
  allow_code:   { label: 'כניסה בקוד מספרי',   needs: 'issue_code'  },
  allow_nfc:    { label: 'כניסה בתג/NFC',      needs: 'use_nfc'     },
  allow_remote: { label: 'פתיחה מרחוק',        needs: 'remote_open' },
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
  // תומך גם במודל הישן (u.window) וגם בחדש (u.schedule עם type)
  const s = u.schedule;
  if (s && s.type) {
    if (s.type === 'permanent') return true;
    if (s.type === 'timed') { const t = now.getTime(); if (s.startDate && t < s.startDate) return false; if (s.endDate && t > s.endDate) return false; return true; }
    if (s.type === 'recurring') {
      // fail-closed: לוח חוזר חייב לפחות יום אחד. ללא ימים = אין גישה.
      const days = Array.isArray(s.days) ? s.days : [];
      if (!days.includes(now.getDay())) return false;
      if (s.from && s.to) { const cur = now.getHours() * 60 + now.getMinutes(); const [fh, fm] = s.from.split(':').map(Number), [th, tm] = s.to.split(':').map(Number); if (cur < fh * 60 + fm || cur > th * 60 + tm) return false; }
      return true;
    }
    return true;
  }
  // תאימות לאחור — מודל window ישן
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

  // PWA manifest — מאפשר "הוספה למסך הבית" כמו אפליקציה
  if (p === '/manifest.json') return send(res, 200, { name: 'מיכאל מערכות — בקרת כניסה', short_name: 'בקרת כניסה', start_url: '/', display: 'standalone', background_color: '#185fa5', theme_color: '#185fa5', icons: [{ src: 'data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 192 192"><rect width="192" height="192" rx="40" fill="#185fa5"/><text x="96" y="130" font-size="96" text-anchor="middle" fill="#fff">🔑</text></svg>'), sizes: '192x192', type: 'image/svg+xml' }] }, 'application/manifest+json');

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
    // אמצעי כניסה מורשה למשתמש? (ברירת מחדל true למשתמשים ישנים ללא access)
    const allowed = (u, key) => !u.access || u.access[key] !== false;
    if (raw.startsWith('CODE:')) {
      method = 'code'; const code = raw.slice(5); user = Object.values(db.users).find(x => x.code && x.code === code);
      if (user) { if (!user.active) reason = 'מושבת'; else if (!allowed(user, 'allow_code')) reason = 'כניסה בקוד לא מורשית'; else if (user.codeType === 'temporary' && user.codeExp && Date.now() > user.codeExp) reason = 'קוד פג'; else if (!withinWindow(user)) reason = 'מחוץ לחלון זמן'; else { result = 'granted'; reason = ''; if (user.codeType === 'onetime') { user.code = null; user.codeType = null; } } }
    } else if (raw.startsWith('NFC:')) {
      method = 'nfc'; const nfc = raw.slice(4); user = Object.values(db.users).find(x => x.nfcId && x.nfcId === nfc);
      // סוג התג שהקורא מדווח (125khz / 13.56mhz) — אם נשלח
      var tagType = (b.tagType && TAG_TYPES[b.tagType]) ? b.tagType : null;
      if (user) { if (!user.active) reason = 'מושבת'; else if (!allowed(user, 'allow_nfc')) reason = 'כניסה בתג לא מורשית'; else if (!withinWindow(user)) reason = 'מחוץ לחלון זמן'; else { result = 'granted'; reason = ''; } }
      else {
        // תג לא מוכר — נשמור אותו לקליטה אוטומטית. הקורא שולח tenantId/doorId + סוג
        let tid = b.tenantId || null;
        if (!tid && b.doorId && db.doors[b.doorId]) tid = db.doors[b.doorId].tenantId;
        if (tid) { lastUnknownTag[tid] = { uid: nfc, type: tagType, ts: Date.now() }; reason = 'תג לא רשום (זמין לשיוך)'; }
      }
    } else {
      method = 'qr'; const [uid, code] = raw.split('.'); user = db.users[uid];
      if (user) { if (!user.active) reason = 'מושבת'; else if (!allowed(user, 'allow_qr')) reason = 'כניסה ב-QR לא מורשית'; else if (!withinWindow(user)) reason = 'מחוץ לחלון זמן'; else if (!code || !verifyTotp(user.secret, code)) reason = 'קוד לא תקף'; else { result = 'granted'; reason = ''; } }
    }
    db.log.unshift({ ts: Date.now(), tenantId: user ? user.tenantId : null, userId: user ? user.id : null, userName: user ? user.name : 'לא ידוע', method, result, reason, tagType: (method === 'nfc' ? (user && user.nfcType ? user.nfcType : (typeof tagType !== 'undefined' ? tagType : null)) : null), doorId: b.doorId || null });
    db.log = db.log.slice(0, 2000); saveDB();
    return send(res, 200, { result, open: result === 'granted', reason, method });
  }

  if (!S) { if (p.startsWith('/api/')) return send(res, 401, { ok: false, error: 'לא מחובר' }); return send(res, 200, loginPage(), 'text/html'); }

  if (p === '/api/me') {
    if (S.role === 'super') return send(res, 200, { role: 'super', version: VERSION, user: SUPER_USER, permDefs: PERMS, stats: todayStats(null), tenantCount: Object.keys(db.tenants).length });
    const a = db.admins[S.adminId]; if (!a) return send(res, 401, { error: 'לא מחובר' });
    // אילו אמצעי כניסה המנהל רשאי להקצות למשתמשים (רק מה שיש לו)
    const grantable = {};
    Object.entries(ACCESS_METHODS).forEach(([k, def]) => { if (a.perms[def.needs]) grantable[k] = def.label; });
    return send(res, 200, { role: 'admin', version: VERSION, name: a.name, tenantName: db.tenants[S.tenantId] ? db.tenants[S.tenantId].name : '', perms: Object.keys(a.perms).filter(k => a.perms[k]), maxUsers: a.maxUsers, permDefs: PERMS, grantable, stats: todayStats(S.tenantId) });
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
    // שכפול מנהל — יוצר לקוח חדש עם מנהל שמעתיק את ההרשאות והמכסה (לא את המשתמשים)
    if (p.startsWith('/api/admins/') && p.endsWith('/duplicate') && m === 'POST') {
      const id = p.split('/')[3]; const src = db.admins[id]; if (!src) return send(res, 404, { error: 'not found' });
      const b = await readBody(req);
      const tid = 't' + crypto.randomBytes(3).toString('hex');
      db.tenants[tid] = { id: tid, name: b.tenantName || ('עותק של ' + (db.tenants[src.tenantId] ? db.tenants[src.tenantId].name : 'אתר')), createdAt: Date.now() };
      const aid = 'a' + crypto.randomBytes(3).toString('hex');
      const { salt, passHash } = makePass(b.adminPassword || 'changeme');
      db.admins[aid] = { id: aid, tenantId: tid, user: b.adminUser || ('admin_' + tid), name: b.adminName || src.name, phone: b.phone || '', email: '', salt, passHash, perms: { ...src.perms }, maxUsers: src.maxUsers, active: true };
      saveDB(); return send(res, 200, { ok: true, tenant: db.tenants[tid], adminUser: db.admins[aid].user });
    }
    if (p.startsWith('/api/admins/') && m === 'POST') {
      const id = p.split('/')[3]; const b = await readBody(req); const a = db.admins[id]; if (!a) return send(res, 404, { error: 'not found' });
      if (b.perms) { a.perms = {}; b.perms.forEach(k => { if (PERMS[k]) a.perms[k] = true; }); }
      if (typeof b.active === 'boolean') a.active = b.active;
      if (typeof b.maxUsers === 'number' && b.maxUsers > 0) a.maxUsers = b.maxUsers;
      if (b.newPassword) { const x = makePass(b.newPassword); a.salt = x.salt; a.passHash = x.passHash; }
      if (typeof b.name === 'string' && b.name.trim()) a.name = b.name.trim();
      // שינוי שם המשתמש (login) — ל"השתלטות"/העברת אתר למנהל אחר. בודק ייחודיות.
      if (typeof b.user === 'string' && b.user.trim() && b.user.trim() !== a.user) {
        const taken = Object.values(db.admins).some(x => x.id !== id && x.user === b.user.trim());
        if (taken) return send(res, 400, { error: 'שם המשתמש כבר תפוס' });
        a.user = b.user.trim();
      }
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
    // פתיחה מרחוק ע"י המנהל (דורש הרשאת remote_open). בפועל תשלח פקודה לחומרה כשתחובר.
    if (p === '/api/remote-open' && m === 'POST') {
      if (!has('remote_open')) return send(res, 403, { ok: false, error: 'אין הרשאת פתיחה מרחוק' });
      db.log.unshift({ ts: Date.now(), tenantId: tid, userId: null, userName: a.name + ' (מנהל)', method: 'remote', result: 'granted', reason: 'פתיחה מרחוק', tagType: null, doorId: null });
      db.log = db.log.slice(0, 2000); saveDB();
      // TODO: כאן תישלח הפקודה לקורא/ממסר (CT9 HTTP / Shelly) כשהחומרה תחובר
      return send(res, 200, { ok: true });
    }
    if (p === '/api/users' && m === 'GET') return send(res, 200, Object.values(db.users).filter(x => x.tenantId === tid));
    if (p === '/api/users' && m === 'POST') {
      if (!has('manage_users')) return send(res, 403, { error: 'אין הרשאה' });
      const count = Object.values(db.users).filter(x => x.tenantId === tid).length;
      if (count >= a.maxUsers) return send(res, 403, { error: `הגעת למכסה (${a.maxUsers})` });
      const b = await readBody(req); const id = 'u' + crypto.randomBytes(3).toString('hex');
      // ברירת מחדל: המשתמש מקבל כל אמצעי כניסה שהמנהל מורשה לתת
      const access = {};
      Object.entries(ACCESS_METHODS).forEach(([k, def]) => { access[k] = has(def.needs); });
      db.users[id] = { id, tenantId: tid, name: b.name || 'משתמש', phone: b.phone || '', secret: newSecret(), code: null, codeType: null, codeExp: null, nfcId: null, nfcType: null, access, active: true, window: null, createdAt: Date.now() };
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
      if ('schedule' in b && has('time_windows')) { user.schedule = b.schedule; user.window = null; }
      if ('nfcId' in b && has('use_nfc')) { user.nfcId = b.nfcId || null; if ('nfcType' in b) user.nfcType = b.nfcType || null; if (!user.nfcId) user.nfcType = null; }
      if (typeof b.phone === 'string') user.phone = b.phone.trim();
      // עדכון אמצעי כניסה למשתמש — רק מה שהמנהל מורשה לתת (אכיפת שרשרת ההרשאות)
      if (b.access && typeof b.access === 'object') {
        if (!user.access) user.access = {};
        Object.entries(ACCESS_METHODS).forEach(([k, def]) => {
          if (k in b.access) { user.access[k] = has(def.needs) ? !!b.access[k] : false; }
        });
      }
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
<meta name="theme-color" content="#185fa5"><title>${title}</title>
<link rel="manifest" href="/manifest.json">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Heebo:wght@400;500;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>${head}
<style>
  :root{--bg:#f2f5f9;--card:#fff;--ink:#17202e;--muted:#6b7a90;--brand:#185fa5;--brand-dark:#0c447c;--brand-soft:#e9f1fb;--ok:#1b8a4b;--bad:#d14343;--line:#e7edf4;--shadow:0 2px 12px rgba(16,42,76,.06)}
  *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
  body{font-family:'Heebo',system-ui,sans-serif;background:var(--bg);color:var(--ink);margin:0;padding:14px;font-size:16px;line-height:1.5}
  .wrap{max-width:760px;margin:0 auto}
  h1{color:var(--ink);font-size:22px;font-weight:700;margin:6px 0 2px}h3{margin:0 0 12px;font-weight:700;font-size:17px}
  .sub{color:var(--muted);font-size:13px;margin:0 0 16px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px;margin-bottom:14px;box-shadow:var(--shadow)}
  button{font-family:inherit;font-size:16px;font-weight:500;border:0;border-radius:12px;padding:13px 18px;cursor:pointer;min-height:48px;transition:transform .06s,background .15s}
  button:active{transform:scale(.97)}
  .primary{background:var(--brand);color:#fff;width:100%}.primary:active{background:var(--brand-dark)}
  .ghost{background:var(--brand-soft);color:var(--brand-dark)}
  .danger{background:#fcebeb;color:var(--bad)}.wa{background:#25d366;color:#fff}
  .sm{padding:9px 14px;font-size:14px;min-height:40px;width:auto}
  input,select{font-family:inherit;font-size:16px;padding:12px 14px;border:1px solid var(--line);border-radius:12px;width:100%;min-height:48px;background:#fbfcfe;transition:border .15s}
  input:focus,select:focus{outline:0;border-color:var(--brand);background:#fff}
  .row{display:flex;gap:9px;align-items:center}.wrap2{flex-wrap:wrap}
  .item{border:1px solid var(--line);border-radius:14px;padding:14px;margin-bottom:11px;background:#fff}
  .item .top{display:flex;justify-content:space-between;align-items:center;gap:8px}
  .item .name{font-weight:700;font-size:17px}
  .btns{display:flex;gap:7px;flex-wrap:wrap;margin-top:12px}
  .pill{display:inline-block;padding:4px 12px;border-radius:999px;font-size:12px;font-weight:500}
  .on{background:#e4f6ec;color:var(--ok)}.off{background:#eef2f7;color:var(--muted)}
  .g{color:var(--ok);font-weight:700}.r{color:var(--bad);font-weight:700}
  a.link{color:var(--brand);text-decoration:none;font-size:14px;font-weight:500}
  .nav{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
  .nav a,.nav span.badge{background:#fff;border:1px solid var(--line);border-radius:11px;padding:9px 14px;color:var(--brand-dark);text-decoration:none;font-size:14px;font-weight:500;box-shadow:var(--shadow)}
  .nav .badge{background:var(--brand-soft);border-color:transparent}
  .nav .ver{margin-right:auto;color:var(--muted);font-size:12px;box-shadow:none;border:0;background:transparent}
  .muted{color:var(--muted);font-size:12px}
  .perm{display:flex;align-items:center;gap:8px;padding:9px 0;font-size:15px;cursor:pointer;border-bottom:1px solid var(--line)}
  .perm:last-child{border-bottom:0}
  .perm input{width:auto;min-height:auto;transform:scale(1.3);margin-left:4px}
  .logline{display:flex;justify-content:space-between;padding:10px 2px;border-bottom:1px solid var(--line);font-size:14px;gap:8px}
  .logline:last-child{border-bottom:0}
  label{font-size:14px;color:var(--muted)}
  .stats{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
  .stat{flex:1;min-width:95px;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:14px;text-align:center;box-shadow:var(--shadow)}
  .stat .n{font-size:28px;font-weight:700;color:var(--brand)}
  .stat .l{font-size:12px;color:var(--muted);margin-top:3px}
  .openbtn{width:150px;height:150px;border-radius:50%;background:var(--brand);color:#fff;font-size:17px;font-weight:500;border:0;cursor:pointer;box-shadow:0 6px 20px rgba(24,95,165,.35);display:inline-flex;flex-direction:column;align-items:center;justify-content:center;gap:6px}
  .openbtn:active{transform:scale(.95);background:var(--brand-dark)}
  .openring{width:186px;height:186px;border-radius:50%;background:#fff;box-shadow:var(--shadow);display:inline-flex;align-items:center;justify-content:center;margin:4px auto}
  .modal{position:fixed;inset:0;background:rgba(16,32,52,.5);display:none;align-items:flex-end;justify-content:center;padding:0;z-index:50}
  .modal.show{display:flex}
  .modal .box{background:#fff;border-radius:20px 20px 0 0;padding:20px 18px 26px;max-width:480px;width:100%;max-height:88vh;overflow:auto;box-shadow:0 -4px 24px rgba(0,0,0,.15)}
  @media(min-width:520px){.modal{align-items:center;padding:16px}.modal .box{border-radius:20px}}
  .modal h3{margin:0 0 14px}
  .modal label{display:block;font-size:13px;color:#64748b;margin:0 0 5px;font-weight:600}
  .modal input[type=time],.modal input[type=datetime-local]{width:100%;padding:11px 12px;border:1.5px solid #d6deea;border-radius:12px;font-size:16px;font-family:inherit;color:#1f3a5f;background:#fff;box-sizing:border-box}
  .modal input[type=time]:focus,.modal input[type=datetime-local]:focus{outline:none;border-color:var(--brand)}
  .segt{display:flex;gap:6px;background:#eef3f9;padding:5px;border-radius:14px;margin-bottom:16px}
  .seg{flex:1;text-align:center;padding:10px 4px;border-radius:10px;font-size:14px;font-weight:600;color:#64748b;cursor:pointer;transition:.15s;user-select:none}
  .seg.act{background:var(--brand);color:#fff;box-shadow:0 2px 6px rgba(24,95,165,.3)}
  .daysrow{display:flex;gap:7px;justify-content:space-between;margin-bottom:4px}
  .day{flex:1;aspect-ratio:1;max-width:44px;display:flex;align-items:center;justify-content:center;border-radius:50%;background:#eef3f9;color:#64748b;font-size:15px;font-weight:700;cursor:pointer;transition:.15s;user-select:none}
  .day.act{background:var(--brand);color:#fff;box-shadow:0 2px 6px rgba(24,95,165,.3)}
  .schinfo{background:var(--brand-soft);color:var(--brand-dark);border-radius:12px;padding:11px 13px;font-size:13.5px;line-height:1.5;margin-top:12px}
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
<div style="height:36px"></div>
<div style="text-align:center;margin-bottom:18px">
  <div style="width:76px;height:76px;border-radius:22px;background:var(--brand);display:inline-flex;align-items:center;justify-content:center;font-size:38px;box-shadow:0 6px 20px rgba(24,95,165,.35)">🔑</div>
  <h1 style="margin:14px 0 2px">מיכאל מערכות</h1>
  <p class="sub" style="margin:0">מערכת בקרת כניסה</p>
</div>
<div class="card" style="max-width:380px;margin:0 auto">
  <div style="display:flex;flex-direction:column;gap:12px">
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
        '<div class="btns"><button class="ghost sm" onclick=\\'editAdmin('+JSON.stringify(JSON.stringify({id:a.id,name:a.name,user:a.user,perms:Object.keys(a.perms).filter(k=>a.perms[k]),maxUsers:a.maxUsers,active:a.active}))+')\\'>ערוך</button>'+
        '<button class="ghost sm" onclick="dupAdmin(\\''+a.id+'\\')">📋 שכפל</button>'+
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
  html+='<label>שם משתמש להתחברות</label><input id="eUser" value="'+(a.user||'')+'" style="margin-bottom:4px"><div class="muted" style="margin-bottom:10px">שינוי = העברת האתר למנהל אחר (למשל אם הקודם עזב)</div>';
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
  const body={name:document.getElementById('eName').value.trim(),user:document.getElementById('eUser').value.trim(),phone:document.getElementById('ePhone').value.trim(),maxUsers:parseInt(document.getElementById('eMax').value)||50,perms:checkedIn('ePerms')};
  const np=document.getElementById('ePass').value; if(np)body.newPassword=np;
  const r=await (await fetch('/api/admins/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})).json();
  if(r.error){alert(r.error);return;}
  closeModal(); load();
}
async function dupAdmin(id){
  const tenantName=prompt('שכפול מנהל — שם הלקוח/אתר החדש:','');
  if(tenantName===null||!tenantName.trim())return;
  const adminUser=prompt('שם משתמש למנהל החדש:','');
  if(adminUser===null||!adminUser.trim())return;
  const adminPassword=prompt('סיסמה למנהל החדש:','');
  if(adminPassword===null||!adminPassword.trim())return;
  const r=await (await fetch('/api/admins/'+id+'/duplicate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tenantName:tenantName.trim(),adminUser:adminUser.trim(),adminPassword:adminPassword.trim()})})).json();
  if(r.ok){alert('✓ נוצר לקוח חדש עם אותן הרשאות!\\nמנהל: '+r.adminUser);load();}
  else alert(r.error||'שגיאה');
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

<div class="card" id="remoteCard" style="display:none;text-align:center;padding:22px 16px">
  <div class="openring"><button class="openbtn" onclick="remoteOpen()"><span style="font-size:34px">🔓</span>פתח דלת</button></div>
  <div class="muted" style="margin-top:4px">לחיצה לפתיחה מרחוק</div>
  <div id="remoteStatus" style="margin-top:8px;font-size:15px"></div>
</div>

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
  if(can('remote_open'))document.getElementById('remoteCard').style.display='block';
  await loadUsers(); if(can('view_log'))loadLog();
}
async function remoteOpen(){
  const st=document.getElementById('remoteStatus'); st.textContent='⏳ פותח...';
  const r=await (await fetch('/api/remote-open',{method:'POST'})).json();
  if(r.ok){st.innerHTML='<span class="g">✓ נפתח</span>';setTimeout(()=>st.textContent='',2500);if(can('view_log'))loadLog();}
  else st.innerHTML='<span class="r">'+(r.error||'שגיאה')+'</span>';
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
    const accNames={allow_qr:'QR',allow_code:'קוד',allow_nfc:'תג',allow_remote:'פתיחה מרחוק'};
    let accList=u.access?Object.keys(accNames).filter(k=>u.access[k]).map(k=>accNames[k]):[];
    let accInfo='<div class="muted">אמצעי כניסה: '+(accList.length?accList.join(', '):'ללא')+'</div>';
    let schInfo=''; { const s=u.schedule; const dn=['א','ב','ג','ד','ה','ו','ש'];
      if(s&&s.type==='timed'){const f=s.startDate?new Date(s.startDate).toLocaleDateString('he-IL'):'';const t=s.endDate?new Date(s.endDate).toLocaleDateString('he-IL'):'';schInfo='<div class="muted">⏳ מתוזמן: '+f+' – '+t+'</div>';}
      else if(s&&s.type==='recurring'){const days=(s.days||[]).map(i=>dn[i]).join(',');schInfo='<div class="muted">🔁 חוזר: '+(days||'—')+' · '+(s.from||'')+'-'+(s.to||'')+'</div>';}
      else if(s&&s.type==='permanent'){schInfo='<div class="muted">♾️ גישה קבועה</div>';} }
    let btns='<a class="link" href="/q/'+u.id+'" target="_blank">QR ↗</a>';
    btns+='<button class="wa sm" onclick="shareWa(\\''+u.id+'\\')">וואטסאפ</button>';
    if(can('issue_code'))btns+='<button class="ghost sm" onclick="issueCode(\\''+u.id+'\\')">הנפק קוד</button>';
    if(can('use_nfc'))btns+='<button class="ghost sm" onclick="setNfc(\\''+u.id+'\\')">NFC</button>';
    if(can('time_windows'))btns+='<button class="ghost sm" onclick="setWindow(\\''+u.id+'\\')">🕑 לוח זמנים</button>';
    if(Object.keys(ME.grantable||{}).length)btns+='<button class="ghost sm" onclick="editAccess(\\''+u.id+'\\')">🔑 הרשאות כניסה</button>';
    if(can('manage_users')){btns+='<button class="ghost sm" onclick="rename(\\''+u.id+'\\',\\''+u.name.replace(/\\x27/g,"")+'\\')">שם</button>';
      btns+='<button class="ghost sm" onclick="resetAccess(\\''+u.id+'\\',\\''+u.name.replace(/\\x27/g,"")+'\\')">🔄 איפוס גישה</button>';
      btns+='<button class="'+(u.active?'danger':'ghost')+' sm" onclick="toggle(\\''+u.id+'\\','+(!u.active)+')">'+(u.active?'השבת':'הפעל')+'</button>';
      btns+='<button class="danger sm" onclick="del(\\''+u.id+'\\',\\''+u.name.replace(/\\x27/g,"")+'\\')">מחק</button>';}
    div.innerHTML='<div class="top"><span class="name">'+u.name+'</span><span class="pill '+(u.active?'on':'off')+'">'+(u.active?'פעיל':'מושבת')+'</span></div>'+accInfo+codeInfo+nfcInfo+'<div class="btns">'+btns+'</div>';
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
  html+='<b>1. קריאה מהנייד (הצמדה)</b><div class="muted" style="margin:4px 0 8px">הצמד תג 13.56MHz לגב הנייד (אנדרואיד + Chrome).</div>';
  html+='<button class="primary sm" style="width:100%" onclick="readTagFromPhone()">📱 קרא תג מהנייד</button>';
  html+='<div id="phoneStatus" class="muted" style="margin-top:8px"></div></div>';
  html+='<div style="border:1px solid #e2e8f0;border-radius:12px;padding:12px;margin-bottom:12px">';
  html+='<b>2. קליטה מהקורא (אוטומטי)</b><div class="muted" style="margin:4px 0 8px">הצמד את התג לקורא בדלת, והמספר יופיע כאן.</div>';
  html+='<button class="ghost sm" style="width:100%" onclick="startTagListen()">🔄 התחל להאזין לקורא</button>';
  html+='<div id="tagStatus" class="muted" style="margin-top:8px"></div></div>';
  html+='<div style="border:1px solid #e2e8f0;border-radius:12px;padding:12px;margin-bottom:12px">';
  html+='<b>3. הזנה ידנית</b><div class="muted" style="margin:4px 0 8px">אם ידוע לך ה-UID — הקלד כאן:</div>';
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
async function readTagFromPhone(){
  const st=document.getElementById('phoneStatus');
  if(!('NDEFReader' in window)){
    st.innerHTML='<span style="color:#b7791f">⚠️ הדפדפן/מכשיר לא תומך בקריאת NFC (נתמך באנדרואיד + Chrome בלבד, ורק תגי 13.56MHz). השתמש בהזנה ידנית למטה או בקורא בדלת.</span>';
    return;
  }
  try{
    st.textContent='⏳ מצמיד תג לגב הנייד...';
    const reader=new NDEFReader();
    await reader.scan();
    reader.onreading=(event)=>{
      const uid=(event.serialNumber||'').toUpperCase().replace(/:/g,'');
      if(uid){
        document.getElementById('nfcManual').value=uid;
        document.getElementById('nfcType').value='13.56mhz';
        st.innerHTML='✓ נקרא תג: <b>'+uid+'</b> — לחץ "שמור תג".';
      } else {
        st.innerHTML='<span style="color:#b7791f">התג נקרא אך ללא מזהה. נסה שוב או הזן ידנית.</span>';
      }
    };
    reader.onreadingerror=()=>{ st.innerHTML='<span style="color:#c0392b">שגיאת קריאה. נסה שוב.</span>'; };
  }catch(e){
    st.innerHTML='<span style="color:#c0392b">לא ניתן לקרוא: '+(e.message||'שגיאה')+'. ודא ש-NFC מופעל בנייד, או הזן ידנית.</span>';
  }
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
function editAccess(id){
  const u=USERS.find(x=>x.id===id); if(!u)return;
  const acc=u.access||{};
  let html='<h3>הרשאות כניסה — '+u.name+'</h3><p class="muted">סמן אילו אמצעי כניסה מותרים למשתמש זה. מוצגים רק אמצעים שאתה מורשה להקצות.</p><div id="accBox">';
  Object.entries(ME.grantable).forEach(([k,label])=>{
    html+='<label class="perm"><input type="checkbox" value="'+k+'" '+(acc[k]?'checked':'')+'> '+label+'</label>';
  });
  html+='</div><div class="btns" style="margin-top:14px"><button class="primary sm" style="flex:1" onclick="saveAccess(\\''+id+'\\')">שמור</button><button class="ghost sm" onclick="closeModal()">ביטול</button></div>';
  openModal(html);
}
async function saveAccess(id){
  const access={};
  Object.keys(ME.grantable).forEach(k=>{access[k]=false;});
  [...document.querySelectorAll('#accBox input:checked')].forEach(c=>{access[c.value]=true;});
  await fetch('/api/users/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({access})});
  closeModal();loadUsers();
}
let schedState={type:'permanent',days:[0,1,2,3,4],from:'08:00',to:'18:00',startDate:'',endDate:''};
function setWindow(id){
  const u=USERS.find(x=>x.id===id);
  const s=(u&&u.schedule)?u.schedule:{type:'permanent'};
  schedState={type:s.type||'permanent',days:s.days||[0,1,2,3,4],from:s.from||'08:00',to:s.to||'18:00',
    startDate:s.startDate?new Date(s.startDate).toISOString().slice(0,16):'',endDate:s.endDate?new Date(s.endDate).toISOString().slice(0,16):''};
  renderSched(id);
}
function renderSched(id){
  _lastSchedId=id;
  const dayNames=['א','ב','ג','ד','ה','ו','ש'];
  let h='<h3>לוח זמנים — '+(USERS.find(x=>x.id===id)||{}).name+'</h3>';
  h+='<div class="segt">';
  [['permanent','קבוע'],['timed','מתוזמן'],['recurring','חוזר']].forEach(([t,l])=>{
    h+='<div class="seg'+(schedState.type===t?' act':'')+'" onclick="schedType(\\''+id+'\\',\\''+t+'\\')">'+l+'</div>';
  });
  h+='</div>';
  if(schedState.type==='permanent'){
    h+='<div class="schinfo">♾️ גישה קבועה — ללא הגבלת זמן.</div>';
  } else if(schedState.type==='timed'){
    h+='<label>מתאריך ושעה</label><input type="datetime-local" id="sStart" value="'+schedState.startDate+'" style="margin-bottom:10px">';
    h+='<label>עד תאריך ושעה</label><input type="datetime-local" id="sEnd" value="'+schedState.endDate+'" style="margin-bottom:10px">';
    h+='<div class="schinfo">גישה בטווח התאריכים בלבד (למשל ספק לשבוע).</div>';
  } else {
    h+='<label>ימים בשבוע</label><div class="daysrow">';
    dayNames.forEach((d,i)=>{h+='<div class="day'+(schedState.days.includes(i)?' act':'')+'" onclick="toggleDay('+i+')">'+d+'</div>';});
    h+='</div>';
    h+='<div style="display:flex;gap:10px;margin:12px 0 6px">';
    h+='<div style="flex:1"><label>משעה</label><input type="time" id="sFrom" value="'+schedState.from+'"></div>';
    h+='<div style="flex:1"><label>עד שעה</label><input type="time" id="sTo" value="'+schedState.to+'"></div></div>';
    const dsel=schedState.days.map(i=>dayNames[i]).join(',');
    h+='<div class="schinfo">גישה בימים '+(dsel||'—')+' בין '+schedState.from+' ל-'+schedState.to+'.</div>';
  }
  h+='<div class="btns" style="margin-top:14px"><button class="primary sm" style="flex:1" onclick="saveSched(\\''+id+'\\')">שמור לוח זמנים</button><button class="ghost sm" onclick="closeModal()">ביטול</button></div>';
  openModal(h);
}
function schedType(id,t){
  if(schedState.type==='timed'){schedState.startDate=(document.getElementById('sStart')||{}).value||schedState.startDate;schedState.endDate=(document.getElementById('sEnd')||{}).value||schedState.endDate;}
  if(schedState.type==='recurring'){schedState.from=(document.getElementById('sFrom')||{}).value||schedState.from;schedState.to=(document.getElementById('sTo')||{}).value||schedState.to;}
  schedState.type=t;renderSched(id);
}
function toggleDay(i){const k=schedState.days.indexOf(i);if(k<0)schedState.days.push(i);else schedState.days.splice(k,1);renderSched_keep();}
let _lastSchedId=null;
function renderSched_keep(){/* save current time inputs then re-render */
  if(schedState.type==='recurring'){schedState.from=(document.getElementById('sFrom')||{}).value||schedState.from;schedState.to=(document.getElementById('sTo')||{}).value||schedState.to;}
  renderSched(_lastSchedId);
}
async function saveSched(id){
  let schedule;
  if(schedState.type==='permanent'){schedule={type:'permanent'};}
  else if(schedState.type==='timed'){
    const sd=(document.getElementById('sStart')||{}).value,ed=(document.getElementById('sEnd')||{}).value;
    schedule={type:'timed',startDate:sd?new Date(sd).getTime():null,endDate:ed?new Date(ed).getTime():null};
  } else {
    if(!schedState.days.length){alert('בחר לפחות יום אחד בשבוע');return;}
    const fr=(document.getElementById('sFrom')||{}).value||'00:00',to=(document.getElementById('sTo')||{}).value||'23:59';
    schedule={type:'recurring',days:schedState.days.slice(),from:fr,to:to};
  }
  await fetch('/api/users/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({schedule})});
  closeModal();loadUsers();
}
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
