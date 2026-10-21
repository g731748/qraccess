#!/usr/bin/env node
/*
 * QR Access — שרת ניהול בקרת כניסה (גרסה 2)
 * ============================================
 * מערכת עצמאית, 100% בבעלותך. QR מתחלף, ללא תלות בספק.
 *
 * חדש בגרסה 2:
 *   - מסך התחברות עם סיסמה (הגנה על הניהול)
 *   - ניהול מותאם לנייד (כפתורים גדולים, עיצוב רספונסיבי)
 *   - עריכת עובד: שינוי שם, מחיקה, חלון זמן (מתי מותר להיכנס)
 *   - גרסה מוצגת במסך, כדי לעקוב אחרי עדכונים
 *
 * מריץ עם Node בלבד (ללא תלויות).  node server.js
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const VERSION = '2.0';
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data', 'db.json');
const STEP_SECONDS = 30;
const TOLERANCE = 1;

// סיסמת ברירת מחדל — שנה אותה דרך משתנה סביבה ADMIN_PASSWORD ב-Render
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'michael2026';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(16).toString('hex');

// ---------- אחסון ----------
function loadDB() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch {
    return {
      tenants: { 't1': { id: 't1', name: 'לקוח ראשון' } },
      employees: {},
      doors: { 'd1': { id: 'd1', tenantId: 't1', name: 'כניסה ראשית' } },
      log: []
    };
  }
}
function saveDB(db) {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
}
let db = loadDB();

// ---------- TOTP (QR מתחלף) ----------
function totp(secret, forTime = Date.now()) {
  const counter = Math.floor(forTime / 1000 / STEP_SECONDS);
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', Buffer.from(secret, 'hex')).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) |
              (hmac[offset + 2] << 8) | (hmac[offset + 3]);
  return (bin % 1000000).toString().padStart(6, '0');
}
function verifyTotp(secret, code, forTime = Date.now()) {
  for (let w = -TOLERANCE; w <= TOLERANCE; w++)
    if (totp(secret, forTime + w * STEP_SECONDS * 1000) === code) return true;
  return false;
}
const newSecret = () => crypto.randomBytes(20).toString('hex');

// ---------- Auth (session cookie פשוט) ----------
function signToken() {
  const payload = 'ok.' + Date.now();
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  return payload + '.' + sig;
}
function validToken(tok) {
  if (!tok) return false;
  const i = tok.lastIndexOf('.');
  const payload = tok.slice(0, i), sig = tok.slice(i + 1);
  const expect = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  return sig === expect;
}
function getCookie(req, name) {
  const c = req.headers.cookie || '';
  const m = c.match(new RegExp('(?:^|; )' + name + '=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : null;
}
function isAuthed(req) { return validToken(getCookie(req, 'qrsess')); }

// ---------- HTTP helpers ----------
function send(res, code, body, type = 'application/json', headers = {}) {
  res.writeHead(code, { 'Content-Type': type + '; charset=utf-8', ...headers });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}
function readBody(req) {
  return new Promise(resolve => {
    let d = ''; req.on('data', c => d += c);
    req.on('end', () => { try { resolve(JSON.parse(d || '{}')); } catch { resolve({}); } });
  });
}
function withinWindow(emp, now = new Date()) {
  // חלון זמן אופציונלי: emp.window = {days:[0..6], from:"HH:MM", to:"HH:MM"}
  if (!emp.window) return true;
  const w = emp.window;
  if (w.days && w.days.length && !w.days.includes(now.getDay())) return false;
  if (w.from && w.to) {
    const cur = now.getHours() * 60 + now.getMinutes();
    const [fh, fm] = w.from.split(':').map(Number);
    const [th, tm] = w.to.split(':').map(Number);
    const from = fh * 60 + fm, to = th * 60 + tm;
    if (cur < from || cur > to) return false;
  }
  return true;
}

// ---------- Server ----------
const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://${req.headers.host}`);
  const p = u.pathname;

  // --- התחברות ---
  if (p === '/api/login' && req.method === 'POST') {
    const b = await readBody(req);
    if (b.user === ADMIN_USER && b.password === ADMIN_PASSWORD) {
      return send(res, 200, { ok: true }, 'application/json',
        { 'Set-Cookie': `qrsess=${encodeURIComponent(signToken())}; HttpOnly; Path=/; Max-Age=2592000; SameSite=Lax` });
    }
    return send(res, 401, { ok: false, error: 'שם משתמש או סיסמה שגויים' });
  }
  if (p === '/api/logout') {
    return send(res, 200, { ok: true }, 'application/json',
      { 'Set-Cookie': 'qrsess=; Path=/; Max-Age=0' });
  }

  // --- דף QR לעובד (ציבורי, לא דורש התחברות) ---
  if (p.startsWith('/q/')) {
    const emp = db.employees[p.split('/')[2]];
    if (!emp) return send(res, 404, 'עובד לא נמצא', 'text/plain');
    return send(res, 200, qrPage(emp), 'text/html');
  }
  if (p.startsWith('/api/qr/')) {
    const emp = db.employees[p.split('/')[3]];
    if (!emp || !emp.active) return send(res, 403, { ok: false });
    const payload = `${emp.id}.${totp(emp.secret)}`;
    const msLeft = STEP_SECONDS * 1000 - (Date.now() % (STEP_SECONDS * 1000));
    return send(res, 200, { ok: true, payload, secondsLeft: Math.ceil(msLeft / 1000), name: emp.name });
  }

  // --- אימות סריקה (ציבורי — נקרא ע"י הקורא בכניסה) ---
  if (p === '/api/verify' && req.method === 'POST') {
    const b = await readBody(req);
    const [empId, code] = (b.payload || '').trim().split('.');
    const emp = db.employees[empId];
    let result = 'denied', reason = '';
    if (!emp) reason = 'לא מוכר';
    else if (!emp.active) reason = 'מושבת';
    else if (!withinWindow(emp)) reason = 'מחוץ לחלון זמן';
    else if (!code || !verifyTotp(emp.secret, code)) reason = 'קוד לא תקף';
    else result = 'granted';
    db.log.unshift({ ts: Date.now(), employeeId: empId || null, employeeName: emp ? emp.name : 'לא ידוע', doorId: b.doorId || 'd1', result, reason });
    db.log = db.log.slice(0, 1000); saveDB(db);
    return send(res, 200, { result, open: result === 'granted', reason });
  }

  // ---- מכאן והלאה: דורש התחברות ----
  const needAuth = p.startsWith('/api/') || p === '/' || p === '/admin';
  if (needAuth && !isAuthed(req)) {
    if (p.startsWith('/api/')) return send(res, 401, { ok: false, error: 'לא מחובר' });
    return send(res, 200, loginPage(), 'text/html');
  }

  // --- API ניהול ---
  if (p === '/api/employees' && req.method === 'GET') return send(res, 200, Object.values(db.employees));
  if (p === '/api/employees' && req.method === 'POST') {
    const b = await readBody(req);
    const id = 'e' + crypto.randomBytes(3).toString('hex');
    db.employees[id] = { id, tenantId: 't1', name: b.name || 'עובד חדש', secret: newSecret(), active: true, window: null, createdAt: Date.now() };
    saveDB(db); return send(res, 200, db.employees[id]);
  }
  if (p.startsWith('/api/employees/') && req.method === 'POST') {
    const id = p.split('/')[3]; const b = await readBody(req);
    const e = db.employees[id]; if (!e) return send(res, 404, { error: 'not found' });
    if (typeof b.active === 'boolean') e.active = b.active;
    if (typeof b.name === 'string' && b.name.trim()) e.name = b.name.trim();
    if ('window' in b) e.window = b.window;
    saveDB(db); return send(res, 200, e);
  }
  if (p.startsWith('/api/employees/') && req.method === 'DELETE') {
    const id = p.split('/')[3];
    delete db.employees[id]; saveDB(db); return send(res, 200, { ok: true });
  }
  if (p === '/api/log') return send(res, 200, db.log.slice(0, 100));
  if (p === '/api/me') return send(res, 200, { version: VERSION, user: ADMIN_USER });

  // --- דפים ---
  if (p === '/' || p === '/admin') return send(res, 200, adminPage(), 'text/html');
  if (p === '/scanner') {
    if (!isAuthed(req)) return send(res, 200, loginPage(), 'text/html');
    return send(res, 200, scannerPage(), 'text/html');
  }
  send(res, 404, 'not found', 'text/plain');
});

server.listen(PORT, () => {
  console.log(`\n  QR Access v${VERSION} — שרת פועל על פורט ${PORT}`);
  console.log(`  משתמש: ${ADMIN_USER}  |  סיסמת ברירת מחדל פעילה: ${ADMIN_PASSWORD === 'michael2026' ? 'כן (שנה אותה!)' : 'הוגדרה מותאמת'}\n`);
});

// ================= HTML =================
function shell(title, body, extraHead = '') {
  return `<!doctype html><html dir="rtl" lang="he"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<meta name="theme-color" content="#1f3a5f">
<title>${title}</title>
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
${extraHead}
<style>
  :root{--bg:#f4f6f9;--card:#fff;--ink:#1a2b3c;--muted:#64748b;--brand:#1f3a5f;--brand2:#2c5282;--ok:#1b8a4b;--bad:#c0392b;--line:#e2e8f0}
  *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
  body{font-family:Arial,system-ui,sans-serif;background:var(--bg);color:var(--ink);margin:0;padding:14px;font-size:16px}
  .wrap{max-width:760px;margin:0 auto}
  h1{color:var(--brand);font-size:21px;margin:6px 0 2px}
  .sub{color:var(--muted);font-size:13px;margin:0 0 14px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:15px;margin-bottom:13px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
  button{font-family:inherit;font-size:16px;border:0;border-radius:11px;padding:13px 18px;cursor:pointer;min-height:48px}
  .primary{background:var(--brand);color:#fff;width:100%}
  .ghost{background:#eef3f8;color:var(--brand)}
  .danger{background:#fdeaea;color:var(--bad)}
  .sm{padding:9px 13px;font-size:14px;min-height:40px}
  input{font-family:inherit;font-size:16px;padding:13px;border:1px solid var(--line);border-radius:11px;width:100%;min-height:48px}
  .row{display:flex;gap:9px;align-items:center}
  .emp{border:1px solid var(--line);border-radius:12px;padding:12px;margin-bottom:10px}
  .emp .top{display:flex;justify-content:space-between;align-items:center;gap:8px}
  .emp .name{font-weight:bold;font-size:17px}
  .emp .btns{display:flex;gap:7px;flex-wrap:wrap;margin-top:10px}
  .pill{display:inline-block;padding:3px 11px;border-radius:999px;font-size:12px}
  .on{background:#e6f6ec;color:var(--ok)} .off{background:#f1f5f9;color:var(--muted)}
  .g{color:var(--ok);font-weight:bold} .r{color:var(--bad);font-weight:bold}
  a.link{color:var(--brand2);text-decoration:none;font-size:14px;font-weight:bold}
  .nav{display:flex;gap:9px;margin-bottom:13px;flex-wrap:wrap;align-items:center}
  .nav a{background:#fff;border:1px solid var(--line);border-radius:10px;padding:9px 13px;color:var(--brand);text-decoration:none;font-size:14px}
  .nav .ver{margin-right:auto;color:var(--muted);font-size:12px}
  .logline{display:flex;justify-content:space-between;padding:9px 2px;border-bottom:1px solid var(--line);font-size:14px;gap:8px}
  .muted{color:var(--muted);font-size:12px}
</style></head><body><div class="wrap">${body}</div></body></html>`;
}

function loginPage() {
  return shell('התחברות — QR Access', `
<div style="height:40px"></div>
<div class="card" style="max-width:380px;margin:0 auto">
  <h1 style="text-align:center">מערכת בקרת כניסה</h1>
  <p class="sub" style="text-align:center">התחברות מנהל</p>
  <div style="display:flex;flex-direction:column;gap:11px">
    <input id="user" placeholder="שם משתמש" autocomplete="username">
    <input id="pass" type="password" placeholder="סיסמה" autocomplete="current-password">
    <button class="primary" onclick="login()">התחבר</button>
    <div id="err" class="r" style="text-align:center;font-size:14px"></div>
  </div>
</div>
<script>
async function login(){
  const user=document.getElementById('user').value.trim();
  const password=document.getElementById('pass').value;
  const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user,password})});
  const d=await r.json();
  if(d.ok){location.href='/admin';}
  else{document.getElementById('err').textContent=d.error||'שגיאה';}
}
document.getElementById('pass').addEventListener('keydown',e=>{if(e.key==='Enter')login();});
</script>`);
}

function adminPage() {
  return shell('ניהול — QR Access', `
<div class="nav">
  <a href="/admin">ניהול</a>
  <a href="/scanner">סימולציית קורא</a>
  <a href="#" onclick="logout();return false;">התנתק</a>
  <span class="ver">גרסה <span id="ver">…</span></span>
</div>
<h1>בקרת כניסה — ניהול</h1>
<p class="sub">נוח לנייד. הוספה, עריכה, חלונות זמן ויומן כניסות.</p>

<div class="card">
  <div class="row">
    <input id="name" placeholder="שם עובד חדש">
    <button class="primary sm" style="width:auto;white-space:nowrap" onclick="addEmp()">הוסף</button>
  </div>
</div>

<div class="card">
  <h3 style="margin:0 0 10px">עובדים</h3>
  <div id="emps"></div>
</div>

<div class="card">
  <h3 style="margin:0 0 6px">יומן כניסות</h3>
  <div id="log"></div>
</div>

<script>
async function logout(){await fetch('/api/logout');location.href='/admin';}
function dayNames(){return['א','ב','ג','ד','ה','ו','ש'];}
async function load(){
  const me=await (await fetch('/api/me')).json(); document.getElementById('ver').textContent=me.version;
  const emps=await (await fetch('/api/employees')).json();
  const box=document.getElementById('emps'); box.innerHTML = emps.length?'':'<div class="muted">אין עדיין עובדים. הוסף למעלה.</div>';
  emps.forEach(e=>{
    const div=document.createElement('div'); div.className='emp';
    const win = e.window ? ('חלון: '+(e.window.days||[]).map(d=>dayNames()[d]).join(',')+' '+(e.window.from||'')+'-'+(e.window.to||'')) : 'גישה: תמיד';
    div.innerHTML=\`
      <div class="top">
        <span class="name">\${e.name}</span>
        <span class="pill \${e.active?'on':'off'}">\${e.active?'פעיל':'מושבת'}</span>
      </div>
      <div class="muted" style="margin-top:4px">\${win}</div>
      <div class="btns">
        <a class="link" href="/q/\${e.id}" target="_blank">פתח QR ↗</a>
        <button class="ghost sm" onclick="rename('\${e.id}','\${e.name.replace(/'/g,"")}')">שנה שם</button>
        <button class="ghost sm" onclick="setWindow('\${e.id}')">חלון זמן</button>
        <button class="\${e.active?'danger':'ghost'} sm" onclick="toggle('\${e.id}',\${!e.active})">\${e.active?'השבת':'הפעל'}</button>
        <button class="danger sm" onclick="del('\${e.id}','\${e.name.replace(/'/g,"")}')">מחק</button>
      </div>\`;
    box.appendChild(div);
  });
  const log=await (await fetch('/api/log')).json();
  const lb=document.getElementById('log'); lb.innerHTML = log.length?'':'<div class="muted">אין כניסות עדיין.</div>';
  log.forEach(l=>{
    const d=document.createElement('div'); d.className='logline';
    const t=new Date(l.ts).toLocaleString('he-IL');
    d.innerHTML=\`<span>\${l.employeeName}</span><span class="\${l.result==='granted'?'g':'r'}">\${l.result==='granted'?'נכנס ✓':'נדחה ✕'+(l.reason?' ('+l.reason+')':'')}</span><span class="muted">\${t}</span>\`;
    lb.appendChild(d);
  });
}
async function addEmp(){
  const name=document.getElementById('name').value.trim()||'עובד חדש';
  await fetch('/api/employees',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});
  document.getElementById('name').value=''; load();
}
async function toggle(id,active){await fetch('/api/employees/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({active})});load();}
async function rename(id,cur){const name=prompt('שם חדש:',cur);if(name&&name.trim()){await fetch('/api/employees/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name.trim()})});load();}}
async function del(id,name){if(confirm('למחוק את '+name+'? פעולה לא הפיכה.')){await fetch('/api/employees/'+id,{method:'DELETE'});load();}}
async function setWindow(id){
  const ans=prompt('חלון זמן — הזן ימים ושעות, או "תמיד" לגישה חופשית.\\nדוגמה: 0,1,2,3,4 08:00 18:00  (ימים א-ה, 8 עד 18)','תמיד');
  if(ans===null)return;
  let win=null;
  if(ans.trim()!=='תמיד'){
    const parts=ans.trim().split(/\\s+/);
    const days=(parts[0]||'').split(',').map(x=>parseInt(x)).filter(x=>!isNaN(x));
    win={days,from:parts[1]||'00:00',to:parts[2]||'23:59'};
  }
  await fetch('/api/employees/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({window:win})});load();
}
load(); setInterval(load,5000);
</script>`);
}

function qrPage(emp) {
  return shell('הכניסה שלך — ' + emp.name, `
<div style="height:16px"></div>
<h1 style="text-align:center">${emp.name}</h1>
<p class="sub" style="text-align:center">הצג לקורא בכניסה. מתחדש כל ${STEP_SECONDS} שניות.</p>
<div class="card" style="text-align:center;max-width:320px;margin:0 auto">
  <div id="qr" style="display:inline-block;padding:14px;background:#fff;border-radius:12px"></div>
  <div style="margin-top:12px;color:var(--muted)">מתחדש בעוד <b id="sec">--</b> ש׳</div>
  <div style="margin-top:6px;height:7px;background:#eef3f8;border-radius:4px;overflow:hidden">
    <div id="bar" style="height:100%;background:var(--brand);width:100%;transition:width 1s linear"></div>
  </div>
</div>
<script>
let qr=new QRCode(document.getElementById('qr'),{width:230,height:230,correctLevel:QRCode.CorrectLevel.M});
async function tick(){
  try{
    const r=await (await fetch('/api/qr/${emp.id}')).json();
    if(!r.ok){document.getElementById('qr').innerHTML='<b style="color:#c0392b">הגישה הושבתה</b>';return;}
    qr.clear(); qr.makeCode(r.payload);
    document.getElementById('sec').textContent=r.secondsLeft;
    document.getElementById('bar').style.width=(r.secondsLeft/${STEP_SECONDS}*100)+'%';
  }catch(e){}
}
tick(); setInterval(tick,1000);
</script>`);
}

function scannerPage() {
  return shell('סימולציית קורא', `
<div class="nav"><a href="/admin">← חזרה לניהול</a></div>
<h1>סימולציית קורא QR</h1>
<p class="sub">במציאות הקורא הפיזי שולח את הסריקה לכאן. לבדיקה — הדבק ערך QR.</p>
<div class="card">
  <input id="payload" placeholder="employeeId.code" style="margin-bottom:11px">
  <button class="primary" onclick="scan()">אמת כניסה</button>
  <div id="result" style="margin-top:14px;font-size:20px;text-align:center"></div>
</div>
<script>
async function scan(){
  const payload=document.getElementById('payload').value.trim();
  const r=await (await fetch('/api/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload,doorId:'d1'})})).json();
  const el=document.getElementById('result');
  el.innerHTML = r.open ? '<span class="g">✓ אושר — השער נפתח</span>' : '<span class="r">✕ נדחה'+(r.reason?' ('+r.reason+')':'')+'</span>';
}
</script>`);
}
