#!/usr/bin/env node
/*
 * QR Access — שרת הדגמה (MVP)
 * ----------------------------------
 * מערכת בקרת כניסה מבוססת QR מתחלף, עצמאית לחלוטין.
 * ללא תלות באף ספק חיצוני. השרת, הניהול, פורמט ה-QR וההיסטוריה — כולם כאן.
 *
 * מריץ עם Node בלבד (ללא תלויות חיצוניות / npm).
 *   node server.js
 * ואז פותחים בדפדפן:  http://localhost:3000
 *
 * רכיבים:
 *   - מנוע QR מתחלף (TOTP): לכל עובד סוד משלו, הקוד מתחדש כל 30 שניות.
 *   - שירות אימות: הקורא/טאבלט שולח את תוכן ה-QR, השרת מאשר/דוחה.
 *   - ניהול: הוספת עובד, השבתה, יומן כניסות.
 *   - ריבוי-לקוחות בסיסי (tenant אחד לדמו; מורחב בקלות).
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data', 'db.json');
const STEP_SECONDS = 30;         // כל כמה שניות ה-QR מתחלף
const TOLERANCE = 1;             // חלון סובלנות (±חלון אחד) להפרשי שעון

// ---------- אחסון נתונים (קובץ JSON פשוט; בקלות יוחלף ב-DB אמיתי) ----------
function loadDB() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    return {
      tenants: {
        't1': { id: 't1', name: 'בית ספר למשחק גודמן' }   // לקוח לדוגמה
      },
      employees: {},   // id -> {id, tenantId, name, secret, active, createdAt}
      doors: {
        'd1': { id: 'd1', tenantId: 't1', name: 'כניסה ראשית' }
      },
      log: []          // {ts, tenantId, employeeId, employeeName, doorId, result}
    };
  }
}
function saveDB(db) {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
}
let db = loadDB();

// ---------- מנוע TOTP (QR מתחלף) ----------
// הקוד הנסרק הוא: <employeeId>.<totp>  — צילום ישן יפוג כעבור 30 שניות.
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
  for (let w = -TOLERANCE; w <= TOLERANCE; w++) {
    if (totp(secret, forTime + w * STEP_SECONDS * 1000) === code) return true;
  }
  return false;
}
function newSecret() {
  return crypto.randomBytes(20).toString('hex');
}

// ---------- עזרי HTTP ----------
function send(res, code, body, type = 'application/json') {
  res.writeHead(code, { 'Content-Type': type + '; charset=utf-8' });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}
function readBody(req) {
  return new Promise(resolve => {
    let d = '';
    req.on('data', c => d += c);
    req.on('end', () => { try { resolve(JSON.parse(d || '{}')); } catch { resolve({}); } });
  });
}

// ---------- השרת ----------
const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://${req.headers.host}`);
  const p = u.pathname;

  // --- דף QR חי לעובד:  /q/<employeeId> ---
  if (p.startsWith('/q/')) {
    const empId = p.split('/')[2];
    const emp = db.employees[empId];
    if (!emp) return send(res, 404, 'עובד לא נמצא', 'text/plain');
    return send(res, 200, qrPage(emp), 'text/html');
  }

  // --- API: ערך QR נוכחי (נקרא ע"י דף העובד כל כמה שניות) ---
  if (p.startsWith('/api/qr/')) {
    const empId = p.split('/')[3];
    const emp = db.employees[empId];
    if (!emp || !emp.active) return send(res, 403, { ok: false });
    const code = totp(emp.secret);
    const payload = `${emp.id}.${code}`;
    const msLeft = STEP_SECONDS * 1000 - (Date.now() % (STEP_SECONDS * 1000));
    return send(res, 200, { ok: true, payload, secondsLeft: Math.ceil(msLeft / 1000) });
  }

  // --- API: אימות סריקה (נקרא ע"י הקורא/טאבלט בכניסה) ---
  if (p === '/api/verify' && req.method === 'POST') {
    const body = await readBody(req);
    const scanned = (body.payload || '').trim();
    const doorId = body.doorId || 'd1';
    const [empId, code] = scanned.split('.');
    const emp = db.employees[empId];
    let result = 'denied';
    if (emp && emp.active && code && verifyTotp(emp.secret, code)) result = 'granted';
    db.log.unshift({
      ts: Date.now(),
      tenantId: emp ? emp.tenantId : null,
      employeeId: empId || null,
      employeeName: emp ? emp.name : 'לא ידוע',
      doorId, result
    });
    db.log = db.log.slice(0, 500);
    saveDB(db);
    return send(res, 200, { result, open: result === 'granted' });
  }

  // --- API: ניהול עובדים ---
  if (p === '/api/employees' && req.method === 'GET') {
    return send(res, 200, Object.values(db.employees));
  }
  if (p === '/api/employees' && req.method === 'POST') {
    const body = await readBody(req);
    const id = 'e' + crypto.randomBytes(3).toString('hex');
    db.employees[id] = {
      id, tenantId: body.tenantId || 't1', name: body.name || 'עובד חדש',
      secret: newSecret(), active: true, createdAt: Date.now()
    };
    saveDB(db);
    return send(res, 200, db.employees[id]);
  }
  if (p.startsWith('/api/employees/') && req.method === 'POST') {
    const id = p.split('/')[3];
    const body = await readBody(req);
    if (db.employees[id]) {
      if (typeof body.active === 'boolean') db.employees[id].active = body.active;
      saveDB(db);
      return send(res, 200, db.employees[id]);
    }
    return send(res, 404, { error: 'not found' });
  }

  // --- API: יומן כניסות ---
  if (p === '/api/log') return send(res, 200, db.log.slice(0, 100));

  // --- דף ניהול ---
  if (p === '/' || p === '/admin') return send(res, 200, adminPage(), 'text/html');

  // --- דף סימולציית קורא (לבדיקה ללא חומרה) ---
  if (p === '/scanner') return send(res, 200, scannerPage(), 'text/html');

  send(res, 404, 'not found', 'text/plain');
});

server.listen(PORT, () => {
  console.log(`\n  QR Access — שרת הדגמה פועל`);
  console.log(`  ניהול:          http://localhost:${PORT}/admin`);
  console.log(`  סימולציית קורא: http://localhost:${PORT}/scanner`);
  console.log(`  (דף QR לעובד נוצר אוטומטית בניהול)\n`);
});

// ================= דפי HTML =================
function htmlShell(title, body) {
  return `<!doctype html><html dir="rtl" lang="he"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
<style>
  :root{--bg:#f4f6f9;--card:#fff;--ink:#1a2b3c;--muted:#64748b;--brand:#1f3a5f;--brand2:#2c5282;--ok:#1b8a4b;--bad:#c0392b;--line:#e2e8f0}
  *{box-sizing:border-box}
  body{font-family:Arial,system-ui,sans-serif;background:var(--bg);color:var(--ink);margin:0;padding:16px}
  .wrap{max-width:820px;margin:0 auto}
  h1{color:var(--brand);font-size:22px;margin:8px 0 4px}
  .sub{color:var(--muted);font-size:14px;margin:0 0 16px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;margin-bottom:14px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
  button{font-family:inherit;font-size:15px;border:0;border-radius:10px;padding:10px 16px;cursor:pointer}
  .primary{background:var(--brand);color:#fff}
  .ghost{background:#eef3f8;color:var(--brand)}
  .danger{background:#fdeaea;color:var(--bad)}
  input{font-family:inherit;font-size:15px;padding:10px;border:1px solid var(--line);border-radius:10px;width:100%}
  table{width:100%;border-collapse:collapse;font-size:14px}
  th,td{text-align:right;padding:9px;border-bottom:1px solid var(--line)}
  th{background:var(--brand);color:#fff}
  tr:nth-child(even) td{background:#f7fafc}
  .pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px}
  .on{background:#e6f6ec;color:var(--ok)} .off{background:#f1f5f9;color:var(--muted)}
  .g{color:var(--ok);font-weight:bold} .r{color:var(--bad);font-weight:bold}
  a.link{color:var(--brand2);text-decoration:none;font-size:13px}
  .nav{display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap}
  .nav a{background:#fff;border:1px solid var(--line);border-radius:10px;padding:8px 14px;color:var(--brand);text-decoration:none;font-size:14px}
</style></head><body><div class="wrap">
<div class="nav"><a href="/admin">ניהול</a><a href="/scanner">סימולציית קורא</a></div>
${body}
</div></body></html>`;
}

function adminPage() {
  return htmlShell('ניהול — QR Access', `
<h1>מערכת בקרת כניסה — ניהול</h1>
<p class="sub">הוספת עובדים, הפעלה/השבתה, וצפייה ביומן כניסות. כל עובד מקבל דף QR מתחלף משלו.</p>

<div class="card">
  <h3 style="margin-top:0">הוספת עובד</h3>
  <div style="display:flex;gap:10px">
    <input id="name" placeholder="שם העובד">
    <button class="primary" onclick="addEmp()">הוסף</button>
  </div>
</div>

<div class="card">
  <h3 style="margin-top:0">עובדים</h3>
  <table id="emps"><thead><tr><th>שם</th><th>סטטוס</th><th>דף QR</th><th>פעולה</th></tr></thead><tbody></tbody></table>
</div>

<div class="card">
  <h3 style="margin-top:0">יומן כניסות (אחרון למעלה)</h3>
  <table id="log"><thead><tr><th>זמן</th><th>עובד</th><th>תוצאה</th></tr></thead><tbody></tbody></table>
</div>

<script>
async function load(){
  const emps = await (await fetch('/api/employees')).json();
  const tb = document.querySelector('#emps tbody'); tb.innerHTML='';
  emps.forEach(e=>{
    const tr=document.createElement('tr');
    tr.innerHTML=\`<td>\${e.name}</td>
      <td><span class="pill \${e.active?'on':'off'}">\${e.active?'פעיל':'מושבת'}</span></td>
      <td><a class="link" href="/q/\${e.id}" target="_blank">פתח QR ↗</a></td>
      <td><button class="\${e.active?'danger':'ghost'}" onclick="toggle('\${e.id}',\${!e.active})">\${e.active?'השבת':'הפעל'}</button></td>\`;
    tb.appendChild(tr);
  });
  const log = await (await fetch('/api/log')).json();
  const lb=document.querySelector('#log tbody'); lb.innerHTML='';
  log.forEach(l=>{
    const tr=document.createElement('tr');
    const t=new Date(l.ts).toLocaleString('he-IL');
    tr.innerHTML=\`<td>\${t}</td><td>\${l.employeeName}</td>
      <td class="\${l.result==='granted'?'g':'r'}">\${l.result==='granted'?'נכנס ✓':'נדחה ✕'}</td>\`;
    lb.appendChild(tr);
  });
}
async function addEmp(){
  const name=document.getElementById('name').value.trim()||'עובד חדש';
  await fetch('/api/employees',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});
  document.getElementById('name').value=''; load();
}
async function toggle(id,active){
  await fetch('/api/employees/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({active})});
  load();
}
load(); setInterval(load,4000);
</script>`);
}

function qrPage(emp) {
  return htmlShell('הכניסה שלך — ' + emp.name, `
<h1>${emp.name}</h1>
<p class="sub">הצג את הקוד הזה לקורא בכניסה. הקוד מתחדש אוטומטית כל ${STEP_SECONDS} שניות — צילום מסך לא יעבוד.</p>
<div class="card" style="text-align:center">
  <div id="qr" style="display:inline-block;padding:14px;background:#fff;border-radius:12px"></div>
  <div style="margin-top:12px;color:var(--muted);font-size:14px">מתחדש בעוד <b id="sec">--</b> שניות</div>
  <div style="margin-top:6px;height:6px;background:#eef3f8;border-radius:4px;overflow:hidden">
    <div id="bar" style="height:100%;background:var(--brand);width:100%;transition:width 1s linear"></div>
  </div>
</div>
<script>
let qr=new QRCode(document.getElementById('qr'),{width:220,height:220,correctLevel:QRCode.CorrectLevel.M});
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
  return htmlShell('סימולציית קורא', `
<h1>סימולציית קורא QR (לבדיקה)</h1>
<p class="sub">במציאות, הקורא הפיזי בכניסה שולח את תוכן ה-QR לשרת. כאן אפשר להדביק ערך ידנית כדי לבדוק את זרימת האימות — או לחבר מצלמה אמיתית בהמשך.</p>
<div class="card">
  <p style="margin-top:0;color:var(--muted);font-size:13px">הדבק כאן את תוכן ה-QR (מהדף של העובד) או הקלד <code>employeeId.code</code>:</p>
  <div style="display:flex;gap:10px">
    <input id="payload" placeholder="לדוגמה: e1a2b3.123456">
    <button class="primary" onclick="scan()">אמת כניסה</button>
  </div>
  <div id="result" style="margin-top:14px;font-size:20px;text-align:center"></div>
</div>
<script>
async function scan(){
  const payload=document.getElementById('payload').value.trim();
  const r=await (await fetch('/api/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload,doorId:'d1'})})).json();
  const el=document.getElementById('result');
  if(r.open){el.innerHTML='<span class="g">✓ גישה אושרה — השער נפתח</span>';}
  else{el.innerHTML='<span class="r">✕ גישה נדחתה</span>';}
}
</script>`);
}
