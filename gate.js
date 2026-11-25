// Nezha 2FA gate v2: Google Authenticator (TOTP) in front of the Nezha dashboard.
// Node built-ins only. Adds a "2FA 设置" page at /__2fa/settings and a button inside the admin UI.
const fs = require('fs');
const path = require('path');
const net = require('net');
const http = require('http');
const crypto = require('crypto');

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32enc(buf) { let bits = 0, v = 0, o = ''; for (const b of buf) { v = (v << 8) | b; bits += 8; while (bits >= 5) { o += B32[(v >>> (bits - 5)) & 31]; bits -= 5; } } if (bits > 0) o += B32[(v << (5 - bits)) & 31]; return o; }
function b32dec(s) { s = String(s).replace(/[\s=]/g, '').toUpperCase(); let bits = 0, v = 0; const o = []; for (const ch of s) { const i = B32.indexOf(ch); if (i < 0) continue; v = (v << 5) | i; bits += 5; if (bits >= 8) { o.push((v >>> (bits - 8)) & 255); bits -= 8; } } return Buffer.from(o); }
function hotp(key, counter) { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(counter)); const h = crypto.createHmac('sha1', key).update(b).digest(); const off = h[h.length - 1] & 15; return String((h.readUInt32BE(off) & 0x7fffffff) % 1000000).padStart(6, '0'); }
const newSecret = () => b32enc(crypto.randomBytes(20));
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function start({ publicPort, internalPort, dir, log, issuer = 'Nezha', account = 'admin' }) {
  const stateFile = path.join(dir, 'gate.json');
  // --- at-rest encryption: secrets in gate.json are AES-256-GCM encrypted.
  // Master key: env NEZHA_2FA_KEY (recommended, keep it outside the data dir), else gate.key (0600) next to gate.json.
  const keyFile = path.join(dir, 'gate.key');
  let master;
  if (process.env.NEZHA_2FA_KEY) master = crypto.createHash('sha256').update(process.env.NEZHA_2FA_KEY).digest();
  else {
    if (!fs.existsSync(keyFile)) fs.writeFileSync(keyFile, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
    try { fs.chmodSync(keyFile, 0o600); } catch (e) {}
    master = crypto.createHash('sha256').update(fs.readFileSync(keyFile, 'utf8').trim()).digest();
  }
  const SECRET_FIELDS = ['secret', 'sessionKey', 'pending', 'setupToken'];
  const seal = (obj) => { const iv = crypto.randomBytes(12); const c = crypto.createCipheriv('aes-256-gcm', master, iv); const d = Buffer.concat([c.update(JSON.stringify(obj)), c.final()]); return { iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), data: d.toString('base64') }; };
  const unseal = (e) => { const c = crypto.createDecipheriv('aes-256-gcm', master, Buffer.from(e.iv, 'base64')); c.setAuthTag(Buffer.from(e.tag, 'base64')); return JSON.parse(Buffer.concat([c.update(Buffer.from(e.data, 'base64')), c.final()]).toString()); };
  const fresh = () => ({ enabled: true, bound: false, secret: newSecret(), sessionKey: crypto.randomBytes(32).toString('hex'), setupToken: crypto.randomBytes(18).toString('base64url'), days: 7, pending: null, lastUsed: -1 });
  let st = null;
  if (fs.existsSync(stateFile)) {
    try {
      const raw = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
      if (raw.enc) { st = { ...raw, ...unseal(raw.enc) }; delete st.enc; }
      else { st = raw; if (st.bound === undefined) st.bound = true; } // migrate plaintext v2 (already bound)
    } catch (e) { log('[2FA] WARNING: cannot decrypt gate.json (master key changed?), generating a new key'); st = null; }
  }
  if (!st) {
    const old = path.join(dir, 'totp-secret.txt'), oldKey = path.join(dir, 'gate-key.txt');
    st = fresh();
    if (fs.existsSync(old)) { st.secret = fs.readFileSync(old, 'utf8').trim(); st.bound = true; st.setupToken = null; }
    if (fs.existsSync(oldKey)) st.sessionKey = fs.readFileSync(oldKey, 'utf8').trim();
  }
  const save = () => {
    const plain = {}, sec = {};
    for (const [k, v] of Object.entries(st)) (SECRET_FIELDS.includes(k) ? sec : plain)[k] = v;
    fs.writeFileSync(stateFile, JSON.stringify({ ...plain, enc: seal(sec) }, null, 2), { mode: 0o600 });
    try { fs.chmodSync(stateFile, 0o600); } catch (e) {}
  };
  save();
  for (const f of ['totp-secret.txt', 'gate-key.txt']) { try { fs.unlinkSync(path.join(dir, f)); } catch (e) {} }

  const uri = (sec) => `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${sec}&issuer=${encodeURIComponent(issuer)}`;
  const announce = () => {
    if (!st.enabled) return log('[2FA] disabled (turn on at /__2fa/settings)');
    if (!st.bound) return log('[2FA] NOT BOUND YET. One-time setup link (open in your browser, then scan): http://<your-host>:' + publicPort + '/__2fa/setup?t=' + st.setupToken);
    log('[2FA] enabled (key is encrypted in gate.json; view it in the dashboard 🔐 2FA settings)');
  };
  announce();

  function verify(code, secB32, consume = true) {
    code = String(code || '').replace(/\D/g, '');
    if (code.length !== 6 || !secB32) return false;
    const key = b32dec(secB32), t = Math.floor(Date.now() / 30000);
    for (const d of [-1, 0, 1]) {
      const c = t + d;
      if (consume && c <= st.lastUsed) continue;
      if (crypto.timingSafeEqual(Buffer.from(hotp(key, c)), Buffer.from(code))) { if (consume) { st.lastUsed = c; save(); } return true; }
    }
    return false;
  }
  const sign = (exp) => crypto.createHmac('sha256', st.sessionKey).update(String(exp)).digest('hex');
  const makeCookie = () => { const exp = Date.now() + st.days * 86400000; return `nzgate=${exp}.${sign(exp)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${st.days * 86400}`; };
  function hasGate(req) {
    if (!st.enabled) return true;
    const m = /(?:^|;\s*)nzgate=(\d+)\.([0-9a-f]{64})/.exec(req.headers.cookie || '');
    if (!m || Number(m[1]) < Date.now()) return false;
    const a = Buffer.from(m[2]), b = Buffer.from(sign(m[1]));
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }
  function needsGate(req) {
    const u = req.url || '/';
    if (u.startsWith('/dashboard')) return true;
    if (/^\/api\/v1\/(login|oauth2|ws\/terminal|ws\/file|file)/.test(u)) return true;
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return true;
    if (req.headers.authorization) return true;
    if (/(?:^|;\s*)nz-jwt=/.test(req.headers.cookie || '')) return true;
    return false;
  }
  const ipOf = (req) => (req.socket.remoteAddress || '').replace(/^::ffff:/, '');

  const fails = new Map(); let globalFails = [];
  function limited(ip) {
    const now = Date.now();
    globalFails = globalFails.filter((t) => now - t < 600000);
    const l = (fails.get(ip) || []).filter((t) => now - t < 600000); fails.set(ip, l);
    return l.length >= 5 || globalFails.length >= 30;
  }
  function addFail(ip) { const now = Date.now(); globalFails.push(now); fails.set(ip, [...(fails.get(ip) || []), now]); }

  // Is this request logged in to Nezha? (asks the dashboard itself)
  function nezhaLoggedIn(req) {
    return new Promise((resolve) => {
      const headers = {}; if (req.headers.cookie) headers.cookie = req.headers.cookie; if (req.headers.authorization) headers.authorization = req.headers.authorization;
      headers['x-real-ip'] = ipOf(req);
      const r = http.request({ host: '127.0.0.1', port: internalPort, path: '/api/v1/profile', method: 'GET', headers }, (res) => {
        let b = ''; res.on('data', (d) => { b += d; }); res.on('end', () => { try { resolve(res.statusCode === 200 && JSON.parse(b).success === true); } catch (e) { resolve(false); } });
      });
      r.on('error', () => resolve(false)); r.setTimeout(5000, () => { r.destroy(); resolve(false); }); r.end();
    });
  }

  const CSS = `body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:#1e293b;padding:26px;border-radius:14px;width:min(380px,92vw);box-sizing:border-box}h2,h3{margin:0 0 14px}
input,select{font-size:16px;width:100%;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#fff}
input.code{font-size:28px;letter-spacing:6px;text-align:center}button{margin-top:10px;width:100%;padding:11px;border:0;border-radius:8px;background:#3b82f6;color:#fff;font-size:15px;cursor:pointer}
button.sec{background:#334155}button.danger{background:#b91c1c}.msg{color:#f87171;min-height:1.2em;margin:8px 0}.ok{color:#4ade80}.muted{color:#94a3b8;font-size:13px}
.row{display:flex;justify-content:space-between;align-items:center;margin:8px 0}.key{font-family:monospace;font-size:15px;word-break:break-all;background:#0f172a;padding:8px;border-radius:6px;user-select:all}
#qr{background:#fff;padding:8px;border-radius:8px;display:inline-block;margin:8px 0}#qr:empty{display:none}hr{border:0;border-top:1px solid #334155;margin:16px 0}a{color:#93c5fd}`;

  const loginPage = (msg, next) => `<!doctype html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>二次验证</title><style>${CSS}</style></head>
<body><form class="card" method="post" action="/__2fa" style="text-align:center"><h3>输入谷歌验证器 6 位码</h3>${st.bound ? '' : '<p class="muted">还没绑定验证器：打开服务器控制台里 [2FA] 那行一次性绑定链接。</p>'}<input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" autofocus>
<input type="hidden" name="next" value="${esc(next)}"><p class="msg">${esc(msg)}</p><button>验证</button></form></body></html>`;

  const settingsPage = () => `<!doctype html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>2FA 设置</title><style>${CSS}</style>
<script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js"></script></head><body><div class="card">
<h2>🔐 2FA 设置</h2>
<div class="row"><span>状态</span><b id="status"></b></div>
<div class="row"><span>验证后免输天数</span><span id="daysv"></span></div>
<p class="muted">敏感操作都需要输入当前谷歌验证器里的 6 位码。</p>
<input id="code" class="code" inputmode="numeric" maxlength="6" placeholder="6 位码">
<div class="msg" id="msg"></div>
<div id="on">
<button onclick="act('reveal')">显示密钥 / 二维码（换手机用）</button>
<button class="sec" onclick="act('rotate_start')">更换密钥</button>
<div class="row" style="gap:8px"><select id="days">${[1, 3, 7, 14, 30].map((d) => `<option value="${d}">${d} 天</option>`).join('')}</select><button class="sec" style="margin:0;width:50%" onclick="act('days')">保存天数</button></div>
<button class="sec" onclick="act('logout_all')">让所有设备重新验证</button>
<button class="danger" onclick="if(confirm('关闭后后台只靠密码保护，确定？'))act('disable')">关闭 2FA</button>
</div>
<div id="off"><button onclick="act('enable_start')">开启 2FA（生成新密钥）</button></div>
<div id="bind" style="display:none"><hr><h3 id="bindt"></h3><p class="muted">谷歌验证器 → ＋ → 扫描二维码，或选「输入设置密钥」，类型选「基于时间」。</p>
<div style="text-align:center"><div id="qr"></div></div><div class="key" id="key"></div>
<div id="confirmbox"><p class="muted">添加后，把<b>新密钥</b>显示的 6 位码填到上面的输入框，再点确认。</p><button id="confirmbtn">确认绑定</button></div></div>
<hr><a href="/dashboard">← 返回哪吒后台</a> · <a href="/__2fa/logout">退出验证</a>
</div><script>
let S={};const $=id=>document.getElementById(id);
async function load(){const r=await fetch('/__2fa/api',{headers:{'X-Gate':'1'}});S=await r.json();render()}
function render(){$('status').textContent=S.enabled?'已开启':'未开启';$('status').className=S.enabled?'ok':'msg';$('daysv').textContent=S.days+' 天';$('days').value=S.days;$('on').style.display=S.enabled?'':'none';$('off').style.display=S.enabled?'none':''}
function showKey(t,sec,uri,confirmAction){$('bind').style.display='';$('bindt').textContent=t;$('key').textContent=sec.replace(/(.{4})/g,'$1 ');$('qr').innerHTML='';
try{const q=qrcode(0,'M');q.addData(uri);q.make();$('qr').innerHTML=q.createSvgTag(5,0)}catch(e){}
$('confirmbox').style.display=confirmAction?'':'none';$('confirmbtn').onclick=()=>act(confirmAction)}
async function act(a){$('msg').textContent='';const body={action:a,code:$('code').value,days:$('days').value};
const r=await fetch('/__2fa/api',{method:'POST',headers:{'Content-Type':'application/json','X-Gate':'1'},body:JSON.stringify(body)});const j=await r.json();
$('code').value='';if(!j.ok){$('msg').textContent=j.error||'失败';return}
if(j.secret)showKey(a==='reveal'?'当前密钥':'新密钥',j.secret,j.uri,a==='reveal'?null:(a==='enable_start'?'enable_confirm':'rotate_confirm'));
else{$('bind').style.display='none';$('msg').innerHTML='<span class="ok">'+(j.done||'已完成')+'</span>'}
if(j.state){S=j.state;render()}}
load();</script></body></html>`;

  const BTN = `<script>(function(){if(document.getElementById('nz2fa'))return;var a=document.createElement('a');a.id='nz2fa';a.href='/__2fa/settings';a.textContent='🔐 2FA';
a.style.cssText='position:fixed;right:14px;bottom:14px;z-index:99999;background:#1e293b;color:#fff;padding:7px 12px;border-radius:18px;font:13px system-ui;text-decoration:none;opacity:.85;box-shadow:0 2px 8px rgba(0,0,0,.3)';
(document.body||document.documentElement).appendChild(a)})();</script>`;

  const json = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); };
  const pub = () => ({ enabled: st.enabled, days: st.days });

  async function api(req, res) {
    if (req.headers['x-gate'] !== '1') return json(res, 403, { ok: false, error: 'bad request' });
    if (!hasGate(req)) return json(res, 401, { ok: false, error: '需要先通过二次验证' });
    if (!(await nezhaLoggedIn(req))) return json(res, 401, { ok: false, error: '请先登录哪吒后台' });
    if (req.method === 'GET') return json(res, 200, pub());
    let body = ''; req.on('data', (d) => { body += d; if (body.length > 4000) req.destroy(); });
    req.on('end', () => {
      let q = {}; try { q = JSON.parse(body); } catch (e) {}
      const ip = ipOf(req);
      if (limited(ip)) return json(res, 429, { ok: false, error: '尝试次数过多，请 10 分钟后再试' });
      const needCur = (fn) => { if (!verify(q.code, st.secret, false)) { addFail(ip); return json(res, 200, { ok: false, error: '验证码不对' }); } return fn(); };
      switch (q.action) {
        case 'reveal': return needCur(() => json(res, 200, { ok: true, secret: st.secret, uri: uri(st.secret) }));
        case 'rotate_start': return needCur(() => { st.pending = newSecret(); save(); json(res, 200, { ok: true, secret: st.pending, uri: uri(st.pending) }); });
        case 'rotate_confirm':
          if (!st.pending || !verify(q.code, st.pending, false)) { addFail(ip); return json(res, 200, { ok: false, error: '新密钥的验证码不对' }); }
          st.secret = st.pending; st.pending = null; st.lastUsed = -1; save(); log('[2FA] key rotated from', ip);
          return json(res, 200, { ok: true, done: '已更换密钥，旧密钥失效', state: pub() });
        case 'days': return needCur(() => { const d = parseInt(q.days, 10); if (![1, 3, 7, 14, 30].includes(d)) return json(res, 200, { ok: false, error: '天数无效' }); st.days = d; save(); json(res, 200, { ok: true, done: '已保存', state: pub() }); });
        case 'logout_all': return needCur(() => { st.sessionKey = crypto.randomBytes(32).toString('hex'); save(); res.setHeader('Set-Cookie', makeCookie()); json(res, 200, { ok: true, done: '其他设备都需要重新验证', state: pub() }); });
        case 'disable': return needCur(() => { st.enabled = false; st.pending = null; save(); log('[2FA] disabled from', ip); json(res, 200, { ok: true, done: '2FA 已关闭', state: pub() }); });
        case 'enable_start': if (st.enabled) return json(res, 200, { ok: false, error: '已经开启' }); st.pending = newSecret(); save(); return json(res, 200, { ok: true, secret: st.pending, uri: uri(st.pending) });
        case 'enable_confirm':
          if (st.enabled || !st.pending || !verify(q.code, st.pending, false)) { addFail(ip); return json(res, 200, { ok: false, error: '新密钥的验证码不对' }); }
          st.secret = st.pending; st.pending = null; st.enabled = true; st.lastUsed = -1; st.sessionKey = crypto.randomBytes(32).toString('hex'); save(); log('[2FA] enabled from', ip);
          res.setHeader('Set-Cookie', makeCookie()); return json(res, 200, { ok: true, done: '2FA 已开启', state: pub() });
        default: return json(res, 200, { ok: false, error: 'unknown action' });
      }
    });
  }

  const setupPage = (tok, msg) => `<!doctype html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>绑定谷歌验证器</title><style>${CSS}</style>
<script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js"></script></head><body><form class="card" method="post" action="/__2fa/setup" style="text-align:center">
<h3>绑定谷歌验证器</h3><p class="muted">用谷歌验证器扫码，或手动输入下面的密钥（基于时间）。此链接绑定成功后立即失效。</p>
<div id="qr"></div><div class="key">${esc(st.secret.replace(/(.{4})/g, '$1 ').trim())}</div>
<p class="muted">再输入验证器里显示的 6 位码确认：</p><input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" autofocus>
<input type="hidden" name="t" value="${esc(tok)}"><p class="msg">${esc(msg)}</p><button>完成绑定</button></form>
<script>try{const q=qrcode(0,'M');q.addData(${JSON.stringify(uri(st.secret))});q.make();document.getElementById('qr').innerHTML=q.createSvgTag(5,0)}catch(e){}</script></body></html>`;
  const tokOk = (t) => !!(st.setupToken && t && t.length === st.setupToken.length && crypto.timingSafeEqual(Buffer.from(t), Buffer.from(st.setupToken)));
  function setup(req, res, u, ip) {
    const html = (code, body) => { res.writeHead(code, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' }); res.end(body); };
    const gone = () => html(404, `<!doctype html><meta charset="utf-8"><style>${CSS}</style><div class="card">链接无效或已使用。需要重新绑定：删除 gate.json 后重启。</div>`);
    if (st.bound || !st.enabled) return gone();
    if (limited(ip)) return html(429, `<!doctype html><meta charset="utf-8"><style>${CSS}</style><div class="card">尝试次数过多，请 10 分钟后再试</div>`);
    if (req.method !== 'POST') { const t = u.searchParams.get('t'); if (!tokOk(t)) { addFail(ip); return gone(); } return html(200, setupPage(t, '')); }
    let body = ''; req.on('data', (d) => { body += d; if (body.length > 2000) req.destroy(); });
    req.on('end', () => {
      const q = new URLSearchParams(body); const t = q.get('t');
      if (!tokOk(t)) { addFail(ip); return gone(); }
      if (!verify(q.get('code'), st.secret)) { addFail(ip); return html(401, setupPage(t, '验证码不对，确认手机时间准确后再试')); }
      st.bound = true; st.setupToken = null; save(); log('[2FA] bound from', ip);
      res.writeHead(302, { 'Set-Cookie': makeCookie(), Location: '/dashboard' }); res.end();
    });
  }

  function proxy(req, res) {
    const headers = { ...req.headers, 'x-real-ip': ipOf(req) };
    const inject = req.method === 'GET' && req.url.startsWith('/dashboard');
    if (inject) delete headers['accept-encoding'];
    const p = http.request({ host: '127.0.0.1', port: internalPort, method: req.method, path: req.url, headers }, (pr) => {
      if (inject && /text\/html/.test(pr.headers['content-type'] || '') && !pr.headers['content-encoding']) {
        const chunks = []; pr.on('data', (c) => chunks.push(c));
        pr.on('end', () => {
          let html = Buffer.concat(chunks).toString('utf8');
          html = html.includes('</body>') ? html.replace('</body>', BTN + '</body>') : html + BTN;
          const h = { ...pr.headers }; delete h['content-length']; h['content-length'] = Buffer.byteLength(html);
          res.writeHead(pr.statusCode, h); res.end(html);
        });
        return;
      }
      res.writeHead(pr.statusCode, pr.headers); pr.pipe(res);
    });
    p.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end('dashboard starting, retry in a few seconds'); });
    req.pipe(p);
  }

  const server = http.createServer((req, res) => {
    const ip = ipOf(req);
    if (req.url.startsWith('/__2fa')) {
      const u = new URL(req.url, 'http://x');
      if (u.pathname === '/__2fa/logout') { res.writeHead(302, { 'Set-Cookie': 'nzgate=; Path=/; Max-Age=0', Location: '/' }); return res.end(); }
      if (u.pathname === '/__2fa/api') return api(req, res);
      if (u.pathname === '/__2fa/setup') return setup(req, res, u, ip);
      if (u.pathname === '/__2fa/settings') {
        if (!hasGate(req)) { res.writeHead(302, { Location: '/__2fa?next=%2F__2fa%2Fsettings' }); return res.end(); }
        return nezhaLoggedIn(req).then((ok) => {
          if (!ok) { res.writeHead(302, { Location: '/dashboard/login' }); return res.end(); }
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(settingsPage());
        });
      }
      let next = u.searchParams.get('next') || '/dashboard';
      if (req.method === 'POST') {
        let body = ''; req.on('data', (d) => { body += d; if (body.length > 2000) req.destroy(); });
        req.on('end', () => {
          const q = new URLSearchParams(body); next = q.get('next') || '/dashboard';
          if (!next.startsWith('/') || next.startsWith('//')) next = '/dashboard';
          if (!st.enabled) { res.writeHead(302, { Location: next }); return res.end(); }
          if (limited(ip)) { res.writeHead(429, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(loginPage('尝试次数过多，请 10 分钟后再试', next)); }
          if (verify(q.get('code'), st.secret)) { log('[2FA] ok from', ip); res.writeHead(302, { 'Set-Cookie': makeCookie(), Location: next }); return res.end(); }
          addFail(ip); log('[2FA] bad code from', ip);
          res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(loginPage('验证码不对', next));
        });
        return;
      }
      if (!next.startsWith('/') || next.startsWith('//')) next = '/dashboard';
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(loginPage('', next));
    }
    if (needsGate(req) && !hasGate(req)) {
      if (req.method === 'GET' && req.url.startsWith('/dashboard')) { res.writeHead(302, { Location: '/__2fa?next=' + encodeURIComponent(req.url) }); return res.end(); }
      return json(res, 401, { success: false, error: '2FA required' });
    }
    proxy(req, res);
  });

  server.on('upgrade', (req, sock, head) => {
    if (needsGate(req) && !hasGate(req)) { sock.end('HTTP/1.1 401 Unauthorized\r\n\r\n'); return; }
    const up = net.connect(internalPort, '127.0.0.1', () => {
      const h = { ...req.headers, 'x-real-ip': ipOf(req) };
      let raw = `${req.method} ${req.url} HTTP/1.1\r\n`;
      for (const [k, v] of Object.entries(h)) for (const vv of [].concat(v)) raw += `${k}: ${vv}\r\n`;
      up.write(raw + '\r\n'); if (head && head.length) up.write(head);
      sock.pipe(up); up.pipe(sock);
    });
    up.on('error', () => sock.destroy()); sock.on('error', () => up.destroy());
  });

  // HTTP/2 cleartext (Nezha agent gRPC) passes straight through; everything else goes through the gate.
  const front = net.createServer((sock) => {
    sock.once('data', (buf) => {
      sock.pause();
      if (buf.slice(0, 3).toString() === 'PRI') {
        const up = net.connect(internalPort, '127.0.0.1', () => { up.write(buf); sock.pipe(up); up.pipe(sock); sock.resume(); });
        up.on('error', () => sock.destroy()); sock.on('error', () => up.destroy());
      } else { sock.unshift(buf); server.emit('connection', sock); sock.resume(); }
    });
    sock.on('error', () => {});
  });
  front.listen(publicPort, '0.0.0.0', () => log('[2FA] gate listening on', publicPort));
}
module.exports = { start };
