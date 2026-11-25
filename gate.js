// Nezha shield (gate v4). Sits in front of a Nezha dashboard that has native TOTP.
// - No secret of its own: login = Nezha username + password + Nezha TOTP code, verified by Nezha itself.
// - "Hide panel" mode (default ON): without a valid Nezha session nothing of Nezha is reachable,
//   not even its login API; visitors only see a neutral login page.
// - Brute force: per-IP exponential lockout + global lockout, persisted across restarts, uniform slow
//   responses, one generic error for every failure (no password oracle).
// - Agent gRPC (h2c) is parsed: only /proto.NezhaService/* gRPC calls pass, so the HTTP API can't be
//   reached over HTTP/2 to bypass the shield.
// - Toggle in the admin UI (🛡 button). Turning protection OFF needs password + TOTP again.
// Node built-ins only.
const fs = require('fs');
const path = require('path');
const net = require('net');
const http = require('http');
const http2 = require('http2');
const crypto = require('crypto');
const { Duplex } = require('stream');

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function start({ publicPort, internalPort, dir, log }) {
  const L = (...a) => log('[shield]', ...a);
  const cfgFile = path.join(dir, 'shield.json');
  const lockFile = path.join(dir, 'shield-lock.json');
  const ALLOW_NO_TOTP = fs.existsSync(path.join(dir, 'shield-allow-no-totp.txt'));

  // ---------- config ----------
  let cfg = { hide: true, publicPage: false };
  try { cfg = { ...cfg, ...JSON.parse(fs.readFileSync(cfgFile, 'utf8')) }; } catch (e) {}
  cfg.hide = cfg.hide !== false; cfg.publicPage = cfg.publicPage === true;
  const saveCfg = () => fs.writeFileSync(cfgFile, JSON.stringify(cfg, null, 2), { mode: 0o600 });
  saveCfg();
  L('hide panel:', cfg.hide ? 'ON' : 'OFF', '| public status page:', cfg.publicPage ? 'open' : 'hidden');

  // ---------- brute-force lockout (persisted) ----------
  const IP_MAX = 5, IP_WIN = 15 * 60e3, IP_BASE_LOCK = 15 * 60e3, IP_MAX_LOCK = 24 * 3600e3;
  const G_MAX = 30, G_WIN = 10 * 60e3, G_LOCK = 30 * 60e3;
  let lk = { ips: {}, g: { fails: [], until: 0 } };
  try { lk = { ...lk, ...JSON.parse(fs.readFileSync(lockFile, 'utf8')) }; } catch (e) {}
  let lkDirty = false;
  setInterval(() => {
    const now = Date.now();
    for (const [ip, r] of Object.entries(lk.ips)) { r.fails = r.fails.filter((t) => now - t < IP_WIN); if (!r.fails.length && r.until < now && now - (r.last || 0) > IP_MAX_LOCK) delete lk.ips[ip]; }
    lk.g.fails = lk.g.fails.filter((t) => now - t < G_WIN);
    if (lkDirty) { try { fs.writeFileSync(lockFile, JSON.stringify(lk), { mode: 0o600 }); } catch (e) {} lkDirty = false; }
  }, 5000).unref();
  function lockedFor(ip) {
    const now = Date.now(), r = lk.ips[ip];
    if (r && r.until > now) return r.until - now;
    if (lk.g.until > now) return lk.g.until - now;
    return 0;
  }
  function addFail(ip, why) {
    const now = Date.now();
    const r = lk.ips[ip] || (lk.ips[ip] = { fails: [], until: 0, level: 0 });
    r.fails = r.fails.filter((t) => now - t < IP_WIN); r.fails.push(now); r.last = now;
    if (r.fails.length >= IP_MAX) { r.until = now + Math.min(IP_BASE_LOCK * 2 ** r.level, IP_MAX_LOCK); r.level++; r.fails = []; L('ip locked', ip, Math.round((r.until - now) / 60e3) + 'min'); }
    lk.g.fails = lk.g.fails.filter((t) => now - t < G_WIN); lk.g.fails.push(now);
    if (lk.g.fails.length >= G_MAX) { lk.g.until = now + G_LOCK; lk.g.fails = []; L('GLOBAL login lock 30min (too many failures)'); }
    lkDirty = true; L('login failed from', ip, why || '');
  }
  function addOk(ip) { const r = lk.ips[ip]; if (r) { r.fails = []; r.level = 0; lkDirty = true; } }

  const ipOf = (req) => ((req.socket && req.socket.remoteAddress) || '').replace(/^::ffff:/, '');

  // ---------- talk to Nezha ----------
  function nz(method, p, { body, cookie, auth, ip } = {}) {
    return new Promise((resolve) => {
      const data = body ? JSON.stringify(body) : null;
      const headers = { 'x-real-ip': ip || '127.0.0.1' };
      if (data) { headers['content-type'] = 'application/json'; headers['content-length'] = Buffer.byteLength(data); }
      if (cookie) headers.cookie = cookie;
      if (auth) headers.authorization = auth;
      const r = http.request({ host: '127.0.0.1', port: internalPort, method, path: p, headers }, (res) => {
        let b = ''; res.on('data', (d) => { if (b.length < 65536) b += d; });
        res.on('end', () => { let j = null; try { j = JSON.parse(b); } catch (e) {} resolve({ status: res.statusCode, json: j, setCookie: [].concat(res.headers['set-cookie'] || []) }); });
      });
      r.on('error', () => resolve({ status: 0, json: null, setCookie: [] }));
      r.setTimeout(15000, () => r.destroy());
      if (data) r.write(data); r.end();
    });
  }
  const jwtOf = (cookieHdr) => { const m = /(?:^|;\s*)nz-jwt=([^;]+)/.exec(cookieHdr || ''); return m ? m[1] : ''; };
  // Session check (cached). Only the nz-jwt cookie / Authorization header are forwarded.
  const sess = new Map();
  async function session(req) {
    const jwt = jwtOf(req.headers.cookie), auth = req.headers.authorization || '';
    if (!jwt && !auth) return false;
    if (jwt.length > 4096 || auth.length > 4096) return false;
    const key = crypto.createHash('sha256').update(jwt + '|' + auth).digest('hex');
    const c = sess.get(key); if (c && c.exp > Date.now()) return c.ok;
    const r = await nz('GET', '/api/v1/profile', { cookie: jwt ? 'nz-jwt=' + jwt : '', auth, ip: ipOf(req) });
    const ok = r.status === 200 && !!(r.json && r.json.success);
    if (sess.size > 2000) sess.clear();
    sess.set(key, { ok, exp: Date.now() + (ok ? 20e3 : 5e3) });
    return ok;
  }
  const dropSessions = () => sess.clear();

  // Full credential check through Nezha (password + TOTP). Returns {ok, setCookie}.
  async function credCheck(ip, username, password, code) {
    if (typeof username !== 'string' || typeof password !== 'string' || typeof code !== 'string') return { ok: false, why: 'bad input' };
    if (!username || !password || username.length > 64 || password.length > 128 || !/^\d{6}$/.test(code)) return { ok: false, why: 'bad input' };
    const r = await nz('POST', '/api/v1/login', { body: { username, password, totp_code: code }, ip });
    if (!(r.status === 200 && r.json && r.json.success)) return { ok: false, why: r.json && r.json.error };
    const jwt = r.setCookie.map((c) => jwtOf(c.split(';')[0])).find(Boolean) || '';
    const tok = (r.json.data && r.json.data.token) || '';
    if (!ALLOW_NO_TOTP) {
      const s = await nz('GET', '/api/v1/totp/status', { cookie: jwt ? 'nz-jwt=' + jwt : '', auth: !jwt && tok ? 'Bearer ' + tok : '', ip });
      if (!(s.json && s.json.success && s.json.data && s.json.data.enabled === true)) {
        if (jwt || tok) nz('POST', '/api/v1/logout', { cookie: jwt ? 'nz-jwt=' + jwt : '', auth: !jwt && tok ? 'Bearer ' + tok : '', ip });
        return { ok: false, why: 'account has no TOTP', noTotp: true };
      }
    }
    return { ok: true, setCookie: r.setCookie };
  }

  // Uniform timing for every login answer: >= 1.2 s plus jitter.
  async function slow(t0) { const left = 1200 + crypto.randomInt(0, 400) - (Date.now() - t0); if (left > 0) await sleep(left); }

  // ---------- pages ----------
  const SEC = { 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store' };
  const CSS = `body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:#1e293b;padding:26px;border-radius:14px;width:min(360px,92vw);box-sizing:border-box}h3{margin:0 0 16px}
input{font-size:16px;width:100%;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#fff;margin:6px 0}
input.code{letter-spacing:6px;text-align:center}button{margin-top:12px;width:100%;padding:11px;border:0;border-radius:8px;background:#3b82f6;color:#fff;font-size:15px;cursor:pointer}
button:disabled{opacity:.6}button.danger{background:#b91c1c}button.sec{background:#334155}.msg{color:#f87171;min-height:1.2em;margin:8px 0}.ok{color:#4ade80}.muted{color:#94a3b8;font-size:13px}
.row{display:flex;justify-content:space-between;align-items:center;margin:10px 0}a{color:#93c5fd}hr{border:0;border-top:1px solid #334155;margin:16px 0}`;
  const LOGIN_CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
  const loginPage = (next) => `<!doctype html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>登录</title><style>${CSS}</style></head>
<body><form class="card" id="f"><h3>登录</h3>
<input name="u" placeholder="用户名" autocomplete="username" required autofocus>
<input name="p" type="password" placeholder="密码" autocomplete="current-password" required>
<input name="c" class="code" placeholder="6 位验证码" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required>
<p class="msg" id="m"></p><button id="b">登录</button></form>
<script>const f=document.getElementById('f'),m=document.getElementById('m'),b=document.getElementById('b');
f.onsubmit=async e=>{e.preventDefault();m.textContent='';b.disabled=true;
try{const r=await fetch('/__shield/login',{method:'POST',headers:{'Content-Type':'application/json','X-Shield':'1'},body:JSON.stringify({username:f.u.value,password:f.p.value,code:f.c.value.replace(/\\D/g,'')})});
const j=await r.json();if(j.ok){location.replace(${JSON.stringify(next)});return}m.textContent=j.error||'登录失败'}catch(x){m.textContent='网络错误'}
f.c.value='';b.disabled=false}</script></body></html>`;

  const settingsPage = () => `<!doctype html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>防护设置</title><style>${CSS}</style></head><body><div class="card">
<h3>🛡 防护设置</h3>
<div class="row"><span>登录前隐藏面板</span><b id="hs"></b></div>
<div class="row"><span>公开状态页（前台）</span><b id="ps"></b></div>
<p class="muted">隐藏开启时，未登录访客只能看到一个无标识的登录页，哪吒的任何页面和接口都访问不到。登录 = 哪吒用户名 + 密码 + 哪吒自己的 TOTP 验证码。</p>
<div id="act"></div>
<div id="re" style="display:none"><hr><p class="muted">关闭防护需要重新验证：</p>
<input id="u" placeholder="用户名" autocomplete="username"><input id="p" type="password" placeholder="密码" autocomplete="current-password">
<input id="c" class="code" placeholder="6 位验证码" inputmode="numeric" maxlength="6"><button class="danger" id="go">确认</button></div>
<p class="msg" id="m"></p><hr><a href="/dashboard">← 返回后台</a></div>
<script>let S={},pend=null;const $=i=>document.getElementById(i);
async function call(body){const r=await fetch('/__shield/api',{method:body?'POST':'GET',headers:{'Content-Type':'application/json','X-Shield':'1'},body:body?JSON.stringify(body):undefined});return r.json()}
function render(){$('hs').textContent=S.hide?'开':'关';$('hs').className=S.hide?'ok':'msg';$('ps').textContent=S.publicPage?'公开':'隐藏';
const a=[];a.push(S.hide?'<button class="danger" data-k="hide" data-v="0">关闭隐藏（不推荐）</button>':'<button data-k="hide" data-v="1">开启隐藏</button>');
if(S.hide)a.push(S.publicPage?'<button class="sec" data-k="publicPage" data-v="0">隐藏公开状态页</button>':'<button class="sec" data-k="publicPage" data-v="1">公开状态页（访客可看前台）</button>');
$('act').innerHTML=a.join('');$('act').querySelectorAll('button').forEach(b=>b.onclick=()=>set(b.dataset.k,b.dataset.v==='1'))}
async function set(k,v){$('m').textContent='';const weaker=(k==='hide'&&!v)||(k==='publicPage'&&v);
if(weaker){pend={k,v};$('re').style.display='';return}done(await call({key:k,value:v}))}
$('go').onclick=async()=>{$('go').disabled=true;const j=await call({key:pend.k,value:pend.v,username:$('u').value,password:$('p').value,code:$('c').value.replace(/\\D/g,'')});$('go').disabled=false;$('p').value='';$('c').value='';if(j.ok){$('re').style.display='none';pend=null}done(j)}
function done(j){if(!j.ok){$('m').textContent=j.error||'失败';return}S=j.state;render();$('m').innerHTML='<span class="ok">已保存，立即生效</span>'}
call().then(j=>{if(j.ok){S=j.state;render()}else $('m').textContent=j.error||'请先登录'});</script></body></html>`;

  const BTN = `<script>(function(){if(document.getElementById('nzshield'))return;var a=document.createElement('a');a.id='nzshield';a.href='/__shield/settings';a.textContent='🛡 防护';
a.style.cssText='position:fixed;right:14px;bottom:14px;z-index:99999;background:#1e293b;color:#fff;padding:7px 12px;border-radius:18px;font:13px system-ui;text-decoration:none;opacity:.85;box-shadow:0 2px 8px rgba(0,0,0,.3)';
(document.body||document.documentElement).appendChild(a)})();</script>`;

  const sendJson = (res, code, obj, extra = {}) => { res.writeHead(code, { 'Content-Type': 'application/json', ...SEC, ...extra }); res.end(JSON.stringify(obj)); };
  const notFound = (res) => { res.writeHead(404, { 'Content-Type': 'text/plain', ...SEC }); res.end('Not Found'); };
  const safeNext = (n) => (typeof n === 'string' && n.startsWith('/') && !n.startsWith('//') && !n.startsWith('/\\') && !n.startsWith('/__shield') && n.length < 2000 ? n : '/dashboard');
  function readBody(req, max) {
    return new Promise((resolve) => {
      let b = '', over = false;
      req.on('data', (d) => { if (over) return; b += d; if (b.length > max) { over = true; resolve(null); req.destroy(); } });
      req.on('end', () => { if (over) return; try { resolve(JSON.parse(b)); } catch (e) { resolve(null); } });
      req.on('error', () => resolve(null));
    });
  }
  const lockMsg = (ms) => `尝试次数过多，请 ${Math.ceil(ms / 60e3)} 分钟后再试`;

  async function handleLogin(req, res) {
    const t0 = Date.now(), ip = ipOf(req);
    if (req.method !== 'POST' || req.headers['x-shield'] !== '1') return notFound(res);
    const q = await readBody(req, 2048);
    const lf = lockedFor(ip);
    if (lf) { await slow(t0); return sendJson(res, 429, { ok: false, error: lockMsg(lf) }); }
    const r = q ? await credCheck(ip, q.username, q.password, q.code) : { ok: false, why: 'bad body' };
    await slow(t0);
    if (!r.ok) {
      addFail(ip, r.why);
      if (r.noTotp) L('NOTE: password+code accepted but this Nezha account has TOTP OFF, login refused. Enable TOTP, or create shield-allow-no-totp.txt and restart.');
      return sendJson(res, 401, { ok: false, error: '用户名、密码或验证码错误' });
    }
    addOk(ip); L('login ok from', ip);
    return sendJson(res, 200, { ok: true }, { 'Set-Cookie': r.setCookie });
  }

  async function handleApi(req, res) {
    const ip = ipOf(req);
    if (req.headers['x-shield'] !== '1') return notFound(res);
    if (!(await session(req))) return sendJson(res, 401, { ok: false, error: '请先登录' });
    if (req.method === 'GET') return sendJson(res, 200, { ok: true, state: cfg });
    if (req.method !== 'POST') return notFound(res);
    const t0 = Date.now();
    const q = await readBody(req, 2048);
    if (!q || !['hide', 'publicPage'].includes(q.key) || typeof q.value !== 'boolean') return sendJson(res, 400, { ok: false, error: '参数错误' });
    const weaker = (q.key === 'hide' && !q.value) || (q.key === 'publicPage' && q.value);
    if (weaker) {
      const lf = lockedFor(ip);
      if (lf) { await slow(t0); return sendJson(res, 429, { ok: false, error: lockMsg(lf) }); }
      const r = await credCheck(ip, q.username, q.password, q.code);
      await slow(t0);
      if (!r.ok) { addFail(ip, 'settings: ' + (r.why || '')); return sendJson(res, 401, { ok: false, error: '用户名、密码或验证码错误' }); }
      addOk(ip);
    }
    cfg[q.key] = q.value; saveCfg(); dropSessions();
    L('setting', q.key, '=', q.value, 'by', ip);
    return sendJson(res, 200, { ok: true, state: cfg });
  }

  // Public status page (only when hide ON and publicPage ON): anonymous read-only requests.
  function isPublicReq(req) {
    const u = req.url || '/';
    if (!['GET', 'HEAD'].includes(req.method)) return false;
    if (u.startsWith('/dashboard') || u.startsWith('/swagger') || u.startsWith('/mcp')) return false;
    if (u.startsWith('/api/')) return /^\/api\/v1\/(setting|server-group|service|ws\/server)(\b|[/?])/.test(u);
    return true;
  }

  function proxy(req, res, { anonymous = false, inject = false } = {}) {
    const headers = { ...req.headers, 'x-real-ip': ipOf(req) };
    delete headers['x-forwarded-for'];
    if (anonymous) { delete headers.cookie; delete headers.authorization; }
    if (inject) delete headers['accept-encoding'];
    const p = http.request({ host: '127.0.0.1', port: internalPort, method: req.method, path: req.url, headers }, (pr) => {
      if (inject && /text\/html/.test(pr.headers['content-type'] || '') && !pr.headers['content-encoding']) {
        const chunks = []; pr.on('data', (c) => chunks.push(c));
        pr.on('end', () => {
          let html = Buffer.concat(chunks).toString('utf8');
          html = html.includes('</body>') ? html.replace('</body>', BTN + '</body>') : html + BTN;
          const h = { ...pr.headers }; h['content-length'] = Buffer.byteLength(html);
          res.writeHead(pr.statusCode, h); res.end(html);
        });
        return;
      }
      res.writeHead(pr.statusCode, pr.headers); pr.pipe(res);
    });
    p.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
    req.pipe(p);
  }

  const server = http.createServer(async (req, res) => {
    try {
      const u = req.url || '/';
      if (u === '/__shield/login' || u.startsWith('/__shield/login?')) {
        if (req.method === 'GET') { const n = safeNext(new URL(u, 'http://x').searchParams.get('next')); res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...SEC, 'Content-Security-Policy': LOGIN_CSP }); return res.end(loginPage(n)); }
        return handleLogin(req, res);
      }
      if (u === '/__shield/api') return handleApi(req, res);
      if (u === '/__shield/settings') {
        if (!(await session(req))) { res.writeHead(302, { Location: '/__shield/login?next=%2F__shield%2Fsettings', ...SEC }); return res.end(); }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...SEC, 'Content-Security-Policy': LOGIN_CSP }); return res.end(settingsPage());
      }
      if (u.startsWith('/__shield')) return notFound(res);
      const authed = await session(req);
      if (!cfg.hide || authed) return proxy(req, res, { inject: req.method === 'GET' && u.startsWith('/dashboard') && authed });
      if (cfg.publicPage && isPublicReq(req)) return proxy(req, res, { anonymous: true });
      if (req.method === 'GET' && /text\/html/.test(req.headers.accept || '')) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...SEC, 'Content-Security-Policy': LOGIN_CSP }); return res.end(loginPage(safeNext(u === '/' ? '/dashboard' : u)));
      }
      return notFound(res);
    } catch (e) { L('error', e.message); if (!res.headersSent) res.writeHead(500); res.end(); }
  });
  server.headersTimeout = 15000;
  server.requestTimeout = 0; // long-lived proxied requests
  server.keepAliveTimeout = 30000;
  server.maxHeadersCount = 100;

  server.on('upgrade', async (req, sock, head) => {
    sock.on('error', () => {});
    let anonymous = false;
    if (cfg.hide && !(await session(req))) {
      if (cfg.publicPage && req.method === 'GET' && /^\/api\/v1\/ws\/server(\b|[/?])/.test(req.url || '')) anonymous = true;
      else { sock.end('HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n'); return; }
    }
    const up = net.connect(internalPort, '127.0.0.1', () => {
      const h = { ...req.headers, 'x-real-ip': ipOf(req) };
      delete h['x-forwarded-for'];
      if (anonymous) { delete h.cookie; delete h.authorization; }
      let raw = `${req.method} ${req.url} HTTP/1.1\r\n`;
      for (const [k, v] of Object.entries(h)) for (const vv of [].concat(v)) raw += `${k}: ${String(vv).replace(/[\r\n]/g, '')}\r\n`;
      up.write(raw + '\r\n'); if (head && head.length) up.write(head);
      sock.pipe(up); up.pipe(sock);
    });
    up.on('error', () => sock.destroy()); sock.on('close', () => up.destroy());
  });

  // ---------- agent gRPC over h2c: only NezhaService gRPC calls pass ----------
  let upstream = null;
  function getUp() {
    if (upstream && !upstream.closed && !upstream.destroyed) return upstream;
    upstream = http2.connect(`http://127.0.0.1:${internalPort}`);
    upstream.on('error', () => {}); upstream.on('close', () => { upstream = null; });
    return upstream;
  }
  const HOP = new Set([':method', ':path', ':scheme', ':authority', 'connection', 'keep-alive', 'transfer-encoding', 'upgrade', 'proxy-connection', 'host']);
  const h2 = http2.createServer({ maxSessionMemory: 64 });
  let pendingIp = '';
  h2.on('session', (sess) => { sess.nzIp = pendingIp; sess.on('error', () => {}); });
  // http2 reads native sockets directly, so the sniffed first bytes are replayed through a Duplex wrapper.
  function wrap(sock, first) {
    const d = new Duplex({
      read() { sock.resume(); },
      write(c, e, cb) { sock.write(c, e, cb); },
      final(cb) { sock.end(); cb(); },
      destroy(err, cb) { sock.destroy(); cb(err); },
    });
    d.push(first);
    sock.on('data', (c) => { if (!d.push(c)) sock.pause(); });
    sock.on('end', () => d.push(null));
    sock.on('close', () => d.destroy());
    return d;
  }
  h2.on('stream', (stream, headers) => {
    stream.on('error', () => {});
    const p = String(headers[':path'] || ''), ct = String(headers['content-type'] || '');
    if (headers[':method'] !== 'POST' || !/^\/proto\.NezhaService\/[A-Za-z0-9_]{1,64}$/.test(p) || !ct.startsWith('application/grpc')) {
      try { stream.respond({ ':status': 404 }, { endStream: true }); } catch (e) {}
      return;
    }
    const fwd = { ':method': 'POST', ':path': p, ':scheme': 'http', ':authority': `127.0.0.1:${internalPort}`, 'x-real-ip': stream.session.nzIp || '' };
    for (const [k, v] of Object.entries(headers)) if (!HOP.has(k) && k !== 'x-real-ip') fwd[k] = v;
    let ureq;
    try { ureq = getUp().request(fwd); } catch (e) { try { stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR); } catch (x) {} return; }
    let trailers = null;
    ureq.on('response', (rh) => {
      const out = {}; for (const [k, v] of Object.entries(rh)) if (!HOP.has(k) || k === ':status') out[k] = v;
      try { stream.respond(out, { waitForTrailers: true }); } catch (e) {}
    });
    ureq.on('trailers', (t) => { trailers = t; });
    stream.on('wantTrailers', () => { try { stream.sendTrailers(trailers || { 'grpc-status': '14' }); } catch (e) { try { stream.close(); } catch (x) {} } });
    ureq.on('error', () => { try { if (!stream.headersSent) stream.respond({ ':status': 200, 'content-type': 'application/grpc', 'grpc-status': '14' }, { endStream: true }); else stream.close(http2.constants.NGHTTP2_CANCEL); } catch (e) {} });
    stream.on('close', () => { if (!ureq.closed) ureq.close(http2.constants.NGHTTP2_CANCEL); });
    stream.pipe(ureq); ureq.pipe(stream);
  });
  h2.on('sessionError', () => {});

  const front = net.createServer((sock) => {
    sock.on('error', () => {});
    sock.setTimeout(20000, () => { if (!sock._nzKnown) sock.destroy(); });
    sock.once('data', (buf) => {
      sock._nzKnown = true; sock.setTimeout(0);
      sock.pause();
      if (buf.slice(0, 3).toString() === 'PRI') { pendingIp = (sock.remoteAddress || '').replace(/^::ffff:/, ''); h2.emit('connection', wrap(sock, buf)); pendingIp = ''; }
      else { sock.unshift(buf); server.emit('connection', sock); sock.resume(); }
    });
  });
  front.maxConnections = 2000;
  front.listen(publicPort, '0.0.0.0', () => L('listening on', publicPort, '-> nezha 127.0.0.1:' + internalPort));
}
module.exports = { start };
