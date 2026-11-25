// Nezha Dashboard launcher for Pterodactyl Node.js eggs (no Docker, no root).
// Downloads the official dashboard binary, writes config on first run,
// listens on the server's allocated port (SERVER_PORT), restarts on crash.
// Uses only Node built-ins.
const fs = require('fs');
const path = require('path');
const https = require('https');
const zlib = require('zlib');
const { spawn } = require('child_process');
const gate = require('./gate.js');

const VERSION = process.env.NEZHA_VERSION || 'v2.7.0';
const ARCH = process.arch === 'arm64' ? 'arm64' : 'amd64';
const GH = process.env.GH_PROXY || '';
const DL_URL = `${GH}https://github.com/nezhahq/nezha/releases/download/${VERSION}/dashboard-linux-${ARCH}.zip`;
const BASE = path.join(__dirname, 'nezha');
const BIN = path.join(BASE, 'dashboard');
const DATA = path.join(BASE, 'data');
const CFG = path.join(DATA, 'config.yaml');
const VERFILE = path.join(BASE, '.version');
const PORT = parseInt(process.env.SERVER_PORT || process.env.PORT || '8008', 10);
// Cloudflare Tunnel (optional): token from env TUNNEL_TOKEN or file cf-token.txt next to this script.
const TOKEN_FILE = path.join(__dirname, 'cf-token.txt');
const CF_DIR = path.join(__dirname, 'cloudflared');
const CF_BIN = path.join(CF_DIR, 'cloudflared');
const CF_URL = `${GH}https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}`;
// If local-only.txt exists, the dashboard listens on 127.0.0.1 only (reachable only through the tunnel).
const LOCAL_ONLY = fs.existsSync(path.join(__dirname, 'local-only.txt'));
// TOTP gate: public PORT is served by this script; Nezha listens on 127.0.0.1:INTERNAL.
const INTERNAL = parseInt(process.env.NEZHA_INTERNAL_PORT || '18008', 10);
// gate-off.txt (or GATE=off): no gate, Nezha listens on the public port itself (use with a build that has native TOTP).
const NO_GATE = process.env.GATE === 'off' || fs.existsSync(path.join(__dirname, 'gate-off.txt'));
const NZPORT = NO_GATE ? PORT : INTERNAL;
// dashboard-custom.gz next to this script: use that (gzip'd) dashboard binary instead of the official release.
const CUSTOM_GZ = path.join(__dirname, 'dashboard-custom.gz');

function log(...a) { console.log('[panel]', ...a); }

function download(url, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 8) return reject(new Error('too many redirects'));
    https.get(url, { headers: { 'User-Agent': 'nezha-launcher' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return resolve(download(new (require("url").URL)(res.headers.location, url).toString(), redirects + 1));
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error('HTTP ' + res.statusCode)); }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    }).on('error', reject);
  });
}

// Minimal zip reader: extract the first regular file via the central directory.
function extractFirstFile(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('zip: no EOCD');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('zip: bad central header');
    const method = buf.readUInt16LE(p + 10);
    const csize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const local = buf.readUInt32LE(p + 42);
    const name = buf.slice(p + 46, p + 46 + nameLen).toString();
    p += 46 + nameLen + extraLen + commentLen;
    if (name.endsWith('/')) continue;
    const lNameLen = buf.readUInt16LE(local + 26);
    const lExtraLen = buf.readUInt16LE(local + 28);
    const start = local + 30 + lNameLen + lExtraLen;
    const data = buf.slice(start, start + csize);
    if (method === 0) return data;
    if (method === 8) return zlib.inflateRawSync(data);
    throw new Error('zip: unsupported method ' + method);
  }
  throw new Error('zip: no file');
}

async function ensureBinary() {
  fs.mkdirSync(DATA, { recursive: true });
  const cur = fs.existsSync(VERFILE) ? fs.readFileSync(VERFILE, 'utf8').trim() : '';
  if (fs.existsSync(CUSTOM_GZ)) {
    const gz = fs.readFileSync(CUSTOM_GZ);
    const tag = 'custom-' + require('crypto').createHash('sha256').update(gz).digest('hex').slice(0, 12);
    if (fs.existsSync(BIN) && cur === tag) return;
    const db = path.join(DATA, 'sqlite.db');
    if (fs.existsSync(db)) { const bak = db + '.bak-' + new Date().toISOString().replace(/[:.]/g, '-'); fs.copyFileSync(db, bak); log('database backed up to', path.basename(bak)); }
    if (fs.existsSync(BIN) && cur && !cur.startsWith('custom-')) fs.copyFileSync(BIN, BIN + '.official');
    const tmp = BIN + '.new'; fs.writeFileSync(tmp, zlib.gunzipSync(gz)); fs.chmodSync(tmp, 0o755); fs.renameSync(tmp, BIN);
    fs.writeFileSync(VERFILE, tag);
    log('using custom dashboard binary', tag);
    return;
  }
  const have = fs.existsSync(BIN) && cur === VERSION;
  if (have) return;
  log('downloading dashboard', VERSION, ARCH);
  const zip = await download(DL_URL);
  fs.writeFileSync(BIN, extractFirstFile(zip));
  fs.chmodSync(BIN, 0o755);
  fs.writeFileSync(VERFILE, VERSION);
  log('binary ready');
}

function ensureConfig() {
  if (fs.existsSync(CFG)) {
    // keep user config, only force the port to the allocated one
    let c = fs.readFileSync(CFG, 'utf8');
    c = c.replace(/^listenport:.*\n?/m, '');
    c = c.replace(/^listen_port:.*\n?/m, '').replace(/^listen_host:.*\n?/m, '').replace(/^web_real_ip_header:.*\n?/m, '');
    if (!c.endsWith('\n')) c += '\n';
    if (NO_GATE) { c += `listen_port: ${PORT}\nlisten_host: ${LOCAL_ONLY ? '127.0.0.1' : '0.0.0.0'}\n`; log('gate off, nezha listens on port', PORT); }
    else { c += `listen_port: ${INTERNAL}\nlisten_host: 127.0.0.1\nweb_real_ip_header: X-Real-Ip\n`; log('nezha internal 127.0.0.1:' + INTERNAL + ', public gate on port', PORT); }
    fs.writeFileSync(CFG, c);
    return;
  }
  fs.writeFileSync(CFG, [
    ...(NO_GATE ? [`listen_port: ${PORT}`, `listen_host: ${LOCAL_ONLY ? '127.0.0.1' : '0.0.0.0'}`] : [`listen_port: ${INTERNAL}`, 'listen_host: 127.0.0.1', 'web_real_ip_header: X-Real-Ip']),
    'language: zh_CN',
    'site_name: 哪吒监控',
    'location: Asia/Shanghai',
    'debug: false',
    '',
  ].join('\n'));
  log('wrote initial config, port', PORT);
}

function run() {
  log('starting dashboard on port', PORT);
  const child = spawn(BIN, [], { cwd: BASE, stdio: 'inherit', env: { ...process.env, TZ: process.env.TZ || 'Asia/Shanghai' } });
  child.on('exit', (code, sig) => {
    log('dashboard exited', code, sig, '- restarting in 5s');
    setTimeout(run, 5000);
  });
  const stop = () => { try { child.kill('SIGTERM'); } catch (e) {} process.exit(0); };
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
}

// One-time: install + activate a user frontend theme (default Lotus) through the dashboard's own API.
// Only works while the admin password is still the default admin/admin (fresh install); otherwise skipped.
const THEME_REPO = process.env.THEME_REPO || 'https://github.com/fl0w1nd/Lotus';
const THEME_MARK = path.join(__dirname, 'theme-done.txt');
function api(method, p, body, cookies) {
  return new Promise((resolve) => {
    const data = body ? JSON.stringify(body) : null;
    const headers = { 'X-Real-Ip': '127.0.0.1', 'Content-Type': 'application/json' };
    if (cookies.length) headers.Cookie = cookies.join('; ');
    const csrf = cookies.find((c) => c.startsWith('nz-csrf='));
    if (csrf) headers['X-CSRF-Token'] = csrf.slice(8);
    if (data) headers['Content-Length'] = Buffer.byteLength(data);
    const r = require('http').request({ host: '127.0.0.1', port: NZPORT, method, path: p, headers }, (res) => {
      for (const sc of [].concat(res.headers['set-cookie'] || [])) {
        const kv = sc.split(';')[0]; const k = kv.split('=')[0];
        const i = cookies.findIndex((c) => c.startsWith(k + '=')); if (i >= 0) cookies.splice(i, 1); cookies.push(kv);
      }
      let b = ''; res.on('data', (d) => { b += d; }); res.on('end', () => { try { resolve(JSON.parse(b)); } catch (e) { resolve({ success: false, error: b.slice(0, 200) }); } });
    });
    r.on('error', (e) => resolve({ success: false, error: e.message })); r.setTimeout(200000, () => r.destroy(new Error('timeout')));
    if (data) r.write(data); r.end();
  });
}
async function setupTheme() {
  if (THEME_REPO === 'none' || fs.existsSync(THEME_MARK)) return;
  const cookies = [];
  let login;
  for (let i = 0; i < 30; i++) { login = await api('POST', '/api/v1/login', { username: 'admin', password: 'admin' }, cookies); if (login.success || (login.error && !/ECONNREFUSED/.test(login.error))) break; await new Promise((r) => setTimeout(r, 2000)); }
  if (!login || !login.success) { log('theme: admin password not default, skip auto theme (install it in 系统设置 > 前端管理)'); fs.writeFileSync(THEME_MARK, 'skipped\n'); return; }
  await api('GET', '/api/v1/profile', null, cookies); // seeds csrf cookie if missing
  let tag = process.env.THEME_TAG;
  if (!tag) {
    const rel = await api('GET', '/api/v1/frontend/releases?repository=' + encodeURIComponent(THEME_REPO), null, cookies);
    const r = rel.success && (rel.data.releases || []).find((x) => !x.prerelease && !x.draft);
    if (!r) { log('theme: cannot list releases:', rel.error || 'none'); return; }
    tag = r.tag_name;
  }
  const inst = await api('POST', '/api/v1/frontend/install', { repository: THEME_REPO, tag, is_admin: false }, cookies);
  if (!inst.success) { log('theme: install failed:', inst.error); return; }
  const act = await api('POST', '/api/v1/frontend/activate', { path: inst.data.path, is_admin: false }, cookies);
  if (!act.success) { log('theme: activate failed:', act.error); return; }
  fs.writeFileSync(THEME_MARK, `${THEME_REPO} ${tag}\n`);
  log('theme: installed and activated', inst.data.name || THEME_REPO, tag);
}

function tunnelToken() {
  if (process.env.TUNNEL_TOKEN) return process.env.TUNNEL_TOKEN.trim();
  if (fs.existsSync(TOKEN_FILE)) return fs.readFileSync(TOKEN_FILE, 'utf8').trim();
  return '';
}

async function ensureCloudflared() {
  if (fs.existsSync(CF_BIN) && fs.statSync(CF_BIN).size > 1000000) return;
  fs.mkdirSync(CF_DIR, { recursive: true });
  log('downloading cloudflared', ARCH);
  fs.writeFileSync(CF_BIN, await download(CF_URL));
  fs.chmodSync(CF_BIN, 0o755);
  log('cloudflared ready');
}

function runTunnel(token) {
  log('starting cloudflare tunnel');
  const child = spawn(CF_BIN, ['tunnel', '--no-autoupdate', '--protocol', 'http2', 'run'],
    { cwd: CF_DIR, stdio: 'inherit', env: { ...process.env, TUNNEL_TOKEN: token } });
  child.on('exit', (code, sig) => {
    log('tunnel exited', code, sig, '- restarting in 10s');
    setTimeout(() => runTunnel(token), 10000);
  });
  process.once('SIGTERM', () => { try { child.kill('SIGTERM'); } catch (e) {} });
}

(async () => {
  try {
    await ensureBinary();
    ensureConfig();
    if (!NO_GATE) gate.start({ publicPort: PORT, internalPort: INTERNAL, dir: __dirname, log });
    log('App is running');
    run();
    setTimeout(() => setupTheme().catch((e) => log('theme error:', e.message)), 3000);
    const token = tunnelToken();
    if (token) {
      try { await ensureCloudflared(); runTunnel(token); }
      catch (e) { console.error('[panel] tunnel setup failed:', e.message); }
    } else log('no tunnel token, tunnel disabled');
  } catch (e) {
    console.error('[panel] fatal:', e);
    process.exit(1);
  }
})();
