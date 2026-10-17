const http = require('http');
const https = require('https');
const tls = require('tls');
const { LocalCertificateAuthority } = require('./tls-inspection');
const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');

const APP_DIR = (process.pkg || process.versions.electron) ? path.dirname(process.execPath) : __dirname;
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = process.env.CEOAI_DATA_DIR || path.join(APP_DIR, 'data');
const CACHE_DIR = path.join(DATA_DIR, 'cache');
const PROXY_PORT = Number(process.env.PROXY_PORT || 8080);
const DASHBOARD_PORT = Number(process.env.DASHBOARD_PORT || 8787);
for (const dir of [DATA_DIR, CACHE_DIR]) fs.mkdirSync(dir, { recursive: true });
const localCA = new LocalCertificateAuthority(DATA_DIR);

const files = {
  config: path.join(DATA_DIR, 'config.json'),
  blocked: path.join(DATA_DIR, 'blocked-hosts.json'),
  allowed: path.join(DATA_DIR, 'allowed-hosts.json'),
  rewrites: path.join(DATA_DIR, 'rewrite-rules.json'),
  log: path.join(DATA_DIR, 'proxy.log')
};
function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function writeJson(file, value) {
  const temp = file + '.tmp-' + process.pid + '-' + crypto.randomBytes(4).toString('hex');
  try {
    fs.writeFileSync(temp, JSON.stringify(value, null, 2), { flag: 'wx' });
    fs.renameSync(temp, file);
  } finally {
    try { if (fs.existsSync(temp)) fs.unlinkSync(temp); } catch {}
  }
}
function readArray(file) {
  const value = readJson(file, []);
  return Array.isArray(value) ? value : [];
}
if (!fs.existsSync(files.config)) writeJson(files.config, { cacheEnabled: true, cacheOnly: false, maxObjectBytes: 2000000, filterMode: 'block', autoCleanHours: 24, lastCacheCleanAt: Date.now(), tlsInspectionEnabled: false, tlsInspectionPorts: [443] });
if (!fs.existsSync(files.blocked)) writeJson(files.blocked, []);
if (!fs.existsSync(files.allowed)) writeJson(files.allowed, []);
if (!fs.existsSync(files.rewrites)) writeJson(files.rewrites, []);

const stats = {
  requests: 0, hits: 0, misses: 0, bypass: 0, blocked: 0, missBypass: 0, missWriteErrors: 0,
  bytesIn: 0, bytesOut: 0, offlineMisses: 0, startedAt: new Date().toISOString(), recent: []
};
const clientStats = new Map();
function recordClient(req, kind = 'HTTP') {
  let ip = req.socket && req.socket.remoteAddress || 'unknown';
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  const now = new Date().toISOString();
  const item = clientStats.get(ip) || { ip, requests: 0, httpRequests: 0, connectRequests: 0, firstSeen: now, lastSeen: now, lastType: kind };
  item.requests++;
  if (kind === 'CONNECT') item.connectRequests++; else item.httpRequests++;
  item.lastSeen = now; item.lastType = kind;
  clientStats.set(ip, item);
  // Keep the monitor bounded for long-running portable instances.
  if (clientStats.size > 500) {
    const oldest = [...clientStats.values()].sort((a, b) => Date.parse(a.lastSeen) - Date.parse(b.lastSeen))[0];
    if (oldest) clientStats.delete(oldest.ip);
  }
}
const MAX_LOG_BYTES = 5 * 1024 * 1024;
let logWriteQueue = Promise.resolve();
function log(type, detail = {}) {
  const item = { time: new Date().toISOString(), type, ...detail };
  stats.recent.unshift(item);
  stats.recent = stats.recent.slice(0, 100);
  const line = JSON.stringify(item) + '\n';
  // Serialize rotation and append operations so concurrent requests cannot race log rotation.
  logWriteQueue = logWriteQueue.then(async () => {
    let size = 0;
    try { size = (await fs.promises.stat(files.log)).size; } catch {}
    if (size + Buffer.byteLength(line) > MAX_LOG_BYTES) {
      const previous = files.log + '.1';
      try { await fs.promises.unlink(previous); } catch {}
      try { await fs.promises.rename(files.log, previous); } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
    }
    await fs.promises.appendFile(files.log, line);
  }).catch(() => {});
}
try {
  const stat = fs.statSync(files.log);
  if (stat.size > 0) {
    const fd = fs.openSync(files.log, 'r');
    try {
      const length = Math.min(stat.size, MAX_LOG_BYTES);
      const buffer = Buffer.alloc(length);
      fs.readSync(fd, buffer, 0, length, Math.max(0, stat.size - length));
      stats.recent = buffer.toString('utf8').split(/\r?\n/).filter(Boolean).slice(-100).reverse().flatMap(line => {
        try { return [JSON.parse(line)]; } catch { return []; }
      });
    } finally { fs.closeSync(fd); }
  }
} catch {}
// Provision the local Root CA once at application startup, even before TLS inspection is enabled.
// The private key stays in the data directory and is never exposed by the dashboard API.
try {
  localCA.ensureCA();
  log('tls-ca-ready', { certificatePath: localCA.certPath });
} catch (error) {
  log('tls-ca-startup-error', { error: error.message });
  console.error('CEOAI Juwet could not initialize the local Root CA: ' + error.message);
}
function normalizeHost(value) {
  return String(value || '').trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
}
function safeDecodeURIComponent(value) {
  try { return decodeURIComponent(value); } catch { return null; }
}
function matchesHost(host, list) {
  const h = normalizeHost(host);
  return list.some(item => {
    const pattern = normalizeHost(item);
    return pattern && (h === pattern || h.endsWith('.' + pattern));
  });
}
function isLoopbackAddress(value) {
  const ip = String(value || '').toLowerCase().replace(/^::ffff:/, '');
  return ip === '::1' || ip === 'localhost' || /^127(?:\.\d{1,3}){3}$/.test(ip);
}
function isLoopbackTarget(value) {
  const host = normalizeHost(value);
  return host === 'localhost' || host.endsWith('.localhost') || host === '::1' ||
    host === '::' || host === '0.0.0.0' || host.startsWith('::ffff:127.') ||
    /^127(?:\.\d{1,3}){3}$/.test(host);
}
function isRemoteLoopbackTarget(req, host) {
  return !isLoopbackAddress(req.socket && req.socket.remoteAddress) && isLoopbackTarget(host);
}
function logBlockedLocalTarget(req, host) {
  log('blocked-local-target', { host, client: req.socket && req.socket.remoteAddress });
}
function filterDecision(host) {
  const config = readJson(files.config, { filterMode: 'block' });
  const blocked = readArray(files.blocked);
  const allowed = readArray(files.allowed);
  if (config.filterMode === 'allow' && !matchesHost(host, allowed)) {
    return { blocked: true, reason: 'not-allowlisted' };
  }
  if (matchesHost(host, blocked)) return { blocked: true, reason: 'blocklist' };
  return { blocked: false };
}
function cacheKey(url) {
  return crypto.createHash('sha256').update(url).digest('hex');
}
function cacheFiles() {
  const files = [];
  function walk(dir) {
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(fullPath);
      else if (entry.isFile() && entry.name.endsWith('.json')) files.push(fullPath);
    }
  }
  walk(CACHE_DIR);
  return files;
}
function cacheFileForUrl(url) {
  const target = new URL(url);
  // Keep one human-readable folder per hostname, with a hash per URL inside it.
  const hostname = normalizeHost(target.hostname).replace(/[^a-z0-9._-]/g, '_') || 'unknown-host';
  const hostDir = path.join(CACHE_DIR, hostname);
  fs.mkdirSync(hostDir, { recursive: true });
  return path.join(hostDir, cacheKey(target.href) + '.json');
}
function jsonResponse(res, status, value) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(value));
}
function serveAsset(res, name, contentType) {
  try {
    const data = fs.readFileSync(path.join(PUBLIC_DIR, name));
    res.writeHead(200, { 'content-type': contentType, 'content-length': data.length, 'cache-control': 'no-store' });
    res.end(data);
  } catch (error) {
    log('asset-read-error', { name, error: error.message });
    res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
    res.end('Dashboard asset unavailable: ' + name);
  }
}
function cleanExpiredCache() {
  let removed = 0;
  for (const file of cacheFiles()) {
    let expired = false;
    try {
      const obj = JSON.parse(fs.readFileSync(file, 'utf8'));
      const expiresAt = Number(obj && obj.expiresAt);
      expired = !Number.isFinite(expiresAt) || expiresAt <= Date.now() || typeof obj.body !== 'string' || !Number.isInteger(obj.statusCode);
    } catch { expired = true; }
    if (expired) try { fs.unlinkSync(file); removed++; } catch {}
  }
  return removed;
}
function purgeAllCache() {
  let removed = 0;
  for (const file of cacheFiles()) {
    try { fs.unlinkSync(file); removed++; } catch {}
  }
  return removed;
}
const MAX_CACHE_TOTAL_BYTES = 512 * 1024 * 1024;
function storeCacheObject(targetFile, value) {
  // writeJson pretty-prints JSON, so capacity accounting must use the exact on-disk representation.
  const serialized = JSON.stringify(value, null, 2);
  const newBytes = Buffer.byteLength(serialized);
  if (newBytes > MAX_CACHE_TOTAL_BYTES) return false;
  const entries = [];
  let totalBytes = 0, targetBytes = 0;
  for (const file of cacheFiles()) {
    try {
      const stat = fs.statSync(file);
      totalBytes += stat.size;
      if (file === targetFile) targetBytes = stat.size;
      else entries.push({ file, size: stat.size, mtime: stat.mtimeMs });
    } catch {}
  }
  totalBytes -= targetBytes;
  entries.sort((a, b) => a.mtime - b.mtime);
  while (totalBytes + newBytes > MAX_CACHE_TOTAL_BYTES && entries.length) {
    const oldest = entries.shift();
    try { fs.unlinkSync(oldest.file); totalBytes -= oldest.size; } catch {}
  }
  if (totalBytes + newBytes > MAX_CACHE_TOTAL_BYTES) return false;
  writeJson(targetFile, value);
  return true;
}
function getCacheSummary() {
  let objects = 0, bytes = 0, expired = 0;
  for (const file of cacheFiles()) {
    try {
      const stat = fs.statSync(file);
      const obj = JSON.parse(fs.readFileSync(file, 'utf8'));
      objects++;
      bytes += stat.size;
      if (Number(obj.expiresAt || 0) <= Date.now()) expired++;
    } catch {}
  }
  return { objects, bytes, expired };
}
function handleApi(req, res, pathname) {
  if (pathname === '/api/status' && req.method === 'GET') {
    const cache = getCacheSummary();
    return jsonResponse(res, 200, {
      ok: true, name: 'CEOAI Juwet', version: '0.2.0',
      proxyPort: PROXY_PORT, dashboardPort: DASHBOARD_PORT,
      httpsMode: readJson(files.config, {}).tlsInspectionEnabled === true ? 'TLS inspection enabled (local CA required)' : 'CONNECT tunnel (TLS payload not inspected)',
      stats, cache, config: readJson(files.config, {})
    });
  }
  if (pathname === '/api/tls/status' && req.method === 'GET') {
    const config = readJson(files.config, {});
    let ca = { available: false };
    try { ca = localCA.getCertificateInfo(); } catch (error) { ca = { available: false, error: error.message }; }
    return jsonResponse(res, 200, { enabled: config.tlsInspectionEnabled === true, ca, warning: 'Gunakan hanya pada perangkat dan jaringan yang Anda berwenang kelola. CA lokal tidak boleh dipasang pada perangkat pihak lain tanpa izin.' });
  }
  if (pathname === '/api/tls/ca.pem' && req.method === 'GET') {
    try {
      const pem = localCA.getCertificatePem();
      res.writeHead(200, { 'content-type': 'application/x-pem-file', 'content-disposition': 'attachment; filename="CEOAI-Juwet-Inspection-CA.pem"', 'cache-control': 'no-store' });
      return res.end(pem);
    } catch (error) { return jsonResponse(res, 500, { ok: false, error: 'CA tidak dapat dibuat: ' + error.message }); }
  }
  if (pathname === '/api/clients' && req.method === 'GET') {
    const clients = [...clientStats.values()].sort((a, b) => Date.parse(b.lastSeen) - Date.parse(a.lastSeen));
    return jsonResponse(res, 200, { clients, trackedClients: clients.length, limit: 500 });
  }
  if (pathname === '/api/config' && req.method === 'GET') {
    return jsonResponse(res, 200, readJson(files.config, {}));
  }
  if (pathname === '/api/config' && req.method === 'POST') {
    let body = '';
    let tooLarge = false;
    req.on('data', chunk => {
      if (tooLarge) return;
      body += chunk;
      if (Buffer.byteLength(body) > 10000) {
        tooLarge = true;
        jsonResponse(res, 413, { ok: false, error: 'Body konfigurasi terlalu besar (maksimum 10 KB)' });
        req.resume();
      }
    });
    req.on('end', () => {
      if (tooLarge) return;
      try {
        const input = JSON.parse(body);
        const old = readJson(files.config, {});
        const next = {
          ...old,
          cacheEnabled: typeof input.cacheEnabled === 'boolean' ? input.cacheEnabled : old.cacheEnabled !== false,
          cacheOnly: typeof input.cacheOnly === 'boolean' ? input.cacheOnly : old.cacheOnly === true,
          autoCleanHours: (() => {
            const raw = input.autoCleanHours !== undefined ? Number(input.autoCleanHours) : Number(old.autoCleanHours === undefined ? 24 : old.autoCleanHours);
            return Number.isFinite(raw) ? Math.max(0, Math.min(168, raw)) : 24;
          })(),
          lastCacheCleanAt: Number.isFinite(Number(old.lastCacheCleanAt)) && Number(old.lastCacheCleanAt) > 0 ? Number(old.lastCacheCleanAt) : Date.now(),
          maxObjectBytes: (() => {
            const raw = input.maxObjectBytes !== undefined ? Number(input.maxObjectBytes) : Number(old.maxObjectBytes === undefined ? 2000000 : old.maxObjectBytes);
            return Number.isFinite(raw) ? Math.max(1024, Math.min(20000000, raw)) : 2000000;
          })(),
          filterMode: input.filterMode === 'allow' ? 'allow' : 'block',
          tlsInspectionEnabled: typeof input.tlsInspectionEnabled === 'boolean' ? input.tlsInspectionEnabled : old.tlsInspectionEnabled === true,
          tlsInspectionPorts: Array.isArray(input.tlsInspectionPorts) ? [...new Set(input.tlsInspectionPorts.map(Number).filter(port => Number.isInteger(port) && port >= 1 && port <= 65535))].slice(0, 32) : (Array.isArray(old.tlsInspectionPorts) ? old.tlsInspectionPorts : [443])
        };
        if (next.tlsInspectionEnabled === true) localCA.ensureCA();
        writeJson(files.config, next);
        log('config-updated', { cacheEnabled: next.cacheEnabled, filterMode: next.filterMode, tlsInspectionEnabled: next.tlsInspectionEnabled });
        jsonResponse(res, 200, { ok: true, config: next });
      } catch (error) {
        const invalidJson = error instanceof SyntaxError;
        jsonResponse(res, invalidJson ? 400 : 500, { ok: false, error: invalidJson ? 'JSON tidak valid' : 'Konfigurasi gagal disimpan: ' + error.message });
      }
    });
    return;
  }
  if (pathname === '/api/blocked' && req.method === 'GET') return jsonResponse(res, 200, readArray(files.blocked));
  if (pathname === '/api/allowed' && req.method === 'GET') return jsonResponse(res, 200, readArray(files.allowed));
  if ((pathname === '/api/blocked' || pathname === '/api/allowed') && req.method === 'POST') {
    const dest = pathname === '/api/blocked' ? files.blocked : files.allowed;
    const kind = pathname === '/api/blocked' ? 'blocked' : 'allowed';
    let body = '';
    let tooLarge = false;
    req.on('data', chunk => {
      if (tooLarge) return;
      body += chunk;
      if (Buffer.byteLength(body) > 10000) {
        tooLarge = true;
        jsonResponse(res, 413, { ok: false, error: 'Body filter terlalu besar (maksimum 10 KB)' });
        req.resume();
      }
    });
    req.on('end', () => {
      if (tooLarge) return;
      try {
        const host = normalizeHost(JSON.parse(body).host);
        if (!host || host.length > 253 || /[^a-z0-9.:[\]-]/i.test(host)) return jsonResponse(res, 400, { ok: false, error: 'Domain tidak valid' });
        const list = readArray(dest);
        if (!list.includes(host)) list.push(host);
        writeJson(dest, list);
        log(kind + '-filter-add', { host });
        jsonResponse(res, 200, { ok: true, hosts: list });
      } catch { jsonResponse(res, 400, { ok: false, error: 'JSON tidak valid' }); }
    });
    return;
  }
  if (pathname.startsWith('/api/blocked/') && req.method === 'DELETE') {
    const decoded = safeDecodeURIComponent(pathname.slice('/api/blocked/'.length));
    if (decoded === null) return jsonResponse(res, 400, { ok: false, error: 'Domain encoding tidak valid' });
    const host = normalizeHost(decoded);
    const list = readArray(files.blocked).filter(item => item !== host);
    writeJson(files.blocked, list); log('block-filter-remove', { host });
    return jsonResponse(res, 200, { ok: true, hosts: list });
  }
  if (pathname.startsWith('/api/allowed/') && req.method === 'DELETE') {
    const decoded = safeDecodeURIComponent(pathname.slice('/api/allowed/'.length));
    if (decoded === null) return jsonResponse(res, 400, { ok: false, error: 'Domain encoding tidak valid' });
    const host = normalizeHost(decoded);
    const list = readArray(files.allowed).filter(item => item !== host);
    writeJson(files.allowed, list); log('allow-filter-remove', { host });
    return jsonResponse(res, 200, { ok: true, hosts: list });
  }
  if (pathname === '/api/rewrite' && req.method === 'GET') return jsonResponse(res, 200, readArray(files.rewrites));
  if (pathname === '/api/rewrite' && req.method === 'POST') {
    let body = '';
    let tooLarge = false;
    req.on('data', chunk => {
      if (tooLarge) return;
      body += chunk;
      if (Buffer.byteLength(body) > 20000) {
        tooLarge = true;
        jsonResponse(res, 413, { ok: false, error: 'Body rewrite terlalu besar (maksimum 20 KB)' });
        req.resume();
      }
    });
    req.on('end', () => {
      if (tooLarge) return;
      try {
        const input = JSON.parse(body);
        const from = String(input.from || '');
        const to = String(input.to || '');
        if (!from || from.length > 500 || to.length > 2000 || from.includes('\n') || to.includes('\n')) {
          return jsonResponse(res, 400, { ok: false, error: 'Aturan rewrite tidak valid' });
        }
        const list = readArray(files.rewrites);
        const rule = { id: crypto.randomBytes(6).toString('hex'), from, to, enabled: true };
        list.push(rule); writeJson(files.rewrites, list);
        log('rewrite-add', { id: rule.id, from });
        jsonResponse(res, 200, { ok: true, rules: list });
      } catch { jsonResponse(res, 400, { ok: false, error: 'JSON tidak valid' }); }
    });
    return;
  }
  if (pathname.startsWith('/api/rewrite/') && req.method === 'DELETE') {
    const id = pathname.slice('/api/rewrite/'.length);
    const list = readArray(files.rewrites).filter(rule => rule.id !== id);
    writeJson(files.rewrites, list); log('rewrite-remove', { id });
    return jsonResponse(res, 200, { ok: true, rules: list });
  }
  if (pathname === '/api/cache' && req.method === 'GET') return jsonResponse(res, 200, getCacheSummary());
  if ((pathname === '/api/cache/purge' || pathname === '/api/cache/clean') && req.method === 'POST') {
    const expiredOnly = pathname.endsWith('/clean');
    const removed = expiredOnly ? cleanExpiredCache() : purgeAllCache();
    log(expiredOnly ? 'cache-clean-expired' : 'cache-purge', { removed });
    return jsonResponse(res, 200, { ok: true, removed, cache: getCacheSummary() });
  }
  if (pathname === '/api/logs' && req.method === 'GET') {
    return jsonResponse(res, 200, stats.recent.slice(0, 100));
  }
  return false;
}
const dashboard = http.createServer((req, res) => {
  try {
    // Bind-to-loopback alone does not stop browser DNS-rebinding attacks; validate Host too.
    const rawHost = String(req.headers.host || '').toLowerCase();
    const hostName = rawHost.startsWith('[') ? rawHost.slice(0, rawHost.indexOf(']') + 1) : rawHost.split(':')[0];
    if (!['127.0.0.1', 'localhost', '[::1]'].includes(hostName)) {
      res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
      res.end('Dashboard accepts requests only for localhost.');
      return;
    }
    const url = new URL(req.url, 'http://127.0.0.1:' + DASHBOARD_PORT);
    if (url.pathname.startsWith('/api/')) {
      const handled = handleApi(req, res, url.pathname);
      if (handled !== false) return;
      return jsonResponse(res, 404, { ok: false, error: 'API route not found' });
    }
    if (url.pathname === '/logo.svg') return serveAsset(res, 'logo.svg', 'image/svg+xml');
    if (url.pathname === '/' || url.pathname === '/index.html') return serveAsset(res, 'index.html', 'text/html; charset=utf-8');
    res.writeHead(404); res.end('Not found');
  } catch (error) {
    log('dashboard-request-error', { error: error.message });
    if (res.headersSent) return res.destroy();
    return jsonResponse(res, 500, { ok: false, error: 'Dashboard gagal memproses permintaan.' });
  }
});
function handleListenError(serverName, port, error) {
  const detail = { server: serverName, port, code: error.code || 'UNKNOWN', error: error.message };
  console.error('CEOAI Juwet failed to bind ' + serverName + ' port ' + port + ': ' + error.message);
  log('server-listen-error', detail);
  if (process.listenerCount('ceoai-server-error') > 0) {
    process.emit('ceoai-server-error', detail);
  } else {
    // A standalone process must not remain half-started with only one listener alive.
    process.exit(1);
  }
}
dashboard.on('error', error => handleListenError('dashboard', DASHBOARD_PORT, error));
dashboard.listen(DASHBOARD_PORT, '127.0.0.1', () => console.log('CEOAI Juwet dashboard http://127.0.0.1:' + DASHBOARD_PORT));
const cleanerTimer = setInterval(() => {
  const config = readJson(files.config, {});
  const rawHours = Number(config.autoCleanHours);
  const hours = Number.isFinite(rawHours) ? Math.max(0, Math.min(168, rawHours)) : 24;
  const rawLast = Number(config.lastCacheCleanAt);
  const last = Number.isFinite(rawLast) && rawLast > 0 ? rawLast : Date.now();
  if (hours > 0 && Date.now() - last >= hours * 3600000) {
    const removed = cleanExpiredCache();
    config.lastCacheCleanAt = Date.now();
    writeJson(files.config, config);
    log('cache-auto-clean', { removed, periodHours: hours });
  }
}, 60000);
cleanerTimer.unref();

function applyRewrites(urlText) {
  let result = urlText;
  for (const rule of readArray(files.rewrites)) {
    if (rule.enabled !== false && rule.from) result = result.split(rule.from).join(rule.to);
  }
  return result;
}
function cleanHeaders(headers) {
  const result = { ...headers };
  const connectionTokens = String(headers.connection || '')
    .split(',')
    .map(value => value.trim().toLowerCase())
    .filter(value => /^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(value));
  for (const key of new Set([
    'proxy-connection', 'proxy-authorization', 'connection', 'keep-alive',
    'transfer-encoding', 'te', 'trailer', 'upgrade', ...connectionTokens
  ])) delete result[key];
  return result;
}
function proxyRequestImpl(req, res) {
  stats.requests++;
  recordClient(req, 'HTTP');
  let original;
  try {
    original = req.socket.ceoaiInterceptHost ? new URL('https://' + req.socket.ceoaiInterceptHost + (String(req.url || '').startsWith('/') ? req.url : '/' + req.url)) : new URL(req.url);
    if (!original.hostname || !['http:', 'https:'].includes(original.protocol)) throw new Error('unsupported url');
  } catch {
    res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('Proxy expects an absolute HTTP/HTTPS URL');
    log('bad-proxy-request', { url: req.url });
    return;
  }
  let target;
  try { target = new URL(applyRewrites(original.href)); } catch {
    res.writeHead(400); res.end('Rewrite produced an invalid URL'); return;
  }
  if (!['http:', 'https:'].includes(target.protocol)) { res.writeHead(400); res.end('Rewrite protocol is not supported'); return; }
  target.username = ''; target.password = '';
  const host = normalizeHost(target.hostname);
  if (isRemoteLoopbackTarget(req, host)) {
    stats.blocked++;
    logBlockedLocalTarget(req, host);
    res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8', 'x-ceoai-filter': 'local-target-blocked' });
    res.end('Access to loopback services through a remote proxy client is blocked.');
    return;
  }
  const decision = filterDecision(host);
  if (decision.blocked) {
    stats.blocked++; log('blocked', { host, reason: decision.reason, url: target.origin + target.pathname });
    res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8', 'x-ceoai-filter': decision.reason });
    res.end('Blocked by CEOAI Juwet URL filter');
    return;
  }

  const config = readJson(files.config, { cacheEnabled: true, maxObjectBytes: 2000000 });
  const safeMethod = req.method === 'GET';
  const hasCredentials = Boolean(req.headers.authorization || req.headers.cookie);
  const requestCacheControl = String(req.headers['cache-control'] || '').toLowerCase();
  const requestForcesRefresh = /(?:^|,)[ \t]*(?:no-cache(?:[ \t]*=[^,]*)?|no-store|max-age[ \t]*=[ \t]*0)(?:[ \t]*(?:,|$))/.test(requestCacheControl) ||
    String(req.headers.pragma || '').toLowerCase().includes('no-cache');
  // Browser revalidation headers (If-None-Match / If-Modified-Since) may still use a fresh local object.
  // Range and write-precondition headers remain ineligible for a full-object cache response.
  const hasRangeOrConditional = Boolean(req.headers.range || req.headers['if-range'] || req.headers['if-match'] || req.headers['if-unmodified-since']);
  const httpsAuthorizedForCache = target.protocol !== 'https:' || req.socket.ceoaiTlsIntercepted === true;
  const canCache = safeMethod && !hasCredentials && !requestForcesRefresh && !hasRangeOrConditional && config.cacheEnabled !== false && httpsAuthorizedForCache;
  // Do not create a domain folder for requests that are ineligible for caching (for example plain HTTPS CONNECT traffic).
  const cacheFile = canCache ? cacheFileForUrl(target.href) : null;
  if (canCache) {
    try {
      const cached = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
      const forbiddenCachedHeaders = new Set([
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
        'te', 'trailer', 'transfer-encoding', 'upgrade', 'content-length', 'set-cookie'
      ]);
      const validHeaders = cached && cached.headers && typeof cached.headers === 'object' && !Array.isArray(cached.headers) &&
        Object.entries(cached.headers).every(([name, value]) =>
          /^[!#$%&'*+.^_\`|~0-9A-Za-z-]+$/.test(name) &&
          !forbiddenCachedHeaders.has(name.toLowerCase()) &&
          (typeof value === 'string' || (Array.isArray(value) && value.every(item => typeof item === 'string'))) &&
          !/[\r\n]/.test(Array.isArray(value) ? value.join('') : value));
      const validBody = cached && typeof cached.body === 'string' &&
        /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(cached.body);
      const valid = cached && cached.statusCode === 200 && Number.isFinite(Number(cached.expiresAt)) &&
        Number(cached.expiresAt) > Date.now() && validHeaders && validBody;
      if (valid) {
        const body = Buffer.from(cached.body, 'base64');
        stats.hits++; stats.bytesOut += body.length;
        log('HIT', { host, url: target.origin + target.pathname, statusCode: cached.statusCode, bytes: body.length });
        res.writeHead(cached.statusCode, { ...cached.headers, 'x-ceoai-cache': 'HIT', 'content-length': body.length });
        res.end(body); return;
      }
      try { fs.unlinkSync(cacheFile); } catch {}
    } catch {
      try { fs.unlinkSync(cacheFile); } catch {}
    }
    stats.misses++;
  } else stats.bypass++;

  if (config.cacheOnly === true) {
    stats.offlineMisses++;
    log('OFFLINE-MISS', { host, url: target.origin + target.pathname });
    res.writeHead(504, { 'content-type': 'text/plain; charset=utf-8', 'x-ceoai-cache': 'OFFLINE-MISS' });
    res.end('Offline cache-only mode: this URL is not available in cache.');
    return;
  }

  const transport = target.protocol === 'https:' ? https : http;
  const headers = { ...cleanHeaders(req.headers), host: target.host };
  // Insecure upstream TLS is permitted only for explicitly opted-in local test targets.
  // This does not affect client-side Schannel checks of certificates generated by TLS interception.
  const allowInsecureLocalUpstreamTls = target.protocol === 'https:' &&
    process.env.CEOAI_TLS_TEST_ALLOW_INVALID_UPSTREAM === '1' && isLoopbackTarget(host);
  // A rewrite that changes origin must never forward origin-bound credentials.
  if (original.origin !== target.origin) {
    delete headers.authorization;
    delete headers.cookie;
  }
  const upstream = transport.request(target, {
    method: req.method,
    headers,
    timeout: 20000,
    // Default remains strict. Never disable certificate validation for public upstreams.
    ...(target.protocol === 'https:' ? { rejectUnauthorized: !allowInsecureLocalUpstreamTls } : {})
  }, upstreamRes => {
    const responseHeaders = cleanHeaders(upstreamRes.headers);
    const rawMaxBytes = Number(config.maxObjectBytes);
    const maxBytes = Number.isFinite(rawMaxBytes) ? Math.max(1024, Math.min(20000000, rawMaxBytes)) : 2000000;
    const upstreamCacheControl = String(upstreamRes.headers['cache-control'] || '').toLowerCase();
    const upstreamDirectives = upstreamCacheControl.split(',').map(value => value.trim().split('=')[0].trim());
    const cachePolicyReason = upstreamRes.headers['set-cookie'] ? 'set-cookie' :
      upstreamRes.headers.vary ? 'vary' :
      upstreamDirectives.includes('no-store') ? 'cache-control-no-store' :
      upstreamDirectives.includes('private') ? 'cache-control-private' : null;
    const cacheHeadersAllowed = canCache &&
      upstreamRes.statusCode === 200 &&
      cachePolicyReason === null;
    let size = 0, tooLarge = false;
    const chunks = [];
    upstreamRes.on('data', chunk => {
      stats.bytesIn += chunk.length;
      size += chunk.length;
      if (cacheHeadersAllowed && !tooLarge) {
        if (size <= maxBytes) chunks.push(chunk);
        else { tooLarge = true; chunks.length = 0; }
      }
    });
    upstreamRes.on('end', () => {
      const cacheControl = String(upstreamRes.headers['cache-control'] || '');
      const directives = cacheControl.toLowerCase().split(',').map(value => value.trim());
      const match = cacheControl.match(/(?:^|,)[ \t]*max-age[ \t]*=[ \t]*([0-9]+)/i);
      const expiresAtHeader = Date.parse(upstreamRes.headers.expires || '');
      const expiresTtl = Number.isFinite(expiresAtHeader) ? Math.floor((expiresAtHeader - Date.now()) / 1000) : 0;
      const requestedTtl = match ? Number(match[1]) : expiresTtl;
      // A small heuristic lifetime is allowed for public static images when the origin supplies
      // no freshness metadata. Never override explicit no-cache/no-store/private/Vary policies.
      const isStaticImage = /^image\/(?:avif|gif|jpeg|png|svg\+xml|webp)(?:;|$)/i.test(String(upstreamRes.headers['content-type'] || ''));
      const heuristicTtl = !match && expiresTtl <= 0 && isStaticImage ? 60 : 0;
      const effectiveTtl = requestedTtl > 0 ? requestedTtl : heuristicTtl;
      const explicitlyFresh = effectiveTtl > 0 && (Boolean(match) || expiresTtl > 0 || directives.includes('public') || heuristicTtl > 0);
      const responsePragma = String(upstreamRes.headers.pragma || '').toLowerCase();
      const hasNoCacheDirective = directives.some(value => /^no-cache(?:[ \t]*=|$)/.test(value));
      const mayStore = explicitlyFresh &&
        !directives.some(value => /^private(?:[ \t]*=|$)/.test(value)) &&
        !directives.some(value => /^no-store(?:[ \t]*=|$)/.test(value)) &&
        !hasNoCacheDirective &&
        !responsePragma.split(',').some(value => value.trim() === 'no-cache') &&
        !directives.includes('must-revalidate') &&
        effectiveTtl > 0;
      const ttl = Math.min(3600, Math.max(1, effectiveTtl));
      // Storage is allowed only for eligible HTTP requests or explicitly intercepted HTTPS.
      if (canCache && cacheHeadersAllowed && !tooLarge && size <= maxBytes && mayStore) {
        const body = Buffer.concat(chunks);
        const storedHeaders = cleanHeaders(upstreamRes.headers);
        delete storedHeaders['set-cookie'];
        delete storedHeaders['transfer-encoding'];
        delete storedHeaders['connection'];
        delete storedHeaders['keep-alive'];
        delete storedHeaders['content-length'];
        try {
          const stored = storeCacheObject(cacheFile, {
            statusCode: upstreamRes.statusCode, headers: storedHeaders,
            body: body.toString('base64'), expiresAt: Date.now() + ttl * 1000
          });
          if (!stored) {
            stats.missBypass++;
            log('MISS_BYPASS', { host, url: target.origin + target.pathname, reason: 'cache-capacity', maxCacheBytes: MAX_CACHE_TOTAL_BYTES });
          } else {
            log('MISS_STORED', { host, url: target.origin + target.pathname, statusCode: upstreamRes.statusCode, bytes: size });
          }
        } catch (error) {
          stats.missWriteErrors++;
          log('MISS_WRITE_ERROR', { host, url: target.origin + target.pathname, code: error.code || 'CACHE_WRITE_FAILED', error: error.message });
        }
      } else if (canCache && cachePolicyReason) {
        stats.missBypass++;
        log('MISS_BYPASS', { host, url: target.origin + target.pathname, reason: cachePolicyReason, statusCode: upstreamRes.statusCode });
      } else {
        log(canCache ? 'MISS_NOT_STORED' : 'BYPASS', { host, url: target.origin + target.pathname, statusCode: upstreamRes.statusCode, bytes: size, reason: tooLarge ? 'object-too-large' : 'cache-policy-or-freshness' });
      }
      // MISS_WRITE_ERROR is surfaced in /api/status stats + recent events. The response is streamed,
      // so a disk error discovered at end-of-stream cannot safely rewrite an already-sent header.
    });
    const responseCacheStatus = !canCache ? 'BYPASS' : (cachePolicyReason ? 'MISS_BYPASS' : 'MISS');
    res.writeHead(upstreamRes.statusCode || 502, { ...responseHeaders, 'x-ceoai-cache': responseCacheStatus });
    upstreamRes.pipe(res);
    res.on('finish', () => { stats.bytesOut += size; });
  });
  upstream.setTimeout(20000, () => upstream.destroy(new Error('upstream timeout')));
  upstream.on('error', error => {
    log('upstream-error', { host, error: error.message });
    if (!res.headersSent) { res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' }); res.end('Upstream error: ' + error.message); }
    else res.destroy();
  });
  req.pipe(upstream);
}
function proxyRequest(req, res) {
  try { return proxyRequestImpl(req, res); }
  catch (error) {
    log('proxy-handler-error', { error: error.message, url: String(req.url || '').slice(0, 300) });
    if (res.headersSent) return res.destroy();
    res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8', 'connection': 'close' });
    res.end('CEOAI Juwet failed to process this request.');
  }
}
const proxy = http.createServer(proxyRequest);
const interceptedHttp = http.createServer(proxyRequest);
proxy.on('connect', (req, client, head) => {
  stats.requests++;
  recordClient(req, 'CONNECT');

  // Parse CONNECT authority safely, including IPv6 literals and explicit ports.
  let host = '';
  let port = 443;
  try {
    const authority = new URL('http://' + String(req.url || ''));
    host = normalizeHost(authority.hostname);
    if (authority.username || authority.password || authority.pathname !== '/' || authority.search || authority.hash) {
      throw new Error('invalid CONNECT authority');
    }
    if (authority.port) port = Number(authority.port);
    if (!host || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('invalid CONNECT host or port');
  } catch {
    log('bad-connect-request', { authority: String(req.url || '').slice(0, 200) });
    client.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
    return;
  }

  if (isRemoteLoopbackTarget(req, host)) {
    stats.blocked++;
    logBlockedLocalTarget(req, host);
    client.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
    return;
  }
  const decision = filterDecision(host);
  if (readJson(files.config, {}).cacheOnly === true) {
    stats.offlineMisses++;
    log('OFFLINE-CONNECT-MISS', { host, port });
    client.end('HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n'); return;
  }
  if (decision.blocked) {
    stats.blocked++; log('blocked-connect', { host, reason: decision.reason });
    client.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return;
  }

  const config = readJson(files.config, {});
  if (config.tlsInspectionEnabled === true && (Array.isArray(config.tlsInspectionPorts) ? config.tlsInspectionPorts : [443]).includes(port)) {
    // Explicit opt-in TLS interception. Only the local CA certificate is exported; its private key stays in the app data folder.
    let context;
    try { context = localCA.getContext(host); }
    catch (error) {
      log('tls-inspection-cert-error', { host, error: error.message });
      client.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n'); return;
    }
    client.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: CEOAI-Juwet\r\n\r\n');
    if (head && head.length) client.unshift(head);
    const secure = new tls.TLSSocket(client, { isServer: true, secureContext: context });
    secure.ceoaiInterceptHost = (host.includes(':') ? '[' + host + ']' : host) + (port === 443 ? '' : ':' + port);
    secure.ceoaiTlsIntercepted = true;
    secure.on('error', error => {
      // Never silently downgrade a failed TLS interception to a raw TCP tunnel.
      log('HTTPS_DECRYPTION_FAILED', {
        host, port, phase: 'client-tls', code: error.code || 'TLS_HANDSHAKE_FAILED', error: error.message
      });
    });
    secure.on('secure', () => {
      const sniHost = normalizeHost(secure.servername || '');
      if (sniHost && sniHost !== host) {
        log('HTTPS_DECRYPTION_FAILED', { host, port, phase: 'sni-mismatch', sniHost, error: 'Client SNI does not match CONNECT authority' });
        secure.destroy(new Error('TLS SNI does not match CONNECT authority'));
        return;
      }
      log('TLS-INSPECTED', { host, port, sniHost: sniHost || null });
      interceptedHttp.emit('connection', secure);
    });
    client.on('close', () => secure.destroy());
    return;
  }

  // Plain CONNECT is an end-to-end TCP tunnel: never inspect or cache its encrypted payload.
  stats.bypass++;
  let tunnelEstablished = false;
  const upstream = net.connect({ port, host });
  const timeout = setTimeout(() => {
    if (!tunnelEstablished) {
      log('connect-timeout', { host, port, timeoutMs: 20000 });
      if (!client.destroyed) client.end('HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n');
      upstream.destroy();
    }
  }, 20000);
  upstream.once('connect', () => {
    tunnelEstablished = true;
    clearTimeout(timeout);
    if (client.destroyed) return upstream.destroy();
    client.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: CEOAI-Juwet\r\n\r\n');
    if (head && head.length) upstream.write(head);
    upstream.pipe(client); client.pipe(upstream);
    log('HTTPS-TUNNEL', { host, port });
  });
  upstream.on('error', error => {
    clearTimeout(timeout);
    log('connect-error', { host, port, error: error.message });
    if (!client.destroyed) client.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
  });
  upstream.on('close', () => clearTimeout(timeout));
  client.on('error', () => upstream.destroy());
  client.on('close', () => upstream.destroy());
});
proxy.on('error', error => handleListenError('proxy', PROXY_PORT, error));
proxy.listen(PROXY_PORT, '0.0.0.0', () => console.log('CEOAI Juwet proxy listening on ' + PROXY_PORT));
if (process.pkg && process.platform === 'win32' && process.env.CEOAI_OPEN_BROWSER !== '0') {
  const openTimer = setTimeout(() => {
    execFile('cmd.exe', ['/c', 'start', '', 'http://127.0.0.1:' + DASHBOARD_PORT], { windowsHide: true }, error => {
      if (error) log('dashboard-browser-open-error', { error: error.message });
    });
  }, 900);
  openTimer.unref();
}
function stop() { proxy.close(); dashboard.close(); process.exit(0); }
process.on('SIGINT', stop); process.on('SIGTERM', stop);
