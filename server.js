const http = require('http');
const https = require('https');
const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const APP_DIR = process.pkg ? path.dirname(process.execPath) : __dirname;
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = process.env.CEOAI_DATA_DIR || path.join(APP_DIR, 'data');
const CACHE_DIR = path.join(DATA_DIR, 'cache');
const PROXY_PORT = Number(process.env.PROXY_PORT || 8080);
const DASHBOARD_PORT = Number(process.env.DASHBOARD_PORT || 8787);
for (const dir of [DATA_DIR, CACHE_DIR]) fs.mkdirSync(dir, { recursive: true });

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
  fs.writeFileSync(file, JSON.stringify(value, null, 2));
}
if (!fs.existsSync(files.config)) writeJson(files.config, { cacheEnabled: true, maxObjectBytes: 2000000, filterMode: 'block' });
if (!fs.existsSync(files.blocked)) writeJson(files.blocked, []);
if (!fs.existsSync(files.allowed)) writeJson(files.allowed, []);
if (!fs.existsSync(files.rewrites)) writeJson(files.rewrites, []);

const stats = {
  requests: 0, hits: 0, misses: 0, bypass: 0, blocked: 0,
  bytesIn: 0, bytesOut: 0, startedAt: new Date().toISOString(), recent: []
};
function log(type, detail = {}) {
  const item = { time: new Date().toISOString(), type, ...detail };
  stats.recent.unshift(item);
  stats.recent = stats.recent.slice(0, 100);
  fs.appendFile(files.log, JSON.stringify(item) + '\n', () => {});
}
function normalizeHost(value) {
  return String(value || '').trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
}
function matchesHost(host, list) {
  const h = normalizeHost(host);
  return list.some(item => {
    const pattern = normalizeHost(item);
    return pattern && (h === pattern || h.endsWith('.' + pattern));
  });
}
function filterDecision(host) {
  const config = readJson(files.config, { filterMode: 'block' });
  const blocked = readJson(files.blocked, []);
  const allowed = readJson(files.allowed, []);
  if (config.filterMode === 'allow' && allowed.length && !matchesHost(host, allowed)) {
    return { blocked: true, reason: 'not-allowlisted' };
  }
  if (matchesHost(host, blocked)) return { blocked: true, reason: 'blocklist' };
  return { blocked: false };
}
function cacheKey(url) {
  return crypto.createHash('sha256').update(url).digest('hex');
}
function jsonResponse(res, status, value) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(value));
}
function getCacheSummary() {
  let objects = 0, bytes = 0, expired = 0;
  for (const name of fs.readdirSync(CACHE_DIR)) {
    if (!name.endsWith('.json')) continue;
    try {
      const file = path.join(CACHE_DIR, name);
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
      httpsMode: 'CONNECT tunnel (TLS payload not inspected)',
      stats, cache, config: readJson(files.config, {})
    });
  }
  if (pathname === '/api/config' && req.method === 'GET') {
    return jsonResponse(res, 200, readJson(files.config, {}));
  }
  if (pathname === '/api/config' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 10000) req.destroy(); });
    req.on('end', () => {
      try {
        const input = JSON.parse(body);
        const old = readJson(files.config, {});
        const next = {
          ...old,
          cacheEnabled: typeof input.cacheEnabled === 'boolean' ? input.cacheEnabled : old.cacheEnabled !== false,
          maxObjectBytes: Math.max(1024, Math.min(20000000, Number(input.maxObjectBytes || old.maxObjectBytes || 2000000))),
          filterMode: input.filterMode === 'allow' ? 'allow' : 'block'
        };
        writeJson(files.config, next);
        log('config-updated', { cacheEnabled: next.cacheEnabled, filterMode: next.filterMode });
        jsonResponse(res, 200, { ok: true, config: next });
      } catch { jsonResponse(res, 400, { ok: false, error: 'JSON tidak valid' }); }
    });
    return;
  }
  if (pathname === '/api/blocked' && req.method === 'GET') return jsonResponse(res, 200, readJson(files.blocked, []));
  if (pathname === '/api/allowed' && req.method === 'GET') return jsonResponse(res, 200, readJson(files.allowed, []));
  if ((pathname === '/api/blocked' || pathname === '/api/allowed') && req.method === 'POST') {
    const dest = pathname === '/api/blocked' ? files.blocked : files.allowed;
    const kind = pathname === '/api/blocked' ? 'blocked' : 'allowed';
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 10000) req.destroy(); });
    req.on('end', () => {
      try {
        const host = normalizeHost(JSON.parse(body).host);
        if (!host || host.length > 253 || /[^a-z0-9.:[\]-]/i.test(host)) return jsonResponse(res, 400, { ok: false, error: 'Domain tidak valid' });
        const list = readJson(dest, []);
        if (!list.includes(host)) list.push(host);
        writeJson(dest, list);
        log(kind + '-filter-add', { host });
        jsonResponse(res, 200, { ok: true, hosts: list });
      } catch { jsonResponse(res, 400, { ok: false, error: 'JSON tidak valid' }); }
    });
    return;
  }
  if (pathname.startsWith('/api/blocked/') && req.method === 'DELETE') {
    const host = normalizeHost(decodeURIComponent(pathname.slice('/api/blocked/'.length)));
    const list = readJson(files.blocked, []).filter(item => item !== host);
    writeJson(files.blocked, list); log('block-filter-remove', { host });
    return jsonResponse(res, 200, { ok: true, hosts: list });
  }
  if (pathname.startsWith('/api/allowed/') && req.method === 'DELETE') {
    const host = normalizeHost(decodeURIComponent(pathname.slice('/api/allowed/'.length)));
    const list = readJson(files.allowed, []).filter(item => item !== host);
    writeJson(files.allowed, list); log('allow-filter-remove', { host });
    return jsonResponse(res, 200, { ok: true, hosts: list });
  }
  if (pathname === '/api/rewrite' && req.method === 'GET') return jsonResponse(res, 200, readJson(files.rewrites, []));
  if (pathname === '/api/rewrite' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 20000) req.destroy(); });
    req.on('end', () => {
      try {
        const input = JSON.parse(body);
        const from = String(input.from || '');
        const to = String(input.to || '');
        if (!from || from.length > 500 || to.length > 2000 || from.includes('\n') || to.includes('\n')) {
          return jsonResponse(res, 400, { ok: false, error: 'Aturan rewrite tidak valid' });
        }
        const list = readJson(files.rewrites, []);
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
    const list = readJson(files.rewrites, []).filter(rule => rule.id !== id);
    writeJson(files.rewrites, list); log('rewrite-remove', { id });
    return jsonResponse(res, 200, { ok: true, rules: list });
  }
  if (pathname === '/api/cache' && req.method === 'GET') return jsonResponse(res, 200, getCacheSummary());
  if ((pathname === '/api/cache/purge' || pathname === '/api/cache/clean') && req.method === 'POST') {
    const expiredOnly = pathname.endsWith('/clean');
    let removed = 0;
    for (const name of fs.readdirSync(CACHE_DIR)) {
      if (!name.endsWith('.json')) continue;
      const file = path.join(CACHE_DIR, name);
      let isExpired = false;
      try { isExpired = Number(JSON.parse(fs.readFileSync(file, 'utf8')).expiresAt || 0) <= Date.now(); } catch { isExpired = true; }
      if (!expiredOnly || isExpired) {
        try { fs.unlinkSync(file); removed++; } catch {}
      }
    }
    log(expiredOnly ? 'cache-clean-expired' : 'cache-purge', { removed });
    return jsonResponse(res, 200, { ok: true, removed, cache: getCacheSummary() });
  }
  if (pathname === '/api/logs' && req.method === 'GET') {
    let rows = [];
    try { rows = fs.readFileSync(files.log, 'utf8').trim().split(/\r?\n/).filter(Boolean).slice(-200).reverse().map(JSON.parse); } catch {}
    return jsonResponse(res, 200, rows);
  }
  return false;
}
const dashboard = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1:' + DASHBOARD_PORT);
  if (url.pathname.startsWith('/api/')) {
    const handled = handleApi(req, res, url.pathname);
    if (handled !== false) return;
    return jsonResponse(res, 404, { ok: false, error: 'API route not found' });
  }
  if (url.pathname === '/logo.svg') {
    res.writeHead(200, { 'content-type': 'image/svg+xml' });
    return fs.createReadStream(path.join(PUBLIC_DIR, 'logo.svg')).pipe(res);
  }
  if (url.pathname === '/' || url.pathname === '/index.html') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
    return fs.createReadStream(path.join(PUBLIC_DIR, 'index.html')).pipe(res);
  }
  res.writeHead(404); res.end('Not found');
});
dashboard.listen(DASHBOARD_PORT, '127.0.0.1', () => console.log('CEOAI Juwet dashboard http://127.0.0.1:' + DASHBOARD_PORT));

function applyRewrites(urlText) {
  let result = urlText;
  for (const rule of readJson(files.rewrites, [])) {
    if (rule.enabled !== false && rule.from) result = result.split(rule.from).join(rule.to);
  }
  return result;
}
function cleanHeaders(headers) {
  const result = { ...headers };
  for (const key of ['proxy-connection', 'proxy-authorization', 'connection', 'keep-alive', 'transfer-encoding']) delete result[key];
  return result;
}
function proxyRequest(req, res) {
  stats.requests++;
  let original;
  try {
    original = new URL(req.url);
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
  const canCache = safeMethod && !hasCredentials && config.cacheEnabled !== false && target.protocol === 'http:';
  const key = cacheKey(target.href), cacheFile = path.join(CACHE_DIR, key + '.json');
  if (canCache) {
    try {
      const cached = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
      if (cached.expiresAt > Date.now()) {
        const body = Buffer.from(cached.body, 'base64');
        stats.hits++; stats.bytesOut += body.length;
        log('HIT', { host, url: target.origin + target.pathname, statusCode: cached.statusCode, bytes: body.length });
        res.writeHead(cached.statusCode, { ...cached.headers, 'x-ceoai-cache': 'HIT', 'content-length': body.length });
        res.end(body); return;
      }
    } catch {}
    stats.misses++;
  } else stats.bypass++;

  const transport = target.protocol === 'https:' ? https : http;
  const headers = { ...req.headers, host: target.host };
  for (const keyName of ['proxy-connection', 'proxy-authorization', 'connection']) delete headers[keyName];
  const upstream = transport.request(target, { method: req.method, headers, timeout: 20000 }, upstreamRes => {
    const responseHeaders = cleanHeaders(upstreamRes.headers);
    const maxBytes = Math.max(1024, Number(config.maxObjectBytes || 2000000));
    const cacheHeadersAllowed = canCache &&
      upstreamRes.statusCode === 200 &&
      !upstreamRes.headers['set-cookie'] &&
      !/private|no-store/i.test(upstreamRes.headers['cache-control'] || '') &&
      !upstreamRes.headers.vary;
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
      log(canCache ? 'MISS' : 'BYPASS', { host, url: target.origin + target.pathname, statusCode: upstreamRes.statusCode, bytes: size });
      if (cacheHeadersAllowed && !tooLarge && size <= maxBytes) {
        const cacheControl = upstreamRes.headers['cache-control'] || '';
        const match = cacheControl.match(/(?:^|,)\s*max-age=(\d+)/i);
        const ttl = Math.min(3600, Math.max(30, Number(match ? match[1] : 120)));
        const body = Buffer.concat(chunks);
        const storedHeaders = cleanHeaders(upstreamRes.headers);
        delete storedHeaders['set-cookie'];
        delete storedHeaders['transfer-encoding'];
        delete storedHeaders['connection'];
        delete storedHeaders['keep-alive'];
        delete storedHeaders['content-length'];
        try {
          fs.writeFileSync(cacheFile, JSON.stringify({
            statusCode: upstreamRes.statusCode, headers: storedHeaders,
            body: body.toString('base64'), expiresAt: Date.now() + ttl * 1000
          }));
        } catch (error) { log('cache-write-error', { error: error.message }); }
      }
    });
    res.writeHead(upstreamRes.statusCode || 502, { ...responseHeaders, 'x-ceoai-cache': canCache ? 'MISS' : 'BYPASS' });
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
const proxy = http.createServer(proxyRequest);
proxy.on('connect', (req, client, head) => {
  stats.requests++;
  const split = req.url.lastIndexOf(':');
  const host = normalizeHost(split >= 0 ? req.url.slice(0, split) : req.url);
  const port = split >= 0 ? Number(req.url.slice(split + 1)) : 443;
  const decision = filterDecision(host);
  if (decision.blocked) {
    stats.blocked++; log('blocked-connect', { host, reason: decision.reason });
    client.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return;
  }
  const upstream = net.connect(port, host, () => {
    client.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: CEOAI-Juwet\r\n\r\n');
    if (head && head.length) upstream.write(head);
    upstream.pipe(client); client.pipe(upstream);
    log('HTTPS-TUNNEL', { host, port });
  });
  upstream.setTimeout(20000, () => upstream.destroy(new Error('connect timeout')));
  upstream.on('error', error => {
    log('connect-error', { host, error: error.message });
    if (!client.destroyed) client.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
  });
  client.on('error', () => upstream.destroy());
});
proxy.listen(PROXY_PORT, '0.0.0.0', () => console.log('CEOAI Juwet proxy listening on ' + PROXY_PORT));
function stop() { proxy.close(); dashboard.close(); process.exit(0); }
process.on('SIGINT', stop); process.on('SIGTERM', stop);
