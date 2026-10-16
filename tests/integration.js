const assert = require('assert');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

function delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close(err => err ? reject(err) : resolve(port));
    });
  });
}
function httpRequest(options, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8')
      }));
    });
    req.setTimeout(6000, () => req.destroy(new Error('HTTP test request timeout')));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}
async function waitForDashboard(port, child) {
  for (let i = 0; i < 80; i++) {
    if (child.exitCode !== null) throw new Error('CEOAI Juwet server exited early: ' + child.exitCode);
    try {
      const response = await httpRequest({ host: '127.0.0.1', port, path: '/api/status', method: 'GET' });
      if (response.status === 200) return JSON.parse(response.body);
    } catch {}
    await delay(125);
  }
  throw new Error('Dashboard did not start within 10 seconds');
}
function proxyGet(proxyPort, originPort, suffix) {
  return httpRequest({
    host: '127.0.0.1',
    port: proxyPort,
    method: 'GET',
    path: 'http://127.0.0.1:' + originPort + '/' + suffix,
    headers: { host: '127.0.0.1:' + originPort }
  });
}
function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}
function closeServer(server) {
  return new Promise(resolve => {
    if (!server || !server.listening) return resolve();
    server.close(() => resolve());
  });
}
function testConnectStatus(proxyPort, authority, expectedStatus) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(proxyPort, '127.0.0.1');
    let data = '';
    let completed = false;
    const timer = setTimeout(() => finish(new Error('CONNECT status test timeout for ' + authority)), 5000);
    function finish(error) {
      if (completed) return;
      completed = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error); else resolve();
    }
    socket.on('connect', () => socket.write('CONNECT ' + authority + ' HTTP/1.1\r\nHost: ' + authority + '\r\n\r\n'));
    socket.on('data', chunk => {
      data += chunk.toString('latin1');
      const end = data.indexOf('\r\n');
      if (end >= 0) {
        const statusLine = data.slice(0, end);
        const match = statusLine.match(/^HTTP\/1\.1 (\d{3})/);
        if (!match) return finish(new Error('Invalid CONNECT response: ' + statusLine));
        if (Number(match[1]) !== expectedStatus) return finish(new Error('Expected CONNECT ' + expectedStatus + ' but got ' + statusLine));
        finish();
      }
    });
    socket.on('error', finish);
  });
}
function testConnectTunnel(proxyPort, echoPort) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(proxyPort, '127.0.0.1');
    let header = '';
    let connected = false;
    let completed = false;
    const timer = setTimeout(() => finish(new Error('CONNECT tunnel test timeout')), 5000);
    function finish(error) {
      if (completed) return;
      completed = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error); else resolve();
    }
    socket.on('connect', () => socket.write('CONNECT 127.0.0.1:' + echoPort + ' HTTP/1.1\r\nHost: 127.0.0.1:' + echoPort + '\r\n\r\n'));
    socket.on('data', chunk => {
      if (!connected) {
        header += chunk.toString('latin1');
        const end = header.indexOf('\r\n\r\n');
        if (end >= 0) {
          const statusLine = header.slice(0, header.indexOf('\r\n'));
          if (!/^HTTP\/1\.1 200 /.test(statusLine)) return finish(new Error('CONNECT failed: ' + statusLine));
          connected = true;
          socket.write('CEOAI-TUNNEL-OK');
        }
      } else if (chunk.toString().includes('CEOAI-TUNNEL-OK')) {
        finish();
      }
    });
    socket.on('error', finish);
  });
}

(async () => {
  const root = path.join(__dirname, '..');
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ceoai-juwet-test-'));
  const proxyPort = await freePort();
  const dashboardPort = await freePort();
  let originCount = 0;
  const origin = http.createServer((req, res) => {
    originCount++;
    const policies = {
      private: 'private, max-age=60',
      'no-store': 'no-store, max-age=60',
      'no-cache': 'no-cache, max-age=60',
      'must-revalidate': 'public, max-age=60, must-revalidate',
      'no-cache-fields': 'public, max-age=60, no-cache="set-cookie"',
      'pragma-no-cache': 'public, max-age=60',
      'no-freshness': ''
    };
    const policy = policies[req.url.slice(1)];
    const headers = { 'content-type': 'text/plain' };
    if (policy !== undefined) {
      if (policy) headers['cache-control'] = policy;
    } else {
      headers['cache-control'] = 'public, max-age=60';
    }
    if (req.url === '/pragma-no-cache') headers.pragma = 'no-cache';
    res.writeHead(200, headers);
    res.end('origin-response-' + originCount);
  });
  const originPort = await listen(origin);
  const echo = net.createServer(socket => socket.pipe(socket));
  const echoPort = await listen(echo);
  const child = spawn(process.execPath, [path.join(root, 'server.js')], {
    cwd: root,
    env: { ...process.env, PROXY_PORT: String(proxyPort), DASHBOARD_PORT: String(dashboardPort), CEOAI_DATA_DIR: dataDir },
    stdio: 'ignore'
  });
  try {
    const health = await waitForDashboard(dashboardPort, child);
    assert.strictEqual(health.ok, true);
    assert.strictEqual(health.proxyPort, proxyPort);
    const index = await httpRequest({ host: '127.0.0.1', port: dashboardPort, path: '/' });
    assert.strictEqual(index.status, 200);
    assert(index.body.includes('CEOAI Juwet'));

    const first = await proxyGet(proxyPort, originPort, 'cache-me');
    assert.strictEqual(first.status, 200);
    assert.strictEqual(first.headers['x-ceoai-cache'], 'MISS');
    assert.strictEqual(first.body, 'origin-response-1');

    const second = await proxyGet(proxyPort, originPort, 'cache-me');
    assert.strictEqual(second.status, 200);
    assert.strictEqual(second.headers['x-ceoai-cache'], 'HIT');
    assert.strictEqual(second.body, 'origin-response-1');
    assert.strictEqual(originCount, 1, 'cache HIT should not request upstream again');

    const forcedRefresh = await httpRequest({
      host: '127.0.0.1', port: proxyPort,
      path: 'http://127.0.0.1:' + originPort + '/cache-me',
      headers: { host: '127.0.0.1:' + originPort, 'cache-control': 'no-cache' }
    });
    assert.strictEqual(forcedRefresh.status, 200);
    assert.strictEqual(forcedRefresh.headers['x-ceoai-cache'], 'BYPASS');
    assert.strictEqual(forcedRefresh.body, 'origin-response-2');
    const afterBypass = await proxyGet(proxyPort, originPort, 'cache-me');
    assert.strictEqual(afterBypass.headers['x-ceoai-cache'], 'HIT');
    assert.strictEqual(afterBypass.body, 'origin-response-1');
    assert.strictEqual(originCount, 2, 'request no-cache must bypass cache and preserve existing object');

    for (const pathName of ['private', 'no-store', 'no-cache', 'must-revalidate', 'no-cache-fields', 'pragma-no-cache', 'no-freshness']) {
      const before = originCount;
      const firstPolicyRequest = await proxyGet(proxyPort, originPort, pathName);
      assert.strictEqual(firstPolicyRequest.status, 200, pathName + ' first request should succeed');
      assert.strictEqual(firstPolicyRequest.headers['x-ceoai-cache'], 'MISS');
      const secondPolicyRequest = await proxyGet(proxyPort, originPort, pathName);
      assert.strictEqual(secondPolicyRequest.status, 200, pathName + ' second request should succeed');
      assert.strictEqual(secondPolicyRequest.headers['x-ceoai-cache'], 'MISS', pathName + ' response must not be stored');
      assert.strictEqual(originCount, before + 2, pathName + ' should reach origin for both requests');
    }

    const malformedDelete = await httpRequest({
      host: '127.0.0.1', port: dashboardPort,
      path: '/api/blocked/%E0%A4%A', method: 'DELETE'
    });
    assert.strictEqual(malformedDelete.status, 400, 'malformed URL encoding should return 400 without crashing the server');

    const clientList = await httpRequest({ host: '127.0.0.1', port: dashboardPort, path: '/api/clients' });
    assert.strictEqual(clientList.status, 200);
    const clientData = JSON.parse(clientList.body);
    assert(clientData.clients.some(client => client.ip === '127.0.0.1'), 'client monitor should track proxy source IP');
    assert(clientData.clients.find(client => client.ip === '127.0.0.1').requests >= 2, 'client monitor should count requests');

    const originCountBeforeRewrite = originCount;
    const rewrite = await httpRequest({
      host: '127.0.0.1', port: dashboardPort, path: '/api/rewrite', method: 'POST',
      headers: { 'content-type': 'application/json' }
    }, JSON.stringify({ from: '/rewrite-me', to: '/cache-me' }));
    assert.strictEqual(rewrite.status, 200);
    const rewritten = await proxyGet(proxyPort, originPort, 'rewrite-me');
    assert.strictEqual(rewritten.status, 200);
    assert.strictEqual(rewritten.headers['x-ceoai-cache'], 'HIT');
    assert.strictEqual(originCount, originCountBeforeRewrite, 'rewrite rule should map URL onto cached object without another origin request');

    const originCountBeforeRangeAndConditional = originCount;
    const rangeRequest = await httpRequest({
      host: '127.0.0.1', port: proxyPort,
      path: 'http://127.0.0.1:' + originPort + '/cache-me',
      headers: { host: '127.0.0.1:' + originPort, range: 'bytes=0-3' }
    });
    assert.strictEqual(rangeRequest.status, 200);
    assert.strictEqual(rangeRequest.headers['x-ceoai-cache'], 'BYPASS', 'Range requests must not receive a cached full response');
    const conditionalRequest = await httpRequest({
      host: '127.0.0.1', port: proxyPort,
      path: 'http://127.0.0.1:' + originPort + '/cache-me',
      headers: { host: '127.0.0.1:' + originPort, 'if-none-match': '"client-etag"' }
    });
    assert.strictEqual(conditionalRequest.status, 200);
    assert.strictEqual(conditionalRequest.headers['x-ceoai-cache'], 'BYPASS', 'conditional requests must reach upstream');
    assert.strictEqual(originCount, originCountBeforeRangeAndConditional + 2, 'Range and conditional requests must reach upstream');

    const addBlock = await httpRequest({
      host: '127.0.0.1', port: dashboardPort, path: '/api/blocked', method: 'POST',
      headers: { 'content-type': 'application/json' }
    }, JSON.stringify({ host: '127.0.0.1' }));
    assert.strictEqual(addBlock.status, 200);
    const blocked = await proxyGet(proxyPort, originPort, 'blocked-check');
    assert.strictEqual(blocked.status, 403);
    await testConnectStatus(proxyPort, '127.0.0.1:' + echoPort, 403);
    await httpRequest({ host: '127.0.0.1', port: dashboardPort, path: '/api/blocked/127.0.0.1', method: 'DELETE' });
    await testConnectStatus(proxyPort, 'user@127.0.0.1:' + echoPort, 400);
    await testConnectStatus(proxyPort, '127.0.0.1:0', 400);

    const invalidNumericConfig = await httpRequest({
      host: '127.0.0.1', port: dashboardPort, path: '/api/config', method: 'POST',
      headers: { 'content-type': 'application/json' }
    }, JSON.stringify({ autoCleanHours: 'not-a-number', maxObjectBytes: 'not-a-number' }));
    assert.strictEqual(invalidNumericConfig.status, 200);
    const sanitizedConfig = JSON.parse(invalidNumericConfig.body).config;
    assert.strictEqual(sanitizedConfig.autoCleanHours, 24, 'invalid auto-clean interval must fall back to 24 hours');
    assert.strictEqual(sanitizedConfig.maxObjectBytes, 2000000, 'invalid cache size must fall back to 2 MB');

    const offlineSettings = await httpRequest({
      host: '127.0.0.1', port: dashboardPort, path: '/api/config', method: 'POST',
      headers: { 'content-type': 'application/json' }
    }, JSON.stringify({ cacheOnly: true, autoCleanHours: 0 }));
    assert.strictEqual(offlineSettings.status, 200);
    const originCountBeforeOffline = originCount;
    const offlineMiss = await proxyGet(proxyPort, originPort, 'offline-miss');
    assert.strictEqual(offlineMiss.status, 504);
    assert.strictEqual(offlineMiss.headers['x-ceoai-cache'], 'OFFLINE-MISS');
    await testConnectStatus(proxyPort, '127.0.0.1:' + echoPort, 504);
    assert.strictEqual(originCount, originCountBeforeOffline, 'offline mode must not contact upstream');

    await httpRequest({
      host: '127.0.0.1', port: dashboardPort, path: '/api/config', method: 'POST',
      headers: { 'content-type': 'application/json' }
    }, JSON.stringify({ cacheOnly: false }));

    const mode = await httpRequest({
      host: '127.0.0.1', port: dashboardPort, path: '/api/config', method: 'POST',
      headers: { 'content-type': 'application/json' }
    }, JSON.stringify({ filterMode: 'allow' }));
    assert.strictEqual(mode.status, 200);
    const emptyAllowlistDenied = await proxyGet(proxyPort, originPort, 'empty-allowlist-check');
    assert.strictEqual(emptyAllowlistDenied.status, 403, 'empty allowlist must fail closed');
    await httpRequest({
      host: '127.0.0.1', port: dashboardPort, path: '/api/allowed', method: 'POST',
      headers: { 'content-type': 'application/json' }
    }, JSON.stringify({ host: 'example.com' }));
    const deniedByAllow = await proxyGet(proxyPort, originPort, 'allow-check');
    assert.strictEqual(deniedByAllow.status, 403);
    await httpRequest({ host: '127.0.0.1', port: dashboardPort, path: '/api/allowed/example.com', method: 'DELETE' });
    await httpRequest({
      host: '127.0.0.1', port: dashboardPort, path: '/api/config', method: 'POST',
      headers: { 'content-type': 'application/json' }
    }, JSON.stringify({ filterMode: 'block' }));

    const expiredPath = path.join(dataDir, 'cache', 'expired-test.json');
    const malformedExpiryPath = path.join(dataDir, 'cache', 'malformed-expiry-test.json');
    fs.writeFileSync(expiredPath, JSON.stringify({ expiresAt: 1, body: '', statusCode: 200 }));
    fs.writeFileSync(malformedExpiryPath, JSON.stringify({ expiresAt: 'not-a-date', body: '', statusCode: 200 }));
    const clean = await httpRequest({ host: '127.0.0.1', port: dashboardPort, path: '/api/cache/clean', method: 'POST' });
    assert.strictEqual(clean.status, 200);
    assert.strictEqual(fs.existsSync(expiredPath), false);
    assert.strictEqual(fs.existsSync(malformedExpiryPath), false, 'malformed cache metadata must be cleaned');

    await testConnectTunnel(proxyPort, echoPort);
    // Repeat cache and tunnel behavior to catch intermittent state and socket regressions.
    for (let round = 1; round <= 25; round++) {
      const suffix = 'repeat-cache-' + round;
      const miss = await proxyGet(proxyPort, originPort, suffix);
      assert.strictEqual(miss.status, 200, 'repeat round ' + round + ' first request');
      assert.strictEqual(miss.headers['x-ceoai-cache'], 'MISS', 'repeat round ' + round + ' should MISS first');
      const hit = await proxyGet(proxyPort, originPort, suffix);
      assert.strictEqual(hit.status, 200, 'repeat round ' + round + ' second request');
      assert.strictEqual(hit.headers['x-ceoai-cache'], 'HIT', 'repeat round ' + round + ' should HIT second');
      assert.strictEqual(hit.body, miss.body, 'repeat round ' + round + ' body should remain identical');
    }
    for (let round = 0; round < 10; round++) await testConnectTunnel(proxyPort, echoPort);

    const logs = await httpRequest({ host: '127.0.0.1', port: dashboardPort, path: '/api/logs' });
    assert.strictEqual(logs.status, 200);
    assert(logs.body.includes('HIT'));
    console.log('CEOAI Juwet integration tests passed: dashboard, HTTP MISS/HIT, request no-cache bypass, private/no-store/no-cache/must-revalidate/no-freshness policies, rewrite, block/allow filters, offline-only mode, cache cleaner, HTTPS CONNECT tunnel, CONNECT block/offline/malformed-authority handling, 25 repeated cache MISS/HIT rounds, 10 repeated CONNECT tunnels, and logs.');
  } finally {
    child.kill();
    await Promise.race([new Promise(resolve => child.once('exit', resolve)), delay(2000)]);
    await closeServer(origin);
    await closeServer(echo);
    try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch {}
  }
})().catch(error => {
  console.error(error && error.stack || error);
  process.exitCode = 1;
});
