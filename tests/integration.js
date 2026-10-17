const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn, execFileSync } = require('child_process');

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
function testPublicHttpsCache(proxyPort, dashboardPort) {
  // Opt-in only: external DNS/network/service availability must not make normal CI flaky.
  if (process.platform !== 'win32' || process.env.CEOAI_PUBLIC_HTTPS_TEST !== '1') return;
  const configBody = JSON.stringify({ tlsInspectionEnabled: true, tlsInspectionPorts: [443], cacheEnabled: true, cacheOnly: false });
  const config = execFileSync('curl.exe', [
    '--silent', '--show-error', '--max-time', '10',
    '--request', 'POST',
    '--header', 'content-type: application/json',
    '--data', configBody,
    'http://127.0.0.1:' + dashboardPort + '/api/config'
  ], { encoding: 'utf8', windowsHide: true });
  assert(JSON.parse(config).ok, 'TLS inspection should enable for public HTTPS test');

  // /cache without a duration commonly returns max-age=0 and is intentionally not reusable.
  // Use /cache/60 so the origin explicitly grants a 60-second freshness lifetime.
  const url = 'https://httpbin.org/cache/60?ceoai_probe=' + crypto.randomBytes(8).toString('hex');
  function curlOnce() {
    return execFileSync('curl.exe', [
      '--silent', '--show-error', '--insecure', '--max-time', '30',
      '--proxy', 'http://127.0.0.1:' + proxyPort,
      '--dump-header', '-', '--output', 'NUL',
      '--write-out', '\n__CEOAI_HTTP_CODE__:%{http_code}\n',
      url
    ], { encoding: 'utf8', windowsHide: true, maxBuffer: 2 * 1024 * 1024 });
  }
  const first = curlOnce();
  const second = curlOnce();
  const status = output => Number((output.match(/__CEOAI_HTTP_CODE__:(\d{3})/) || [])[1] || 0);
  const cacheStatus = output => ((output.match(/(?:^|\r?\n)x-ceoai-cache:\s*([^\r\n]+)/i) || [])[1] || '').trim();
  assert.strictEqual(status(first), 200, 'public HTTPS first response should be 200; output: ' + first.slice(-1000));
  assert.strictEqual(status(second), 200, 'public HTTPS second response should be 200; output: ' + second.slice(-1000));
  assert.strictEqual(cacheStatus(first), 'MISS', 'public HTTPS first request should MISS; output: ' + first.slice(0, 1000));
  assert.strictEqual(cacheStatus(second), 'HIT', 'public HTTPS second request should HIT; output: ' + second.slice(0, 1000));
  console.log('Optional public HTTPS cache test passed: httpbin.org/cache/60 MISS -> HIT via curl.exe');
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
  let receivedConnectionNominatedHeader = false;
  const origin = http.createServer((req, res) => {
    originCount++;
    if (req.url === '/hop-by-hop') receivedConnectionNominatedHeader = Object.prototype.hasOwnProperty.call(req.headers, 'x-client-hop');
    const policies = {
      private: 'private, max-age=60',
      'no-store': 'no-store, max-age=60',
      'no-cache': 'no-cache, max-age=60',
      'must-revalidate': 'public, max-age=60, must-revalidate',
      'no-cache-fields': 'public, max-age=60, no-cache="set-cookie"',
      'pragma-no-cache': 'public, max-age=60',
      'no-freshness': '',
      'static-image-no-freshness': '',
      'vary-response': 'public, max-age=60',
      'set-cookie-response': 'public, max-age=60'
    };
    const policy = policies[req.url.slice(1)];
    const headers = { 'content-type': req.url === '/static-image-no-freshness' ? 'image/png' : 'text/plain' };
    if (req.url === '/hop-by-hop') {
      headers.connection = 'x-origin-hop';
      headers['x-origin-hop'] = 'must-not-cross-proxy';
    }
    if (req.url === '/vary-response') headers.vary = 'Accept-Encoding';
    if (req.url === '/set-cookie-response') headers['set-cookie'] = 'session=secret; HttpOnly';
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
  const appEnv = { ...process.env, PROXY_PORT: String(proxyPort), DASHBOARD_PORT: String(dashboardPort), CEOAI_DATA_DIR: dataDir, CEOAI_OPEN_BROWSER: '0' };
  const testExecutable = process.env.CEOAI_TEST_EXECUTABLE;
  const child = testExecutable
    ? spawn(path.resolve(testExecutable), [], { cwd: root, env: appEnv, stdio: 'ignore' })
    : spawn(process.execPath, [path.join(root, 'server.js')], { cwd: root, env: appEnv, stdio: 'ignore' });
  try {
    const health = await waitForDashboard(dashboardPort, child);
    assert.strictEqual(health.ok, true);
    assert.strictEqual(health.proxyPort, proxyPort);

    const conflictDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ceoai-port-conflict-'));
    const conflictChild = spawn(process.execPath, [path.join(root, 'server.js')], {
      cwd: root,
      env: { ...process.env, PROXY_PORT: String(await freePort()), DASHBOARD_PORT: String(dashboardPort), CEOAI_DATA_DIR: conflictDataDir },
      stdio: 'ignore'
    });
    const conflictExit = await Promise.race([
      new Promise(resolve => conflictChild.once('exit', code => resolve(code))),
      delay(5000).then(() => 'timeout')
    ]);
    if (conflictExit === 'timeout') conflictChild.kill();
    assert.strictEqual(conflictExit, 1, 'port conflict must terminate cleanly instead of leaving a half-started server');
    fs.rmSync(conflictDataDir, { recursive: true, force: true });

    const hostileHost = await httpRequest({
      host: '127.0.0.1', port: dashboardPort, path: '/api/status',
      headers: { host: 'attacker.example:' + dashboardPort }
    });
    assert.strictEqual(hostileHost.status, 403, 'dashboard must reject hostile Host headers');
    const index = await httpRequest({ host: '127.0.0.1', port: dashboardPort, path: '/' });
    assert.strictEqual(index.status, 200);
    assert(index.body.includes('CEOAI Juwet'));

    const oversizedConfig = await httpRequest({
      host: '127.0.0.1', port: dashboardPort, path: '/api/config', method: 'POST',
      headers: { 'content-type': 'application/json' }
    }, JSON.stringify({ note: 'x'.repeat(11000) }));
    assert.strictEqual(oversizedConfig.status, 413, 'oversized dashboard request should return HTTP 413 without resetting the connection');


    const hopByHop = await httpRequest({
      host: '127.0.0.1', port: proxyPort, method: 'GET',
      path: 'http://127.0.0.1:' + originPort + '/hop-by-hop',
      headers: { host: '127.0.0.1:' + originPort, connection: 'x-client-hop', 'x-client-hop': 'must-not-cross-proxy' }
    });
    assert.strictEqual(hopByHop.status, 200);
    assert.strictEqual(receivedConnectionNominatedHeader, false, 'Connection-nominated request headers must not reach upstream');
    assert.strictEqual(hopByHop.headers['x-origin-hop'], undefined, 'Connection-nominated response headers must not reach clients');

    const originCountBeforeCacheTest = originCount;
    const first = await proxyGet(proxyPort, originPort, 'cache-me');
    assert.strictEqual(first.status, 200);
    assert.strictEqual(first.headers['x-ceoai-cache'], 'MISS');
    assert(fs.existsSync(path.join(dataDir, 'cache', '127.0.0.1')), 'cache entries must be grouped into a hostname folder');
    assert(fs.readdirSync(path.join(dataDir, 'cache', '127.0.0.1')).some(name => name.endsWith('.json')), 'hostname folder must contain JSON cache entries');
    const cachedBody = first.body;
    assert.strictEqual(originCount, originCountBeforeCacheTest + 1, 'cache MISS should request upstream once');

    const second = await proxyGet(proxyPort, originPort, 'cache-me');
    assert.strictEqual(second.status, 200);
    assert.strictEqual(second.headers['x-ceoai-cache'], 'HIT');
    assert.strictEqual(second.body, cachedBody);
    assert.strictEqual(originCount, originCountBeforeCacheTest + 1, 'cache HIT should not request upstream again');

    const forcedRefresh = await httpRequest({
      host: '127.0.0.1', port: proxyPort,
      path: 'http://127.0.0.1:' + originPort + '/cache-me',
      headers: { host: '127.0.0.1:' + originPort, 'cache-control': 'no-cache' }
    });
    assert.strictEqual(forcedRefresh.status, 200);
    assert.strictEqual(forcedRefresh.headers['x-ceoai-cache'], 'BYPASS');
    assert.strictEqual(forcedRefresh.body, 'origin-response-' + (originCountBeforeCacheTest + 2));
    const afterBypass = await proxyGet(proxyPort, originPort, 'cache-me');
    assert.strictEqual(afterBypass.headers['x-ceoai-cache'], 'HIT');
    assert.strictEqual(afterBypass.body, cachedBody);
    assert.strictEqual(originCount, originCountBeforeCacheTest + 2, 'request no-cache must bypass cache and preserve existing object');

    for (const pathName of ['private', 'no-store', 'vary-response', 'set-cookie-response']) {
      const before = originCount;
      const firstPolicyRequest = await proxyGet(proxyPort, originPort, pathName);
      assert.strictEqual(firstPolicyRequest.status, 200, pathName + ' first request should succeed');
      assert.strictEqual(firstPolicyRequest.headers['x-ceoai-cache'], 'MISS_BYPASS', pathName + ' should expose policy bypass');
      const secondPolicyRequest = await proxyGet(proxyPort, originPort, pathName);
      assert.strictEqual(secondPolicyRequest.status, 200, pathName + ' second request should succeed');
      assert.strictEqual(secondPolicyRequest.headers['x-ceoai-cache'], 'MISS_BYPASS', pathName + ' response must not be stored');
      assert.strictEqual(originCount, before + 2, pathName + ' should reach origin for both requests');
    }
    for (const pathName of ['no-cache', 'must-revalidate', 'no-cache-fields', 'pragma-no-cache', 'no-freshness']) {
      const before = originCount;
      const firstPolicyRequest = await proxyGet(proxyPort, originPort, pathName);
      assert.strictEqual(firstPolicyRequest.status, 200, pathName + ' first request should succeed');
      const secondPolicyRequest = await proxyGet(proxyPort, originPort, pathName);
      assert.strictEqual(secondPolicyRequest.status, 200, pathName + ' second request should succeed');
      assert.strictEqual(secondPolicyRequest.headers['x-ceoai-cache'], 'MISS', pathName + ' response must not be stored');
      assert.strictEqual(originCount, before + 2, pathName + ' should reach origin for both requests');
    }

    const imageBefore = originCount;
    const imageFirst = await proxyGet(proxyPort, originPort, 'static-image-no-freshness');
    assert.strictEqual(imageFirst.status, 200);
    assert.strictEqual(imageFirst.headers['x-ceoai-cache'], 'MISS', 'public static image without explicit freshness should be stored with a short heuristic lifetime');
    const imageSecond = await proxyGet(proxyPort, originPort, 'static-image-no-freshness');
    assert.strictEqual(imageSecond.status, 200);
    assert.strictEqual(imageSecond.headers['x-ceoai-cache'], 'HIT', 'public static image should be served from the local cache on repeat request');
    assert.strictEqual(imageSecond.body, imageFirst.body);
    assert.strictEqual(originCount, imageBefore + 1, 'cached static image repeat must not reach origin');

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
    assert.strictEqual(conditionalRequest.headers['x-ceoai-cache'], 'HIT', 'If-None-Match revalidation should reuse the fresh local object');
    assert.strictEqual(conditionalRequest.body, cachedBody, 'conditional local cache response should preserve the cached body');
    assert.strictEqual(originCount, originCountBeforeRangeAndConditional + 1, 'Range requests should reach upstream while a fresh cached conditional request should not');

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

    const cleanerDomainDir = path.join(dataDir, 'cache', 'cache-cleaner.test');
    fs.mkdirSync(cleanerDomainDir, { recursive: true });
    const expiredPath = path.join(cleanerDomainDir, 'expired-test.json');
    const malformedExpiryPath = path.join(cleanerDomainDir, 'malformed-expiry-test.json');
    fs.writeFileSync(expiredPath, JSON.stringify({ expiresAt: 1, body: '', statusCode: 200 }));
    fs.writeFileSync(malformedExpiryPath, JSON.stringify({ expiresAt: 'not-a-date', body: '', statusCode: 200 }));
    const clean = await httpRequest({ host: '127.0.0.1', port: dashboardPort, path: '/api/cache/clean', method: 'POST' });
    assert.strictEqual(clean.status, 200);
    assert.strictEqual(fs.existsSync(expiredPath), false);
    assert.strictEqual(fs.existsSync(malformedExpiryPath), false, 'malformed cache metadata must be cleaned');

    const beforePlainTunnel = await httpRequest({ host: '127.0.0.1', port: dashboardPort, path: '/api/status' });
    assert.strictEqual(beforePlainTunnel.status, 200);
    const bypassBeforePlainTunnel = JSON.parse(beforePlainTunnel.body).stats.bypass;
    await testConnectTunnel(proxyPort, echoPort);
    const afterPlainTunnel = await httpRequest({ host: '127.0.0.1', port: dashboardPort, path: '/api/status' });
    assert.strictEqual(afterPlainTunnel.status, 200);
    assert.strictEqual(
      JSON.parse(afterPlainTunnel.body).stats.bypass,
      bypassBeforePlainTunnel + 1,
      'plain CONNECT TCP tunnels must bypass cache'
    );
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

    const corruptUrl = 'http://127.0.0.1:' + originPort + '/corrupt-cache';
    const corruptKey = crypto.createHash('sha256').update(corruptUrl).digest('hex');
    const corruptDomainDir = path.join(dataDir, 'cache', '127.0.0.1');
    fs.mkdirSync(corruptDomainDir, { recursive: true });
    fs.writeFileSync(path.join(corruptDomainDir, corruptKey + '.json'), JSON.stringify({
      statusCode: 200, expiresAt: Date.now() + 60000, body: Buffer.from('poisoned').toString('base64'),
      headers: { 'x-corrupt': 'bad\nheader' }
    }));
    const corruptMiss = await proxyGet(proxyPort, originPort, 'corrupt-cache');
    assert.strictEqual(corruptMiss.status, 200);
    assert.strictEqual(corruptMiss.headers['x-ceoai-cache'], 'MISS', 'corrupt cache headers must never be served');
    const corruptHit = await proxyGet(proxyPort, originPort, 'corrupt-cache');
    assert.strictEqual(corruptHit.headers['x-ceoai-cache'], 'HIT', 'valid upstream response should replace corrupt cache metadata');
    assert.strictEqual(corruptHit.body, corruptMiss.body);

    // A manually edited/corrupt config must not silently disable cache storage.
    const configPath = path.join(dataDir, 'config.json');
    fs.writeFileSync(configPath, JSON.stringify({
      cacheEnabled: true, cacheOnly: false, maxObjectBytes: 'invalid',
      autoCleanHours: 'invalid', filterMode: 'block', tlsInspectionEnabled: false
    }));
    const invalidConfigFirst = await proxyGet(proxyPort, originPort, 'invalid-config-runtime');
    assert.strictEqual(invalidConfigFirst.status, 200);
    assert.strictEqual(invalidConfigFirst.headers['x-ceoai-cache'], 'MISS');
    const invalidConfigSecond = await proxyGet(proxyPort, originPort, 'invalid-config-runtime');
    assert.strictEqual(invalidConfigSecond.status, 200);
    assert.strictEqual(invalidConfigSecond.headers['x-ceoai-cache'], 'HIT', 'invalid persisted numeric settings should use safe defaults');
    const restoreConfig = await httpRequest({
      host: '127.0.0.1', port: dashboardPort, path: '/api/config', method: 'POST',
      headers: { 'content-type': 'application/json' }
    }, JSON.stringify({ cacheEnabled: true, cacheOnly: false, autoCleanHours: 24, maxObjectBytes: 2000000, filterMode: 'block', tlsInspectionEnabled: false }));
    assert.strictEqual(restoreConfig.status, 200);

    testPublicHttpsCache(proxyPort, dashboardPort);

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
