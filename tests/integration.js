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
    res.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'public, max-age=60' });
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

    const rewrite = await httpRequest({
      host: '127.0.0.1', port: dashboardPort, path: '/api/rewrite', method: 'POST',
      headers: { 'content-type': 'application/json' }
    }, JSON.stringify({ from: '/rewrite-me', to: '/cache-me' }));
    assert.strictEqual(rewrite.status, 200);
    const rewritten = await proxyGet(proxyPort, originPort, 'rewrite-me');
    assert.strictEqual(rewritten.status, 200);
    assert.strictEqual(rewritten.headers['x-ceoai-cache'], 'HIT');
    assert.strictEqual(originCount, 1, 'rewrite rule should map URL onto cached object');

    const addBlock = await httpRequest({
      host: '127.0.0.1', port: dashboardPort, path: '/api/blocked', method: 'POST',
      headers: { 'content-type': 'application/json' }
    }, JSON.stringify({ host: '127.0.0.1' }));
    assert.strictEqual(addBlock.status, 200);
    const blocked = await proxyGet(proxyPort, originPort, 'blocked-check');
    assert.strictEqual(blocked.status, 403);
    await httpRequest({ host: '127.0.0.1', port: dashboardPort, path: '/api/blocked/127.0.0.1', method: 'DELETE' });

    const mode = await httpRequest({
      host: '127.0.0.1', port: dashboardPort, path: '/api/config', method: 'POST',
      headers: { 'content-type': 'application/json' }
    }, JSON.stringify({ filterMode: 'allow' }));
    assert.strictEqual(mode.status, 200);
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
    fs.writeFileSync(expiredPath, JSON.stringify({ expiresAt: 1, body: '' }));
    const clean = await httpRequest({ host: '127.0.0.1', port: dashboardPort, path: '/api/cache/clean', method: 'POST' });
    assert.strictEqual(clean.status, 200);
    assert.strictEqual(fs.existsSync(expiredPath), false);

    await testConnectTunnel(proxyPort, echoPort);
    const logs = await httpRequest({ host: '127.0.0.1', port: dashboardPort, path: '/api/logs' });
    assert.strictEqual(logs.status, 200);
    assert(logs.body.includes('HIT'));
    console.log('CEOAI Juwet integration tests passed: dashboard, HTTP MISS/HIT, rewrite, block/allow filters, cache cleaner, HTTPS CONNECT tunnel, and logs.');
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
