'use strict';
const assert = require('assert');
const fs = require('fs');
const http = require('http');
const https = require('https');
const tls = require('tls');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const forge = require('node-forge');
const { LocalCertificateAuthority } = require('../tls-inspection');

function certPair(host) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const ca = forge.pki.createCertificate();
  ca.publicKey = keys.publicKey;
  ca.serialNumber = '01' + require('crypto').randomBytes(15).toString('hex');
  ca.validity.notBefore = new Date(Date.now() - 60000);
  ca.validity.notAfter = new Date(Date.now() + 86400000);
  const subject = [{ name: 'commonName', value: 'CEOAI test origin CA' }];
  ca.setSubject(subject); ca.setIssuer(subject);
  ca.setExtensions([{ name: 'basicConstraints', cA: true }, { name: 'keyUsage', keyCertSign: true, cRLSign: true }]);
  ca.sign(keys.privateKey, forge.md.sha256.create());
  const leafKeys = forge.pki.rsa.generateKeyPair(2048);
  const leaf = forge.pki.createCertificate();
  leaf.publicKey = leafKeys.publicKey;
  leaf.serialNumber = '02' + require('crypto').randomBytes(15).toString('hex');
  leaf.validity.notBefore = new Date(Date.now() - 60000);
  leaf.validity.notAfter = new Date(Date.now() + 86400000);
  leaf.setSubject([{ name: 'commonName', value: host }]); leaf.setIssuer(ca.subject.attributes);
  leaf.setExtensions([{ name: 'basicConstraints', cA: false }, { name: 'keyUsage', digitalSignature: true, keyEncipherment: true }, { name: 'extKeyUsage', serverAuth: true }, { name: 'subjectAltName', altNames: [{ type: 7, ip: host }, { type: 2, value: 'localhost' }] }]);
  leaf.sign(keys.privateKey, forge.md.sha256.create());
  return { ca: forge.pki.certificateToPem(ca), key: forge.pki.privateKeyToPem(leafKeys.privateKey), cert: forge.pki.certificateToPem(leaf) };
}
function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer(); s.once('error', reject);
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(e => e ? reject(e) : resolve(p)); });
  });
}
function request(port, pathName, method = 'GET', body = '') {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: pathName, method, headers: body ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } : {} }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.setTimeout(8000, () => req.destroy(new Error('request timeout')));
    req.on('error', reject); if (body) req.write(body); req.end();
  });
}
function interceptedGet(proxyPort, originPort, caPem) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(proxyPort, '127.0.0.1');
    let responseHeader = ''; let tlsSocket; let finished = false; let response = Buffer.alloc(0);
    const timer = setTimeout(() => finish(new Error('TLS HTTPS cache request timeout')), 12000);
    function finish(err, result) {
      if (finished) return; finished = true; clearTimeout(timer);
      socket.destroy(); if (tlsSocket) tlsSocket.destroy();
      if (err) reject(err); else resolve(result);
    }
    socket.once('connect', () => socket.write('CONNECT localhost:' + originPort + ' HTTP/1.1\r\nHost: localhost:' + originPort + '\r\n\r\n'));
    socket.on('data', chunk => {
      if (tlsSocket) return;
      responseHeader += chunk.toString('latin1');
      const end = responseHeader.indexOf('\r\n\r\n');
      if (end < 0) return;
      const statusLine = responseHeader.slice(0, responseHeader.indexOf('\r\n'));
      if (!/^HTTP\/1\.1 200 /.test(statusLine)) return finish(new Error('CONNECT rejected: ' + statusLine));
      socket.removeAllListeners('data');
      tlsSocket = tls.connect({ socket, ca: caPem, rejectUnauthorized: true, checkServerIdentity: (_host, cert) => tls.checkServerIdentity('localhost', cert) });
      tlsSocket.once('secureConnect', () => tlsSocket.write('GET /https-cache HTTP/1.1\r\nHost: localhost:' + originPort + '\r\nConnection: close\r\n\r\n'));
      tlsSocket.on('data', chunk2 => {
        response = Buffer.concat([response, chunk2]);
        const split = response.indexOf('\r\n\r\n');
        if (split < 0) return;
        const header = response.subarray(0, split).toString('latin1');
        const lenMatch = header.match(/(?:^|\r\n)content-length:\s*(\d+)/i);
        if (!lenMatch) return;
        const length = Number(lenMatch[1]);
        if (response.length >= split + 4 + length) {
          const status = Number((header.match(/^HTTP\/1\.1 (\d+)/) || [])[1]);
          const cache = (header.match(/(?:^|\r\n)x-ceoai-cache:\s*([^\r\n]+)/i) || [])[1] || '';
          const body = response.subarray(split + 4, split + 4 + length).toString();
          finish(null, { status, cache: cache.trim(), body, header });
        }
      });
      tlsSocket.on('error', finish);
    });
    socket.on('error', finish);
  });
}
(async () => {
  const root = path.join(__dirname, '..');
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ceoai-tls-test-'));
  const recoveryDir = path.join(dataDir, 'ca-recovery');
  const recoveryCA = new LocalCertificateAuthority(recoveryDir);
  fs.mkdirSync(recoveryCA.dir, { recursive: true });
  fs.writeFileSync(recoveryCA.keyPath, 'not-a-private-key');
  fs.writeFileSync(recoveryCA.certPath, 'not-a-certificate');
  fs.writeFileSync(path.join(recoveryCA.leafDir, 'stale-leaf.json'), '{"key":"stale","cert":"stale"}');
  const recoveredPem = recoveryCA.getCertificatePem();
  assert(recoveredPem.includes('BEGIN CERTIFICATE'), 'invalid local CA files should be regenerated');
  assert.strictEqual(recoveryCA.getCertificateInfo().available, true, 'regenerated CA should be readable');
  assert.strictEqual(fs.readdirSync(recoveryCA.leafDir).length, 0, 'old leaf certificates must be removed after CA rotation');
  recoveryCA.getContext('localhost');

  const originCA = certPair('127.0.0.1');
  const originCaPath = path.join(dataDir, 'origin-ca.pem');
  fs.writeFileSync(originCaPath, originCA.ca);
  const origin = https.createServer({ key: originCA.key, cert: originCA.cert }, (req, res) => {
    originCount++;
    res.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'public, max-age=60', 'content-length': Buffer.byteLength('secure-origin-' + originCount) });
    res.end('secure-origin-' + originCount);
  });
  let originCount = 0;
  const originPort = await new Promise((resolve, reject) => { origin.once('error', reject); origin.listen(0, '127.0.0.1', () => resolve(origin.address().port)); });
  const proxyPort = await freePort(), dashboardPort = await freePort();
  const appEnv = { ...process.env, PROXY_PORT: String(proxyPort), DASHBOARD_PORT: String(dashboardPort), CEOAI_DATA_DIR: path.join(dataDir, 'appdata'), NODE_EXTRA_CA_CERTS: originCaPath, CEOAI_OPEN_BROWSER: '0' };
  const testExecutable = process.env.CEOAI_TEST_EXECUTABLE;
  const child = testExecutable
    ? spawn(path.resolve(testExecutable), [], { cwd: root, env: appEnv, stdio: 'ignore' })
    : spawn(process.execPath, [path.join(root, 'server.js')], { cwd: root, env: appEnv, stdio: 'ignore' });
  try {
    let ready = false;
    for (let i = 0; i < 80; i++) { try { if ((await request(dashboardPort, '/api/status')).status === 200) { ready = true; break; } } catch {} await new Promise(r => setTimeout(r, 125)); }
    assert(ready, 'dashboard should start');
    const initial = await request(dashboardPort, '/api/tls/status');
    assert.strictEqual(initial.status, 200);
    assert.strictEqual(JSON.parse(initial.body).enabled, false, 'TLS inspection must be disabled by default');
    assert.strictEqual(JSON.parse(initial.body).ca.available, true, 'startup should provision a Root CA while TLS inspection is disabled');
    assert.strictEqual(fs.existsSync(path.join(dataDir, 'appdata', 'tls', 'rootCA.key')), true, 'startup should create the Root CA private key');
    assert.strictEqual(fs.existsSync(path.join(dataDir, 'appdata', 'tls', 'rootCA.pem')), true, 'startup should create the Root CA certificate');
    const ca = await request(dashboardPort, '/api/tls/ca.pem');
    assert.strictEqual(ca.status, 200);
    const config = await request(dashboardPort, '/api/config', 'POST', JSON.stringify({ tlsInspectionEnabled: true, tlsInspectionPorts: [originPort] }));
    assert.strictEqual(config.status, 200);
    const first = await interceptedGet(proxyPort, originPort, ca.body);
    assert.strictEqual(first.status, 200, first.header);
    assert.strictEqual(first.cache, 'MISS');
    assert.strictEqual(first.body, 'secure-origin-1');
    const second = await interceptedGet(proxyPort, originPort, ca.body);
    assert.strictEqual(second.status, 200, second.header);
    assert.strictEqual(second.cache, 'HIT');
    assert.strictEqual(second.body, 'secure-origin-1');
    assert.strictEqual(originCount, 1, 'HTTPS HIT must not reach upstream');

    const caCertPath = path.join(dataDir, 'appdata', 'tls', 'rootCA.pem');
    fs.writeFileSync(caCertPath, 'corrupted-certificate');
    const repairedCa = await request(dashboardPort, '/api/tls/ca.pem');
    assert.strictEqual(repairedCa.status, 200, 'invalid persisted CA must be regenerated');
    assert.notStrictEqual(repairedCa.body, ca.body, 'CA rotation should replace invalid certificate material');
    const afterRepair = await interceptedGet(proxyPort, originPort, repairedCa.body);
    assert.strictEqual(afterRepair.status, 200, afterRepair.header);
    assert.strictEqual(afterRepair.cache, 'HIT');
    assert.strictEqual(afterRepair.body, 'secure-origin-1');
    assert.strictEqual(originCount, 1, 'repairing CA must preserve valid cached HTTPS object');
    console.log('TLS inspection + HTTPS cache MISS/HIT + CA corruption recovery: PASS');
  } finally {
    child.kill(); await new Promise(resolve => origin.close(resolve)); fs.rmSync(dataDir, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
