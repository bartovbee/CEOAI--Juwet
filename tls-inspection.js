'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const tls = require('tls');
const forge = require('node-forge');

class LocalCertificateAuthority {
  constructor(dataDir) {
    this.dir = path.join(dataDir, 'tls');
    this.keyPath = path.join(this.dir, 'ca-key.pem');
    this.certPath = path.join(this.dir, 'ca-cert.pem');
    this.leafDir = path.join(this.dir, 'hosts');
    this.contexts = new Map();
    fs.mkdirSync(this.leafDir, { recursive: true });
  }
  ensureCA() {
    if (fs.existsSync(this.keyPath) && fs.existsSync(this.certPath)) return;
    fs.mkdirSync(this.dir, { recursive: true });
    // If either CA file is missing, rotate the CA and discard host leaves signed by the previous CA.
    for (const name of fs.readdirSync(this.leafDir)) { try { fs.unlinkSync(path.join(this.leafDir, name)); } catch {} }
    this.contexts.clear();
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = crypto.randomBytes(16).toString('hex');
    cert.validity.notBefore = new Date(Date.now() - 86400000);
    cert.validity.notAfter = new Date(Date.now() + 10 * 365 * 86400000);
    const name = [{ name: 'commonName', value: 'CEOAI Juwet Local Inspection CA' }, { name: 'organizationName', value: 'CEOAI Juwet' }];
    cert.setSubject(name); cert.setIssuer(name);
    cert.setExtensions([
      { name: 'basicConstraints', cA: true, pathLenConstraint: 0 },
      { name: 'keyUsage', keyCertSign: true, cRLSign: true },
      { name: 'subjectKeyIdentifier' }
    ]);
    cert.sign(keys.privateKey, forge.md.sha256.create());
    fs.writeFileSync(this.keyPath, forge.pki.privateKeyToPem(keys.privateKey), { mode: 0o600 });
    fs.writeFileSync(this.certPath, forge.pki.certificateToPem(cert), { mode: 0o644 });
    this.contexts.clear();
  }
  getCertificatePem() {
    this.ensureCA();
    return fs.readFileSync(this.certPath, 'utf8');
  }
  getContext(host) {
    host = String(host || '').replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
    if (!host || host.length > 253 || /[\r\n/\\]/.test(host)) throw new Error('Invalid TLS inspection host');
    if (this.contexts.has(host)) return this.contexts.get(host);
    this.ensureCA();
    const leafKeyPath = path.join(this.leafDir, crypto.createHash('sha256').update(host).digest('hex') + '.json');
    let leaf;
    try { leaf = JSON.parse(fs.readFileSync(leafKeyPath, 'utf8')); } catch {}
    if (!leaf) {
      const caKey = forge.pki.privateKeyFromPem(fs.readFileSync(this.keyPath, 'utf8'));
      const caCert = forge.pki.certificateFromPem(fs.readFileSync(this.certPath, 'utf8'));
      const keys = forge.pki.rsa.generateKeyPair(2048);
      const cert = forge.pki.createCertificate();
      cert.publicKey = keys.publicKey;
      cert.serialNumber = crypto.randomBytes(16).toString('hex');
      cert.validity.notBefore = new Date(Date.now() - 3600000);
      cert.validity.notAfter = new Date(Date.now() + 2 * 365 * 86400000);
      cert.setSubject([{ name: 'commonName', value: host }]);
      cert.setIssuer(caCert.subject.attributes);
      const ip = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
      cert.setExtensions([
        { name: 'basicConstraints', cA: false },
        { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
        { name: 'extKeyUsage', serverAuth: true },
        { name: 'subjectAltName', altNames: [ip ? { type: 7, ip: host } : { type: 2, value: host }] }
      ]);
      cert.sign(caKey, forge.md.sha256.create());
      leaf = { key: forge.pki.privateKeyToPem(keys.privateKey), cert: forge.pki.certificateToPem(cert) };
      fs.writeFileSync(leafKeyPath, JSON.stringify(leaf), { mode: 0o600 });
    }
    const context = tls.createSecureContext({ key: leaf.key, cert: leaf.cert });
    this.contexts.set(host, context);
    return context;
  }
  getCertificateInfo() {
    this.ensureCA();
    const cert = forge.pki.certificateFromPem(this.getCertificatePem());
    return { available: true, subject: cert.subject.getField('CN').value, expiresAt: cert.validity.notAfter.toISOString(), certificatePath: this.certPath };
  }
}
module.exports = { LocalCertificateAuthority };
