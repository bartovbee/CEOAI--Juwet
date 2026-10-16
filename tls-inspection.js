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
    if (fs.existsSync(this.keyPath) && fs.existsSync(this.certPath)) {
      try {
        const privateKey = forge.pki.privateKeyFromPem(fs.readFileSync(this.keyPath, 'utf8'));
        const certificate = forge.pki.certificateFromPem(fs.readFileSync(this.certPath, 'utf8'));
        const publicKey = certificate.publicKey;
        const pairMatches = privateKey.n && privateKey.e && publicKey.n && publicKey.e &&
          privateKey.n.compareTo(publicKey.n) === 0 && privateKey.e.compareTo(publicKey.e) === 0;
        const isCA = certificate.extensions.some(extension => extension.name === 'basicConstraints' && extension.cA === true);
        const isSelfSigned = certificate.verify(certificate);
        const now = new Date();
        const isCurrentlyValid = certificate.validity.notBefore <= now && certificate.validity.notAfter > now;
        if (pairMatches && isCA && isSelfSigned && isCurrentlyValid) return;
      } catch {}
      // Invalid, expired, or mismatched CA files cannot be trusted; rotate and clear leaves.
    }
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
      { name: 'keyUsage', keyCertSign: true, cRLSign: true, digitalSignature: true },
      { name: 'subjectKeyIdentifier' }
    ]);
    cert.sign(keys.privateKey, forge.md.sha256.create());
    fs.writeFileSync(this.keyPath, forge.pki.privateKeyToPem(keys.privateKey), { mode: 0o600 });
    fs.writeFileSync(this.certPath, forge.pki.certificateToPem(cert));
  }
  getContext(host) {
    this.ensureCA();
    if (this.contexts.has(host)) return this.contexts.get(host);
    const file = path.join(this.leafDir, crypto.createHash('sha256').update(host).digest('hex') + '.json');
    let pair;
    try { pair = JSON.parse(fs.readFileSync(file, 'utf8')); } catch {}
    if (!pair || !pair.key || !pair.cert) {
      const keys = forge.pki.rsa.generateKeyPair(2048);
      const cert = forge.pki.createCertificate();
      cert.publicKey = keys.publicKey;
      cert.serialNumber = crypto.randomBytes(16).toString('hex');
      cert.validity.notBefore = new Date(Date.now() - 86400000);
      cert.validity.notAfter = new Date(Date.now() + 825 * 86400000);
      cert.setSubject([{ name: 'commonName', value: host }]);
      cert.setIssuer(forge.pki.certificateFromPem(fs.readFileSync(this.certPath, 'utf8')).subject.attributes);
      cert.setExtensions([
        { name: 'basicConstraints', cA: false },
        { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
        { name: 'extKeyUsage', serverAuth: true },
        { name: 'subjectAltName', altNames: [{ type: 2, value: host }] }
      ]);
      const caKey = forge.pki.privateKeyFromPem(fs.readFileSync(this.keyPath, 'utf8'));
      cert.sign(caKey, forge.md.sha256.create());
      pair = { key: forge.pki.privateKeyToPem(keys.privateKey), cert: forge.pki.certificateToPem(cert) };
      fs.writeFileSync(file, JSON.stringify(pair), { mode: 0o600 });
    }
    const context = tls.createSecureContext({ key: pair.key, cert: pair.cert });
    this.contexts.set(host, context);
    return context;
  }
  exportCertificate() { this.ensureCA(); return fs.readFileSync(this.certPath); }
}
module.exports = { LocalCertificateAuthority };
