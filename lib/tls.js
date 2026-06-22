const fs = require('fs');
const path = require('path');
const forge = require('node-forge');
const config = require('./config');

function loadCerts(force) {
  try {
    if (fs.existsSync(config.https.certPath) && fs.existsSync(config.https.keyPath) && !force) {
      console.log(`[TLS] Using certificate: ${config.https.certPath}`);
      return {
        cert: fs.readFileSync(config.https.certPath, 'utf8'),
        key: fs.readFileSync(config.https.keyPath, 'utf8')
      };
    }
  } catch (e) {
    console.warn(`[TLS] Could not read configured cert/key: ${e.message}`);
  }

  if (!config.https.enabled && !force) return null;

  try {
    const certDir = path.dirname(config.https.certPath);
    return generateSelfSigned(certDir);
  } catch (e) {
    console.error(`[TLS] Failed to generate self-signed certificate: ${e.message}`);
    return null;
  }
}

function generateSelfSigned(certDir) {
  if (!fs.existsSync(certDir)) fs.mkdirSync(certDir, { recursive: true });

  console.log(`[TLS] Generating self-signed certificate...`);

  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = Date.now().toString(16);
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 1);

  const attrs = [{ name: 'commonName', value: 'localhost' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  cert.setExtensions([
    { name: 'basicConstraints', cA: true },
    { name: 'keyUsage', keyCertSign: true, digitalSignature: true },
    { name: 'extKeyUsage', serverAuth: true },
    { name: 'subjectAltName', altNames: [{ type: 2, value: 'localhost' }, { type: 7, value: '127.0.0.1' }] }
  ]);

  cert.sign(keys.privateKey, forge.md.sha256.create());

  const certPem = forge.pki.certificateToPem(cert);
  const keyPem = forge.pki.privateKeyToPem(keys.privateKey);

  const keyPath = path.join(certDir, 'key.pem');
  const certPath = path.join(certDir, 'cert.pem');

  fs.writeFileSync(certPath, certPem, 'utf8');
  fs.writeFileSync(keyPath, keyPem, 'utf8');

  console.log(`[TLS] Self-signed certificate generated`);
  console.log(`       Cert: ${certPath}`);
  console.log(`       Key:  ${keyPath}`);
  console.log(`[TLS] WARNING: Development certificate. For production, set`);
  console.log(`       HTTPS_CERT_PATH and HTTPS_KEY_PATH to real certificates.`);

  return { cert: certPem, key: keyPem };
}

module.exports = { loadCerts };
