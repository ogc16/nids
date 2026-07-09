const fs = require('fs');
const path = require('path');

function loadCerts() {
  const certPath = path.join(__dirname, '..', 'certs');
  try {
    const key = fs.readFileSync(path.join(certPath, 'server.key'));
    const cert = fs.readFileSync(path.join(certPath, 'server.crt'));
    return { key, cert };
  } catch {
    return null;
  }
}

module.exports = { loadCerts };
