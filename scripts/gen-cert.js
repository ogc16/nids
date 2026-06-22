const { loadCerts } = require('../lib/tls');
const config = require('../lib/config');

console.log('Generating self-signed TLS certificate...\n');

const tls = loadCerts(true);

if (tls) {
  console.log('\nCertificate generated successfully.');
  console.log(`Cert: ${config.https.certPath}`);
  console.log(`Key:  ${config.https.keyPath}`);
  console.log('\nStart the server with HTTPS enabled:');
  console.log('  $env:HTTPS_ENABLED="true"; node server.js');
} else {
  console.error('Failed to generate certificate.');
  process.exit(1);
}
