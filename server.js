const https = require('https');
const { seedAdminUser } = require('./lib/auth');
const config = require('./lib/config');
const { loadCerts } = require('./lib/tls');
const app = require('./app');

seedAdminUser();

const tls = loadCerts();

if (tls) {
  https.createServer(tls, app).listen(config.https.port, config.host, () => {
    console.log(`NIDS Enterprise running at https://localhost:${config.https.port}`);
    console.log(`  Auth: POST /api/auth/login`);
    console.log(`  CSRF: Include X-CSRF-Token header (get from csrf-token cookie on login)`);
  });
}

app.listen(config.port, config.host, () => {
  console.log(`NIDS Enterprise running at http://localhost:${config.port}`);
  console.log(`  Auth: POST /api/auth/login`);
  console.log(`  CSRF: Include X-CSRF-Token header (get from csrf-token cookie on login)`);
});
