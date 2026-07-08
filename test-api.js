const http = require('http');

const BASE = process.env.API_BASE || 'http://localhost:3000';
const TEST_USER = process.env.TEST_USER || 'admin';
const TEST_PASS = process.env.TEST_PASS || 'admin123';

let passed = 0;
let failed = 0;
let token = null;

function request(method, path, body, useAuth = true) {
  return new Promise((resolve, reject) => {
    const opts = {
      method,
      hostname: 'localhost',
      port: 3000,
      path: `/api${path}`,
      headers: { 'Content-Type': 'application/json' }
    };
    if (useAuth && token) opts.headers['Authorization'] = `Bearer ${token}`;

    const req = http.request(opts, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

function assert(label, condition) {
  if (condition) { passed++; console.log(`  PASS: ${label}`); }
  else { failed++; console.log(`  FAIL: ${label}`); }
}

async function run() {
  console.log('\n=== NIDS Security Test Suite ===\n');

  // 0. Unauthenticated access should fail
  console.log('0. Auth Enforcement');
  const noAuthPkts = await request('GET', '/packets', null, false);
  assert('GET /api/packets without auth returns 401', noAuthPkts.status === 401);

  const noAuthAlerts = await request('DELETE', '/alerts', {}, false);
  assert('DELETE /api/alerts without auth returns 401', noAuthAlerts.status === 401);

  // 1. Login
  console.log('\n1. Authentication');
  const login = await request('POST', '/auth/login', { username: TEST_USER, password: TEST_PASS }, false);
  assert('POST /api/auth/login returns 200', login.status === 200);
  assert('Login returns token', login.body && login.body.token);
  assert('Login returns user info', login.body && login.body.user && login.body.user.role === 'admin');
  token = login.body.token;
  console.log(`  Token: ${token.substring(0, 20)}...`);

  // 2. Authenticated access
  console.log('\n2. Authenticated API Access');
  const pkts = await request('GET', '/packets');
  assert('GET /api/packets with auth returns 200', pkts.status === 200);
  assert('Returns array', Array.isArray(pkts.body));

  const stats = await request('GET', '/stats');
  assert('GET /api/stats returns 200', stats.status === 200);
  assert('Has totalPackets', typeof stats.body.totalPackets === 'number');

  const rules = await request('GET', '/rules');
  assert('GET /api/rules returns 200', rules.status === 200);

  const assets = await request('GET', '/assets');
  assert('GET /api/assets returns 200', assets.status === 200);

  const me = await request('GET', '/auth/me');
  assert('GET /api/auth/me returns 200', me.status === 200);
  assert('Me has admin role', me.body.role === 'admin');

  // 3. State-changing operations
  console.log('\n3. State-changing Operations');

  const newPkt = await request('POST', '/packets', { count: 5 });
  assert('POST /api/packets generates packets', newPkt.status === 200);
  assert('Returns count', newPkt.body.count > 0);

  const alerts = await request('GET', '/alerts');
  assert('GET /api/alerts returns 200', alerts.status === 200);

  // 4. CSRF enforcement (POST without CSRF should fail when cookie present)
  console.log('\n4. CSRF Protection');
  const noCsrf = await request('POST', '/packets', { count: 1 });
  assert('POST with Bearer token bypasses CSRF (no cookie)', noCsrf.status === 200);

  // 5. Rate limiting
  console.log('\n5. Input Validation');
  const badAsset = await request('POST', '/assets', { name: '', ip: 'not-an-ip' });
  assert('POST /api/assets with invalid data returns 422', badAsset.status === 422);
  assert('Returns validation details', badAsset.body && badAsset.body.details);

  const badAlert = await request('PATCH', '/alerts', { alertId: '', status: 'invalid' });
  assert('PATCH /api/alerts with invalid status returns 422', badAlert.status === 422);

  // 6. 404 handling
  console.log('\n6. Edge Cases');
  const missing = await request('GET', '/assets?ip=999.999.999.999', null);
  assert('GET unknown asset returns 404', missing.status === 404);

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
  process.exit(failed > 0 ? 1 : 0);
}

run().catch(err => {
  console.error('Test failed:', err.message);
  process.exit(1);
});
