const http = require('http');

const BASE = 'http://localhost:3000/api';
let passed = 0;
let failed = 0;
let token = null;
let csrfToken = null;
let cookieJar = [];

function parseCookies(setCookieHeaders) {
  if (!setCookieHeaders) return;
  const arr = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
  for (const c of arr) {
    const parts = c.split(';')[0];
    const [name, ...valParts] = parts.split('=');
    const value = valParts.join('=');
    // Update cookie jar
    const idx = cookieJar.findIndex(ck => ck.startsWith(name + '='));
    const entry = `${name}=${value}`;
    if (idx >= 0) cookieJar[idx] = entry;
    else cookieJar.push(entry);
    if (name === 'csrf-token') csrfToken = value;
  }
}

function getCookieHeader() {
  return cookieJar.join('; ');
}

async function request(method, path, body, useToken = true) {
  return new Promise((resolve, reject) => {
    const opts = {
      method,
      hostname: 'localhost',
      port: 3000,
      path: `/api${path}`,
      headers: { 'Content-Type': 'application/json' }
    };
    if (useToken && token) opts.headers['Authorization'] = `Bearer ${token}`;
    if (useToken && csrfToken) opts.headers['X-CSRF-Token'] = csrfToken;
    const cookieHeader = getCookieHeader();
    if (cookieHeader) opts.headers['Cookie'] = cookieHeader;

    const req = http.request(opts, res => {
      parseCookies(res.headers['set-cookie']);
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data), headers: res.headers }); }
        catch { resolve({ status: res.statusCode, body: data, headers: res.headers }); }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

function assert(label, condition) {
  if (condition) { passed++; console.log(`  PASS: ${label}`); }
  else { failed++; console.log(`  FAIL: ${label} ${condition === false ? '(false)' : (condition === undefined ? '(undefined)' : '')}`); }
}

async function run() {
  console.log('\n=== NIDS Enterprise Test Suite ===\n');

  // Authenticate - handle mustChangePwd flow
  console.log('0. Authentication');
  const auth = await request('POST', '/auth/login', { username: 'admin', password: 'admin' }, false);
  assert('POST /auth/login returns 200', auth.status === 200);

  if (auth.body.mustChangePwd) {
    // First login with new admin account - must change password
    token = auth.body.tempToken;
    const changePwd = await request('POST', '/auth/change-password', { currentPassword: 'admin', newPassword: 'Test@Admin!2026Secure' }, true);
    assert('POST /auth/change-password returns 200', changePwd.status === 200);

    // Login again with new password
    const auth2 = await request('POST', '/auth/login', { username: 'admin', password: 'Test@Admin!2026Secure' }, false);
    assert('POST /auth/login after password change returns 200', auth2.status === 200);
    assert('login returns token', auth2.body && auth2.body.token);
    assert('login returns csrfToken', auth2.body && auth2.body.csrfToken);
    token = auth2.body.token;
    csrfToken = auth2.body.csrfToken;
  } else {
    assert('login returns token', auth.body && auth.body.token);
    token = auth.body.token;
    if (auth.body.csrfToken) csrfToken = auth.body.csrfToken;
  }
  console.log(`  Token: ${token.substring(0, 20)}...`);

  const me = await request('GET', '/auth/me');
  assert('GET /auth/me returns 200', me.status === 200);
  assert('me has role admin', me.body.role === 'admin');

  // Test GET all tables (paginated)
  console.log('\n1. GET all tables');
  for (const table of ['incidents', 'detection-rules', 'threat-intel', 'engineering-tasks', 'network-assets', 'qa-tests']) {
    const res = await request('GET', `/${table}?limit=100`);
    assert(`GET /${table} returns 200`, res.status === 200);
    assert(`GET /${table} returns items array`, Array.isArray(res.body.items));
  }

  // Test GET stats
  console.log('\n2. GET /stats');
  const stats = await request('GET', '/stats');
  assert('GET /stats returns 200', stats.status === 200);
  assert('stats has totalIncidents', typeof stats.body.totalIncidents === 'number');
  assert('stats has severityCounts', stats.body.severityCounts && stats.body.severityCounts.Critical >= 0);
  assert('stats has activeRules', typeof stats.body.activeRules === 'number');
  assert('stats has csfIncidentCounts', stats.body.csfIncidentCounts && typeof stats.body.csfIncidentCounts.DE === 'number');
  assert('stats has csfRuleCounts', stats.body.csfRuleCounts && typeof stats.body.csfRuleCounts.DE === 'number');

  // Test GET by ID
  console.log('\n3. GET by ID');
  const inc = await request('GET', '/incidents/1');
  assert('GET /incidents/1 returns 200', inc.status === 200);
  assert('incident has title', inc.body.title && inc.body.title.length > 0);

  const notFound = await request('GET', '/incidents/999');
  assert('GET /incidents/999 returns 404', notFound.status === 404);

  // Test POST incident
  console.log('\n4. POST new incident');
  const newInc = await request('POST', '/incidents', {
    title: 'Enterprise API test incident',
    severity: 'High',
    status: 'New',
    attackType: 'Brute Force',
    sourceIp: '10.0.0.99',
    assignee: 'Tester',
    detectedAt: new Date().toISOString(),
    cvssScore: 7.5,
    csfFunction: 'DE'
  });
  assert('POST /incidents returns 201', newInc.status === 201);
  assert('new incident has id', newInc.body.id && newInc.body.id > 0);

  // Test PUT incident
  console.log('\n5. PUT update incident');
  const updated = await request('PUT', `/incidents/${newInc.body.id}`, { status: 'Resolved', resolutionNotes: 'Enterprise test resolution' });
  assert('PUT returns 200', updated.status === 200);
  assert('status is Resolved', updated.body.status === 'Resolved');

  // Test DELETE incident
  console.log('\n6. DELETE incident');
  const deleted = await request('DELETE', `/incidents/${newInc.body.id}`);
  assert('DELETE returns 204', deleted.status === 204);

  // Test GET customer-report
  console.log('\n7. GET /customer-report');
  const report = await request('GET', '/customer-report');
  assert('customer-report returns 200', report.status === 200);
  assert('customer-report returns array', Array.isArray(report.body));

  // Test QA CRUD
  console.log('\n8. QA tests');
  const newTest = await request('POST', '/qa-tests', {
    testName: 'Enterprise QA test',
    ruleId: 1,
    status: 'Pending',
    category: 'Automation',
    tester: 'API Test',
    notes: 'Enterprise test'
  });
  assert('POST /qa-tests returns 201', newTest.status === 201);
  const qaGet = await request('GET', `/qa-tests/${newTest.body.id}`);
  assert('GET /qa-tests/:id returns 200', qaGet.status === 200);
  await request('DELETE', `/qa-tests/${newTest.body.id}`);
  const qaDel = await request('GET', `/qa-tests/${newTest.body.id}`);
  assert('Deleted qa test returns 404', qaDel.status === 404);

  // Test automations
  console.log('\n9. Automations');
  const autoLog = await request('GET', '/automations/log');
  assert('GET /automations/log returns 200', autoLog.status === 200);
  assert('automations log has items', Array.isArray(autoLog.body.items));

  const criticalAlert = await request('POST', '/automations/trigger/severity-critical');
  assert('POST critical-severity trigger returns 200', criticalAlert.status === 200);

  // Test POST detection rule
  console.log('\n10. Detection Rules');
  const newRule = await request('POST', '/detection-rules', {
    name: 'Enterprise Test Rule',
    status: 'In Development',
    protocol: 'TCP',
    threatCategory: 'Test',
    priority: 'High',
    lastUpdated: new Date().toISOString().split('T')[0],
    falsePositiveRate: 0,
    csfFunction: 'DE'
  });
  assert('POST rule returns 201', newRule.status === 201);
  await request('DELETE', `/detection-rules/${newRule.body.id}`);

  // Test auth failures
  console.log('\n11. Auth enforcement');
  const savedCsrf = csrfToken;
  const savedCookies = [...cookieJar];
  cookieJar = [];
  csrfToken = null;
  const noAuth = await request('POST', '/incidents', { title: 'should fail', severity: 'Low', status: 'New', attackType: 'Test', sourceIp: '0.0.0.0' }, false);
  assert('POST without token returns 401', noAuth.status === 401);
  cookieJar = savedCookies;
  csrfToken = savedCsrf;

  // Test CSV export
  console.log('\n12. CSV export');
  const csv = await request('GET', '/incidents/export');
  assert('GET /incidents/export returns 200', csv.status === 200);
  assert('export is CSV text', typeof csv.body === 'string');

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
  process.exit(failed > 0 ? 1 : 0);
}

run().catch(err => {
  console.error('Test failed to run:', err.message);
  console.log('Make sure the server is running (node server.js)');
  process.exit(1);
});
