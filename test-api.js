const http = require('http');

const BASE = 'http://localhost:3000/api';
let passed = 0;
let failed = 0;

async function request(method, path, body) {
  return new Promise((resolve, reject) => {
    const opts = {
      method,
      hostname: 'localhost',
      port: 3000,
      path: `/api${path}`,
      headers: { 'Content-Type': 'application/json' }
    };
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
  console.log('\n=== NIDS API Test Suite ===\n');

  // Test GET all tables
  console.log('1. GET all tables');
  for (const table of ['incidents', 'detection-rules', 'threat-intel', 'engineering-tasks', 'network-assets', 'qa-tests']) {
    const res = await request('GET', `/${table}`);
    assert(`GET /${table} returns 200`, res.status === 200);
    assert(`GET /${table} returns array`, Array.isArray(res.body));
  }

  // Test GET stats
  console.log('\n2. GET /stats');
  const stats = await request('GET', '/stats');
  assert('GET /stats returns 200', stats.status === 200);
  assert('stats has totalIncidents', typeof stats.body.totalIncidents === 'number');
  assert('stats has severityCounts', stats.body.severityCounts && stats.body.severityCounts.Critical >= 0);
  assert('stats has activeRules', typeof stats.body.activeRules === 'number');

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
    title: 'Test incident from API test',
    severity: 'High',
    status: 'New',
    attackType: 'Brute Force',
    sourceIp: '10.0.0.99',
    assignee: 'Tester',
    detectedAt: new Date().toISOString(),
    cvssScore: 7.5
  });
  assert('POST /incidents returns 201', newInc.status === 201);
  assert('new incident has id', newInc.body.id && newInc.body.id > 0);
  assert('new incident has cvssScore 7.5', newInc.body.cvssScore === 7.5);

  // Test PUT incident
  console.log('\n5. PUT update incident');
  const updated = await request('PUT', `/incidents/${newInc.body.id}`, {
    status: 'Resolved',
    resolutionNotes: 'Test resolution'
  });
  assert('PUT returns 200', updated.status === 200);
  assert('status is Resolved', updated.body.status === 'Resolved');

  // Test DELETE incident
  console.log('\n6. DELETE incident');
  const deleted = await request('DELETE', `/incidents/${newInc.body.id}`);
  assert('DELETE returns 204', deleted.status === 204);

  // Test GET customer report
  console.log('\n7. GET /customer-report');
  const report = await request('GET', '/customer-report');
  assert('customer-report returns 200', report.status === 200);
  assert('customer-report returns array', Array.isArray(report.body));
  if (report.body.length > 0) {
    assert('resolved incidents have cvssScore', report.body.every(i => i.cvssScore != null));
  }

  // Test QA tests CRUD
  console.log('\n8. QA tests');
  const newTest = await request('POST', '/qa-tests', {
    testName: 'Automated test case',
    ruleId: 1,
    status: 'Pending',
    category: 'Automation',
    tester: 'API Test',
    notes: 'Created during test'
  });
  assert('POST /qa-tests returns 201', newTest.status === 201);

  const qaGet = await request('GET', `/qa-tests/${newTest.body.id}`);
  assert('GET /qa-tests/:id returns 200', qaGet.status === 200);
  assert('qa test has testName', qaGet.body.testName === 'Automated test case');

  await request('DELETE', `/qa-tests/${newTest.body.id}`);
  const qaDel = await request('GET', `/qa-tests/${newTest.body.id}`);
  assert('Deleted qa test returns 404', qaDel.status === 404);

  // Test automations
  console.log('\n9. Automations');
  const autoLog = await request('GET', '/automations/log');
  assert('GET /automations/log returns 200', autoLog.status === 200);
  assert('automations log is array', Array.isArray(autoLog.body));

  const criticalAlert = await request('POST', '/automations/trigger/severity-critical');
  assert('POST critical-severity trigger returns 200', criticalAlert.status === 200);

  // Test POST detection rule
  console.log('\n10. Detection Rules');
  const newRule = await request('POST', '/detection-rules', {
    name: 'Test Rule from API',
    status: 'In Development',
    protocol: 'TCP',
    threatCategory: 'Test',
    priority: 'High',
    lastUpdated: new Date().toISOString().split('T')[0],
    falsePositiveRate: 0
  });
  assert('POST rule returns 201', newRule.status === 201);
  await request('DELETE', `/detection-rules/${newRule.body.id}`);

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
  process.exit(failed > 0 ? 1 : 0);
}

run().catch(err => {
  console.error('Test failed to run:', err.message);
  console.log('Make sure the server is running (node server.js)');
  process.exit(1);
});
