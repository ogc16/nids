import { NextRequest, NextResponse } from 'next/server';
import { getUserFromRequest } from '@/lib/route-adapter';
import db from '@/lib/db';
import { sseClients } from '@/app/api/events/route';

export const dynamic = 'force-dynamic';

function broadcast(event: string, data: any) {
  const message = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try { client.encoder.write(message); } catch {}
  }
}

const PROTOCOLS = ['HTTPS', 'HTTP', 'DNS', 'SSH', 'SMB', 'RDP', 'TCP', 'SMTP', 'NTP', 'MODBUS'];
const APPS = ['Web', 'DNS', 'Remote Access', 'File Sharing', 'Email', 'Infrastructure', 'SCADA', 'P2P'];
const STATUSES = ['allowed', 'allowed', 'allowed', 'blocked', 'suspicious'];
const COUNTRIES = ['US', 'US', 'US', 'CN', 'RU', 'DE', 'FR', 'GB', 'NL', 'BR'];
const HTTP_METHODS = ['GET', 'GET', 'GET', 'GET', 'POST', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'];
const HTTP_URIS = ['/api/users', '/api/incidents', '/api/dashboard', '/login', '/api/search', '/index.html', '/api/assets', '/api/reports', '/api/settings', '/api/auth/login', '/api/traffic', '/api/rules', '/api/threat-intel', '/api/tasks', '/css/styles.css', '/js/app.js', '/api/health', '/api/metrics'];
const HTTP_HOSTS = ['app.internal.local', 'api.internal.local', 'dashboard.internal.local', 'login.internal.local', 'cdn.internal.local', 's3.internal.local'];
const HTTP_USER_AGENTS = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14) Safari/17', 'curl/8.4', 'python-requests/2.31', 'Mozilla/5.0 (X11; Linux x86_64) Firefox/126', 'Go-http-client/2.0'];
const HTTP_CONTENT_TYPES = ['application/json', 'text/html', 'text/css', 'application/javascript', 'image/png', 'application/octet-stream', 'text/plain', 'multipart/form-data'];

function generateHttpFields(protocol: string) {
  if (protocol !== 'HTTP' && protocol !== 'HTTPS') {
    return { httpMethod: null, httpUri: null, httpStatus: null, httpHost: null, httpUserAgent: null, httpContentType: null };
  }
  const method = HTTP_METHODS[Math.floor(Math.random() * HTTP_METHODS.length)];
  const uri = HTTP_URIS[Math.floor(Math.random() * HTTP_URIS.length)];
  const statuses = method === 'POST' ? [200, 201, 400, 401, 500] : method === 'DELETE' ? [200, 204, 404, 500] : method === 'PUT' ? [200, 201, 400, 500] : HTTP_STATUSES;
  return {
    httpMethod: method,
    httpUri: uri,
    httpStatus: statuses[Math.floor(Math.random() * statuses.length)],
    httpHost: HTTP_HOSTS[Math.floor(Math.random() * HTTP_HOSTS.length)],
    httpUserAgent: HTTP_USER_AGENTS[Math.floor(Math.random() * HTTP_USER_AGENTS.length)],
    httpContentType: HTTP_CONTENT_TYPES[Math.floor(Math.random() * HTTP_CONTENT_TYPES.length)]
  };
}
const HTTP_STATUSES = [200, 200, 200, 200, 200, 200, 200, 201, 301, 302, 304, 400, 401, 403, 404, 404, 404, 500, 502, 503];

export async function POST(req: NextRequest) {
  const user = getUserFromRequest(req);
  if (!user || (user.role !== 'admin' && user.role !== 'analyst')) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
  }
  const assets = db.readTable('network-assets');
  if (assets.length === 0) return NextResponse.json({ error: 'No assets found. Add an asset first.' }, { status: 400 });
  const asset = assets[Math.floor(Math.random() * assets.length)];
  const isExternal = Math.random() > 0.5;
  const protocol = PROTOCOLS[Math.floor(Math.random() * PROTOCOLS.length)];
  const flow: any = {
    id: db.nextId(db.readTable('network-traffic')),
    srcIp: isExternal ? `${Math.floor(Math.random() * 223 + 1)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}` : asset.ipRange.split('/')[0],
    destIp: isExternal ? asset.ipRange.split('/')[0] : `${Math.floor(Math.random() * 223 + 1)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
    srcPort: Math.floor(Math.random() * 60000 + 1024),
    destPort: protocol === 'HTTP' ? 80 : protocol === 'HTTPS' ? 443 : [22, 53, 445, 3389, 25, 123, 8080, 8443][Math.floor(Math.random() * 8)],
    protocol,
    bytes: Math.floor(Math.random() * 10000000 + 500),
    packets: Math.floor(Math.random() * 8000 + 10),
    duration: parseFloat((Math.random() * 300 + 0.1).toFixed(1)),
    timestamp: new Date().toISOString(),
    status: STATUSES[Math.floor(Math.random() * STATUSES.length)],
    application: APPS[Math.floor(Math.random() * APPS.length)],
    assetId: asset.id,
    ruleId: Math.random() > 0.7 ? Math.floor(Math.random() * 10 + 1) : null,
    country: COUNTRIES[Math.floor(Math.random() * COUNTRIES.length)],
    ...generateHttpFields(protocol)
  };
  const traffic = db.readTable('network-traffic');
  traffic.push(flow);
  db.writeTable('network-traffic', traffic);
  const audit = (await import('@/lib/audit')).audit;
  audit('traffic_simulated', { user: user.username, ip: req.headers.get('x-forwarded-for') || req.headers.get('x-real-ip') || 'unknown' }, { flowId: flow.id });
  broadcast('traffic-flow', flow);
  if (flow.status === 'suspicious' || flow.status === 'blocked') {
    try {
      const automations = await import('@/lib/automations');
      if (automations.logAutomation) automations.logAutomation('realtime_traffic_alert', {
        message: `${flow.status.toUpperCase()} traffic: ${flow.srcIp}:${flow.srcPort} -> ${flow.destIp}:${flow.destPort} (${flow.protocol})`,
        srcIp: flow.srcIp, destIp: flow.destIp, protocol: flow.protocol, status: flow.status
      });
    } catch {}
  }
  return NextResponse.json(flow, { status: 201 });
}
