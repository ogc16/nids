const config = require('./config');

function createMockReq(request, params = {}) {
  const headers = Object.fromEntries(request.headers);
  return {
    body: null,
    headers,
    cookies: Object.fromEntries(request.cookies.getAll().map(c => [c.name, c.value])),
    method: request.method,
    url: request.nextUrl.pathname,
    originalUrl: request.nextUrl.pathname,
    secure: request.nextUrl.protocol === 'https:',
    ip: request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || request.headers.get('x-real-ip') || '127.0.0.1',
    connection: { remoteAddress: '127.0.0.1' },
    params
  };
}

function createMockRes() {
  let statusCode = 200;
  let responseBody = null;
  const cookies = [];

  return {
    _getStatus() { return statusCode; },
    _getBody() { return responseBody; },
    _getCookies() { return cookies; },
    status(code) { statusCode = code; return this; },
    json(body) { responseBody = body; return this; },
    send(body) {
      if (body !== undefined) responseBody = body;
      if (statusCode === 204) responseBody = null;
      return this;
    },
    cookie(name, value, options) {
      cookies.push({ name, value, options });
      return this;
    },
    clearCookie(name, options) {
      cookies.push({ name, value: '', options: { ...options, maxAge: 0 } });
      return this;
    },
    setHeader() { return this; },
    end() { return this; }
  };
}

function getUserFromRequest(request) {
  const header = request.headers.get('x-user');
  if (!header) return null;
  try {
    return JSON.parse(Buffer.from(header, 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

module.exports = { createMockReq, createMockRes, getUserFromRequest };
