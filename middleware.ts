import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { jwtVerify } from 'jose';

const JWT_SECRET = new TextEncoder().encode(
  process.env.JWT_SECRET || 'nids-enterprise-secret-change-in-production'
);
const COOKIE_NAME = 'nids_token';
const CSRF_COOKIE = 'csrf-token';
const CORS_ORIGIN =
  process.env.CORS_ORIGIN ||
  (process.env.NODE_ENV === 'production'
    ? 'http://localhost:3000'
    : '*');
const RATE_LIMIT_WINDOW_MS = parseInt(
  process.env.RATE_LIMIT_WINDOW_MS || '60000',
  10
);
const GENERAL_RATE_LIMIT_MAX =
  parseInt(process.env.RATE_LIMIT_MAX || '100', 10) * 5;
const API_RATE_LIMIT_MAX = parseInt(
  process.env.RATE_LIMIT_MAX || '100',
  10
);
const AUTH_RATE_LIMIT_MAX = parseInt(
  process.env.AUTH_RATE_LIMIT_MAX || '10',
  10
);
const COOKIE_MAX_AGE = 8 * 3600;

const PUBLIC_PATHS = ['/login', '/_next/'];

interface RateEntry {
  count: number;
  windowStart: number;
}

const rateLimitMap = new Map<string, RateEntry>();

function getClientIp(request: NextRequest): string {
  const forwarded = request.headers.get('x-forwarded-for');
  if (forwarded) return forwarded.split(',')[0].trim();
  return request.headers.get('x-real-ip') ?? 'unknown';
}

function generateCsrfToken(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('');
}

function checkRateLimit(
  key: string,
  max: number,
  windowMs: number
): { allowed: boolean; remaining: number } {
  const now = Date.now();
  let entry = rateLimitMap.get(key);
  if (!entry || now - entry.windowStart > windowMs) {
    entry = { count: 0, windowStart: now };
    rateLimitMap.set(key, entry);
  }
  entry.count++;
  return {
    allowed: entry.count <= max,
    remaining: Math.max(0, max - entry.count),
  };
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const method = request.method;

  const response = NextResponse.next();

  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-XSS-Protection', '1; mode=block');
  response.headers.set('Referrer-Policy', 'same-origin');
  response.headers.set(
    'Access-Control-Allow-Origin',
    CORS_ORIGIN
  );
  response.headers.set(
    'Access-Control-Allow-Methods',
    'GET, POST, PUT, DELETE, OPTIONS'
  );
  response.headers.set(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, X-CSRF-Token'
  );
  response.headers.set('Access-Control-Allow-Credentials', 'true');

  if (method === 'OPTIONS') {
    return new NextResponse(null, {
      status: 204,
      headers: Object.fromEntries(response.headers),
    });
  }

  if (PUBLIC_PATHS.some((p) => pathname.startsWith(p))) {
    return response;
  }

  let rateLimitKey: string;
  let rateLimitMax: number;
  if (pathname.startsWith('/api/auth/')) {
    rateLimitKey = `auth:${getClientIp(request)}`;
    rateLimitMax = AUTH_RATE_LIMIT_MAX;
  } else if (pathname.startsWith('/api/')) {
    rateLimitKey = `api:${getClientIp(request)}`;
    rateLimitMax = API_RATE_LIMIT_MAX;
  } else {
    rateLimitKey = `gen:${getClientIp(request)}`;
    rateLimitMax = GENERAL_RATE_LIMIT_MAX;
  }

  const { allowed, remaining } = checkRateLimit(
    rateLimitKey,
    rateLimitMax,
    RATE_LIMIT_WINDOW_MS
  );
  response.headers.set('X-RateLimit-Limit', String(rateLimitMax));
  response.headers.set(
    'X-RateLimit-Remaining',
    String(remaining)
  );
  response.headers.set(
    'X-RateLimit-Reset',
    String(Math.ceil((Date.now() + RATE_LIMIT_WINDOW_MS) / 1000))
  );

  if (!allowed) {
    return NextResponse.json(
      { error: 'Too many requests' },
      {
        status: 429,
        headers: {
          'Retry-After': String(
            Math.ceil(RATE_LIMIT_WINDOW_MS / 1000)
          ),
        },
      }
    );
  }

  const token = request.cookies.get(COOKIE_NAME)?.value;
  let user: {
    id: number;
    username: string;
    role: string;
    mustChangePwd?: boolean;
  } | null = null;

  if (token) {
    try {
      const { payload } = await jwtVerify(token, JWT_SECRET);
      user = {
        id: payload.id as number,
        username: payload.username as string,
        role: payload.role as string,
      };
    } catch {
      /* token expired or invalid */
    }
  }

  if (
    user &&
    !request.cookies.get(CSRF_COOKIE)?.value
  ) {
    const newCsrf = generateCsrfToken();
    response.cookies.set(CSRF_COOKIE, newCsrf, {
      httpOnly: false,
      sameSite: 'strict',
      maxAge: COOKIE_MAX_AGE,
      path: '/',
    });
  }

  const csrfSkipPaths = ['/api/auth/login', '/api/auth/change-password'];
  if (
    !csrfSkipPaths.some((p) => pathname.startsWith(p)) &&
    !['GET', 'HEAD', 'OPTIONS'].includes(method)
  ) {
    const csrfHeader = request.headers.get('x-csrf-token');
    const csrfCookie = request.cookies.get(CSRF_COOKIE)?.value;
    if (!csrfCookie || !csrfHeader || csrfHeader !== csrfCookie) {
      return NextResponse.json(
        { error: 'Invalid CSRF token' },
        { status: 403 }
      );
    }
  }

  if (user) {
    response.headers.set(
      'X-User',
      Buffer.from(JSON.stringify(user)).toString('base64')
    );
  }

  if (!pathname.startsWith('/api/') && !user) {
    const loginUrl = new URL('/login', request.url);
    return NextResponse.redirect(loginUrl);
  }

  return response;
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
