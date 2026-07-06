import { NextRequest, NextResponse } from 'next/server';
const { loginRoute } = require('@/lib/auth');
const { schemas } = require('@/lib/validate');
const { audit } = require('@/lib/audit');
const { createMockReq, createMockRes } = require('@/lib/route-adapter');

interface SchemaRule {
  required?: boolean;
  type?: string;
  minLength?: number;
  maxLength?: number;
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();

    const errors: string[] = [];
    const loginSchema = schemas.login as Record<string, SchemaRule>;
    for (const [field, rules] of Object.entries(loginSchema)) {
      const value = body[field];
      if (rules.required && (value === undefined || value === null || value === '')) {
        errors.push(`${field} is required`);
      } else if (value !== undefined && value !== null && value !== '') {
        if (rules.type === 'string' && typeof value !== 'string') {
          errors.push(`${field} must be a string`);
        }
        if (rules.minLength && typeof value === 'string' && value.length < rules.minLength) {
          errors.push(`${field} must be at least ${rules.minLength} characters`);
        }
        if (rules.maxLength && typeof value === 'string' && value.length > rules.maxLength) {
          errors.push(`${field} must be at most ${rules.maxLength} characters`);
        }
      }
    }
    if (errors.length > 0) {
      return NextResponse.json({ error: 'Validation failed', details: errors }, { status: 400 });
    }

    const req = createMockReq(request);
    req.body = body;

    audit('login_attempt', req, { username: body.username });

    const res = createMockRes();
    loginRoute(req, res);

    const response = NextResponse.json(res._getBody(), { status: res._getStatus() });
    for (const { name, value, options } of res._getCookies()) {
      response.cookies.set(name, value, options);
    }
    return response;
  } catch (err: any) {
    return NextResponse.json({ error: err.message || 'Login failed' }, { status: 500 });
  }
}
