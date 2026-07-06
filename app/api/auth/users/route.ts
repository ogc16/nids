import { NextRequest, NextResponse } from 'next/server';
const { createUserRoute, readUsers } = require('@/lib/auth');
const { createMockReq, createMockRes, getUserFromRequest } = require('@/lib/route-adapter');
const { schemas } = require('@/lib/validate');

interface SchemaRule {
  required?: boolean;
  type?: string;
  minLength?: number;
  maxLength?: number;
}

export async function GET(request: NextRequest) {
  const user = getUserFromRequest(request);
  if (!user) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
  }
  if (user.role !== 'admin') {
    return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
  }

  const users = readUsers();
  return NextResponse.json(
    users.map((u: any) => ({
      id: u.id,
      username: u.username,
      role: u.role,
      displayName: u.displayName,
      email: u.email,
      createdAt: u.createdAt,
      lastLogin: u.lastLogin
    }))
  );
}

export async function POST(request: NextRequest) {
  const user = getUserFromRequest(request);
  if (!user) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
  }
  if (user.role !== 'admin') {
    return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
  }

  try {
    const body = await request.json();

    const errors: string[] = [];
    const loginSchema = schemas.login as Record<string, SchemaRule>;
    for (const [field, rules] of Object.entries(loginSchema)) {
      const value = body[field];
      if (rules.required && (value === undefined || value === null || value === '')) {
        errors.push(`${field} is required`);
      } else if (value !== undefined && value !== null && value !== '') {
        if (rules.type === 'string' && typeof value !== 'string') errors.push(`${field} must be a string`);
        if (rules.minLength && typeof value === 'string' && value.length < rules.minLength) errors.push(`${field} must be at least ${rules.minLength} characters`);
        if (rules.maxLength && typeof value === 'string' && value.length > rules.maxLength) errors.push(`${field} must be at most ${rules.maxLength} characters`);
      }
    }
    if (errors.length > 0) {
      return NextResponse.json({ error: 'Validation failed', details: errors }, { status: 400 });
    }

    const req = createMockReq(request);
    req.body = body;
    req.user = user;

    const res = createMockRes();
    createUserRoute(req, res, (err: any) => { throw err; });

    return NextResponse.json(res._getBody(), { status: res._getStatus() });
  } catch (err: any) {
    if (err.isOperational) {
      return NextResponse.json({ error: err.message }, { status: err.statusCode || 400 });
    }
    return NextResponse.json({ error: err.message || 'Failed to create user' }, { status: 500 });
  }
}
