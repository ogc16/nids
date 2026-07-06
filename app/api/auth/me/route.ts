import { NextRequest, NextResponse } from 'next/server';
const { readUsers } = require('@/lib/auth');
const { getUserFromRequest } = require('@/lib/route-adapter');

export async function GET(request: NextRequest) {
  const user = getUserFromRequest(request);
  if (!user) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
  }

  const users = readUsers();
  const found = users.find((u: any) => u.id === user.id);
  if (!found) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 });
  }

  return NextResponse.json({
    id: found.id,
    username: found.username,
    role: found.role,
    displayName: found.displayName,
    email: found.email,
    createdAt: found.createdAt,
    lastLogin: found.lastLogin,
    mustChangePwd: found.mustChangePwd || false
  });
}
