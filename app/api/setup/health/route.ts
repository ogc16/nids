import { NextResponse } from 'next/server';
const config = require('@/lib/config');

export const dynamic = 'force-dynamic';

export async function GET() {
  return NextResponse.json({
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    memory: process.memoryUsage(),
    version: config.version || '2.0.0',
    node: process.version
  });
}
