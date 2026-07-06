import { NextRequest } from 'next/server';
import { getUserFromRequest } from '@/lib/route-adapter';

export const dynamic = 'force-dynamic';

export const sseClients: { id: number; encoder: { write: (msg: string) => void }; user: any }[] = [];

export function broadcast(event: string, data: any) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach(c => { try { c.encoder.write(msg); } catch {} });
}

export async function GET(req: NextRequest) {
  const user = getUserFromRequest(req);
  if (!user) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode('data: {"type":"connected"}\n\n'));
      const client = { id: Date.now(), encoder: { write: (msg: string) => { try { controller.enqueue(encoder.encode(msg)); } catch {} } }, user };
      sseClients.push(client);
      req.signal.addEventListener('abort', () => {
        const idx = sseClients.indexOf(client);
        if (idx >= 0) sseClients.splice(idx, 1);
      });
    }
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    }
  });
}
