import { NextResponse } from "next/server";

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const stores = new Map<string, Map<string, RateLimitEntry>>();

const FIVE_MINUTES = 5 * 60 * 1000;

setInterval(() => {
  const now = Date.now();
  for (const [, store] of stores) {
    for (const [key, entry] of store) {
      if (entry.resetAt <= now) {
        store.delete(key);
      }
    }
  }
}, 60_000);

export function rateLimit(
  prefix: string,
  maxRequests: number,
  windowMs: number = FIVE_MINUTES
) {
  if (!stores.has(prefix)) {
    stores.set(prefix, new Map());
  }
  const store = stores.get(prefix)!;

  return (ip: string): { success: boolean; remaining: number; resetAt: number } => {
    const now = Date.now();
    const entry = store.get(ip);

    if (!entry || entry.resetAt <= now) {
      store.set(ip, { count: 1, resetAt: now + windowMs });
      return { success: true, remaining: maxRequests - 1, resetAt: now + windowMs };
    }

    if (entry.count >= maxRequests) {
      return { success: false, remaining: 0, resetAt: entry.resetAt };
    }

    entry.count++;
    return { success: true, remaining: maxRequests - entry.count, resetAt: entry.resetAt };
  };
}

export function rateLimitMiddleware(
  request: Request,
  prefix: string,
  maxRequests: number,
  windowMs?: number
): NextResponse | null {
  const limiter = rateLimit(prefix, maxRequests, windowMs);
  const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || request.headers.get("x-real-ip")
    || "127.0.0.1";
  const result = limiter(ip);

  if (!result.success) {
    const retryAfter = Math.ceil((result.resetAt - Date.now()) / 1000);
    return NextResponse.json(
      { error: "Too many requests. Please try again later." },
      {
        status: 429,
        headers: {
          "Retry-After": String(retryAfter),
          "X-RateLimit-Remaining": "0",
        },
      }
    );
  }

  return null;
}

export const globalLimit = rateLimitMiddleware;
export const apiLimit = (req: Request) => rateLimitMiddleware(req, "api", 100);
export const authLimit = (req: Request) => rateLimitMiddleware(req, "auth", 20, 5 * 60 * 1000);
export const streamLimit = (req: Request) => rateLimitMiddleware(req, "stream", 10);
