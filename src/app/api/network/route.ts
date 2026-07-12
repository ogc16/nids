import { NextRequest, NextResponse } from "next/server";
import { authenticate } from "@/lib/auth";
import { apiLimit } from "@/lib/rate-limit";
import { csrfProtection } from "@/lib/csrf";
import { handleApiError } from "@/lib/errors";

export async function GET(request: NextRequest) {
  try {
    const rateCheck = apiLimit(request);
    if (rateCheck) return rateCheck;

    await authenticate(request);

    const localIp = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
      || request.headers.get("x-real-ip")
      || "127.0.0.1";

    let publicIp = "";
    try {
      const res = await fetch("https://api.ipify.org?format=json", { signal: AbortSignal.timeout(3000) });
      const data = await res.json() as { ip: string };
      publicIp = data.ip;
    } catch {
      /* ipify unavailable */
    }

    return NextResponse.json({ ip: localIp, publicIp });
  } catch (err) {
    return handleApiError(err);
  }
}

export async function POST(request: NextRequest) {
  try {
    const rateCheck = apiLimit(request);
    if (rateCheck) return rateCheck;

    await authenticate(request);

    const type = request.nextUrl.searchParams.get("type");

    if (type === "upload") {
      const buffer = await request.arrayBuffer();
      const size = buffer.byteLength;
      const t0 = performance.now();
      try {
        await fetch("https://speed.cloudflare.com/__up", {
          method: "POST",
          body: buffer,
          signal: AbortSignal.timeout(30000),
        });
      } catch {
        /* Cloudflare unreachable, still measure client->server time */
      }
      const elapsed = performance.now() - t0;
      if (elapsed <= 0) return NextResponse.json({ bytes: size, elapsed: 0, mbps: 0 });
      const mbps = parseFloat(((size * 8) / elapsed / 1000).toFixed(1));
      return NextResponse.json({ bytes: size, elapsed: Math.round(elapsed), mbps });
    }

    return NextResponse.json({ error: "unknown type" }, { status: 400 });
  } catch (err) {
    return handleApiError(err);
  }
}
