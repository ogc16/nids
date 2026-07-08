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

    const csrfCheck = await csrfProtection(request);
    if (csrfCheck) return csrfCheck;

    const type = request.nextUrl.searchParams.get("type");

    if (type === "upload") {
      const text = await request.text();
      const start = Date.now();
      try {
        await fetch("https://speed.cloudflare.com/__up", {
          method: "PUT",
          body: text,
          headers: { "Content-Type": "application/octet-stream" },
          signal: AbortSignal.timeout(30000),
        });
      } catch {
        /* fallback */
      }
      const elapsed = Date.now() - start;
      const mbps = elapsed > 0 ? ((text.length * 8) / elapsed / 1000).toFixed(1) : "0";
      return NextResponse.json({ bytes: text.length, elapsed, mbps: Number(mbps) });
    }

    return NextResponse.json({ error: "unknown type" }, { status: 400 });
  } catch (err) {
    return handleApiError(err);
  }
}
