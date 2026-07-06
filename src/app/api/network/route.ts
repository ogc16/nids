import { NextRequest, NextResponse } from "next/server";

export async function GET(request: NextRequest) {
  const type = request.nextUrl.searchParams.get("type");

  if (type === "download") {
    const size = Math.min(Number(request.nextUrl.searchParams.get("size")) || 1_048_576, 10_485_760);
    const buf = Buffer.alloc(size, 0x61);
    return new NextResponse(buf, {
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": String(size),
        "Cache-Control": "no-store",
      },
    });
  }

  if (type === "latency") {
    return NextResponse.json({ t: Date.now() });
  }

  const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || request.headers.get("x-real-ip")
    || "127.0.0.1";

  return NextResponse.json({ ip });
}

export async function POST(request: NextRequest) {
  const type = request.nextUrl.searchParams.get("type");

  if (type === "upload") {
    const start = Date.now();
    const text = await request.text();
    const elapsed = Date.now() - start;
    const mbps = elapsed > 0 ? ((text.length * 8) / elapsed / 1000).toFixed(1) : "0";
    return NextResponse.json({ bytes: text.length, elapsed, mbps: Number(mbps) });
  }

  return NextResponse.json({ error: "unknown type" }, { status: 400 });
}
