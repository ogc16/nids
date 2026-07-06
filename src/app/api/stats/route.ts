import { NextRequest, NextResponse } from "next/server";
import { getTrafficStats } from "@/lib/store";
import { TimeRange } from "@/lib/types";

export async function GET(request: NextRequest) {
  const range = (request.nextUrl.searchParams.get("range") as TimeRange) || "1m";
  const stats = getTrafficStats(range);
  return NextResponse.json(stats);
}
