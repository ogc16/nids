import { NextRequest, NextResponse } from "next/server";
import { authenticate } from "@/lib/auth";
import { apiLimit } from "@/lib/rate-limit";
import { handleApiError } from "@/lib/errors";
import { getTrafficStats } from "@/lib/store";
import { TimeRange } from "@/lib/types";

export async function GET(request: NextRequest) {
  try {
    const rateCheck = apiLimit(request);
    if (rateCheck) return rateCheck;

    await authenticate(request);

    const range = (request.nextUrl.searchParams.get("range") as TimeRange) || "1m";
    const stats = getTrafficStats(range);
    return NextResponse.json(stats);
  } catch (err) {
    return handleApiError(err);
  }
}
