import { NextRequest, NextResponse } from "next/server";
import { authenticate } from "@/lib/auth";
import { schemas } from "@/lib/validate";
import { apiLimit } from "@/lib/rate-limit";
import { csrfProtection } from "@/lib/csrf";
import { handleApiError } from "@/lib/errors";
import { generateBatch } from "@/lib/traffic";
import { evaluateBatch } from "@/lib/detection-engine";
import { getRules } from "@/lib/rules-engine";
import { addPackets, getPackets, addAlerts } from "@/lib/store";

export async function GET(request: NextRequest) {
  try {
    const rateCheck = apiLimit(request);
    if (rateCheck) return rateCheck;

    await authenticate(request);

    const packets = getPackets();
    return NextResponse.json(packets.slice(-200));
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

    const body = await request.json().catch(() => ({}));
    const parsed = schemas.packetGenerate.safeParse(body);
    const count = parsed.success ? parsed.data.count ?? Math.floor(Math.random() * 8) + 3 : Math.floor(Math.random() * 8) + 3;

    const newPackets = generateBatch(count);
    addPackets(newPackets);

    const rules = getRules();
    const newAlerts = evaluateBatch(newPackets, rules);
    if (newAlerts.length > 0) {
      addAlerts(newAlerts);
    }

    return NextResponse.json({ count: newPackets.length, alerts: newAlerts.length });
  } catch (err) {
    return handleApiError(err);
  }
}
