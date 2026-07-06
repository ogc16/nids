import { NextRequest, NextResponse } from "next/server";
import { generatePacket, generateBatch } from "@/lib/traffic";
import { evaluateBatch } from "@/lib/detection-engine";
import { getRules } from "@/lib/rules-engine";
import { addPackets, getPackets, addAlerts } from "@/lib/store";

export async function GET() {
  const packets = getPackets();
  return NextResponse.json(packets.slice(-200));
}

export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({}));
  const count = body.count || Math.floor(Math.random() * 8) + 3;

  const newPackets = generateBatch(count);
  addPackets(newPackets);

  const rules = getRules();
  const newAlerts = evaluateBatch(newPackets, rules);
  if (newAlerts.length > 0) {
    addAlerts(newAlerts);
  }

  return NextResponse.json({ count: newPackets.length, alerts: newAlerts.length });
}
