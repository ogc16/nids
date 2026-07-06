import { NextRequest, NextResponse } from "next/server";
import { getAlerts, updateAlertStatus, clearAlerts } from "@/lib/store";

export async function GET() {
  const alerts = getAlerts();
  return NextResponse.json(alerts.slice(-100).reverse());
}

export async function PATCH(request: NextRequest) {
  const { alertId, status } = await request.json();
  const updated = updateAlertStatus(alertId, status);
  if (!updated) {
    return NextResponse.json({ error: "Alert not found" }, { status: 404 });
  }
  return NextResponse.json(updated);
}

export async function DELETE() {
  clearAlerts();
  return NextResponse.json({ success: true });
}
