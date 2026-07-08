import { NextRequest, NextResponse } from "next/server";
import { authenticate } from "@/lib/auth";
import { schemas } from "@/lib/validate";
import { apiLimit } from "@/lib/rate-limit";
import { csrfProtection } from "@/lib/csrf";
import { handleApiError } from "@/lib/errors";
import { getAlerts, updateAlertStatus, clearAlerts } from "@/lib/store";

export async function GET(request: NextRequest) {
  try {
    const rateCheck = apiLimit(request);
    if (rateCheck) return rateCheck;

    await authenticate(request);

    const alerts = getAlerts();
    return NextResponse.json(alerts.slice(-100).reverse());
  } catch (err) {
    return handleApiError(err);
  }
}

export async function PATCH(request: NextRequest) {
  try {
    const rateCheck = apiLimit(request);
    if (rateCheck) return rateCheck;

    await authenticate(request);

    const csrfCheck = await csrfProtection(request);
    if (csrfCheck) return csrfCheck;

    const body = await request.json().catch(() => ({}));
    const parsed = schemas.alertUpdate.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Validation failed", details: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) },
        { status: 422 }
      );
    }

    const { alertId, status } = parsed.data;
    const updated = updateAlertStatus(alertId, status);
    if (!updated) {
      return NextResponse.json({ error: "Alert not found" }, { status: 404 });
    }
    return NextResponse.json(updated);
  } catch (err) {
    return handleApiError(err);
  }
}

export async function DELETE(request: NextRequest) {
  try {
    const rateCheck = apiLimit(request);
    if (rateCheck) return rateCheck;

    await authenticate(request);

    const csrfCheck = await csrfProtection(request);
    if (csrfCheck) return csrfCheck;

    clearAlerts();
    return NextResponse.json({ success: true });
  } catch (err) {
    return handleApiError(err);
  }
}
