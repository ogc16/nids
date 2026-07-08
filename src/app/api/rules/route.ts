import { NextRequest, NextResponse } from "next/server";
import { authenticate } from "@/lib/auth";
import { schemas } from "@/lib/validate";
import { apiLimit } from "@/lib/rate-limit";
import { csrfProtection } from "@/lib/csrf";
import { handleApiError } from "@/lib/errors";
import {
  getRules,
  addRule,
  toggleRule,
  deleteRule,
  resetRules,
  loadBuiltinSignatures,
  getBuiltinSignaturesCount,
} from "@/lib/rules-engine";

export async function GET(request: NextRequest) {
  try {
    const rateCheck = apiLimit(request);
    if (rateCheck) return rateCheck;

    await authenticate(request);

    return NextResponse.json({
      rules: getRules(),
      builtinCount: getBuiltinSignaturesCount(),
    });
  } catch (err) {
    return handleApiError(err);
  }
}

export async function PUT(request: NextRequest) {
  try {
    const rateCheck = apiLimit(request);
    if (rateCheck) return rateCheck;

    await authenticate(request);

    const csrfCheck = await csrfProtection(request);
    if (csrfCheck) return csrfCheck;

    const body = await request.json().catch(() => ({}));
    const parsed = schemas.ruleCreate.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Validation failed", details: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) },
        { status: 422 }
      );
    }

    const rule = addRule(parsed.data);
    return NextResponse.json(rule, { status: 201 });
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
    const parsed = schemas.ruleToggle.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json({ error: "id required" }, { status: 400 });
    }

    const updated = toggleRule(parsed.data.id);
    if (!updated) {
      return NextResponse.json({ error: "Rule not found" }, { status: 404 });
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

    const body = await request.json().catch(() => ({}));
    const parsed = schemas.ruleDelete.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json({ error: "id required" }, { status: 400 });
    }

    const deleted = deleteRule(parsed.data.id);
    if (!deleted) {
      return NextResponse.json({ error: "Rule not found" }, { status: 404 });
    }
    return NextResponse.json({ success: true });
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
    const parsed = schemas.ruleAction.safeParse(body);

    if (parsed.success && parsed.data.action === "load-builtins") {
      const rules = loadBuiltinSignatures();
      return NextResponse.json({ success: true, count: rules.length });
    }

    if (parsed.success && parsed.data.action === "reset") {
      resetRules();
      return NextResponse.json({ success: true });
    }

    resetRules();
    return NextResponse.json({ success: true });
  } catch (err) {
    return handleApiError(err);
  }
}
