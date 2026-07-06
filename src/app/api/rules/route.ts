import { NextRequest, NextResponse } from "next/server";
import {
  getRules,
  addRule,
  toggleRule,
  deleteRule,
  resetRules,
  loadBuiltinSignatures,
  getBuiltinSignaturesCount,
} from "@/lib/rules-engine";

export async function GET() {
  return NextResponse.json({
    rules: getRules(),
    builtinCount: getBuiltinSignaturesCount(),
  });
}

export async function PUT(request: NextRequest) {
  const data = await request.json();
  const rule = addRule(data);
  return NextResponse.json(rule, { status: 201 });
}

export async function PATCH(request: NextRequest) {
  const { id } = await request.json();
  const updated = toggleRule(id);
  if (!updated) {
    return NextResponse.json({ error: "Rule not found" }, { status: 404 });
  }
  return NextResponse.json(updated);
}

export async function DELETE(request: NextRequest) {
  const { id } = await request.json();
  const deleted = deleteRule(id);
  if (!deleted) {
    return NextResponse.json({ error: "Rule not found" }, { status: 404 });
  }
  return NextResponse.json({ success: true });
}

export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({}));
  if (body.action === "load-builtins") {
    const rules = loadBuiltinSignatures();
    return NextResponse.json({ success: true, count: rules.length });
  }
  resetRules();
  return NextResponse.json({ success: true });
}
