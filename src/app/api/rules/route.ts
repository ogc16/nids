import { NextRequest, NextResponse } from "next/server";
import {
  getRules,
  addRule,
  toggleRule,
  deleteRule,
  resetRules,
} from "@/lib/rules-engine";

export async function GET() {
  return NextResponse.json(getRules());
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

export async function POST() {
  resetRules();
  return NextResponse.json({ success: true });
}
