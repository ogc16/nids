import { NextRequest, NextResponse } from "next/server";
import { getAssets, getAssetById, addAsset, updateAsset, deleteAsset, getAllAssetTraffic } from "@/lib/asset-store";

export async function GET(request: NextRequest) {
  const ip = request.nextUrl.searchParams.get("ip");
  const id = request.nextUrl.searchParams.get("id");
  const withTraffic = request.nextUrl.searchParams.get("traffic") === "true";

  if (ip) {
    const { getAssetByIp } = await import("@/lib/asset-store");
    const asset = getAssetByIp(ip);
    if (!asset) return NextResponse.json({ error: "Asset not found" }, { status: 404 });
    return NextResponse.json(asset);
  }

  if (id) {
    const asset = getAssetById(id);
    if (!asset) return NextResponse.json({ error: "Asset not found" }, { status: 404 });
    return NextResponse.json(asset);
  }

  if (withTraffic) {
    const all = getAllAssetTraffic();
    return NextResponse.json(all);
  }

  return NextResponse.json(getAssets());
}

export async function POST(request: NextRequest) {
  const data = await request.json();
  const asset = addAsset(data);
  return NextResponse.json(asset, { status: 201 });
}

export async function PATCH(request: NextRequest) {
  const { id, ...updates } = await request.json();
  if (!id) return NextResponse.json({ error: "id required" }, { status: 400 });
  const updated = updateAsset(id, updates);
  if (!updated) return NextResponse.json({ error: "Asset not found" }, { status: 404 });
  return NextResponse.json(updated);
}

export async function DELETE(request: NextRequest) {
  const { id } = await request.json();
  if (!id) return NextResponse.json({ error: "id required" }, { status: 400 });
  const deleted = deleteAsset(id);
  if (!deleted) return NextResponse.json({ error: "Asset not found" }, { status: 404 });
  return NextResponse.json({ success: true });
}
