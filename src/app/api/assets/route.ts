import { NextRequest, NextResponse } from "next/server";
import { authenticate } from "@/lib/auth";
import { schemas } from "@/lib/validate";
import { apiLimit } from "@/lib/rate-limit";
import { csrfProtection } from "@/lib/csrf";
import { handleApiError } from "@/lib/errors";
import { getAssets, getAssetById, addAsset, updateAsset, deleteAsset, getAllAssetTraffic } from "@/lib/asset-store";

export async function GET(request: NextRequest) {
  try {
    const rateCheck = apiLimit(request);
    if (rateCheck) return rateCheck;

    await authenticate(request);

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
    const parsed = schemas.assetCreate.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Validation failed", details: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) },
        { status: 422 }
      );
    }

    const asset = addAsset(parsed.data);
    return NextResponse.json(asset, { status: 201 });
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
    const parsed = schemas.assetUpdate.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Validation failed", details: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) },
        { status: 422 }
      );
    }

    const { id, ...updates } = parsed.data;
    const updated = updateAsset(id, updates);
    if (!updated) return NextResponse.json({ error: "Asset not found" }, { status: 404 });
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
    const parsed = schemas.assetDelete.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json({ error: "id required" }, { status: 400 });
    }

    const deleted = deleteAsset(parsed.data.id);
    if (!deleted) return NextResponse.json({ error: "Asset not found" }, { status: 404 });
    return NextResponse.json({ success: true });
  } catch (err) {
    return handleApiError(err);
  }
}
