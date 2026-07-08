import { NextRequest } from "next/server";
import { verifyToken } from "@/lib/auth";
import { generateBatch } from "@/lib/traffic";
import { getRules } from "@/lib/rules-engine";
import { addPackets, addAlerts, getTrafficStats, getAlerts, getPackets } from "@/lib/store";
import { processBatch, getInspectionMetrics } from "@/lib/inspector";
import { getAllAssetTraffic } from "@/lib/asset-store";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

let generationTimer: ReturnType<typeof setInterval> | null = null;
let connectionCount = 0;

function startTraffic() {
  connectionCount++;
  if (generationTimer) return;
  generationTimer = setInterval(() => {
    const count = Math.floor(Math.random() * 4) + 1;
    const newPackets = generateBatch(count);
    addPackets(newPackets);
    const rules = getRules();
    const results = processBatch(newPackets, rules);
    const newAlerts = results.flatMap((r) => r.alerts);
    if (newAlerts.length > 0) addAlerts(newAlerts);
  }, 500);
}

function stopTraffic() {
  connectionCount--;
  if (connectionCount <= 0 && generationTimer) {
    clearInterval(generationTimer);
    generationTimer = null;
  }
}

export async function GET(req: NextRequest) {
  const token = req.cookies.get("nids_token")?.value
    || req.headers.get("Authorization")?.replace("Bearer ", "");

  if (!token) {
    return new Response("Unauthorized", { status: 401 });
  }

  const user = await verifyToken(token);
  if (!user) {
    return new Response("Unauthorized", { status: 401 });
  }

  const encoder = new TextEncoder();

  startTraffic();

  let statsInterval: ReturnType<typeof setInterval> | null = null;
  let cleanedUp = false;

  const cleanup = () => {
    if (cleanedUp) return;
    cleanedUp = true;
    if (statsInterval) clearInterval(statsInterval);
    stopTraffic();
  };

  const stream = new ReadableStream({
    start(controller) {
      try {
        const initialStats = getTrafficStats("1m");
        controller.enqueue(encoder.encode(`event: stats\ndata: ${JSON.stringify(initialStats)}\n\n`));
        const initialAlerts = getAlerts().slice(-100).reverse();
        controller.enqueue(encoder.encode(`event: alerts\ndata: ${JSON.stringify(initialAlerts)}\n\n`));
        const initialPackets = getPackets().slice(-100).reverse();
        controller.enqueue(encoder.encode(`event: packets\ndata: ${JSON.stringify(initialPackets)}\n\n`));
        const initialAssets = getAllAssetTraffic();
        controller.enqueue(encoder.encode(`event: assets\ndata: ${JSON.stringify(initialAssets)}\n\n`));
      } catch {
        // Ignore initial push errors
      }

      statsInterval = setInterval(() => {
        try {
          const stats = getTrafficStats("1m");
          stats.inspection = getInspectionMetrics();
          controller.enqueue(encoder.encode(`event: stats\ndata: ${JSON.stringify(stats)}\n\n`));
          const recentAlerts = getAlerts().slice(-100).reverse();
          controller.enqueue(encoder.encode(`event: alerts\ndata: ${JSON.stringify(recentAlerts)}\n\n`));
          const recentPackets = getPackets().slice(-100).reverse();
          controller.enqueue(encoder.encode(`event: packets\ndata: ${JSON.stringify(recentPackets)}\n\n`));
          const assets = getAllAssetTraffic();
          controller.enqueue(encoder.encode(`event: assets\ndata: ${JSON.stringify(assets)}\n\n`));
        } catch {
          // Ignore push errors
        }
      }, 2000);

      req.signal.addEventListener("abort", cleanup);
    },
  });

  req.signal.addEventListener("abort", cleanup);

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      "Connection": "keep-alive",
    },
  });
}
