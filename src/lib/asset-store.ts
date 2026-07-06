import { NetworkAsset, AssetTraffic } from "./types";
import { getPackets, getAlerts } from "./store";

let idCounter = 0;

function generateId(): string {
  idCounter++;
  return `asset_${Date.now()}_${idCounter}`;
}

let assets: NetworkAsset[] = [];

export function getAssets(): NetworkAsset[] {
  return assets;
}

export function getAssetById(id: string): NetworkAsset | undefined {
  return assets.find((a) => a.id === id);
}

export function getAssetByIp(ip: string): NetworkAsset | undefined {
  return assets.find((a) => a.ip === ip);
}

function ensureDiscovered(ip: string): NetworkAsset {
  const existing = getAssetByIp(ip);
  if (existing) return existing;

  const asset: NetworkAsset = {
    id: generateId(),
    name: ip,
    nickname: "",
    ip,
    type: "other",
    group: "Discovered",
    tags: [],
    criticality: "medium",
    description: "Auto-discovered from network traffic",
    createdAt: Date.now(),
  };
  assets.push(asset);
  return asset;
}

export function addAsset(
  data: Omit<NetworkAsset, "id" | "createdAt">
): NetworkAsset {
  const asset: NetworkAsset = {
    ...data,
    id: generateId(),
    createdAt: Date.now(),
  };
  assets.push(asset);
  return asset;
}

export function updateAsset(
  id: string,
  updates: Partial<NetworkAsset>
): NetworkAsset | null {
  const idx = assets.findIndex((a) => a.id === id);
  if (idx === -1) return null;
  assets[idx] = { ...assets[idx], ...updates };
  return assets[idx];
}

export function deleteAsset(id: string): boolean {
  const idx = assets.findIndex((a) => a.id === id);
  if (idx === -1) return false;
  assets.splice(idx, 1);
  return true;
}

export function getAssetTraffic(assetIp: string): AssetTraffic {
  const packets = getPackets();
  const asset = getAssetByIp(assetIp);
  if (!asset) {
    return { assetId: "", totalPackets: 0, incomingPackets: 0, outgoingPackets: 0,
      totalAlerts: 0, bytesIn: 0, bytesOut: 0, protocols: {}, topTalkers: [], lastSeen: 0 };
  }

  const assetPackets = packets.filter((p) => p.srcIp === assetIp || p.dstIp === assetIp);

  if (assetPackets.length === 0) {
    return { assetId: asset.id, totalPackets: 0, incomingPackets: 0, outgoingPackets: 0,
      totalAlerts: 0, bytesIn: 0, bytesOut: 0, protocols: {}, topTalkers: [], lastSeen: 0 };
  }

  const incoming = assetPackets.filter((p) => p.dstIp === assetIp);
  const outgoing = assetPackets.filter((p) => p.srcIp === assetIp);
  const protocols: Record<string, number> = {};
  const talkers = new Map<string, number>();

  let lastSeen = 0;
  for (const p of assetPackets) {
    protocols[p.protocol] = (protocols[p.protocol] || 0) + 1;
    const peer = p.srcIp === assetIp ? p.dstIp : p.srcIp;
    talkers.set(peer, (talkers.get(peer) || 0) + 1);
    if (p.timestamp > lastSeen) lastSeen = p.timestamp;
  }

  const assetAlerts = getAlerts().filter(
    (a) => a.sourceIp === assetIp || a.destinationIp === assetIp
  );

  return {
    assetId: asset.id,
    totalPackets: assetPackets.length,
    incomingPackets: incoming.length,
    outgoingPackets: outgoing.length,
    totalAlerts: assetAlerts.length,
    bytesIn: incoming.reduce((s, p) => s + p.length, 0),
    bytesOut: outgoing.reduce((s, p) => s + p.length, 0),
    protocols,
    topTalkers: [...talkers.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([ip, count]) => ({ ip, count })),
    lastSeen,
  };
}

function scanNetwork(): void {
  const packets = getPackets();
  const seen = new Set<string>();
  for (const p of packets) {
    if (!seen.has(p.srcIp)) { seen.add(p.srcIp); ensureDiscovered(p.srcIp); }
    if (!seen.has(p.dstIp)) { seen.add(p.dstIp); ensureDiscovered(p.dstIp); }
  }
}

export function getAllAssetTraffic(): (AssetTraffic & { asset: NetworkAsset })[] {
  scanNetwork();
  return assets.map((a) => ({
    asset: a,
    ...getAssetTraffic(a.ip),
  }));
}
