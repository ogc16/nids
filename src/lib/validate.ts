import { z } from "zod/v4";
import { NextRequest, NextResponse } from "next/server";

const protocols = ["TCP", "UDP", "ICMP", "HTTP", "DNS", "HTTPS", "ARP", "DHCP"] as const;
const severities = ["critical", "high", "medium", "low"] as const;
const alertStatuses = ["new", "investigating", "resolved", "dismissed"] as const;
const assetTypes = ["server", "workstation", "database", "firewall", "router", "service", "other"] as const;
const assetCriticalities = ["critical", "high", "medium", "low"] as const;

export const schemas = {
  login: z.object({
    username: z.string().min(1).max(100),
    password: z.string().min(1).max(256),
  }),

  changePassword: z.object({
    currentPassword: z.string().min(1).max(256),
    newPassword: z.string().min(8).max(256),
  }),

  packetGenerate: z.object({
    count: z.number().int().min(1).max(100).optional(),
  }),

  alertUpdate: z.object({
    alertId: z.string().min(1),
    status: z.enum(alertStatuses),
  }),

  ruleCreate: z.object({
    name: z.string().min(1).max(200),
    description: z.string().max(1000).optional().default(""),
    signature: z.string().min(1).max(100),
    protocol: z.enum([...protocols, "ANY"] as const),
    severity: z.enum(severities),
    category: z.string().max(100).optional().default("General"),
    sourcePort: z.number().int().min(0).max(65535).nullable().optional().default(null),
    destinationPort: z.number().int().min(0).max(65535).nullable().optional().default(null),
    pattern: z.string().min(1).max(500),
    enabled: z.boolean().optional().default(true),
  }),

  ruleToggle: z.object({
    id: z.string().min(1),
  }),

  ruleDelete: z.object({
    id: z.string().min(1),
  }),

  ruleAction: z.object({
    action: z.enum(["load-builtins", "reset"]).optional(),
  }),

  assetCreate: z.object({
    name: z.string().min(1).max(200),
    nickname: z.string().max(200).optional().default(""),
    ip: z.string().regex(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/),
    type: z.enum(assetTypes).optional().default("other"),
    group: z.string().max(100).optional().default("Default"),
    tags: z.array(z.string().max(50)).optional().default([]),
    criticality: z.enum(assetCriticalities).optional().default("medium"),
    description: z.string().max(1000).optional().default(""),
  }),

  assetUpdate: z.object({
    id: z.string().min(1),
    name: z.string().min(1).max(200).optional(),
    nickname: z.string().max(200).optional(),
    ip: z.string().regex(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/).optional(),
    type: z.enum(assetTypes).optional(),
    group: z.string().max(100).optional(),
    tags: z.array(z.string().max(50)).optional(),
    criticality: z.enum(assetCriticalities).optional(),
    description: z.string().max(1000).optional(),
  }),

  assetDelete: z.object({
    id: z.string().min(1),
  }),
};

export function validate(schema: z.ZodSchema) {
  return async (request: NextRequest): Promise<{ data: unknown; error: NextResponse | null }> => {
    try {
      const body = await request.json().catch(() => ({}));
      const data = schema.parse(body);
      return { data, error: null };
    } catch (err) {
      if (err instanceof z.ZodError) {
        return {
          data: null,
          error: NextResponse.json(
            { error: "Validation failed", details: err.issues.map((e) => ({ path: e.path.join("."), message: e.message })) },
            { status: 422 }
          ),
        };
      }
      return {
        data: null,
        error: NextResponse.json({ error: "Invalid request body" }, { status: 400 }),
      };
    }
  };
}
