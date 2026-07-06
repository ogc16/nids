import { DetectionRule, AlertSeverity, Protocol } from "./types";

let rules: DetectionRule[] = [];

export function getRules(): DetectionRule[] {
  return rules;
}

export function getRuleById(id: string): DetectionRule | undefined {
  return rules.find((r) => r.id === id);
}

export function addRule(rule: Omit<DetectionRule, "id" | "createdAt">): DetectionRule {
  const newRule: DetectionRule = {
    ...rule,
    id: `rule_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    createdAt: Date.now(),
  };
  rules.push(newRule);
  return newRule;
}

export function updateRule(id: string, updates: Partial<DetectionRule>): DetectionRule | null {
  const index = rules.findIndex((r) => r.id === id);
  if (index === -1) return null;
  rules[index] = { ...rules[index], ...updates };
  return rules[index];
}

export function deleteRule(id: string): boolean {
  const index = rules.findIndex((r) => r.id === id);
  if (index === -1) return false;
  rules.splice(index, 1);
  return true;
}

export function toggleRule(id: string): DetectionRule | null {
  const rule = rules.find((r) => r.id === id);
  if (!rule) return null;
  rule.enabled = !rule.enabled;
  return rule;
}

export function resetRules(): void {
  rules = [];
}
