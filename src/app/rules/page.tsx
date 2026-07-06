"use client";

import { useEffect, useState } from "react";
import { DetectionRule } from "@/lib/types";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { downloadAsJson } from "@/lib/export";

export default function RulesPage() {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [builtinCount, setBuiltinCount] = useState(0);

  const fetchRules = async () => {
    try {
      const res = await fetch("/api/rules");
      const data = await res.json();
      setRules(data.rules ?? data);
      setBuiltinCount(data.builtinCount ?? 0);
    } catch {
      // Ignore
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const toggleRule = async (id: string) => {
    await fetch("/api/rules", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    fetchRules();
  };

  const deleteRule = async (id: string) => {
    await fetch("/api/rules", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    fetchRules();
  };

  const loadSignatures = async () => {
    await fetch("/api/rules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "load-builtins" }),
    });
    fetchRules();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-zinc-100">Detection Rules</h1>
          <p className="mt-1 text-sm text-zinc-500">
            {rules.filter((r) => r.enabled).length} active / {rules.length} total rules
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button variant="secondary" size="sm" onClick={() => downloadAsJson(rules, "rules")}>
            Export JSON
          </Button>
          {builtinCount > 0 && (
            <Button variant="secondary" size="sm" onClick={loadSignatures}>
              Load {builtinCount} Signatures
            </Button>
          )}
          <Button variant="primary" size="sm" onClick={() => setShowForm(!showForm)}>
            {showForm ? "Cancel" : "New Rule"}
          </Button>
        </div>
      </div>

      {showForm && (
        <Card title="Create New Rule">
          <RuleForm
            onSubmit={async (rule) => {
              await fetch("/api/rules", {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(rule),
              });
              fetchRules();
              setShowForm(false);
            }}
            onCancel={() => setShowForm(false)}
          />
        </Card>
      )}

      <div className="space-y-2">
        {rules.map((rule) => (
          <div
            key={rule.id}
            className={`rounded-xl border p-4 backdrop-blur-sm transition-colors ${
              rule.enabled
                ? "border-zinc-800 bg-zinc-900/60"
                : "border-zinc-800/50 bg-zinc-900/30 opacity-60"
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span
                    className={`inline-block h-2 w-2 rounded-full ${
                      rule.enabled ? "bg-emerald-500" : "bg-zinc-600"
                    }`}
                  />
                  <span className="text-sm font-semibold text-zinc-100">{rule.name}</span>
                  <Badge variant={rule.severity}>{rule.severity}</Badge>
                  <span className="rounded bg-zinc-800 px-2 py-0.5 text-xs text-zinc-400">
                    {rule.protocol}
                  </span>
                </div>
                <p className="mt-1 text-xs text-zinc-500">{rule.description}</p>
                <div className="mt-2 flex flex-wrap gap-3 text-xs text-zinc-600">
                  <span>
                    Pattern: <span className="font-mono text-zinc-400">{rule.pattern || "*"}</span>
                  </span>
                  <span>Category: {rule.category}</span>
                  {rule.destinationPort && <span>Port: {rule.destinationPort}</span>}
                </div>
              </div>
              <div className="ml-4 flex shrink-0 gap-2">
                <Button
                  variant={rule.enabled ? "secondary" : "primary"}
                  size="sm"
                  onClick={() => toggleRule(rule.id)}
                >
                  {rule.enabled ? "Disable" : "Enable"}
                </Button>
                <Button variant="ghost" size="sm" onClick={() => deleteRule(rule.id)}>
                  Delete
                </Button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function RuleForm({
  onSubmit,
  onCancel,
}: {
  onSubmit: (rule: Omit<DetectionRule, "id" | "createdAt">) => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [protocol, setProtocol] = useState("ANY");
  const [severity, setSeverity] = useState("medium");
  const [category, setCategory] = useState("Custom");
  const [pattern, setPattern] = useState("");
  const [destinationPort, setDestinationPort] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({
      name,
      description,
      protocol: protocol as DetectionRule["protocol"],
      severity: severity as DetectionRule["severity"],
      category,
      pattern,
      signature: "CUSTOM_" + pattern.toUpperCase().replace(/\s+/g, "_"),
      enabled: true,
      sourcePort: null,
      destinationPort: destinationPort ? parseInt(destinationPort) : null,
    });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="mb-1 block text-xs font-medium text-zinc-400">Name</label>
          <input
            required
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-emerald-500"
            placeholder="Rule name"
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-zinc-400">Protocol</label>
          <select
            value={protocol}
            onChange={(e) => setProtocol(e.target.value)}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-emerald-500"
          >
            {["ANY", "TCP", "UDP", "ICMP", "HTTP", "DNS", "HTTPS", "ARP", "DHCP"].map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-zinc-400">Severity</label>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-emerald-500"
          >
            {["critical", "high", "medium", "low"].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-zinc-400">Category</label>
          <input
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-emerald-500"
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-zinc-400">
            Destination Port (optional)
          </label>
          <input
            type="number"
            value={destinationPort}
            onChange={(e) => setDestinationPort(e.target.value)}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-emerald-500"
            placeholder="e.g. 80"
          />
        </div>
        <div className="col-span-2">
          <label className="mb-1 block text-xs font-medium text-zinc-400">Pattern</label>
          <input
            value={pattern}
            onChange={(e) => setPattern(e.target.value)}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-emerald-500"
            placeholder="Payload pattern to match (e.g. SELECT, <script>)"
          />
        </div>
        <div className="col-span-2">
          <label className="mb-1 block text-xs font-medium text-zinc-400">Description</label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-emerald-500"
            rows={2}
            placeholder="What this rule detects"
          />
        </div>
      </div>
      <div className="flex justify-end gap-3">
        <Button variant="secondary" type="button" onClick={onCancel}>
          Cancel
        </Button>
        <Button variant="primary" type="submit">
          Create Rule
        </Button>
      </div>
    </form>
  );
}
