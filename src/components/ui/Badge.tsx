import { AlertSeverity, AlertStatus } from "@/lib/types";

interface BadgeProps {
  variant: AlertSeverity | AlertStatus | "info" | "success" | "warning" | "error";
  children: string;
}

const variantStyles: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  new: "bg-red-500/15 text-red-400 border-red-500/30",
  investigating: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  resolved: "bg-green-500/15 text-green-400 border-green-500/30",
  dismissed: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
  info: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  success: "bg-green-500/15 text-green-400 border-green-500/30",
  warning: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  error: "bg-red-500/15 text-red-400 border-red-500/30",
};

export function Badge({ variant, children }: BadgeProps) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${variantStyles[variant] || variantStyles.info}`}
    >
      {children}
    </span>
  );
}
