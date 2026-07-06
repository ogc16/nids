interface StatusDotProps {
  status: "active" | "inactive" | "error" | "warning";
}

const colors = {
  active: "bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.5)]",
  inactive: "bg-zinc-600",
  error: "bg-red-500 shadow-[0_0_6px_rgba(239,68,68,0.5)]",
  warning: "bg-amber-500 shadow-[0_0_6px_rgba(245,158,11,0.5)]",
};

export function StatusDot({ status }: StatusDotProps) {
  return <span className={`inline-block h-2 w-2 rounded-full ${colors[status]}`} />;
}
