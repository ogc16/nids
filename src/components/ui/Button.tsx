import { ButtonHTMLAttributes, forwardRef } from "react";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger" | "ghost";
  size?: "sm" | "md" | "lg";
}

const variantStyles: Record<string, string> = {
  primary: "bg-emerald-600 text-white hover:bg-emerald-500 active:bg-emerald-700",
  secondary: "hover:bg-zinc-200 active:bg-zinc-300 dark:hover:bg-zinc-700 dark:active:bg-zinc-600",
  danger: "bg-red-600 text-white hover:bg-red-500 active:bg-red-700",
  ghost: "hover:bg-zinc-100 active:bg-zinc-200 dark:hover:bg-zinc-800 dark:active:bg-zinc-700",
};

const variantColors: Record<string, React.CSSProperties> = {
  secondary: { backgroundColor: "var(--bg-input)", color: "var(--text-primary)", borderColor: "var(--border-strong)" },
  ghost: { color: "var(--text-muted)" },
};

const sizes = {
  sm: "px-2.5 py-1 text-xs",
  md: "px-4 py-2 text-sm",
  lg: "px-6 py-2.5 text-base",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = "primary", size = "md", className = "", children, style, ...props }, ref) => (
    <button
      ref={ref}
      className={`inline-flex items-center justify-center rounded-lg font-medium transition-all duration-150 disabled:opacity-50 disabled:cursor-not-allowed border ${variantStyles[variant]} ${sizes[size]} ${className}`}
      style={{ ...variantColors[variant], ...style, ...(variant === "secondary" ? { borderWidth: "1px" } : { borderWidth: "0px" }) }}
      {...props}
    >
      {children}
    </button>
  )
);
Button.displayName = "Button";
