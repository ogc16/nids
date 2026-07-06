import { ButtonHTMLAttributes, forwardRef } from "react";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger" | "ghost";
  size?: "sm" | "md" | "lg";
}

const variants = {
  primary: "bg-emerald-600 text-white hover:bg-emerald-500 active:bg-emerald-700",
  secondary: "bg-zinc-800 text-zinc-100 hover:bg-zinc-700 active:bg-zinc-600 border border-zinc-700",
  danger: "bg-red-600 text-white hover:bg-red-500 active:bg-red-700",
  ghost: "text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800",
};

const sizes = {
  sm: "px-2.5 py-1 text-xs",
  md: "px-4 py-2 text-sm",
  lg: "px-6 py-2.5 text-base",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = "primary", size = "md", className = "", children, ...props }, ref) => (
    <button
      ref={ref}
      className={`inline-flex items-center justify-center rounded-lg font-medium transition-all duration-150 disabled:opacity-50 disabled:cursor-not-allowed ${variants[variant]} ${sizes[size]} ${className}`}
      {...props}
    >
      {children}
    </button>
  )
);
Button.displayName = "Button";
