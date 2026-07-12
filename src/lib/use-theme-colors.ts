"use client";

import { useEffect, useState } from "react";

const darkColors = {
  grid: "#27272a",
  tick: "#a1a1aa",
  tooltipBg: "#18181b",
  tooltipBorder: "#27272a",
  tooltipText: "#e4e4e7",
  tooltipLabel: "#a1a1aa",
  normalGradStart: "#10b981",
  normalGradEnd: "#10b981",
  maliciousGradStart: "#ef4444",
  maliciousGradEnd: "#ef4444",
  normalStroke: "#10b981",
  maliciousStroke: "#ef4444",
  barBlue: "#58a6ff",
  barGreen: "#3fb950",
};

const lightColors = {
  grid: "#e5e5e5",
  tick: "#71717a",
  tooltipBg: "#ffffff",
  tooltipBorder: "#e5e5e5",
  tooltipText: "#18181b",
  tooltipLabel: "#71717a",
  normalGradStart: "#059669",
  normalGradEnd: "#059669",
  maliciousGradStart: "#dc2626",
  maliciousGradEnd: "#dc2626",
  normalStroke: "#059669",
  maliciousStroke: "#dc2626",
  barBlue: "#2563eb",
  barGreen: "#16a34a",
};

export function useThemeColors() {
  const [isDark, setIsDark] = useState(true);

  useEffect(() => {
    const check = () => setIsDark(document.documentElement.classList.contains("dark"));
    check();
    const observer = new MutationObserver(check);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
    return () => observer.disconnect();
  }, []);

  return isDark ? darkColors : lightColors;
}
