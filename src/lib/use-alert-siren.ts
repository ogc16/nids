import { useRef } from "react";
import { Alert } from "./types";
import { playSiren } from "./siren";

export function useAlertSiren() {
  const seenRef = useRef(new Set<string>());

  return (alerts: Alert[]) => {
    for (const alert of alerts) {
      if ((alert.severity === "high" || alert.severity === "critical") && !seenRef.current.has(alert.id)) {
        playSiren(4000);
      }
      seenRef.current.add(alert.id);
    }
  };
}
