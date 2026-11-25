import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { useEffect, useState } from "react";
import type { RunningApp } from "./model";

const REFRESH_MS = 3000;

export function useScan() {
  const [apps, setApps] = useState<RunningApp[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isTauri()) return;
    const window = getCurrentWindow();
    let disposed = false;
    let active = false;
    let inFlight = false;
    let generation = 0;
    let visibilityCheck = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const unlisteners: (() => void)[] = [];

    async function refresh() {
      if (!active || inFlight || disposed) return;
      inFlight = true;
      const revision = generation;
      try {
        const rows = await invoke<RunningApp[] | null>("scan_apps");
        if (active && !disposed && revision === generation && rows !== null) {
          setApps(rows);
          setError(null);
        }
      } catch (cause) {
        if (active && !disposed && revision === generation) setError(String(cause));
      } finally {
        inFlight = false;
        if (active && !disposed) timer = setTimeout(refresh, revision === generation ? REFRESH_MS : 0);
      }
    }

    async function syncVisibility() {
      const request = ++visibilityCheck;
      let shown = false;
      try {
        if (!document.hidden) {
          const [visible, minimized] = await Promise.all([window.isVisible(), window.isMinimized()]);
          shown = visible && !minimized;
        }
      } catch (cause) {
        if (!disposed && request === visibilityCheck) setError(String(cause));
      }
      if (disposed || request !== visibilityCheck || shown === active) return;
      active = shown;
      generation += 1;
      clearTimeout(timer);
      if (active) void refresh();
    }

    function subscribe(subscription: Promise<() => void>) {
      void subscription.then((stop) => {
        if (disposed) stop();
        else unlisteners.push(stop);
      }).catch((cause) => {
        if (!disposed) setError(String(cause));
      });
    }

    document.addEventListener("visibilitychange", syncVisibility);
    subscribe(listen("armcheck://visibility", syncVisibility));
    void syncVisibility();
    return () => {
      disposed = true;
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", syncVisibility);
      unlisteners.forEach((stop) => stop());
    };
  }, []);

  return { apps, error };
}
