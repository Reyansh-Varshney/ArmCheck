import { invoke, isTauri } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Download, File, X } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { evidenceText, type CheckedFile } from "./model";

const labels = { arm64: "Native (ARM64)", x64: "x64", x86: "x86", managed_any_cpu: "AnyCPU (.NET)", could_not_verify: "Couldn’t verify" };

export function FileCheckPanel({ technical }: { technical: boolean }) {
  const [result, setResult] = useState<CheckedFile | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const checking = useRef(false);
  const zone = useRef<HTMLDivElement>(null);

  const check = useCallback(async (path?: string) => {
    if (checking.current) return;
    checking.current = true;
    setBusy(true);
    setError(null);
    try {
      const next = path
        ? await invoke<CheckedFile>("check_path", { path })
        : await invoke<CheckedFile | null>("choose_file");
      if (next) setResult(next);
    } catch (cause) {
      setError(String(cause));
    } finally {
      checking.current = false;
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    if (!isTauri()) return;
    let disposed = false;
    let stop: (() => void) | undefined;
    void getCurrentWindow().onDragDropEvent(({ payload }) => {
      if (disposed) return;
      if (payload.type === "leave") {
        setDragging(false);
        return;
      }
      const bounds = zone.current?.getBoundingClientRect();
      const x = payload.position.x / devicePixelRatio;
      const y = payload.position.y / devicePixelRatio;
      const overZone = Boolean(bounds && x >= bounds.left && x <= bounds.right && y >= bounds.top && y <= bounds.bottom);
      setDragging(payload.type !== "drop" && overZone);
      if (payload.type === "drop" && overZone) {
        if (payload.paths.length === 1) void check(payload.paths[0]);
        else setError("Drop one file at a time.");
      }
    }).then((unlisten) => {
      if (disposed) unlisten();
      else stop = unlisten;
    }).catch((cause) => { if (!disposed) setError(String(cause)); });
    return () => { disposed = true; stop?.(); };
  }, [check]);

  const finding = result && "Ok" in result.finding ? result.finding.Ok : null;
  return (
    <section aria-labelledby="file-heading" className="file-section">
      <h2 id="file-heading">Check a file</h2>
      <div className="file-controls">
        <div ref={zone} className={`drop-zone${dragging ? " dragging" : ""}`}>
          <Download size={21} aria-hidden="true" />
          {busy ? "Checking file…" : "Drop an executable or installer here"}
        </div>
        <button className="secondary" onClick={() => void check()} disabled={busy}>Choose file</button>
      </div>
      {error && <p className="message" role="alert">{error}</p>}
      {result && (
        <div className="file-result" role="status">
          <div className="file-line">
            <File size={22} aria-hidden="true" />
            <strong title={result.name}>{result.name}</strong>
            <span className={`pill${finding?.architecture === "arm64" ? " native" : ""}`}>
              {finding ? labels[finding.architecture] : "Couldn’t verify"}
            </span>
            <button className="icon-button" aria-label="Clear file result" onClick={() => setResult(null)}><X size={18} /></button>
          </div>
          <p>An installer’s architecture can differ from the app it installs.</p>
          {"Err" in result.finding && <p>{result.finding.Err}</p>}
          {technical && finding && <ul className="evidence">{finding.evidence.map((item, index) => <li key={index}>{evidenceText(item)}</li>)}</ul>}
        </div>
      )}
    </section>
  );
}
