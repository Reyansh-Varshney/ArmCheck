import { AppWindow, ChevronDown, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { FileCheckPanel } from "./FileCheckPanel";
import {
  appKey, appLabel, evidenceText, fileArchitectureLabels, issueDescriptions, issueLabels,
  processLabels, summary, verificationCounts, verificationIssues,
  type RunningApp, type VerificationIssue,
} from "./model";
import { useScan } from "./useScan";
import "./style.css";

type Sort = "name" | "cpu" | "ram";
type Filter = "all" | "native" | "emulated" | "unknown";

function App() {
  const { scan, error } = useScan();
  const [scope, setScope] = useState<"desktop" | "all">("desktop");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<Sort>("name");
  const [filter, setFilter] = useState<Filter>("all");
  const [issue, setIssue] = useState<VerificationIssue | null>(null);
  const [technical, setTechnical] = useState(false);
  const desktopScope = scope === "desktop" && scan?.desktop_scope_available !== false;
  const apps = useMemo(() => {
    const rows = scan?.apps ?? [];
    return desktopScope ? rows.filter((app) => app.desktop_app) : rows;
  }, [desktopScope, scan]);
  const visible = useMemo(() => {
    const search = query.trim().toLocaleLowerCase();
    return apps.filter((app) => {
      if (filter === "native" && app.architecture !== "native_arm64") return false;
      if (filter === "emulated" && app.architecture !== "emulated" && app.architecture !== "mixed") return false;
      if (filter === "unknown" && app.architecture !== "could_not_verify") return false;
      if (issue && !verificationIssues(app).includes(issue)) return false;
      return app.name.toLocaleLowerCase().includes(search);
    }).sort((a, b) => {
      const gap = sort === "cpu" ? (b.cpu_percent ?? -1) - (a.cpu_percent ?? -1)
        : sort === "ram" ? (b.working_set_bytes ?? -1) - (a.working_set_bytes ?? -1) : 0;
      return gap || a.name.localeCompare(b.name);
    });
  }, [apps, filter, issue, query, sort]);
  const reasons = useMemo(() => {
    const counts = verificationCounts(apps);
    // Keep a selected reason visible even when a refresh leaves it with no matches.
    if (issue && !counts.has(issue)) counts.set(issue, 0);
    return [...counts].sort((left, right) => right[1] - left[1]);
  }, [apps, issue]);
  const unverified = apps.filter((app) => app.architecture === "could_not_verify").length;
  const hasFilter = Boolean(query.trim()) || filter !== "all" || issue !== null;
  const title = scan ? summary(apps, desktopScope) : error ? "Running apps couldn’t be checked" : "Checking running apps…";

  function switchScope(next: "desktop" | "all") {
    setScope(next);
    if (issue !== null) setFilter("all");
    setIssue(null);
  }

  return (
    <main>
      <div className="scope-controls">
        <div className="scope-switch" role="group" aria-label="App view">
          <button aria-pressed={desktopScope} disabled={scan?.desktop_scope_available === false} onClick={() => switchScope("desktop")}>Desktop apps</button>
          <button aria-pressed={!desktopScope} onClick={() => switchScope("all")}>All processes</button>
        </div>
        <p className="scope-description">{scan?.desktop_scope_available === false
          ? "Desktop windows couldn’t be checked. Showing all processes."
          : desktopScope ? "Apps with a window on this desktop, including minimized apps." : "Includes background and system processes."}</p>
      </div>
      <h1>{title}</h1>
      {(unverified > 0 || issue !== null) && (
        <div className="verification-summary">
          <p>{unverified} {unverified === 1 ? "app couldn’t" : "apps couldn’t"} be verified.</p>
          <div className="issue-filters" role="group" aria-label="Filter by verification reason">
            {reasons.map(([reason, count]) => (
              <button key={reason} aria-pressed={issue === reason} onClick={() => {
                setFilter("unknown");
                setIssue(issue === reason ? null : reason);
              }}>{issueLabels[reason]} <span>{count}</span></button>
            ))}
          </div>
        </div>
      )}
      <div className="toolbar">
        <label className="search">
          <Search size={21} aria-hidden="true" />
          <input type="search" placeholder="Search apps" aria-label="Search apps" value={query} onChange={(event) => setQuery(event.target.value)} />
        </label>
        <label className="sort">
          <select aria-label="Sort running apps" value={sort} onChange={(event) => setSort(event.target.value as Sort)}>
            <option value="name">Sort by name</option>
            <option value="cpu">Sort by CPU</option>
            <option value="ram">Sort by RAM</option>
          </select>
          <ChevronDown size={17} aria-hidden="true" />
        </label>
        <label className="sort architecture-filter">
          <select aria-label="Filter by architecture" value={filter} onChange={(event) => {
            setFilter(event.target.value as Filter);
            setIssue(null);
          }}>
            <option value="all">All architectures</option>
            <option value="native">Native (ARM64)</option>
            <option value="emulated">Uses emulation</option>
            <option value="unknown">Couldn’t verify</option>
          </select>
          <ChevronDown size={17} aria-hidden="true" />
        </label>
        <label className="technical">
          <input type="checkbox" role="switch" checked={technical} onChange={(event) => setTechnical(event.target.checked)} />
          <span className="switch" aria-hidden="true" />
          Technical details
        </label>
      </div>
      {error && <p className="message" role="alert">{error}</p>}
      <section className="app-list" aria-label="Running apps" aria-busy={scan === null && !error}>
        {visible.map((app) => <AppItem key={appKey(app)} app={app} technical={technical} />)}
        {visible.length === 0 && <p className="empty">{scan
          ? hasFilter ? "No apps match your filters." : desktopScope ? "No desktop apps found." : "No running apps found."
          : error ? "ArmCheck will try again shortly." : "Checking processes…"}</p>}
      </section>
      <FileCheckPanel technical={technical} />
    </main>
  );
}

const number = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });

function AppItem({ app, technical }: { app: RunningApp; technical: boolean }) {
  const [expanded, setExpanded] = useState(false);
  const showDetails = technical && expanded;
  const metrics = app.cpu_percent !== null || app.working_set_bytes !== null;
  const reasons = verificationIssues(app);
  const singleProcess = app.processes.length === 1 ? app.processes[0] : undefined;
  const fileArchitecture = app.architecture === "could_not_verify"
    ? singleProcess?.classification.image_file_architecture : null;
  return (
    <article className="app-item">
      <div className={`app-row${technical ? " expandable" : ""}`}>
        <div className="app-icon">
          {app.icon ? <img src={app.icon} width="34" height="34" alt="" /> : <AppWindow size={29} aria-hidden="true" />}
        </div>
        <div className="app-identity">
          {technical
            ? <button className="row-toggle" aria-expanded={showDetails} onClick={() => setExpanded(!expanded)}>{app.name}</button>
            : <h2 title={app.name}>{app.name}</h2>}
          <span className={`pill${app.architecture === "native_arm64" ? " native" : ""}`}>{appLabel(app)}</span>
          {reasons.length > 0 && <p className="reason">{reasons.map((reason) => issueDescriptions[reason]).join(" ")}</p>}
          {fileArchitecture && <p className="reason">File on disk: {fileArchitectureLabels[fileArchitecture]}</p>}
        </div>
        <div className={`metrics${metrics ? "" : " unavailable"}`}>
          {metrics ? <>
            <span>{app.cpu_percent === null ? "CPU unavailable" : `${number.format(app.cpu_percent)}% CPU`}</span>
            <span>{app.working_set_bytes === null ? "RAM unavailable" : `${number.format(app.working_set_bytes / 1_000_000)} MB RAM`}</span>
          </> : <span>Unavailable</span>}
        </div>
        {technical && <ChevronDown size={18} aria-hidden="true" className={showDetails ? "chevron expanded" : "chevron"} />}
      </div>
      {showDetails && <div className="details">
        {app.processes.map((process, index) => (
          <div key={`${process.pid}-${index}`} className="process">
            <strong>{process.name} · PID {process.pid}</strong>
            <span>{processLabels[process.classification.architecture]}</span>
            {process.classification.verification_issue && (
              <p className="reason">{issueDescriptions[process.classification.verification_issue]}</p>
            )}
            {process.classification.verification_issue && process.classification.image_file_architecture && (
              <p className="reason">File on disk: {fileArchitectureLabels[process.classification.image_file_architecture]}</p>
            )}
            <ul className="evidence">{process.classification.evidence.map((item, entry) => <li key={entry}>{evidenceText(item)}</li>)}</ul>
          </div>
        ))}
      </div>}
    </article>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
