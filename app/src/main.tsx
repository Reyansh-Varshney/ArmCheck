import { AppWindow, ChevronDown, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { FileCheckPanel } from "./FileCheckPanel";
import { appKey, appLabel, evidenceText, processLabels, summary, unverifiedReasons, type RunningApp } from "./model";
import { useScan } from "./useScan";
import "./style.css";

type Sort = "name" | "cpu" | "ram";
type Filter = "all" | "native" | "emulated" | "unknown";

function App() {
  const { apps, error } = useScan();
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<Sort>("name");
  const [filter, setFilter] = useState<Filter>("all");
  const [technical, setTechnical] = useState(false);
  const visible = useMemo(() => {
    const search = query.trim().toLocaleLowerCase();
    return (apps ?? [])
      .filter((app) => {
        if (filter === "native" && app.architecture !== "native_arm64") return false;
        if (filter === "emulated" && app.architecture !== "emulated" && app.architecture !== "mixed") return false;
        if (filter === "unknown" && app.architecture !== "could_not_verify") return false;
        return app.name.toLocaleLowerCase().includes(search);
      })
      .sort((a, b) => {
        const gap = sort === "cpu" ? (b.cpu_percent ?? -1) - (a.cpu_percent ?? -1)
          : sort === "ram" ? (b.working_set_bytes ?? -1) - (a.working_set_bytes ?? -1) : 0;
        return gap || a.name.localeCompare(b.name);
      });
  }, [apps, filter, query, sort]);
  const unverified = apps?.filter((app) => app.architecture === "could_not_verify").length ?? 0;

  return (
    <main>
      <h1>{apps ? summary(apps) : error ? "Running apps couldn’t be checked" : "Checking running apps…"}</h1>
      {unverified > 0 &&
        <p className="notice">{unverified} {unverified === 1 ? "app couldn’t" : "apps couldn’t"} be verified.</p>}
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
          <select aria-label="Filter by architecture" value={filter} onChange={(event) => setFilter(event.target.value as Filter)}>
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
      <section className="app-list" aria-label="Running apps" aria-busy={apps === null && !error}>
        {visible.map((app) => <AppItem key={appKey(app)} app={app} technical={technical} />)}
        {!visible.length && <p className="empty">{apps ? (query.trim() || filter !== "all" ? "No apps match your filters." : "No running apps found.") : error ? "ArmCheck will try again shortly." : "Checking processes…"}</p>}
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
  const reasons = unverifiedReasons(app);
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
          {reasons.length > 0 && <p className="reason">{reasons.join(" ")}</p>}
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
            <ul className="evidence">{process.classification.evidence.map((item, entry) => <li key={entry}>{evidenceText(item)}</li>)}</ul>
          </div>
        ))}
      </div>}
    </article>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
