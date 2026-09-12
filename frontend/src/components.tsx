import { ReactNode, useEffect, useRef, useState } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "./auth";

export function Emblem({ size = 34 }: { size?: number }) {
  // Abstract CHEKWE mark: shield (defense) + staff (monitoring) + feathers (telemetry)
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" aria-label="CHEKWE emblem">
      <path d="M24 3 42 11v13c0 11-8 18-18 21C14 42 6 35 6 24V11L24 3z"
        fill="none" stroke="#B08D57" strokeWidth="2" />
      <path d="M24 10v28M14 18h20M14 30h20" stroke="#8B0000" strokeWidth="1.6" />
      <circle cx="24" cy="24" r="4.5" fill="none" stroke="#E8E3D8" strokeWidth="1.4" />
      <path d="M24 14l3 3-3 3-3-3zM24 28l3 3-3 3-3-3z" fill="#FF1A1A" opacity="0.85" />
    </svg>
  );
}

export function Badge({ level }: { level: string }) {
  return <span className={`badge sev-${level}`}>{level.toUpperCase()}</span>;
}

export function StatusBadge({ status }: { status: string }) {
  const cls = status === "executed" || status === "connected" || status === "resolved" ? "ok"
    : status === "failed" || status === "rejected" || status === "connection_failed" || status === "invalid_credentials" ? "bad"
    : status === "pending" || status === "approval" ? "warn" : "neutral";
  return <span className={`badge st-${cls}`}>{status.replace(/_/g, " ").toUpperCase()}</span>;
}

export function Stat({ label, value, tone = "ivory" }: { label: string; value: ReactNode; tone?: string }) {
  return (
    <div className={`stat tone-${tone}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <Emblem size={44} />
      <h3>{title}</h3>
      <p>{children ?? "No data yet. Connect a data source or generate a clearly-labeled demo scenario."}</p>
    </div>
  );
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  return <div className="error-box">{error instanceof Error ? error.message : String(error)}</div>;
}

export function Section({ title, actions, children }: { title: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="panel">
      <header className="panel-head">
        <h2>{title}</h2>
        <div className="panel-actions">{actions}</div>
      </header>
      {children}
    </section>
  );
}

export function usePolling(fn: () => void, ms: number, deps: unknown[] = []) {
  const saved = useRef(fn);
  saved.current = fn;
  useEffect(() => {
    saved.current();
    const id = setInterval(() => saved.current(), ms);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}

const NAV: [string, string, string?][] = [
  ["/", "Overview"],
  ["/events", "Live Events"],
  ["/alerts", "Alerts"],
  ["/incidents", "Incidents"],
  ["/intel", "Threat Intelligence"],
  ["/assets", "Assets"],
  ["/rules", "Detection Rules"],
  ["/response", "Response"],
  ["/ai", "AI Analyst"],
  ["/system", "System & Audit"],
  ["/settings", "Settings"],
];

export function Layout({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth();
  const nav = useNavigate();
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <Emblem />
          <div>
            <div className="brand-name">CHEKWE</div>
            <div className="brand-sub">Security Operations</div>
          </div>
        </div>
        <div className="nav-group">COMMAND CENTER</div>
        <nav>
          {NAV.map(([to, label]) => (
            <NavLink key={to} to={to} end={to === "/"}>{label}</NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="user-chip">{user?.username} · {user?.role}</div>
          <button className="btn ghost" onClick={() => { logout(); nav("/login"); }}>Sign out</button>
          <div className="credit">CHEKWE — by Anonymous-beta</div>
        </div>
      </aside>
      <main className="content">{children}</main>
    </div>
  );
}

export function fmtTime(t?: string | null) {
  if (!t) return "—";
  const d = new Date(t);
  return isNaN(d.getTime()) ? String(t) : d.toLocaleString();
}

export function MiniBars({ data, height = 60 }: { data: number[]; height?: number }) {
  const max = Math.max(...data, 1);
  const w = 100 / Math.max(data.length, 1);
  return (
    <svg viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" className="spark">
      {data.map((v, i) => (
        <rect key={i} x={i * w + 0.5} y={height - (v / max) * (height - 4) - 2}
          width={Math.max(w - 1, 0.4)} height={(v / max) * (height - 4) + 2}
          fill={v > max * 0.7 ? "#FF1A1A" : "#B08D57"} opacity="0.8" />
      ))}
    </svg>
  );
}

export function useAutoRefreshDeps() { return undefined as never; }
export function useStateWithDeps() { return undefined as never; }

export function useToggle(initial = false) {
  const [v, setV] = useState(initial);
  return [v, () => setV((x) => !x)] as const;
}
