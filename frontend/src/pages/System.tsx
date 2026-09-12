import { useState } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { EmptyState, ErrorBox, Section, StatusBadge, fmtTime, usePolling } from "../components";

export default function System() {
  const { can } = useAuth();
  const [health, setHealth] = useState<any>(null);
  const [audit, setAudit] = useState<any[]>([]);
  const [error, setError] = useState<unknown>(null);

  usePolling(() => {
    api.get("/health").then(setHealth).catch(setError);
    if (can("analyst")) api.get("/auth/audit?limit=100").then(setAudit).catch(() => undefined);
  }, 8000);

  return (
    <div>
      <div className="page-head"><h1>System Health & Audit</h1></div>
      <ErrorBox error={error} />
      {!health && <EmptyState title="Polling backend health…" />}

      {health && (
        <Section title={`Platform status: ${health.status.toUpperCase()}`}>
          {Object.entries(health.checks).map(([k, v]: [string, any]) => (
            <div className="kv" key={k}>
              <span>{k.replace(/_/g, " ")}</span>
              <span>{typeof v === "object" ? JSON.stringify(v) : <StatusBadge status={String(v)} />}</span>
            </div>
          ))}
          <div className="kv"><span>Checked at</span><span className="mono">{health.time}</span></div>
          {health.integrations?.length > 0 && (
            <table style={{ marginTop: 8 }}>
              <thead><tr><th>Integration</th><th>Type</th><th>Status</th></tr></thead>
              <tbody>
                {health.integrations.map((i: any) => (
                  <tr key={i.name}><td>{i.name}</td><td className="mono">{i.type}</td>
                    <td><StatusBadge status={i.status} /></td></tr>
                ))}
              </tbody>
            </table>
          )}
        </Section>
      )}

      {can("analyst") && (
        <Section title="Audit log (append-only)">
          <table>
            <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Result</th><th>IP</th></tr></thead>
            <tbody>
              {audit.map((a) => (
                <tr key={a.id}>
                  <td className="mono">{fmtTime(a.timestamp)}</td>
                  <td>{a.actor}</td>
                  <td className="mono">{a.action}</td>
                  <td className="mono">{a.target}</td>
                  <td><StatusBadge status={a.result} /></td>
                  <td className="mono">{a.ip || "—"}</td>
                </tr>
              ))}
              {!audit.length && <tr><td colSpan={6} style={{ color: "#8a8a86" }}>No audit records.</td></tr>}
            </tbody>
          </table>
        </Section>
      )}
    </div>
  );
}
