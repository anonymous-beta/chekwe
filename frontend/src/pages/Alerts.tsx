import { useState } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { Badge, EmptyState, ErrorBox, Section, StatusBadge, fmtTime, usePolling } from "../components";

export default function Alerts() {
  const { can } = useAuth();
  const [alerts, setAlerts] = useState<any[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [selected, setSelected] = useState<any>(null);
  const [severity, setSeverity] = useState("");

  usePolling(() => {
    api.get(`/alerts${severity ? `?severity=${severity}` : ""}`).then(setAlerts).catch(setError);
  }, 6000, [severity]);

  const open = (a: any) => api.get(`/alerts/${a.id}`).then(setSelected).catch(setError);

  const setStatus = (a: any, status: string) =>
    api.patch(`/alerts/${a.id}`, { status }).then(() =>
      setAlerts((prev) => prev.map((x) => (x.id === a.id ? { ...x, status } : x)))).catch(setError);

  return (
    <div>
      <div className="page-head">
        <h1>Alerts</h1>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} style={{ width: 180 }}>
          <option value="">Severity: all</option>
          {["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>
      <ErrorBox error={error} />
      {!alerts.length && <EmptyState title="No alerts" />}
      <Section title={`${alerts.length} alerts`}>
        <div style={{ maxHeight: 520, overflow: "auto" }}>
          <table>
            <thead><tr><th>Time</th><th>Severity</th><th>Title</th><th>Rule</th><th>Confidence</th><th>Status</th><th></th></tr></thead>
            <tbody>
              {alerts.map((a) => (
                <tr key={a.id} className="row-click" onClick={() => open(a)}>
                  <td className="mono">{fmtTime(a.created_at)}</td>
                  <td><Badge level={a.severity} /></td>
                  <td>{a.title}</td>
                  <td className="mono">{a.rule_code}</td>
                  <td>{(a.confidence * 100).toFixed(0)}%</td>
                  <td><StatusBadge status={a.status} /></td>
                  <td onClick={(e) => e.stopPropagation()}>
                    {can("analyst") && a.status === "open" && (
                      <button className="btn ghost" onClick={() => setStatus(a, "acknowledged")}>Ack</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>
      {selected && (
        <Section title={`Alert #${selected.alert.id}: ${selected.alert.title}`} actions={
          <button className="btn ghost" onClick={() => setSelected(null)}>Close</button>
        }>
          <div className="ai-block observed">
            <h4>DETECTION REASON</h4>
            <p>{selected.alert.reason}</p>
          </div>
          <div className="detail-grid">
            <div><dt>MITRE ATT&amp;CK</dt><dd className="mono">
              {selected.alert.mitre?.tactic || "—"} / {selected.alert.mitre?.technique || ""} {selected.alert.mitre?.name || ""}</dd></div>
            <div><dt>Recommended response</dt><dd>{selected.alert.recommended_response || "—"}</dd></div>
            <div><dt>Evidence</dt><dd className="mono">{JSON.stringify(selected.alert.evidence)}</dd></div>
          </div>
          {selected.event && (
            <div style={{ padding: "0 16px 16px" }}>
              <label>Triggering event {selected.event.is_synthetic ? "(DEMO/SYNTHETIC)" : ""}</label>
              <pre className="raw">{JSON.stringify(selected.event, null, 2)}</pre>
            </div>
          )}
        </Section>
      )}
    </div>
  );
}
