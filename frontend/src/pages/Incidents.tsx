import { useState } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { Badge, EmptyState, ErrorBox, Section, fmtTime, usePolling } from "../components";

const FLOW = ["new", "triaged", "investigating", "contained", "remediating", "resolved", "closed"];

export default function Incidents() {
  const { can, user } = useAuth();
  const [incidents, setIncidents] = useState<any[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [selected, setSelected] = useState<any>(null);
  const [note, setNote] = useState("");
  const [title, setTitle] = useState("");

  usePolling(() => {
    api.get("/incidents").then(setIncidents).catch(setError);
  }, 8000);

  const open = (i: any) => api.get(`/incidents/${i.id}`).then(setSelected).catch(setError);

  const setStatus = (status: string) =>
    api.patch(`/incidents/${selected.id}/status`, { status })
      .then(() => open(selected)).catch(setError);

  const create = () => {
    if (!title.trim()) return;
    api.post("/incidents", { title, severity: "medium" }).then(() => {
      setTitle("");
      api.get("/incidents").then(setIncidents);
    }).catch(setError);
  };

  const analyze = () =>
    api.post(`/ai/analyze-incident/${selected.id}`).then(() => open(selected)).catch(setError);

  const addNote = () => {
    if (!note.trim()) return;
    api.post(`/incidents/${selected.id}/notes`, { body: note }).then(() => {
      setNote("");
      open(selected);
    }).catch(setError);
  };

  const ai = selected?.ai_analysis;

  return (
    <div>
      <div className="page-head">
        <h1>Incidents</h1>
        {can("analyst") && (
          <div style={{ display: "flex", gap: 8 }}>
            <input placeholder="New incident title" value={title} onChange={(e) => setTitle(e.target.value)}
              style={{ width: 260 }} />
            <button className="btn primary" onClick={create}>Create</button>
          </div>
        )}
      </div>
      <ErrorBox error={error} />
      {!incidents.length && <EmptyState title="No incidents" />}
      <Section title={`${incidents.length} incidents`}>
        <table>
          <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Confidence</th><th>Updated</th></tr></thead>
          <tbody>
            {incidents.map((i) => (
              <tr key={i.id} className="row-click" onClick={() => open(i)}>
                <td className="mono">#{i.id}</td>
                <td>{i.title}</td>
                <td><Badge level={i.severity} /></td>
                <td>{i.status}</td>
                <td>{(i.confidence * 100).toFixed(0)}%</td>
                <td>{fmtTime(i.updated_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      {selected && (
        <>
          <Section title={`Incident #${selected.id}: ${selected.title}`} actions={
            <button className="btn ghost" onClick={() => setSelected(null)}>Close</button>
          }>
            <div className="detail-grid">
              <div><dt>Severity</dt><dd><Badge level={selected.severity} /></dd></div>
              <div><dt>Status</dt><dd>{selected.status}</dd></div>
              <div><dt>Summary</dt><dd>{selected.summary || "—"}</dd></div>
            </div>
            {can("analyst") && (
              <div style={{ padding: "0 16px 16px", display: "flex", gap: 8, flexWrap: "wrap" }}>
                {FLOW.filter((s) => s !== selected.status).map((s) => (
                  <button key={s} className="btn" onClick={() => setStatus(s)}>→ {s}</button>
                ))}
                <button className="btn primary" onClick={analyze}>
                  {ai?.ai_available === false && ai?.provider === "none" ? "Heuristic analysis" : "Run AI analysis"}
                </button>
              </div>
            )}
          </Section>

          {ai && (
            <Section title="AI analysis — OBSERVED / INFERRED / UNKNOWN">
              <div className="ai-block observed"><h4>OBSERVED</h4>
                {ai.observed.map((o: string, k: number) => <p key={k}>· {o}</p>)}</div>
              <div className="ai-block inferred"><h4>INFERRED</h4>
                {ai.inferred.map((o: string, k: number) => <p key={k}>· {o}</p>)}</div>
              <div className="ai-block unknown"><h4>UNKNOWN</h4>
                {ai.unknown.map((o: string, k: number) => <p key={k}>· {o}</p>)}</div>
              <div style={{ padding: 12 }}>
                <label>Provider output {ai.provider !== "none" ? `(provider: ${ai.provider})` : "(heuristic — AI provider not configured)"}</label>
                <pre className="raw">{ai.ai_raw}</pre>
              </div>
            </Section>
          )}

          <Section title="Timeline & related alerts">
            <table>
              <thead><tr><th>Time</th><th>Type</th><th>Source IP</th><th>User</th><th>Synthetic</th></tr></thead>
              <tbody>
                {selected.events.map((e: any) => (
                  <tr key={e.id}>
                    <td className="mono">{fmtTime(e.timestamp)}</td>
                    <td className="mono">{e.event_type}</td>
                    <td className="mono">{e.source_ip || "—"}</td>
                    <td>{e.username || "—"}</td>
                    <td>{e.is_synthetic ? <span className="pill demo-tag">DEMO</span> : "—"}</td>
                  </tr>
                ))}
                {selected.alerts.map((a: any) => (
                  <tr key={`a${a.id}`}>
                    <td className="mono">{fmtTime(a.created_at)}</td>
                    <td><Badge level={a.severity} /> {a.title}</td>
                    <td colSpan={3} className="mono">{a.rule_code}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>

          <Section title="Analyst notes">
            {(ai?.notes || []).map((n: any, k: number) => (
              <div className="note" key={k}><strong>{n.author}</strong> · {fmtTime(n.at)}<br />{n.body}</div>
            ))}
            {can("analyst") && (
              <div style={{ padding: 12, display: "flex", gap: 8 }}>
                <input placeholder="Add note as @{user?.username}" value={note} onChange={(e) => setNote(e.target.value)} />
                <button className="btn" onClick={addNote}>Add note</button>
              </div>
            )}
          </Section>
        </>
      )}
    </div>
  );
}
