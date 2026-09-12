import { useState } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { Badge, EmptyState, ErrorBox, Section, usePolling } from "../components";

export default function Rules() {
  const { can } = useAuth();
  const [rules, setRules] = useState<any[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [testCode, setTestCode] = useState("");
  const [testPayload, setTestPayload] = useState('{\n  "source_ip": "1.2.3.4",\n  "username": "root",\n  "event_type": "auth_failure"\n}');
  const [testResult, setTestResult] = useState<any>(null);

  usePolling(() => { api.get("/rules").then(setRules).catch(setError); }, 15000);

  const toggle = (r: any) =>
    api.patch(`/rules/${r.code}`, { enabled: !r.enabled }).then(() => api.get("/rules").then(setRules)).catch(setError);

  const saveSeverity = (r: any, severity: string) =>
    api.patch(`/rules/${r.code}`, { severity }).then(() => api.get("/rules").then(setRules)).catch(setError);

  const saveThreshold = (r: any, raw: string) => {
    try {
      api.patch(`/rules/${r.code}`, { threshold: JSON.parse(raw) })
        .then(() => api.get("/rules").then(setRules)).catch(setError);
    } catch { setError(new Error("Threshold must be valid JSON")); }
  };

  const runTest = () => {
    try {
      api.post(`/rules/${testCode}/test`, JSON.parse(testPayload))
        .then(setTestResult).catch(setError);
    } catch { setError(new Error("Sample event must be valid JSON")); }
  };

  return (
    <div>
      <div className="page-head"><h1>Detection Rules</h1></div>
      <ErrorBox error={error} />
      {!rules.length && <EmptyState title="No detection rules" />}
      {rules.map((r) => (
        <Section key={r.code} title={r.name} actions={
          can("analyst") ? (
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <select value={r.severity} style={{ width: 110 }} onChange={(e) => saveSeverity(r, e.target.value)}>
                {["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}
              </select>
              <button className={`btn ${r.enabled ? "" : "danger"}`} onClick={() => toggle(r)}>
                {r.enabled ? "Enabled" : "Disabled"}
              </button>
            </div>
          ) : <Badge level={r.severity} />
        }>
          <div className="detail-grid">
            <div><dt>Code</dt><dd className="mono">{r.code}</dd></div>
            <div><dt>Description</dt><dd>{r.description}</dd></div>
            <div><dt>MITRE</dt><dd className="mono">{r.mitre?.technique || "—"} {r.mitre?.name || ""}</dd></div>
            <div><dt>Triggers</dt><dd>{r.trigger_count} {r.last_triggered ? `· last ${r.last_triggered}` : ""}</dd></div>
          </div>
          {can("analyst") && (
            <div style={{ padding: "0 16px 16px" }}>
              <label>Threshold (JSON)</label>
              <input className="mono" defaultValue={JSON.stringify(r.threshold)}
                onBlur={(e) => saveThreshold(r, e.target.value)} />
            </div>
          )}
        </Section>
      ))}
      <Section title="Test a rule against a sample event">
        <div style={{ padding: 12 }}>
          <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
            <select value={testCode} onChange={(e) => setTestCode(e.target.value)} style={{ width: 220 }}>
              <option value="">Select rule…</option>
              {rules.map((r) => <option key={r.code} value={r.code}>{r.code}</option>)}
            </select>
            <button className="btn primary" onClick={runTest} disabled={!testCode}>Run test</button>
          </div>
          <textarea className="mono" rows={5} value={testPayload} onChange={(e) => setTestPayload(e.target.value)} />
          {testResult && (
            <pre className="raw" style={{ marginTop: 8 }}>
              {JSON.stringify(testResult, null, 2)}
            </pre>
          )}
        </div>
      </Section>
    </div>
  );
}
