import { useState } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { EmptyState, ErrorBox, Section, StatusBadge, usePolling } from "../components";

export default function AIAnalyst() {
  const { can } = useAuth();
  const [config, setConfig] = useState<any>(null);
  const [test, setTest] = useState<any>(null);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [analysis, setAnalysis] = useState<any>(null);
  const [error, setError] = useState<unknown>(null);
  const [form, setForm] = useState({ provider: "openai", endpoint: "", api_key: "", model: "", temperature: 0.2, max_tokens: 1200 });

  usePolling(() => {
    if (can("analyst")) api.get("/ai/config").then(setConfig).catch(setError);
    api.get("/incidents").then(setIncidents).catch(setError);
  }, 15000);

  const save = () => api.put("/ai/config", { ...form, temperature: Number(form.temperature), max_tokens: Number(form.max_tokens) })
    .then(() => api.get("/ai/config").then(setConfig)).catch(setError);

  const testConn = () => api.post("/ai/test").then(setTest).catch(setError);

  const analyze = (id: number) =>
    api.post(`/ai/analyze-incident/${id}`).then(setAnalysis).catch(setError);

  return (
    <div>
      <div className="page-head"><h1>AI Analyst</h1></div>
      <ErrorBox error={error} />

      {can("admin") && (
        <Section title="AI provider configuration">
          <div className="form-grid">
            <div>
              <label>Provider</label>
              <select value={form.provider} onChange={(e) => setForm({ ...form, provider: e.target.value })}>
                {["openai", "anthropic", "google", "custom"].map((p) => <option key={p}>{p}</option>)}
              </select>
            </div>
            <div>
              <label>Model</label>
              <input placeholder="e.g. gpt-4o-mini / claude-3-5-sonnet" value={form.model}
                onChange={(e) => setForm({ ...form, model: e.target.value })} />
            </div>
            <div>
              <label>API endpoint</label>
              <input placeholder="https://api.openai.com/v1" value={form.endpoint}
                onChange={(e) => setForm({ ...form, endpoint: e.target.value })} />
            </div>
            <div>
              <label>API key (stored encrypted server-side, never shown again)</label>
              <input type="password" placeholder={config?.key_masked ? `saved: ${config.key_masked}` : "sk-…"}
                value={form.api_key} onChange={(e) => setForm({ ...form, api_key: e.target.value })} />
            </div>
            <div>
              <label>Temperature</label>
              <input type="number" step="0.1" value={form.temperature}
                onChange={(e) => setForm({ ...form, temperature: e.target.value as any })} />
            </div>
            <div>
              <label>Max tokens</label>
              <input type="number" value={form.max_tokens}
                onChange={(e) => setForm({ ...form, max_tokens: e.target.value as any })} />
            </div>
          </div>
          <div style={{ padding: "0 16px 16px", display: "flex", gap: 8 }}>
            <button className="btn primary" onClick={save}>Save configuration</button>
            <button className="btn" onClick={testConn}>Test connection</button>
            {test && <StatusBadge status={test.state} />}
            {test && <span style={{ color: "#8a8a86", fontSize: 12, alignSelf: "center" }}>{test.message}</span>}
          </div>
          <p style={{ padding: "0 16px 16px", color: "#8a8a86", fontSize: 12 }}>
            State: {config?.configured ? "Configured" : "Not configured"}.
            The browser never communicates with the AI provider; CHEKWE's backend does.
            The AI recommends — the policy engine decides — the response engine executes.
          </p>
        </Section>
      )}

      {!incidents.length && <EmptyState title="No incidents to analyze" />}
      <Section title="Analyze an incident">
        <table>
          <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th></th></tr></thead>
          <tbody>
            {incidents.map((i) => (
              <tr key={i.id}>
                <td className="mono">#{i.id}</td>
                <td>{i.title}</td>
                <td>{i.severity}</td>
                <td>{i.status}</td>
                <td>{can("analyst") &&
                  <button className="btn" onClick={() => analyze(i.id)}>Analyze</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      {analysis && (
        <Section title="Analysis output">
          <div className="ai-block observed"><h4>OBSERVED</h4>
            {analysis.observed.map((o: string, k: number) => <p key={k}>· {o}</p>)}</div>
          <div className="ai-block inferred"><h4>INFERRED</h4>
            {analysis.inferred.map((o: string, k: number) => <p key={k}>· {o}</p>)}</div>
          <div className="ai-block unknown"><h4>UNKNOWN</h4>
            {analysis.unknown.map((o: string, k: number) => <p key={k}>· {o}</p>)}</div>
          <div style={{ padding: 12 }}>
            <label>Raw model output {analysis.ai_available ? "" : "(provider unavailable — heuristic analysis shown)"}</label>
            <pre className="raw">{analysis.ai_raw}</pre>
          </div>
        </Section>
      )}
    </div>
  );
}
