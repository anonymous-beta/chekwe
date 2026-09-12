import { useState } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { EmptyState, ErrorBox, Section, usePolling } from "../components";

export default function Intel() {
  const { can } = useAuth();
  const [iocs, setIocs] = useState<any[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [form, setForm] = useState({ type: "ip", value: "", confidence: 80, source: "manual" });

  usePolling(() => {
    api.get("/iocs").then(setIocs).catch(setError);
  }, 10000);

  const add = () => {
    if (!form.value.trim()) return;
    api.post("/iocs", { ...form, confidence: Number(form.confidence) })
      .then(() => { setForm({ ...form, value: "" }); api.get("/iocs").then(setIocs); })
      .catch(setError);
  };

  const deactivate = (id: number) =>
    api.del(`/iocs/${id}`).then(() => api.get("/iocs").then(setIocs)).catch(setError);

  return (
    <div>
      <div className="page-head"><h1>Threat Intelligence & IOCs</h1></div>
      <ErrorBox error={error} />
      {can("analyst") && (
        <Section title="Add indicator">
          <div style={{ padding: 12, display: "flex", gap: 8, flexWrap: "wrap" }}>
            <select value={form.type} style={{ width: 110 }} onChange={(e) => setForm({ ...form, type: e.target.value })}>
              {["ip", "domain", "url", "hash", "cve"].map((t) => <option key={t}>{t}</option>)}
            </select>
            <input placeholder="Indicator value" style={{ flex: 1, minWidth: 240 }}
              value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} />
            <input type="number" min={0} max={100} style={{ width: 110 }} value={form.confidence}
              onChange={(e) => setForm({ ...form, confidence: e.target.value as any })} />
            <input placeholder="Source" style={{ width: 140 }} value={form.source}
              onChange={(e) => setForm({ ...form, source: e.target.value })} />
            <button className="btn primary" onClick={add}>Add IOC</button>
          </div>
        </Section>
      )}
      {!iocs.length && <EmptyState title="No indicators stored" />}
      <Section title={`${iocs.length} indicators`}>
        <table>
          <thead><tr><th>Type</th><th>Value</th><th>Confidence</th><th>Source</th><th>Active</th><th>Last seen</th><th></th></tr></thead>
          <tbody>
            {iocs.map((i) => (
              <tr key={i.id}>
                <td className="mono">{i.type}</td>
                <td className="mono">{i.value}</td>
                <td>{i.confidence}%</td>
                <td>{i.source}</td>
                <td>{i.active ? "yes" : "no"}</td>
                <td>{i.last_seen}</td>
                <td>{can("analyst") && i.active &&
                  <button className="btn danger" onClick={() => deactivate(i.id)}>Deactivate</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>
    </div>
  );
}
