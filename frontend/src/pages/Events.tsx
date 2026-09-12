import { useEffect, useRef, useState } from "react";
import { api, connectWS } from "../api";
import { Badge, EmptyState, ErrorBox, Section, fmtTime } from "../components";

type Ev = {
  id: number; timestamp: string; source: string; host: string; source_ip: string;
  dest_ip: string; event_type: string; severity: string; username: string; process: string;
  port: number | null; correlation_id: string; is_synthetic: boolean; parse_error: string;
};

const SCENARIOS = ["brute_force", "suspicious_login", "port_scan", "ioc_match", "outbound_spike"];

export default function Events() {
  const [events, setEvents] = useState<Ev[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<unknown>(null);
  const [paused, setPaused] = useState(false);
  const [selected, setSelected] = useState<any>(null);
  const [detail, setDetail] = useState<any>(null);
  const [scenario, setScenario] = useState(SCENARIOS[0]);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  const [filters, setFilters] = useState({ severity: "", source: "", host: "", event_type: "", search: "" });

  const load = () => {
    const q = new URLSearchParams(Object.entries(filters).filter(([, v]) => v));
    api.get(`/events?limit=200&${q}`).then((r) => {
      setEvents(r.events); setTotal(r.total); setError(null);
    }).catch(setError);
  };

  useEffect(() => { load(); }, [filters]); // eslint-disable-line
  useEffect(() => connectWS((msg) => {
    if (msg.type === "event" && !pausedRef.current) {
      setEvents((prev) => [msg.event, ...prev].slice(0, 500));
    }
  }), []);

  const openDetail = (id: number) => {
    setSelected(id);
    api.get(`/events/${id}`).then(setDetail).catch(setError);
  };

  const generate = () =>
    api.post(`/demo/generate?scenario=${scenario}`).then(load).catch(setError);

  return (
    <div>
      <div className="page-head">
        <h1>Live Events</h1>
        <div style={{ display: "flex", gap: 8 }}>
          <select value={scenario} onChange={(e) => setScenario(e.target.value)} style={{ width: 170 }}>
            {SCENARIOS.map((s) => <option key={s}>{s}</option>)}
          </select>
          <button className="btn" onClick={generate}>Generate DEMO / SYNTHETIC</button>
          <button className={`btn ${paused ? "danger" : ""}`} onClick={() => setPaused(!paused)}>
            {paused ? "Resume stream" : "Pause stream"}
          </button>
        </div>
      </div>
      <ErrorBox error={error} />
      <div className="filters">
        <select value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}>
          <option value="">Severity: all</option>
          {["info", "low", "medium", "high", "critical"].map((s) => <option key={s}>{s}</option>)}
        </select>
        <input placeholder="Source" value={filters.source}
          onChange={(e) => setFilters({ ...filters, source: e.target.value })} />
        <input placeholder="Host" value={filters.host}
          onChange={(e) => setFilters({ ...filters, host: e.target.value })} />
        <input placeholder="Event type" value={filters.event_type}
          onChange={(e) => setFilters({ ...filters, event_type: e.target.value })} />
        <input placeholder="Search IP / user / process" value={filters.search}
          onChange={(e) => setFilters({ ...filters, search: e.target.value })} />
      </div>
      <p style={{ color: "#8a8a86", fontSize: 12 }}>{total} matching events · showing {events.length} · live via WebSocket</p>
      {!events.length && <EmptyState title="No events match">
        Telemetry flows in via POST /api/v1/events. Demo scenarios are tagged SYNTHETIC and never presented as production data.
      </EmptyState>}
      <Section title="Event stream">
        <div style={{ maxHeight: 480, overflow: "auto" }}>
          <table>
            <thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Source IP</th><th>User</th><th>Host</th><th>Process</th><th></th></tr></thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id} className="row-click" onClick={() => openDetail(e.id)}
                  style={selected === e.id ? { background: "#1A1A1A" } : undefined}>
                  <td className="mono">{fmtTime(e.timestamp)}</td>
                  <td className="mono">{e.event_type}</td>
                  <td><Badge level={e.severity} /></td>
                  <td className="mono">{e.source_ip || "—"}</td>
                  <td>{e.username || "—"}</td>
                  <td>{e.host || "—"}</td>
                  <td className="mono">{e.process || "—"}</td>
                  <td>{e.is_synthetic && <span className="pill demo-tag">DEMO</span>}
                    {e.parse_error && <span className="pill st-bad">PARSE ERR</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>
      {detail && (
        <Section title={`Event #${detail.event.id} — investigation`} actions={
          <button className="btn ghost" onClick={() => { setDetail(null); setSelected(null); }}>Close</button>
        }>
          <div className="detail-grid">
            <div><dt>Source → Destination</dt><dd className="mono">{detail.event.source_ip || "?"} → {detail.event.dest_ip || "?"}:{detail.event.port ?? ""}</dd></div>
            <div><dt>Protocol</dt><dd className="mono">{detail.event.normalized?.protocol || "—"}</dd></div>
            <div><dt>User</dt><dd>{detail.event.username || "—"}</dd></div>
            <div><dt>Host</dt><dd>{detail.event.host || "—"}</dd></div>
            <div><dt>Process</dt><dd className="mono">{detail.event.process || "—"}</dd></div>
            <div><dt>Correlation ID</dt><dd className="mono">{detail.event.correlation_id}</dd></div>
            <div><dt>IOC hits</dt><dd className="mono">{(detail.event.ioc_hits || []).length || "none"}</dd></div>
            <div><dt>Related incidents</dt><dd>{detail.related_incidents.map((i: any) => `#${i.id} ${i.title}`).join("; ") || "none"}</dd></div>
          </div>
          <div style={{ padding: "0 16px 16px" }}>
            <label>Normalized event</label>
            <pre className="raw">{JSON.stringify(detail.event.normalized, null, 2)}</pre>
            <label>Raw event {detail.event.is_synthetic ? "(DEMO/SYNTHETIC)" : ""}</label>
            <pre className="raw">{JSON.stringify(detail.event.raw, null, 2)}</pre>
            {detail.related_events.length > 0 && (
              <>
                <label>Correlated events ({detail.related_events.length})</label>
                <pre className="raw">{JSON.stringify(detail.related_events.map((r: any) =>
                  ({ id: r.id, time: r.timestamp, type: r.event_type, src: r.source_ip, user: r.username })), null, 2)}</pre>
              </>
            )}
          </div>
        </Section>
      )}
    </div>
  );
}
