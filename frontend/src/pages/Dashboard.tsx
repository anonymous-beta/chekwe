import { useState } from "react";
import { api } from "../api";
import { Badge, EmptyState, ErrorBox, MiniBars, Section, Stat, fmtTime, usePolling } from "../components";

type Dash = {
  events_per_second: number; events_1h: number; open_incidents: number;
  open_alerts: Record<string, number>; hosts_monitored: number; sensors: number;
  suspicious_ips: number; detection_rate: number; threat_level: string;
  timeline: { minute: string; events: number }[]; top_rules: { rule: string; triggers: number }[];
  affected_assets: { hostname: string; risk: number }[];
  recent_incidents: any[]; recent_actions: any[];
};

export default function Dashboard() {
  const [data, setData] = useState<Dash | null>(null);
  const [error, setError] = useState<unknown>(null);
  usePolling(() => {
    api.get("/dashboard").then(setData).catch(setError);
  }, 5000);

  if (error) return <ErrorBox error={error} />;
  if (!data) return <EmptyState title="Connecting to CHEKWE backend…" />;
  const noData = data.events_1h === 0 && data.open_incidents === 0;

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Command Center</h1>
          <div className="tagline">THREAT LEVEL: {data.threat_level.toUpperCase()}</div>
        </div>
      </div>
      {noData && <EmptyState title="No telemetry yet">
        Ingest events via <span className="mono">POST /api/v1/events</span> or run a clearly-labeled
        demo scenario from Live Events → Generate Demo.
      </EmptyState>}
      <div className="grid cols-4">
        <Stat label="Events / second" value={data.events_per_second} />
        <Stat label="Events (1h)" value={data.events_1h} />
        <Stat label="Open incidents" value={data.open_incidents}
          tone={data.open_incidents > 0 ? "red" : "ivory"} />
        <Stat label="Critical alerts" value={data.open_alerts.critical}
          tone={data.open_alerts.critical > 0 ? "red" : "ivory"} />
        <Stat label="High alerts" value={data.open_alerts.high}
          tone={data.open_alerts.high > 0 ? "red" : "ivory"} />
        <Stat label="Hosts monitored" value={data.hosts_monitored} tone="gold" />
        <Stat label="Active sensors" value={data.sensors} />
        <Stat label="Suspicious IPs (IOC)" value={data.suspicious_ips}
          tone={data.suspicious_ips > 0 ? "red" : "ivory"} />
      </div>

      <div className="grid cols-2" style={{ marginTop: 14 }}>
        <Section title="Event volume — last 60 minutes">
          <div style={{ padding: 12 }}>
            <MiniBars data={data.timeline.map((t) => t.events)} height={70} />
            <p style={{ color: "#8a8a86", fontSize: 11, margin: "6px 0 0" }}>
              Detection rate: {(data.detection_rate * 100).toFixed(2)}% of events alerted
            </p>
          </div>
        </Section>
        <Section title="Top detection rules">
          <table>
            <tbody>
              {data.top_rules.map((r) => (
                <tr key={r.rule}>
                  <td className="mono">{r.rule}</td>
                  <td>{r.triggers} triggers</td>
                </tr>
              ))}
              {!data.top_rules.length && <tr><td colSpan={2} style={{ color: "#8a8a86" }}>No rule triggers yet.</td></tr>}
            </tbody>
          </table>
        </Section>
        <Section title="Recent incidents">
          <table>
            <thead><tr><th>Title</th><th>Severity</th><th>Status</th><th>Created</th></tr></thead>
            <tbody>
              {data.recent_incidents.map((i) => (
                <tr key={i.id}>
                  <td>{i.title}</td>
                  <td><Badge level={i.severity} /></td>
                  <td>{i.status}</td>
                  <td>{fmtTime(i.created_at)}</td>
                </tr>
              ))}
              {!data.recent_incidents.length && <tr><td colSpan={4} style={{ color: "#8a8a86" }}>No incidents.</td></tr>}
            </tbody>
          </table>
        </Section>
        <Section title="Recent response actions">
          <table>
            <thead><tr><th>Action</th><th>Target</th><th>Status</th><th>Dry run</th></tr></thead>
            <tbody>
              {data.recent_actions.map((a) => (
                <tr key={a.id}>
                  <td className="mono">{a.action_type}</td>
                  <td className="mono">{a.target}</td>
                  <td>{a.status}</td>
                  <td>{a.dry_run ? "yes" : "no"}</td>
                </tr>
              ))}
              {!data.recent_actions.length && <tr><td colSpan={4} style={{ color: "#8a8a86" }}>No response actions yet.</td></tr>}
            </tbody>
          </table>
        </Section>
      </div>
    </div>
  );
}
