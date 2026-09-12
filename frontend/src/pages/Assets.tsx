import { useState } from "react";
import { api } from "../api";
import { EmptyState, ErrorBox, Section, usePolling } from "../components";

export default function Assets() {
  const [assets, setAssets] = useState<any[]>([]);
  const [error, setError] = useState<unknown>(null);
  usePolling(() => { api.get("/assets").then(setAssets).catch(setError); }, 10000);

  return (
    <div>
      <div className="page-head"><h1>Asset Inventory</h1></div>
      <ErrorBox error={error} />
      {!assets.length && <EmptyState title="No assets discovered">
        Assets are created automatically as telemetry arrives with host or IP fields.
      </EmptyState>}
      <Section title={`${assets.length} monitored assets`}>
        <table>
          <thead><tr><th>Hostname</th><th>IP</th><th>Status</th><th>Agent</th><th>Risk</th><th>Open alerts</th><th>Open incidents</th><th>Last seen</th></tr></thead>
          <tbody>
            {assets.map((a) => (
              <tr key={a.id}>
                <td>{a.hostname}</td>
                <td className="mono">{a.ip || "—"}</td>
                <td>{a.status}</td>
                <td>{a.agent_status}</td>
                <td style={{ color: a.risk_score > 50 ? "#FF1A1A" : a.risk_score > 20 ? "#B08D57" : "#E8E3D8" }}>
                  {a.risk_score.toFixed(0)}</td>
                <td>{a.open_alerts}</td>
                <td>{a.open_incidents}</td>
                <td className="mono">{a.last_seen}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>
    </div>
  );
}
