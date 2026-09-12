import { useState } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { EmptyState, ErrorBox, Section, StatusBadge, fmtTime, usePolling } from "../components";

const ACTION_TYPES = ["block_ip", "blocklist_ioc", "terminate_process", "isolate_host", "lock_account", "quarantine_file"];

export default function Response() {
  const { can } = useAuth();
  const [actions, setActions] = useState<any[]>([]);
  const [policies, setPolicies] = useState<any[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [form, setForm] = useState({ action_type: "block_ip", target: "", reason: "", dry_run: true });

  const load = () => {
    api.get("/response/actions").then(setActions).catch(setError);
    api.get("/response/policies").then(setPolicies).catch(setError);
  };
  usePolling(load, 8000);

  const request = () => {
    api.post("/response/actions", form).then(() => {
      setForm({ ...form, target: "", reason: "" });
      load();
    }).catch(setError);
  };

  const approve = (id: number) => api.post(`/response/actions/${id}/approve`).then(load).catch(setError);
  const reject = (id: number) => api.post(`/response/actions/${id}/reject`, { reason: "rejected by analyst" }).then(load).catch(setError);

  const setPolicy = (p: any, patch: any) =>
    api.patch(`/response/policies/${p.id}`, patch).then(load).catch(setError);

  return (
    <div>
      <div className="page-head"><h1>Response</h1></div>
      <ErrorBox error={error} />
      {can("analyst") && (
        <Section title="Request response action">
          <div style={{ padding: 12, display: "flex", gap: 8, flexWrap: "wrap", alignItems: "end" }}>
            <div>
              <label>Action type</label>
              <select value={form.action_type} onChange={(e) => setForm({ ...form, action_type: e.target.value })}>
                {ACTION_TYPES.map((t) => <option key={t}>{t}</option>)}
              </select>
            </div>
            <div style={{ flex: 1, minWidth: 200 }}>
              <label>Target (IP / host / account / path)</label>
              <input value={form.target} onChange={(e) => setForm({ ...form, target: e.target.value })} />
            </div>
            <div style={{ flex: 2, minWidth: 260 }}>
              <label>Reason (linked to detection)</label>
              <input value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} />
            </div>
            <label style={{ display: "flex", gap: 6, alignItems: "center", margin: 0 }}>
              <input type="checkbox" style={{ width: "auto" }} checked={form.dry_run}
                onChange={(e) => setForm({ ...form, dry_run: e.target.checked })} /> Dry run
            </label>
            <button className="btn primary" onClick={request}
              disabled={!form.target || form.reason.length < 3}>Request</button>
          </div>
          <p style={{ padding: "0 12px 12px", color: "#8a8a86", fontSize: 12 }}>
            Actions without a configured integration (EDR / identity / firewall webhook) report
            “unavailable” instead of pretending to succeed. All actions are audited.
          </p>
        </Section>
      )}

      <Section title="Response policies">
        <table>
          <thead><tr><th>Action type</th><th>Mode</th><th>Enabled</th>{can("admin") && <th></th>}</tr></thead>
          <tbody>
            {policies.map((p) => (
              <tr key={p.id}>
                <td className="mono">{p.action_type}</td>
                <td><StatusBadge status={p.mode} /></td>
                <td>{p.enabled ? "yes" : "no"}</td>
                {can("admin") && (
                  <td>
                    <select value={p.mode} style={{ width: 130 }}
                      onChange={(e) => setPolicy(p, { mode: e.target.value })}>
                      {["automatic", "manual", "approval"].map((m) => <option key={m}>{m}</option>)}
                    </select>{" "}
                    <button className="btn ghost" onClick={() => setPolicy(p, { enabled: !p.enabled })}>
                      {p.enabled ? "Disable" : "Enable"}
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      {!actions.length && <EmptyState title="No response actions yet" />}
      <Section title="Response actions">
        <table>
          <thead><tr><th>Time</th><th>Action</th><th>Target</th><th>Reason</th><th>Mode</th><th>Status</th><th>Result</th><th></th></tr></thead>
          <tbody>
            {actions.map((a) => (
              <tr key={a.id}>
                <td className="mono">{fmtTime(a.created_at)}</td>
                <td className="mono">{a.action_type}</td>
                <td className="mono">{a.target}</td>
                <td>{a.reason}</td>
                <td>{a.dry_run ? "dry-run" : "live"}</td>
                <td><StatusBadge status={a.status} /></td>
                <td style={{ maxWidth: 280 }}>{a.result?.message || "—"}</td>
                <td onClick={(e) => e.stopPropagation()}>
                  {can("analyst") && a.status === "pending" && (
                    <>
                      <button className="btn primary" onClick={() => approve(a.id)}>Approve &amp; execute</button>{" "}
                      <button className="btn danger" onClick={() => reject(a.id)}>Reject</button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>
    </div>
  );
}
