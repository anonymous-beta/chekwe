import { useEffect, useState } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { ErrorBox, Section, StatusBadge } from "../components";

export default function Settings() {
  const { can } = useAuth();
  const [users, setUsers] = useState<any[]>([]);
  const [settings, setSettings] = useState<any>(null);
  const [integrations, setIntegrations] = useState<any[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [newUser, setNewUser] = useState({ username: "", password: "", role: "viewer" });
  const [itForm, setItForm] = useState({ name: "", type: "webhook", endpoint: "", secret: "", enabled: false });

  const load = () => {
    if (can("admin")) api.get("/auth/users").then(setUsers).catch(setError);
    api.get("/settings").then(setSettings).catch(setError);
    api.get("/integrations").then(setIntegrations).catch(setError);
  };
  useEffect(load, []); // eslint-disable-line

  const addUser = () => api.post("/auth/users", newUser).then(() => {
    setNewUser({ username: "", password: "", role: "viewer" }); load();
  }).catch(setError);

  const changeRole = (u: any, role: string) =>
    api.patch(`/auth/users/${u.username}`, { role }).then(load).catch(setError);

  const addIntegration = () => api.post("/integrations", itForm).then(() => {
    setItForm({ name: "", type: "webhook", endpoint: "", secret: "", enabled: false }); load();
  }).catch(setError);

  const toggleIt = (i: any) => api.patch(`/integrations/${i.id}`, { enabled: !i.enabled }).then(load).catch(setError);
  const testIt = (i: any) => api.post(`/integrations/${i.id}/test`).then(load).catch(setError);

  return (
    <div>
      <div className="page-head"><h1>Settings</h1></div>
      <ErrorBox error={error} />

      <Section title="General">
        <div className="kv"><span>Application</span><span>{settings?.app} v{settings?.version}</span></div>
        <div className="kv"><span>Tagline</span><span>DETECT. UNDERSTAND. RESPOND.</span></div>
        <div className="kv"><span>Demo mode</span><span>{settings?.demo_mode ? "ENABLED (synthetic events labeled)" : "disabled"}</span></div>
        <div className="kv"><span>Creator</span><span>CHEKWE — by Anonymous-beta</span></div>
      </Section>

      {can("admin") && (
        <>
          <Section title="Users & roles">
            <table>
              <thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Active</th><th></th></tr></thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.username}>
                    <td>{u.username}</td>
                    <td>{u.email || "—"}</td>
                    <td>
                      <select value={u.role} onChange={(e) => changeRole(u, e.target.value)}>
                        {["admin", "analyst", "viewer"].map((r) => <option key={r}>{r}</option>)}
                      </select>
                    </td>
                    <td>{u.is_active ? "yes" : "no"}</td>
                    <td></td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div style={{ padding: 12, display: "flex", gap: 8 }}>
              <input placeholder="Username" value={newUser.username}
                onChange={(e) => setNewUser({ ...newUser, username: e.target.value })} />
              <input placeholder="Password (min 8 chars)" type="password" value={newUser.password}
                onChange={(e) => setNewUser({ ...newUser, password: e.target.value })} />
              <select value={newUser.role} onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}>
                {["viewer", "analyst", "admin"].map((r) => <option key={r}>{r}</option>)}
              </select>
              <button className="btn primary" onClick={addUser}>Create user</button>
            </div>
          </Section>

          <Section title="Integrations (EDR / identity / firewall webhook / email)">
            <table>
              <thead><tr><th>Name</th><th>Type</th><th>Endpoint</th><th>Enabled</th><th>Status</th><th></th></tr></thead>
              <tbody>
                {integrations.map((i) => (
                  <tr key={i.id}>
                    <td>{i.name}</td>
                    <td className="mono">{i.type}</td>
                    <td className="mono">{i.endpoint || "—"}</td>
                    <td>{i.enabled ? "yes" : "no"}</td>
                    <td><StatusBadge status={i.last_status} /></td>
                    <td>
                      <button className="btn ghost" onClick={() => toggleIt(i)}>{i.enabled ? "Disable" : "Enable"}</button>{" "}
                      <button className="btn" onClick={() => testIt(i)}>Test</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div style={{ padding: 12, display: "flex", gap: 8, flexWrap: "wrap" }}>
              <input placeholder="Name" value={itForm.name} style={{ width: 150 }}
                onChange={(e) => setItForm({ ...itForm, name: e.target.value })} />
              <select value={itForm.type} onChange={(e) => setItForm({ ...itForm, type: e.target.value })}>
                {["webhook", "edr", "identity", "firewall", "email", "blocklist"].map((t) => <option key={t}>{t}</option>)}
              </select>
              <input placeholder="https://…" value={itForm.endpoint} style={{ flex: 1 }}
                onChange={(e) => setItForm({ ...itForm, endpoint: e.target.value })} />
              <input placeholder="Bearer secret (optional)" type="password" value={itForm.secret}
                onChange={(e) => setItForm({ ...itForm, secret: e.target.value })} />
              <button className="btn primary" onClick={addIntegration}>Add integration</button>
            </div>
          </Section>
        </>
      )}
    </div>
  );
}
