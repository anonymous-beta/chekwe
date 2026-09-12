import { FormEvent, useState } from "react";
import { useAuth } from "../auth";
import { Emblem, ErrorBox } from "../components";

export default function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try { await login(username, password); }
    catch (err) { setError(err); }
    finally { setBusy(false); }
  };

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <Emblem size={52} />
        <h1 style={{ marginTop: 12 }}>CHEKWE</h1>
        <p className="tagline">DETECT. UNDERSTAND. RESPOND.</p>
        <ErrorBox error={error} />
        <label>Username</label>
        <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
        <label>Password</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password" required />
        <div style={{ marginTop: 18 }}>
          <button className="btn primary" style={{ width: "100%" }} disabled={busy}>
            {busy ? "Authenticating…" : "Enter Command Center"}
          </button>
        </div>
        <p style={{ color: "#8a8a86", fontSize: 11, marginTop: 16 }}>
          CHEKWE — by Anonymous-beta · Security Operations &amp; Defense Platform
        </p>
      </form>
    </div>
  );
}
