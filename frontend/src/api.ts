const TOKEN_KEY = "chekwe_token";

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}
export function setToken(t: string | null) {
  if (t) sessionStorage.setItem(TOKEN_KEY, t);
  else sessionStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request(path: string, options: RequestInit = {}): Promise<any> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  let res: Response;
  try {
    res = await fetch(`/api/v1${path}`, { ...options, headers });
  } catch {
    throw new ApiError(0, "Network failure — backend unreachable");
  }
  if (res.status === 401) {
    setToken(null);
    window.dispatchEvent(new Event("chekwe:unauthorized"));
  }
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try { msg = (await res.json()).detail || msg; } catch { /* keep */ }
    throw new ApiError(res.status, msg);
  }
  return res.json();
}

export const api = {
  get: (p: string) => request(p),
  post: (p: string, body?: any) => request(p, { method: "POST", body: JSON.stringify(body ?? {}) }),
  put: (p: string, body?: any) => request(p, { method: "PUT", body: JSON.stringify(body ?? {}) }),
  patch: (p: string, body?: any) => request(p, { method: "PATCH", body: JSON.stringify(body ?? {}) }),
  del: (p: string) => request(p, { method: "DELETE" }),
  login: (username: string, password: string) =>
    request("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ username, password }),
    }),
};

export function connectWS(onEvent: (msg: any) => void): () => void {
  let ws: WebSocket | null = null;
  let closed = false;
  const open = () => {
    const token = getToken();
    if (!token || closed) return;
    const proto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${proto}://${location.host}/ws/events?token=${encodeURIComponent(token)}`);
    ws.onmessage = (m) => { try { onEvent(JSON.parse(m.data)); } catch { /* ignore */ } };
    ws.onclose = () => { if (!closed) setTimeout(open, 3000); };
  };
  open();
  return () => { closed = true; ws?.close(); };
}
