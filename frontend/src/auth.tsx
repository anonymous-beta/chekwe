import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { api, setToken, getToken } from "./api";

export type Role = "admin" | "analyst" | "viewer";

type AuthCtx = {
  user: { username: string; role: Role } | null;
  loading: boolean;
  login: (u: string, p: string) => Promise<void>;
  logout: () => void;
  can: (min: Role) => boolean;
};

const Ctx = createContext<AuthCtx>(null as any);
const rank: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 };

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthCtx["user"]>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!getToken()) { setLoading(false); return; }
    api.get("/auth/me")
      .then((u) => setUser({ username: u.username, role: u.role }))
      .catch(() => setToken(null))
      .finally(() => setLoading(false));
    const onExpire = () => setUser(null);
    window.addEventListener("chekwe:unauthorized", onExpire);
    return () => window.removeEventListener("chekwe:unauthorized", onExpire);
  }, []);

  const login = async (u: string, p: string) => {
    const r = await api.login(u, p);
    setToken(r.access_token);
    const me = await api.get("/auth/me");
    setUser({ username: me.username, role: me.role });
  };

  const logout = () => {
    api.post("/auth/logout").catch(() => undefined);
    setToken(null);
    setUser(null);
  };

  const can = (min: Role) => !!user && rank[user.role] >= rank[min];

  return <Ctx.Provider value={{ user, loading, login, logout, can }}>{children}</Ctx.Provider>;
}

export const useAuth = () => useContext(Ctx);
