import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth";
import { Layout } from "./components";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Events from "./pages/Events";
import Alerts from "./pages/Alerts";
import Incidents from "./pages/Incidents";
import Intel from "./pages/Intel";
import Assets from "./pages/Assets";
import Rules from "./pages/Rules";
import Response from "./pages/Response";
import AIAnalyst from "./pages/AIAnalyst";
import Settings from "./pages/Settings";
import System from "./pages/System";

export default function App() {
  const { user, loading } = useAuth();
  if (loading) return <div className="login-wrap"><p style={{ color: "#8a8a86" }}>Loading CHEKWE…</p></div>;
  if (!user) return <Login />;
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/events" element={<Events />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/intel" element={<Intel />} />
        <Route path="/assets" element={<Assets />} />
        <Route path="/rules" element={<Rules />} />
        <Route path="/response" element={<Response />} />
        <Route path="/ai" element={<AIAnalyst />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="/system" element={<System />} />
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </Layout>
  );
}
