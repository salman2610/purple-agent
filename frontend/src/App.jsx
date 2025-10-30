import React, { useState, useEffect } from "react";
import axios from "axios";
import useWebSocket from "react-use-websocket";
import { PieChart, Pie, Cell, Legend, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer } from "recharts";
import { TailSpin } from 'react-loader-spinner';

const API_BASE = "http://localhost:8000";

// Dark theme colors
const DARK_THEME = {
  background: "#1a1a1a",
  cardBackground: "#222",
  border: "#444",
  text: "#fff",
  textMuted: "#aaa",
  primary: "#007bff",
  success: "#28a745",
  danger: "#dc3545",
  warning: "#ffc107",
  info: "#6f42c1"
};

// Colors for charts (adjusted for dark background)
const COLORS = ["#8884d8", "#82ca9d", "#ffc658", "#ff8042", "#00C49F"];

// Dark theme styles - COMPLETELY UPDATED FOR CENTERING
const darkStyles = {
  container: {
    backgroundColor: DARK_THEME.background,
    color: DARK_THEME.text,
    minHeight: "100vh",
    padding: "20px",
    display: "flex",
    flexDirection: "column",
    alignItems: "center"
  },
  mainContent: {
    width: "100%",
    maxWidth: "1200px",
    display: "flex",
    flexDirection: "column",
    alignItems: "center"
  },
  loginContainer: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    minHeight: "60vh",
    width: "100%"
  },
  card: {
    backgroundColor: DARK_THEME.cardBackground,
    border: `1px solid ${DARK_THEME.border}`,
    padding: "20px",
    borderRadius: "8px",
    marginBottom: "20px",
    width: "100%",
    boxSizing: "border-box"
  },
  centeredCard: {
    backgroundColor: DARK_THEME.cardBackground,
    border: `1px solid ${DARK_THEME.border}`,
    padding: "20px",
    borderRadius: "8px",
    marginBottom: "20px",
    width: "100%",
    maxWidth: "800px",
    boxSizing: "border-box",
    textAlign: "center"
  },
  input: {
    width: "100%",
    padding: "10px",
    marginBottom: "15px",
    backgroundColor: "#333",
    color: DARK_THEME.text,
    border: `1px solid ${DARK_THEME.border}`,
    borderRadius: "4px",
    fontSize: "14px",
    boxSizing: "border-box"
  },
  button: {
    padding: "10px 20px",
    border: "none",
    borderRadius: "4px",
    cursor: "pointer",
    color: "white",
    fontSize: "14px",
    fontWeight: "500"
  },
  gridContainer: {
    display: "grid",
    gap: "20px",
    gridTemplateColumns: "1fr 1fr",
    width: "100%",
    maxWidth: "1000px"
  },
  gridFullWidth: {
    display: "grid",
    gap: "20px",
    gridTemplateColumns: "1fr",
    width: "100%",
    maxWidth: "1000px"
  },
  table: {
    width: "100%",
    borderCollapse: "collapse"
  },
  tableHeader: {
    backgroundColor: "#333",
    color: DARK_THEME.text,
    padding: "10px",
    textAlign: "left",
    cursor: "pointer",
    borderBottom: `1px solid ${DARK_THEME.border}`,
    fontSize: "12px"
  },
  tableCell: {
    padding: "10px",
    borderBottom: `1px solid ${DARK_THEME.border}`,
    fontSize: "12px"
  },
  pre: {
    backgroundColor: "#333",
    color: DARK_THEME.text,
    padding: "15px",
    borderRadius: "4px",
    overflow: "auto",
    fontFamily: "monospace",
    fontSize: "12px",
    maxHeight: "200px",
    textAlign: "left"
  },
  message: {
    padding: "12px",
    margin: "10px 0",
    borderRadius: "4px",
    textAlign: "center",
    width: "100%",
    maxWidth: "800px",
    boxSizing: "border-box"
  },
  quickActions: {
    display: "flex",
    gap: "10px",
    flexWrap: "wrap",
    justifyContent: "center",
    width: "100%"
  },
  centeredContent: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    width: "100%"
  }
};

// Metrics Chart Component
function MetricsChart({ cpu, memory, disk }) {
  const data = [
    { name: "CPU Usage", value: cpu || 0 },
    { name: "Memory Usage", value: memory || 0 },
    { name: "Disk Usage", value: disk || 0 },
  ];

  return (
    <div style={darkStyles.card}>
      <h4 style={{ color: DARK_THEME.text, margin: "0 0 15px 0", textAlign: "center" }}>System Usage</h4>
      <div style={{ display: "flex", justifyContent: "center" }}>
        <PieChart width={280} height={250}>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            outerRadius={80}
            dataKey="value"
            label={(entry) => `${entry.name}: ${entry.value.toFixed(1)}%`}
          >
            {data.map((entry, idx) => (
              <Cell key={`cell-${idx}`} fill={COLORS[idx % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip 
            formatter={(value) => `${value.toFixed(2)}%`}
            contentStyle={{ backgroundColor: DARK_THEME.cardBackground, border: `1px solid ${DARK_THEME.border}`, color: DARK_THEME.text }}
          />
          <Legend />
        </PieChart>
      </div>
    </div>
  );
}

// Network Activity Chart
function NetworkChart({ networkData }) {
  if (!networkData) return null;

  const data = [
    { name: "Bytes Sent", value: networkData.bytes_sent || 0 },
    { name: "Bytes Received", value: networkData.bytes_received || 0 },
  ];

  return (
    <div style={darkStyles.card}>
      <h4 style={{ color: DARK_THEME.text, margin: "0 0 15px 0", textAlign: "center" }}>Network Activity</h4>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke={DARK_THEME.border} />
          <XAxis dataKey="name" stroke={DARK_THEME.text} fontSize={12} />
          <YAxis stroke={DARK_THEME.text} fontSize={12} />
          <Tooltip 
            formatter={(value) => `${(value / 1024 / 1024).toFixed(2)} MB`}
            contentStyle={{ backgroundColor: DARK_THEME.cardBackground, border: `1px solid ${DARK_THEME.border}`, color: DARK_THEME.text }}
          />
          <Bar dataKey="value" fill="#8884d8" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// Process List Component
function ProcessList({ processes }) {
  const [search, setSearch] = useState("");
  const [sortKey, setSortKey] = useState("pid");
  const [sortAsc, setSortAsc] = useState(true);

  if (!processes || processes.length === 0) {
    return <p style={{ color: DARK_THEME.textMuted, textAlign: "center" }}>No processes data available</p>;
  }

  const filtered = processes
    .filter(
      (p) =>
        p.name.toLowerCase().includes(search.toLowerCase()) ||
        p.pid.toString().includes(search)
    )
    .sort((a, b) => {
      if (a[sortKey] < b[sortKey]) return sortAsc ? -1 : 1;
      if (a[sortKey] > b[sortKey]) return sortAsc ? 1 : -1;
      return 0;
    });

  const toggleSort = (key) => {
    if (sortKey === key) setSortAsc(!sortAsc);
    else {
      setSortKey(key);
      setSortAsc(true);
    }
  };

  return (
    <div style={darkStyles.card}>
      <h4 style={{ color: DARK_THEME.text, margin: "0 0 15px 0", textAlign: "center" }}>Running Processes</h4>
      <input
        type="text"
        placeholder="Search processes..."
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        style={darkStyles.input}
      />
      <div style={{ maxHeight: "300px", overflow: "auto" }}>
        <table style={darkStyles.table}>
          <thead>
            <tr>
              <th 
                onClick={() => toggleSort("pid")}
                style={darkStyles.tableHeader}
              >
                PID {sortKey === "pid" && (sortAsc ? "↑" : "↓")}
              </th>
              <th 
                onClick={() => toggleSort("name")}
                style={darkStyles.tableHeader}
              >
                Name {sortKey === "name" && (sortAsc ? "↑" : "↓")}
              </th>
              <th 
                onClick={() => toggleSort("cpu")}
                style={darkStyles.tableHeader}
              >
                CPU (%) {sortKey === "cpu" && (sortAsc ? "↑" : "↓")}
              </th>
              <th 
                onClick={() => toggleSort("memory")}
                style={darkStyles.tableHeader}
              >
                Memory (%) {sortKey === "memory" && (sortAsc ? "↑" : "↓")}
              </th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((proc) => (
              <tr key={proc.pid}>
                <td style={{ ...darkStyles.tableCell, color: DARK_THEME.text }}>{proc.pid}</td>
                <td style={{ ...darkStyles.tableCell, color: DARK_THEME.text }}>{proc.name}</td>
                <td style={{ ...darkStyles.tableCell, color: DARK_THEME.text }}>{proc.cpu}</td>
                <td style={{ ...darkStyles.tableCell, color: DARK_THEME.text }}>{proc.memory}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div style={{ fontSize: "12px", color: DARK_THEME.textMuted, marginTop: "8px", textAlign: "center" }}>
        Showing {filtered.length} of {processes.length} processes
      </div>
    </div>
  );
}

// Alert Banner Component
function AlertBanner({ alerts }) {
  const [hiddenAlerts, setHiddenAlerts] = useState([]);

  const acknowledge = (index) => {
    setHiddenAlerts((prev) => [...prev, index]);
  };

  if (!alerts || alerts.length === 0) return null;

  return (
    <div style={{ marginBottom: "20px", width: "100%", maxWidth: "1000px" }}>
      {alerts.map((alert, i) =>
        hiddenAlerts.includes(i) ? null : (
          <div
            key={i}
            style={{
              border: "1px solid #dc3545",
              padding: "15px",
              marginBottom: "8px",
              backgroundColor: "#2d1a1a",
              position: "relative",
              borderRadius: "4px",
              color: DARK_THEME.text,
              textAlign: "center",
              width: "100%"
            }}
          >
            <strong>🚨 Alert: </strong> {alert.message || JSON.stringify(alert)}
            <button
              onClick={() => acknowledge(i)}
              style={{ 
                position: "absolute", 
                right: "10px", 
                top: "10px", 
                background: "none", 
                border: "none", 
                cursor: "pointer",
                fontSize: "18px",
                color: DARK_THEME.text
              }}
            >
              ×
            </button>
          </div>
        )
      )}
    </div>
  );
}

// Live Dashboard Component
function LiveDashboard() {
  const [messages, setMessages] = useState([]);
  const [alerts, setAlerts] = useState([]);

  const { lastMessage, readyState } = useWebSocket("ws://localhost:8000/ws");

  useEffect(() => {
    if (lastMessage !== null) {
      const data = JSON.parse(lastMessage.data);
      setMessages((prev) => [...prev.slice(-49), data]);
      
      if (data.type === 'agent_data_update' && data.data) {
        const cpu = data.data.cpu_usage || 0;
        const memory = data.data.memory_usage || 0;
        const disk = data.data.disk_usage || 0;
        
        if (cpu > 90) {
          setAlerts(prev => [...prev, {
            message: `High CPU Usage: ${cpu.toFixed(1)}% on ${data.data.hostname}`,
            timestamp: new Date().toISOString()
          }]);
        }
        if (memory > 90) {
          setAlerts(prev => [...prev, {
            message: `High Memory Usage: ${memory.toFixed(1)}% on ${data.data.hostname}`,
            timestamp: new Date().toISOString()
          }]);
        }
        if (disk > 90) {
          setAlerts(prev => [...prev, {
            message: `High Disk Usage: ${disk.toFixed(1)}% on ${data.data.hostname}`,
            timestamp: new Date().toISOString()
          }]);
        }
      }
    }
  }, [lastMessage]);

  const connectionStatus = {
    [WebSocket.CONNECTING]: 'Connecting',
    [WebSocket.OPEN]: 'Open',
    [WebSocket.CLOSING]: 'Closing',
    [WebSocket.CLOSED]: 'Closed'
  }[readyState];

  return (
    <div style={{...darkStyles.card, maxWidth: "1000px"}}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" }}>
        <h3 style={{ color: DARK_THEME.text, margin: 0 }}>Live Dashboard</h3>
        <span style={{ 
          padding: "4px 8px", 
          borderRadius: "4px", 
          fontSize: "12px",
          backgroundColor: readyState === WebSocket.OPEN ? DARK_THEME.success : DARK_THEME.danger,
          color: "white"
        }}>
          WebSocket: {connectionStatus}
        </span>
      </div>
      
      <AlertBanner alerts={alerts} />
      
      {messages.length === 0 ? (
        <p style={{ color: DARK_THEME.textMuted, textAlign: "center" }}>No live messages yet. WebSocket connection will show real-time updates.</p>
      ) : (
        <div style={{ maxHeight: "300px", overflow: "auto" }}>
          {messages.map((msg, i) => (
            <div key={i} style={{ 
              padding: "8px", 
              marginBottom: "8px", 
              backgroundColor: "#333", 
              borderRadius: "4px",
              borderLeft: `4px solid ${
                msg.type === 'agent_data_update' ? DARK_THEME.primary : 
                msg.type === 'heartbeat' ? DARK_THEME.textMuted : 
                msg.type === 'connection_established' ? DARK_THEME.success : 
                DARK_THEME.warning
              }`
            }}>
              <div style={{ fontSize: "12px", color: DARK_THEME.textMuted, marginBottom: "4px" }}>
                <strong>Type:</strong> {msg.type} • {new Date(msg.timestamp || Date.now()).toLocaleTimeString()}
              </div>
              <div style={{ fontSize: "14px", color: DARK_THEME.text }}>
                {msg.type === 'agent_data_update' && `New agent data from ${msg.data?.hostname || 'unknown'}`}
                {msg.type === 'heartbeat' && `Heartbeat: ${msg.message}`}
                {msg.type === 'connection_established' && `Connected: ${msg.message}`}
                {msg.type === 'client_message' && msg.message}
                {msg.type === 'initial_data' && `Initial data loaded: ${msg.total_agent_data} entries`}
              </div>
              {msg.data && msg.type === 'agent_data_update' && (
                <div style={{ fontSize: "12px", color: DARK_THEME.textMuted, marginTop: "4px" }}>
                  CPU: {msg.data.cpu_usage?.toFixed(1)}% • Memory: {msg.data.memory_usage?.toFixed(1)}% • Disk: {msg.data.disk_usage?.toFixed(1)}%
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// Main App Component
function App() {
  const [token, setToken] = useState(localStorage.getItem("token") || "");
  const [userInfo, setUserInfo] = useState(null);
  const [agentData, setAgentData] = useState(null);
  const [form, setForm] = useState({ username: "", password: "" });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [dashboardLoading, setDashboardLoading] = useState(false);

  useEffect(() => {
    if (token) {
      fetchUserInfo(token);
      fetchLatestAgentData();
    }
  }, [token]);

  const handleChange = (e) =>
    setForm({ ...form, [e.target.name]: e.target.value });

  const showMessage = (msg, isError = false) => {
    setMessage(msg);
    setTimeout(() => setMessage(""), 5000);
  };

  const login = async () => {
    if (!form.username || !form.password) {
      setError("Please enter both username and password");
      return;
    }

    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.append("username", form.username);
      params.append("password", form.password);

      const resp = await axios.post(`${API_BASE}/token`, params, {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      });
      const newToken = resp.data.access_token;
      setToken(newToken);
      localStorage.setItem("token", newToken);
      setError("");
      showMessage("Login successful!");
      setForm({ username: "", password: "" });
    } catch (err) {
      const errorMsg = err.response?.data?.detail || "Login failed";
      setError(errorMsg);
      showMessage(errorMsg, true);
    } finally {
      setLoading(false);
    }
  };

  const fetchUserInfo = async (userToken = token) => {
    try {
      const resp = await axios.get(`${API_BASE}/users/me`, {
        headers: { Authorization: `Bearer ${userToken}` },
      });
      setUserInfo(resp.data);
    } catch {
      setError("Failed to fetch user info");
      setUserInfo(null);
      logout();
    }
  };

  const logout = () => {
    setToken("");
    setUserInfo(null);
    setAgentData(null);
    localStorage.removeItem("token");
    setError("");
    showMessage("Logged out successfully");
  };

  const fetchLatestAgentData = async () => {
    setDashboardLoading(true);
    try {
      const resp = await axios.get(`${API_BASE}/agent/data/latest`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setAgentData(resp.data.data);
    } catch {
      showMessage("Failed to fetch agent data", true);
    } finally {
      setDashboardLoading(false);
    }
  };

  const submitSampleAgentData = async () => {
    setDashboardLoading(true);
    try {
      const sampleData = {
        timestamp: new Date().toISOString(),
        hostname: "sample-host",
        cpu_usage: Math.random() * 100,
        memory_usage: Math.random() * 100,
        disk_usage: Math.random() * 100,
        network_activity: {
          bytes_sent: Math.floor(Math.random() * 1000000),
          bytes_received: Math.floor(Math.random() * 1000000),
        },
        processes: [
          { pid: 1, name: "systemd", cpu: 0.1, memory: 0.5 },
          { pid: 2, name: "bash", cpu: 0.2, memory: 0.3 },
          { pid: 3, name: "node", cpu: 1.5, memory: 2.1 },
          { pid: 4, name: "python", cpu: 0.8, memory: 1.2 },
        ]
      };

      await axios.post(`${API_BASE}/agent/data`, sampleData, {
        headers: { Authorization: `Bearer ${token}` },
      });
      
      showMessage("Sample agent data submitted!");
      setTimeout(fetchLatestAgentData, 500);
    } catch {
      showMessage("Failed to submit agent data", true);
      setDashboardLoading(false);
    }
  };

  const testSlackAlert = async () => {
    try {
      await axios.post(`${API_BASE}/slack/test`, {}, {
        headers: { Authorization: `Bearer ${token}` },
      });
      showMessage("Slack test alert sent!");
    } catch {
      showMessage("Failed to send Slack test alert", true);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === "Enter") {
      login();
    }
  };

  return (
    <div style={darkStyles.container}>
      <div style={darkStyles.mainContent}>
        <h1 style={{ color: DARK_THEME.text, marginBottom: "30px", textAlign: "center", width: "100%" }}>PurpleTeam Dashboard</h1>
        
        {message && (
          <div style={{
            ...darkStyles.message,
            backgroundColor: message.includes("failed") ? "#2d1a1a" : "#1a2d1a",
            border: `1px solid ${message.includes("failed") ? DARK_THEME.danger : DARK_THEME.success}`,
            color: message.includes("failed") ? "#ff6b6b" : "#6bff6b"
          }}>
            {message}
          </div>
        )}

        {!token ? (
          <div style={darkStyles.loginContainer}>
            <div style={{ ...darkStyles.centeredCard, maxWidth: "400px" }}>
              <h2 style={{ color: DARK_THEME.text, marginBottom: "20px", textAlign: "center" }}>Login</h2>
              <div style={{ marginBottom: "15px" }}>
                <input 
                  name="username" 
                  placeholder="Username (admin)" 
                  value={form.username}
                  onChange={handleChange}
                  onKeyPress={handleKeyPress}
                  style={darkStyles.input}
                />
                <input
                  name="password"
                  type="password"
                  placeholder="Password (adminpass)"
                  value={form.password}
                  onChange={handleChange}
                  onKeyPress={handleKeyPress}
                  style={darkStyles.input}
                />
              </div>
              <button 
                onClick={login} 
                disabled={loading}
                style={{ 
                  ...darkStyles.button,
                  width: "100%", 
                  padding: "12px", 
                  backgroundColor: loading ? DARK_THEME.border : DARK_THEME.primary,
                  cursor: loading ? "not-allowed" : "pointer"
                }}
              >
                {loading ? <TailSpin height={20} width={20} color="white" /> : "Login"}
              </button>
              {error && <p style={{ color: DARK_THEME.danger, marginTop: "15px", textAlign: "center" }}>{error}</p>}
              <div style={{ marginTop: "15px", fontSize: "12px", color: DARK_THEME.textMuted, textAlign: "center" }}>
                <strong>Demo credentials:</strong> admin / adminpass
              </div>
            </div>
          </div>
        ) : (
          <div style={darkStyles.centeredContent}>
            {/* Header */}
            <div style={darkStyles.centeredCard}>
              <h2 style={{ color: DARK_THEME.text, margin: "0 0 10px 0" }}>Welcome, {userInfo?.username}!</h2>
              <button onClick={logout} style={{ ...darkStyles.button, backgroundColor: DARK_THEME.danger }}>
                Logout
              </button>
            </div>

            {/* Quick Actions */}
            <div style={darkStyles.centeredCard}>
              <h3 style={{ color: DARK_THEME.text, margin: "0 0 15px 0", textAlign: "center" }}>Quick Actions</h3>
              <div style={darkStyles.quickActions}>
                <button onClick={() => fetchUserInfo()} style={darkStyles.button}>
                  Refresh User Info
                </button>
                <button onClick={fetchLatestAgentData} disabled={dashboardLoading} style={darkStyles.button}>
                  {dashboardLoading ? <TailSpin height={20} width={20} /> : "Refresh Agent Data"}
                </button>
                <button onClick={submitSampleAgentData} disabled={dashboardLoading} style={{ ...darkStyles.button, backgroundColor: DARK_THEME.success }}>
                  {dashboardLoading ? <TailSpin height={20} width={20} /> : "Submit Sample Data"}
                </button>
                <button onClick={testSlackAlert} style={{ ...darkStyles.button, backgroundColor: DARK_THEME.info }}>
                  Test Slack Alert
                </button>
              </div>
            </div>

            {/* Dashboard Content */}
            {dashboardLoading ? (
              <div style={darkStyles.centeredCard}>
                <TailSpin height={40} width={40} />
                <p style={{ color: DARK_THEME.text, marginTop: "15px" }}>Loading agent data...</p>
              </div>
            ) : agentData ? (
              <div style={darkStyles.centeredContent}>
                {/* Charts Row */}
                <div style={darkStyles.gridContainer}>
                  <MetricsChart 
                    cpu={agentData.cpu_usage}
                    memory={agentData.memory_usage}
                    disk={agentData.disk_usage}
                  />
                  <NetworkChart networkData={agentData.network_activity} />
                </div>

                {/* Data Row */}
                <div style={darkStyles.gridContainer}>
                  <div style={darkStyles.card}>
                    <h3 style={{ color: DARK_THEME.text, margin: "0 0 15px 0", textAlign: "center" }}>User Information</h3>
                    {userInfo ? (
                      <pre style={darkStyles.pre}>
                        {JSON.stringify(userInfo, null, 2)}
                      </pre>
                    ) : (
                      <p style={{ color: DARK_THEME.textMuted, textAlign: "center" }}>Loading user info...</p>
                    )}
                  </div>
                  <ProcessList processes={agentData.processes} />
                </div>

                {/* Raw Data */}
                <div style={{...darkStyles.card, maxWidth: "1000px"}}>
                  <h3 style={{ color: DARK_THEME.text, margin: "0 0 15px 0", textAlign: "center" }}>Raw Agent Data</h3>
                  <textarea
                    value={JSON.stringify(agentData, null, 2)}
                    readOnly
                    style={{
                      width: "100%",
                      height: "200px",
                      background: "#333",
                      color: "#fff",
                      fontFamily: "monospace",
                      padding: "15px",
                      borderRadius: "4px",
                      border: `1px solid ${DARK_THEME.border}`,
                      resize: "none",
                      fontSize: "12px"
                    }}
                  />
                </div>
              </div>
            ) : (
              <div style={darkStyles.centeredCard}>
                <p style={{ color: DARK_THEME.textMuted }}>No agent data available. Submit sample data to get started.</p>
              </div>
            )}

            {/* Live Dashboard */}
            <LiveDashboard />
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
