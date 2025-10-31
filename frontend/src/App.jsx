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
  info: "#6f42c1",
  secondary: "#6c757d"
};

// Colors for charts (adjusted for dark background)
const COLORS = ["#8884d8", "#82ca9d", "#ffc658", "#ff8042", "#00C49F"];

// PROPERLY CENTERED Dark theme styles
const darkStyles = {
  container: {
    backgroundColor: DARK_THEME.background,
    color: DARK_THEME.text,
    minHeight: "100vh",
    width: "100vw",
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    padding: "20px",
    boxSizing: "border-box"
  },
  mainContent: {
    maxWidth: "1000px",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    gap: "20px"
  },
  loginContainer: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    minHeight: "60vh"
  },
  card: {
    backgroundColor: DARK_THEME.cardBackground,
    border: `1px solid ${DARK_THEME.border}`,
    padding: "20px",
    borderRadius: "8px",
    width: "100%",
    maxWidth: "800px",
    textAlign: "center",
    boxSizing: "border-box"
  },
  gridCard: {
    backgroundColor: DARK_THEME.cardBackground,
    border: `1px solid ${DARK_THEME.border}`,
    padding: "20px",
    borderRadius: "8px",
    width: "100%",
    textAlign: "center",
    boxSizing: "border-box",
    height: "100%"
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
  select: {
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
    fontWeight: "500",
    margin: "5px"
  },
  gridContainer: {
    display: "grid",
    gap: "20px",
    gridTemplateColumns: "1fr 1fr",
    width: "100%"
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
  tabContainer: {
    display: "flex",
    gap: "10px",
    marginBottom: "20px",
    justifyContent: "center"
  },
  tab: {
    padding: "10px 20px",
    border: "none",
    borderRadius: "4px",
    cursor: "pointer",
    fontSize: "14px",
    fontWeight: "500"
  }
};

// Create axios instance with auth interceptor
const createApiClient = (token) => {
  const client = axios.create({
    baseURL: API_BASE,
  });

  if (token) {
    client.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  }

  return client;
};

// MetricsChart Component
function MetricsChart({ cpu, memory, disk }) {
  const data = [
    { name: 'CPU', value: cpu, color: COLORS[0] },
    { name: 'Memory', value: memory, color: COLORS[1] },
    { name: 'Disk', value: disk, color: COLORS[2] }
  ];
  
  return (
    <div style={darkStyles.gridCard}>
      <h3 style={{ color: DARK_THEME.text, marginBottom: "15px" }}>System Metrics</h3>
      <ResponsiveContainer width="100%" height={300}>
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            outerRadius={100}
            label={({ name, value }) => `${name}: ${value.toFixed(1)}%`}
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip 
            formatter={(value) => [`${value.toFixed(1)}%`, 'Usage']}
            contentStyle={{ backgroundColor: DARK_THEME.cardBackground, border: `1px solid ${DARK_THEME.border}` }}
          />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
      <div style={{ marginTop: "10px", display: "flex", justifyContent: "space-around" }}>
        <span style={{ color: COLORS[0] }}>CPU: {cpu?.toFixed(1)}%</span>
        <span style={{ color: COLORS[1] }}>Memory: {memory?.toFixed(1)}%</span>
        <span style={{ color: COLORS[2] }}>Disk: {disk?.toFixed(1)}%</span>
      </div>
    </div>
  );
}

// NetworkChart Component
function NetworkChart({ networkData }) {
  const data = [
    { 
      name: 'Bytes Sent', 
      value: networkData?.bytes_sent || 0,
      readable: formatBytes(networkData?.bytes_sent || 0)
    },
    { 
      name: 'Bytes Received', 
      value: networkData?.bytes_received || 0,
      readable: formatBytes(networkData?.bytes_received || 0)
    }
  ];

  function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
  
  return (
    <div style={darkStyles.gridCard}>
      <h3 style={{ color: DARK_THEME.text, marginBottom: "15px" }}>Network Activity</h3>
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke={DARK_THEME.border} />
          <XAxis 
            dataKey="name" 
            stroke={DARK_THEME.text}
            fontSize={12}
          />
          <YAxis 
            stroke={DARK_THEME.text}
            fontSize={12}
          />
          <Tooltip 
            formatter={(value) => [formatBytes(value), 'Network Traffic']}
            contentStyle={{ backgroundColor: DARK_THEME.cardBackground, border: `1px solid ${DARK_THEME.border}` }}
          />
          <Bar 
            dataKey="value" 
            fill={COLORS[3]}
            radius={[4, 4, 0, 0]}
          />
        </BarChart>
      </ResponsiveContainer>
      <div style={{ marginTop: "10px", display: "flex", justifyContent: "space-around", fontSize: "12px" }}>
        <span>Sent: {data[0].readable}</span>
        <span>Received: {data[1].readable}</span>
      </div>
    </div>
  );
}

// ProcessList Component
function ProcessList({ processes }) {
  return (
    <div style={darkStyles.gridCard}>
      <h3 style={{ color: DARK_THEME.text, marginBottom: "15px" }}>Running Processes ({processes?.length || 0})</h3>
      <div style={{ maxHeight: '400px', overflow: 'auto' }}>
        {processes && processes.length > 0 ? (
          <table style={darkStyles.table}>
            <thead>
              <tr>
                <th style={darkStyles.tableHeader}>PID</th>
                <th style={darkStyles.tableHeader}>Process Name</th>
                <th style={darkStyles.tableHeader}>CPU %</th>
                <th style={darkStyles.tableHeader}>Memory %</th>
              </tr>
            </thead>
            <tbody>
              {processes.map((process, index) => (
                <tr key={index} style={{ 
                  backgroundColor: index % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.05)'
                }}>
                  <td style={{ ...darkStyles.tableCell, fontFamily: 'monospace' }}>{process.pid}</td>
                  <td style={{ ...darkStyles.tableCell, color: DARK_THEME.primary }}>{process.name}</td>
                  <td style={{ 
                    ...darkStyles.tableCell, 
                    color: process.cpu > 50 ? DARK_THEME.danger : DARK_THEME.text,
                    fontWeight: process.cpu > 50 ? 'bold' : 'normal'
                  }}>
                    {process.cpu?.toFixed(1)}%
                  </td>
                  <td style={{ 
                    ...darkStyles.tableCell, 
                    color: process.memory > 50 ? DARK_THEME.warning : DARK_THEME.text,
                    fontWeight: process.memory > 50 ? 'bold' : 'normal'
                  }}>
                    {process.memory?.toFixed(1)}%
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p style={{ color: DARK_THEME.textMuted, textAlign: "center", padding: "20px" }}>
            No processes data available
          </p>
        )}
      </div>
    </div>
  );
}

// AlertBanner Component
function AlertBanner({ message, type = 'info' }) {
  const bgColor = type === 'error' ? '#2d1a1a' : type === 'warning' ? '#2d2a1a' : '#1a2d1a';
  const borderColor = type === 'error' ? DARK_THEME.danger : type === 'warning' ? DARK_THEME.warning : DARK_THEME.success;
  const textColor = type === 'error' ? '#ff6b6b' : type === 'warning' ? '#ffd700' : '#6bff6b';
  
  return (
    <div style={{
      ...darkStyles.message,
      backgroundColor: bgColor,
      border: `1px solid ${borderColor}`,
      color: textColor,
      marginBottom: "15px"
    }}>
      {message}
    </div>
  );
}

// LiveDashboard Component
function LiveDashboard({ token }) {
  const [messages, setMessages] = useState([]);
  
  const { lastMessage, readyState } = useWebSocket(
    `ws://localhost:8000/ws`,
    {
      shouldReconnect: () => true,
      retryOnError: true,
      reconnectAttempts: 10,
      reconnectInterval: 3000
    }
  );

  useEffect(() => {
    if (lastMessage) {
      const data = JSON.parse(lastMessage.data);
      setMessages(prev => [data, ...prev.slice(0, 9)]); // Keep last 10 messages
    }
  }, [lastMessage]);

  const connectionStatus = {
    0: 'Connecting...',
    1: 'Connected ✅',
    2: 'Closing',
    3: 'Closed'
  }[readyState];

  return (
    <div style={darkStyles.card}>
      <h3 style={{ color: DARK_THEME.text, marginBottom: "15px" }}>Live Dashboard</h3>
      <div style={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center',
        marginBottom: '15px',
        padding: '10px',
        backgroundColor: readyState === 1 ? '#1a2d1a' : '#2d1a1a',
        border: `1px solid ${readyState === 1 ? DARK_THEME.success : DARK_THEME.danger}`,
        borderRadius: '4px'
      }}>
        <span style={{ color: DARK_THEME.text }}>
          WebSocket Status: <strong>{connectionStatus}</strong>
        </span>
        <span style={{ 
          color: readyState === 1 ? DARK_THEME.success : DARK_THEME.danger,
          fontSize: '12px'
        }}>
          {messages.length} messages
        </span>
      </div>
      
      <div style={{ 
        maxHeight: '300px', 
        overflow: 'auto',
        border: `1px solid ${DARK_THEME.border}`,
        borderRadius: '4px',
        padding: '10px'
      }}>
        {messages.length > 0 ? (
          messages.map((msg, index) => (
            <div 
              key={index} 
              style={{ 
                padding: '8px', 
                borderBottom: index < messages.length - 1 ? `1px solid ${DARK_THEME.border}` : 'none',
                fontSize: '12px',
                color: DARK_THEME.textMuted,
                backgroundColor: index % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.05)'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ 
                  color: msg.type === 'agent_data_update' ? DARK_THEME.success : 
                         msg.type === 'heartbeat' ? DARK_THEME.info : DARK_THEME.primary,
                  fontWeight: 'bold'
                }}>
                  {msg.type}
                </span>
                <span style={{ fontSize: '11px' }}>
                  {new Date(msg.timestamp).toLocaleTimeString()}
                </span>
              </div>
              <div style={{ marginTop: '4px' }}>
                {msg.message || (msg.data ? 'Data updated' : 'Heartbeat')}
              </div>
            </div>
          ))
        ) : (
          <div style={{ 
            textAlign: 'center', 
            padding: '20px', 
            color: DARK_THEME.textMuted,
            fontStyle: 'italic'
          }}>
            No messages yet. WebSocket events will appear here.
          </div>
        )}
      </div>
    </div>
  );
}

// User Management Component
function UserManagement({ apiClient, currentUser }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");

  const showMessage = (msg, isError = false) => {
    setMessage(msg);
    setTimeout(() => setMessage(""), 5000);
  };

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const resp = await apiClient.get("/admin/users");
      setUsers(resp.data);
    } catch (error) {
      showMessage("Failed to fetch users", true);
    } finally {
      setLoading(false);
    }
  };

  const updateUserRole = async (userId, newRole) => {
    try {
      await apiClient.put(`/admin/users/${userId}/role`, { role: newRole });
      showMessage("User role updated successfully");
      fetchUsers(); // Refresh the list
    } catch (error) {
      showMessage("Failed to update user role", true);
    }
  };

  const toggleUserStatus = async (userId, currentStatus) => {
    try {
      if (currentStatus) {
        await apiClient.put(`/admin/users/${userId}/enable`);
        showMessage("User enabled successfully");
      } else {
        await apiClient.put(`/admin/users/${userId}/disable`);
        showMessage("User disabled successfully");
      }
      fetchUsers(); // Refresh the list
    } catch (error) {
      showMessage("Failed to update user status", true);
    }
  };

  useEffect(() => {
    if (currentUser?.role === 'admin') {
      fetchUsers();
    }
  }, [currentUser]);

  if (currentUser?.role !== 'admin') {
    return (
      <div style={darkStyles.card}>
        <h3 style={{ color: DARK_THEME.text }}>User Management</h3>
        <p style={{ color: DARK_THEME.textMuted }}>Admin access required to manage users.</p>
      </div>
    );
  }

  return (
    <div style={darkStyles.card}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
        <h3 style={{ color: DARK_THEME.text, margin: 0 }}>User Management</h3>
        <button 
          onClick={fetchUsers} 
          style={{ ...darkStyles.button, backgroundColor: DARK_THEME.secondary }}
        >
          Refresh Users
        </button>
      </div>

      {message && (
        <AlertBanner 
          message={message} 
          type={message.includes("Failed") ? "error" : "success"} 
        />
      )}

      {loading ? (
        <div style={{ textAlign: "center", padding: "20px" }}>
          <TailSpin height={30} width={30} />
          <p style={{ color: DARK_THEME.textMuted, marginTop: "10px" }}>Loading users...</p>
        </div>
      ) : (
        <div style={{ maxHeight: "400px", overflow: "auto" }}>
          <table style={darkStyles.table}>
            <thead>
              <tr>
                <th style={darkStyles.tableHeader}>Username</th>
                <th style={darkStyles.tableHeader}>Email</th>
                <th style={darkStyles.tableHeader}>Role</th>
                <th style={darkStyles.tableHeader}>Status</th>
                <th style={darkStyles.tableHeader}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.id} style={{
                  backgroundColor: user.id === currentUser.id ? 'rgba(0, 123, 255, 0.1)' : 'transparent'
                }}>
                  <td style={{ ...darkStyles.tableCell, color: DARK_THEME.text }}>
                    {user.username} {user.id === currentUser.id && "(You)"}
                  </td>
                  <td style={{ ...darkStyles.tableCell, color: DARK_THEME.text }}>{user.email}</td>
                  <td style={{ ...darkStyles.tableCell, color: DARK_THEME.text }}>
                    <select
                      value={user.role}
                      onChange={(e) => updateUserRole(user.id, e.target.value)}
                      style={darkStyles.select}
                      disabled={user.id === currentUser.id}
                    >
                      <option value="guest">Guest</option>
                      <option value="agent">Agent</option>
                      <option value="admin">Admin</option>
                    </select>
                  </td>
                  <td style={{ ...darkStyles.tableCell, color: DARK_THEME.text }}>
                    <span style={{ 
                      color: user.disabled ? DARK_THEME.danger : DARK_THEME.success,
                      fontWeight: "bold"
                    }}>
                      {user.disabled ? "Disabled" : "Active"}
                    </span>
                  </td>
                  <td style={darkStyles.tableCell}>
                    <button
                      onClick={() => toggleUserStatus(user.id, user.disabled)}
                      style={{
                        ...darkStyles.button,
                        backgroundColor: user.disabled ? DARK_THEME.success : DARK_THEME.warning,
                        padding: "5px 10px",
                        fontSize: "12px"
                      }}
                      disabled={user.id === currentUser.id}
                    >
                      {user.disabled ? "Enable" : "Disable"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// Password Change Component
function PasswordChange({ apiClient }) {
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: "",
    newPassword: "",
    confirmPassword: ""
  });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");

  const showMessage = (msg, isError = false) => {
    setMessage(msg);
    setTimeout(() => setMessage(""), 5000);
  };

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      showMessage("New passwords don't match", true);
      return;
    }

    if (passwordForm.newPassword.length < 6) {
      showMessage("Password must be at least 6 characters", true);
      return;
    }

    setLoading(true);
    try {
      await apiClient.put("/users/me/password", {
        current_password: passwordForm.currentPassword,
        new_password: passwordForm.newPassword
      });
      showMessage("Password changed successfully");
      setPasswordForm({
        currentPassword: "",
        newPassword: "",
        confirmPassword: ""
      });
    } catch (error) {
      showMessage(error.response?.data?.detail || "Failed to change password", true);
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (e) => {
    setPasswordForm({
      ...passwordForm,
      [e.target.name]: e.target.value
    });
  };

  return (
    <div style={darkStyles.card}>
      <h3 style={{ color: DARK_THEME.text, marginBottom: "20px" }}>Change Password</h3>
      
      {message && (
        <AlertBanner 
          message={message} 
          type={message.includes("Failed") ? "error" : "success"} 
        />
      )}

      <form onSubmit={handlePasswordChange}>
        <input
          type="password"
          name="currentPassword"
          placeholder="Current Password"
          value={passwordForm.currentPassword}
          onChange={handleInputChange}
          style={darkStyles.input}
          required
        />
        <input
          type="password"
          name="newPassword"
          placeholder="New Password"
          value={passwordForm.newPassword}
          onChange={handleInputChange}
          style={darkStyles.input}
          required
        />
        <input
          type="password"
          name="confirmPassword"
          placeholder="Confirm New Password"
          value={passwordForm.confirmPassword}
          onChange={handleInputChange}
          style={darkStyles.input}
          required
        />
        <button 
          type="submit" 
          disabled={loading}
          style={{ 
            ...darkStyles.button, 
            backgroundColor: loading ? DARK_THEME.border : DARK_THEME.primary,
            width: "100%"
          }}
        >
          {loading ? <TailSpin height={20} width={20} color="white" /> : "Change Password"}
        </button>
      </form>
    </div>
  );
}

// Registration Component
function Registration({ onSwitchToLogin }) {
  const [registerForm, setRegisterForm] = useState({
    username: "",
    email: "",
    password: "",
    confirmPassword: "",
    role: "guest"
  });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");

  const showMessage = (msg, isError = false) => {
    setMessage(msg);
    setTimeout(() => setMessage(""), 5000);
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    
    if (registerForm.password !== registerForm.confirmPassword) {
      showMessage("Passwords don't match", true);
      return;
    }

    if (registerForm.password.length < 6) {
      showMessage("Password must be at least 6 characters", true);
      return;
    }

    setLoading(true);
    try {
      await axios.post(`${API_BASE}/register`, {
        username: registerForm.username,
        email: registerForm.email,
        password: registerForm.password,
        role: registerForm.role
      });
      showMessage("Registration successful! Please login.");
      setRegisterForm({
        username: "",
        email: "",
        password: "",
        confirmPassword: "",
        role: "guest"
      });
      setTimeout(() => onSwitchToLogin(), 2000);
    } catch (error) {
      showMessage(error.response?.data?.detail || "Registration failed", true);
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (e) => {
    setRegisterForm({
      ...registerForm,
      [e.target.name]: e.target.value
    });
  };

  return (
    <div style={{ ...darkStyles.card, maxWidth: "400px" }}>
      <h2 style={{ color: DARK_THEME.text, marginBottom: "20px", textAlign: "center" }}>Register</h2>
      
      {message && (
        <AlertBanner 
          message={message} 
          type={message.includes("failed") ? "error" : "success"} 
        />
      )}

      <form onSubmit={handleRegister}>
        <input
          name="username"
          placeholder="Username"
          value={registerForm.username}
          onChange={handleInputChange}
          style={darkStyles.input}
          required
        />
        <input
          type="email"
          name="email"
          placeholder="Email"
          value={registerForm.email}
          onChange={handleInputChange}
          style={darkStyles.input}
          required
        />
        <select
          name="role"
          value={registerForm.role}
          onChange={handleInputChange}
          style={darkStyles.select}
        >
          <option value="guest">Guest (Read-only)</option>
          <option value="agent">Agent (Can submit data)</option>
        </select>
        <input
          type="password"
          name="password"
          placeholder="Password"
          value={registerForm.password}
          onChange={handleInputChange}
          style={darkStyles.input}
          required
        />
        <input
          type="password"
          name="confirmPassword"
          placeholder="Confirm Password"
          value={registerForm.confirmPassword}
          onChange={handleInputChange}
          style={darkStyles.input}
          required
        />
        <button 
          type="submit" 
          disabled={loading}
          style={{ 
            ...darkStyles.button,
            width: "100%", 
            padding: "12px", 
            backgroundColor: loading ? DARK_THEME.border : DARK_THEME.primary,
            cursor: loading ? "not-allowed" : "pointer"
          }}
        >
          {loading ? <TailSpin height={20} width={20} color="white" /> : "Register"}
        </button>
      </form>
      
      <div style={{ marginTop: "15px", textAlign: "center" }}>
        <button 
          onClick={onSwitchToLogin}
          style={{ 
            ...darkStyles.button, 
            backgroundColor: "transparent", 
            color: DARK_THEME.primary,
            textDecoration: "underline"
          }}
        >
          Already have an account? Login
        </button>
      </div>
    </div>
  );
}

// Login Component
function Login({ onLogin, onSwitchToRegister }) {
  const [form, setForm] = useState({ username: "", password: "" });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleChange = (e) =>
    setForm({ ...form, [e.target.name]: e.target.value });

  const login = async (e) => {
    e.preventDefault();
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
      
      onLogin(resp.data.access_token, resp.data.user);
      setError("");
      setForm({ username: "", password: "" });
    } catch (err) {
      const errorMsg = err.response?.data?.detail || "Login failed";
      setError(errorMsg);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === "Enter") {
      login(e);
    }
  };

  return (
    <div style={{ ...darkStyles.card, maxWidth: "400px" }}>
      <h2 style={{ color: DARK_THEME.text, marginBottom: "20px", textAlign: "center" }}>Login</h2>
      <form onSubmit={login}>
        <div style={{ marginBottom: "15px" }}>
          <input 
            name="username" 
            placeholder="Username or Email" 
            value={form.username}
            onChange={handleChange}
            onKeyPress={handleKeyPress}
            style={darkStyles.input}
          />
          <input
            name="password"
            type="password"
            placeholder="Password"
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
        {error && <AlertBanner message={error} type="error" />}
      </form>
      
      <div style={{ marginTop: "15px", textAlign: "center" }}>
        <button 
          onClick={onSwitchToRegister}
          style={{ 
            ...darkStyles.button, 
            backgroundColor: "transparent", 
            color: DARK_THEME.primary,
            textDecoration: "underline"
          }}
        >
          Don't have an account? Register
        </button>
      </div>
      
      <div style={{ marginTop: "15px", fontSize: "12px", color: DARK_THEME.textMuted, textAlign: "center" }}>
        <strong>Demo admin:</strong> admin / adminpass
      </div>
    </div>
  );
}

// Main App Component
function App() {
  const [token, setToken] = useState(localStorage.getItem("token") || "");
  const [currentUser, setCurrentUser] = useState(null);
  const [agentData, setAgentData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [dashboardLoading, setDashboardLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("dashboard");
  const [authMode, setAuthMode] = useState("login"); // "login" or "register"

  // Create API client with current token
  const apiClient = createApiClient(token);

  useEffect(() => {
    if (token) {
      fetchUserInfo();
      fetchLatestAgentData();
    }
  }, [token]);

  const fetchUserInfo = async () => {
    try {
      const resp = await apiClient.get("/users/me");
      setCurrentUser(resp.data);
    } catch {
      logout();
    }
  };

  const fetchLatestAgentData = async () => {
    setDashboardLoading(true);
    try {
      const resp = await apiClient.get("/agent/data/latest");
      setAgentData(resp.data.data);
    } catch {
      // Handle error silently
    } finally {
      setDashboardLoading(false);
    }
  };

  const handleLogin = (newToken, user) => {
    setToken(newToken);
    setCurrentUser(user);
    localStorage.setItem("token", newToken);
  };

  const logout = () => {
    setToken("");
    setCurrentUser(null);
    setAgentData(null);
    localStorage.removeItem("token");
    setActiveTab("dashboard");
    setAuthMode("login");
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

      await apiClient.post("/agent/data", sampleData);
      setTimeout(fetchLatestAgentData, 500);
    } catch {
      // Handle error silently
    } finally {
      setDashboardLoading(false);
    }
  };

  const testSlackAlert = async () => {
    try {
      await apiClient.post("/slack/test", {});
    } catch {
      // Handle error silently
    }
  };

  // Render dashboard content
  const renderDashboardContent = () => {
    if (dashboardLoading) {
      return (
        <div style={{ ...darkStyles.card, textAlign: "center", padding: "40px" }}>
          <TailSpin height={40} width={40} />
          <p style={{ color: DARK_THEME.text, marginTop: "15px" }}>Loading agent data...</p>
        </div>
      );
    }

    if (agentData) {
      return (
        <>
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
            <div style={darkStyles.gridCard}>
              <h3 style={{ color: DARK_THEME.text, margin: "0 0 15px 0", textAlign: "center" }}>User Information</h3>
              {currentUser ? (
                <pre style={darkStyles.pre}>
                  {JSON.stringify(currentUser, null, 2)}
                </pre>
              ) : (
                <p style={{ color: DARK_THEME.textMuted, textAlign: "center" }}>Loading user info...</p>
              )}
            </div>
            <ProcessList processes={agentData.processes} />
          </div>

          {/* Raw Data */}
          <div style={darkStyles.card}>
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
        </>
      );
    }

    return (
      <div style={{ ...darkStyles.card, textAlign: "center", padding: "40px" }}>
        <p style={{ color: DARK_THEME.textMuted }}>No agent data available. Submit sample data to get started.</p>
      </div>
    );
  };

  // Render based on authentication status
  if (!token) {
    return (
      <div style={darkStyles.container}>
        <div style={darkStyles.mainContent}>
          <h1 style={{ color: DARK_THEME.text, marginBottom: "10px", textAlign: "center", width: "100%" }}>PurpleTeam Dashboard</h1>
          
          {authMode === "login" ? (
            <Login 
              onLogin={handleLogin}
              onSwitchToRegister={() => setAuthMode("register")}
            />
          ) : (
            <Registration 
              onSwitchToLogin={() => setAuthMode("login")}
            />
          )}
        </div>
      </div>
    );
  }

  return (
    <div style={darkStyles.container}>
      <div style={darkStyles.mainContent}>
        <h1 style={{ color: DARK_THEME.text, marginBottom: "10px", textAlign: "center", width: "100%" }}>PurpleTeam Dashboard</h1>

        {/* Header */}
        <div style={darkStyles.card}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <h2 style={{ color: DARK_THEME.text, margin: "0 0 5px 0" }}>Welcome, {currentUser?.username}!</h2>
              <p style={{ color: DARK_THEME.textMuted, margin: 0 }}>
                Role: <span style={{ 
                  color: currentUser?.role === 'admin' ? DARK_THEME.success : 
                         currentUser?.role === 'agent' ? DARK_THEME.primary : DARK_THEME.textMuted,
                  fontWeight: 'bold'
                }}>{currentUser?.role}</span> | Email: {currentUser?.email}
              </p>
            </div>
            <button onClick={logout} style={{ ...darkStyles.button, backgroundColor: DARK_THEME.danger }}>
              Logout
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div style={darkStyles.tabContainer}>
          <button
            onClick={() => setActiveTab("dashboard")}
            style={{
              ...darkStyles.tab,
              backgroundColor: activeTab === "dashboard" ? DARK_THEME.primary : DARK_THEME.secondary
            }}
          >
            Dashboard
          </button>
          <button
            onClick={() => setActiveTab("account")}
            style={{
              ...darkStyles.tab,
              backgroundColor: activeTab === "account" ? DARK_THEME.primary : DARK_THEME.secondary
            }}
          >
            Account Settings
          </button>
          {currentUser?.role === 'admin' && (
            <button
              onClick={() => setActiveTab("users")}
              style={{
                ...darkStyles.tab,
                backgroundColor: activeTab === "users" ? DARK_THEME.primary : DARK_THEME.secondary
              }}
            >
              User Management
            </button>
          )}
        </div>

        {/* Tab Content */}
        {activeTab === "dashboard" && (
          <>
            {/* Quick Actions */}
            <div style={darkStyles.card}>
              <h3 style={{ color: DARK_THEME.text, margin: "0 0 15px 0" }}>Quick Actions</h3>
              <div style={darkStyles.quickActions}>
                <button onClick={fetchUserInfo} style={darkStyles.button}>
                  Refresh User Info
                </button>
                <button onClick={fetchLatestAgentData} disabled={dashboardLoading} style={darkStyles.button}>
                  {dashboardLoading ? <TailSpin height={20} width={20} /> : "Refresh Agent Data"}
                </button>
                {(currentUser?.role === 'agent' || currentUser?.role === 'admin') && (
                  <>
                    <button onClick={submitSampleAgentData} disabled={dashboardLoading} style={{ ...darkStyles.button, backgroundColor: DARK_THEME.success }}>
                      {dashboardLoading ? <TailSpin height={20} width={20} /> : "Submit Sample Data"}
                    </button>
                    <button onClick={testSlackAlert} style={{ ...darkStyles.button, backgroundColor: DARK_THEME.info }}>
                      Test Slack Alert
                    </button>
                  </>
                )}
              </div>
            </div>

            {/* Dashboard Content */}
            {renderDashboardContent()}

            {/* Live Dashboard */}
            <LiveDashboard token={token} />
          </>
        )}

        {activeTab === "account" && (
          <PasswordChange apiClient={apiClient} />
        )}

        {activeTab === "users" && (
          <UserManagement apiClient={apiClient} currentUser={currentUser} />
        )}
      </div>
    </div>
  );
}

export default App;
