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

// SVG Icons as React components
const FilterIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M10 18h4v-2h-4v2zM3 6v2h18V6H3zm3 7h12v-2H6v2z"/>
  </svg>
);

const DownloadIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z"/>
  </svg>
);

const SettingsIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/>
  </svg>
);

const CloseIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
  </svg>
);

const ChevronRightIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z"/>
  </svg>
);

const SlidersIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M4 21h16c.55 0 1-.45 1-1s-.45-1-1-1H4c-.55 0-1 .45-1 1s.45 1 1 1zm0-4h16c.55 0 1-.45 1-1s-.45-1-1-1H4c-.55 0-1 .45-1 1s.45 1 1 1zm0-4h16c.55 0 1-.45 1-1s-.45-1-1-1H4c-.55 0-1 .45-1 1s.45 1 1 1zm0-4h16c.55 0 1-.45 1-1s-.45-1-1-1H4c-.55 0-1 .45-1 1s.45 1 1 1zm0-4h16c.55 0 1-.45 1-1s-.45-1-1-1H4c-.55 0-1 .45-1 1s.45 1 1 1z"/>
  </svg>
);

const FileTextIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/>
  </svg>
);

const DashboardIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/>
  </svg>
);

const UsersIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M16 4c0-1.11.89-2 2-2s2 .89 2 2-.89 2-2 2-2-.89-2-2zm4 18v-6h2.5l-2.54-7.63A2.01 2.01 0 0 0 18.06 7h-.12a2 2 0 0 0-1.9 1.37l-.86 2.58c1.08.6 1.82 1.73 1.82 3.05v8h3zm-7.5-10.5c.28 0 .5.22.5.5s-.22.5-.5.5-.5-.22-.5-.5.22-.5.5-.5zm-5 0c.28 0 .5.22.5.5s-.22.5-.5.5-.5-.22-.5-.5.22-.5.5-.5zM9 4c0-1.11.89-2 2-2s2 .89 2 2-.89 2-2 2-2-.89-2-2zm5.5 12v-2.5c0-.83-.67-1.5-1.5-1.5h-2c-.83 0-1.5.67-1.5 1.5V16h-2v-2.5c0-1.38 1.12-2.5 2.5-2.5h2c1.38 0 2.5 1.12 2.5 2.5V16h-2z"/>
  </svg>
);

const AlertIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
  </svg>
);

const AccountIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/>
  </svg>
);

const LayoutIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M4 13h6c.55 0 1-.45 1-1V4c0-.55-.45-1-1-1H4c-.55 0-1 .45-1 1v8c0 .55.45 1 1 1zm0 8h6c.55 0 1-.45 1-1v-4c0-.55-.45-1-1-1H4c-.55 0-1 .45-1 1v4c0 .55.45 1 1 1zm10 0h6c.55 0 1-.45 1-1v-8c0-.55-.45-1-1-1h-6c-.55 0-1 .45-1 1v8c0 .55.45 1 1 1zM13 4v4c0 .55.45 1 1 1h6c.55 0 1-.45 1-1V4c0-.55-.45-1-1-1h-6c-.55 0-1 .45-1 1z"/>
  </svg>
);

// Dark theme styles
const darkStyles = {
  container: {
    backgroundColor: DARK_THEME.background,
    color: DARK_THEME.text,
    minHeight: "100vh",
    width: "100vw",
    display: "flex",
    padding: "0",
    boxSizing: "border-box",
    overflow: "hidden"
  },
  sidebar: {
    width: "320px",
    backgroundColor: "#222",
    borderRight: `1px solid ${DARK_THEME.border}`,
    padding: "20px",
    overflowY: "auto",
    height: "100vh",
    position: "sticky",
    top: 0
  },
  mainContent: {
    flex: 1,
    padding: "20px",
    overflowY: "auto",
    height: "100vh",
    display: "flex",
    flexDirection: "column"
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
    textAlign: "center",
    boxSizing: "border-box",
    marginBottom: "20px"
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
    margin: "5px",
    display: "flex",
    alignItems: "center",
    gap: "8px",
    transition: "all 0.3s ease"
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
    justifyContent: "flex-start",
    flexWrap: "wrap"
  },
  tab: {
    padding: "10px 20px",
    border: "none",
    borderRadius: "4px",
    cursor: "pointer",
    fontSize: "14px",
    fontWeight: "500",
    display: "flex",
    alignItems: "center",
    gap: "8px",
    transition: "all 0.3s ease"
  },
  sidebarSection: {
    marginBottom: "25px",
    padding: "15px",
    backgroundColor: "#2a2a2a",
    borderRadius: "8px",
    border: `1px solid ${DARK_THEME.border}`
  },
  sidebarHeader: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    marginBottom: "15px",
    color: DARK_THEME.text,
    fontSize: "16px",
    fontWeight: "600"
  },
  filterGroup: {
    marginBottom: "15px"
  },
  filterLabel: {
    display: "block",
    marginBottom: "5px",
    color: DARK_THEME.textMuted,
    fontSize: "12px",
    fontWeight: "500"
  },
  exportOption: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    padding: "10px",
    marginBottom: "8px",
    backgroundColor: "#333",
    borderRadius: "4px",
    cursor: "pointer",
    transition: "all 0.3s ease",
    border: `1px solid ${DARK_THEME.border}`
  },
  navMenu: {
    display: "flex",
    flexDirection: "column",
    gap: "5px",
    marginBottom: "20px"
  },
  navItem: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    padding: "12px 15px",
    color: DARK_THEME.text,
    textDecoration: "none",
    borderRadius: "6px",
    transition: "all 0.3s ease",
    cursor: "pointer"
  }
};

// ==================== COMPONENTS ====================

// LoginForm Component
function LoginForm({ onLogin, loading, authMode, setAuthMode }) {
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: "",
    confirmPassword: "",
    role: "guest"
  });
  const [message, setMessage] = useState("");
  const [authLoading, setAuthLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage("");
    setAuthLoading(true);

    if (authMode === "register") {
      // Registration validation
      if (formData.password !== formData.confirmPassword) {
        setMessage("Passwords do not match");
        setAuthLoading(false);
        return;
      }
      if (formData.password.length < 6) {
        setMessage("Password must be at least 6 characters");
        setAuthLoading(false);
        return;
      }
    }

    try {
      let response;
      if (authMode === "login") {
        // Login request
        const formDataObj = new FormData();
        formDataObj.append("username", formData.username);
        formDataObj.append("password", formData.password);
        
        response = await axios.post(`${API_BASE}/token`, formDataObj, {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded"
          }
        });
      } else {
        // Register request
        response = await axios.post(`${API_BASE}/register`, {
          username: formData.username,
          email: formData.email,
          password: formData.password,
          role: formData.role
        });
      }

      if (response.data.access_token || response.data.id) {
        const user = authMode === "login" ? response.data.user : response.data;
        const token = authMode === "login" ? response.data.access_token : "mock-token";
        
        onLogin(token, user);
        setMessage(authMode === "login" ? "Login successful!" : "Registration successful!");
      }
    } catch (error) {
      console.error("Auth error:", error);
      setMessage(
        error.response?.data?.detail || 
        (authMode === "login" ? "Login failed" : "Registration failed")
      );
    } finally {
      setAuthLoading(false);
    }
  };

  const handleInputChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const toggleAuthMode = () => {
    setAuthMode(authMode === "login" ? "register" : "login");
    setMessage("");
    setFormData({
      username: "",
      email: "",
      password: "",
      confirmPassword: "",
      role: "guest"
    });
  };

  return (
    <div style={darkStyles.card}>
      <h2 style={{ color: DARK_THEME.text, marginBottom: "20px" }}>
        {authMode === "login" ? "Login" : "Register"}
      </h2>
      
      {message && (
        <div style={{
          ...darkStyles.message,
          backgroundColor: message.includes("failed") || message.includes("error") ? '#2d1a1a' : '#1a2d1a',
          border: `1px solid ${message.includes("failed") || message.includes("error") ? DARK_THEME.danger : DARK_THEME.success}`,
          color: message.includes("failed") || message.includes("error") ? '#ff6b6b' : '#6bff6b',
          marginBottom: "15px"
        }}>
          {message}
        </div>
      )}

      <form onSubmit={handleSubmit}>
        {/* Hidden username field for accessibility */}
        <input
          type="text"
          name="hidden_username"
          autoComplete="username"
          style={{ display: 'none' }}
        />
        
        <input
          type="text"
          name="username"
          placeholder="Username"
          value={formData.username}
          onChange={handleInputChange}
          style={darkStyles.input}
          required
          autoComplete="username"
        />

        {authMode === "register" && (
          <>
            <input
              type="email"
              name="email"
              placeholder="Email"
              value={formData.email}
              onChange={handleInputChange}
              style={darkStyles.input}
              required
              autoComplete="email"
            />
            
            <select
              name="role"
              value={formData.role}
              onChange={handleInputChange}
              style={darkStyles.select}
            >
              <option value="guest">Guest</option>
              <option value="agent">Agent</option>
            </select>
          </>
        )}

        <input
          type="password"
          name="password"
          placeholder="Password"
          value={formData.password}
          onChange={handleInputChange}
          style={darkStyles.input}
          required
          autoComplete={authMode === "login" ? "current-password" : "new-password"}
        />

        {authMode === "register" && (
          <input
            type="password"
            name="confirmPassword"
            placeholder="Confirm Password"
            value={formData.confirmPassword}
            onChange={handleInputChange}
            style={darkStyles.input}
            required
            autoComplete="new-password"
          />
        )}

        <button 
          type="submit" 
          disabled={authLoading}
          style={{ 
            ...darkStyles.button, 
            backgroundColor: authLoading ? DARK_THEME.border : DARK_THEME.primary,
            width: "100%",
            justifyContent: "center"
          }}
        >
          {authLoading ? <TailSpin height={20} width={20} /> : (authMode === "login" ? "Login" : "Register")}
        </button>
      </form>

      <div style={{ marginTop: "15px", textAlign: "center" }}>
        <button
          onClick={toggleAuthMode}
          style={{
            background: "none",
            border: "none",
            color: DARK_THEME.primary,
            cursor: "pointer",
            textDecoration: "underline",
            fontSize: "14px"
          }}
        >
          {authMode === "login" 
            ? "Don't have an account? Register" 
            : "Already have an account? Login"}
        </button>
      </div>

      {/* Demo login button */}
      <div style={{ marginTop: "20px", paddingTop: "20px", borderTop: `1px solid ${DARK_THEME.border}` }}>
        <p style={{ color: DARK_THEME.textMuted, marginBottom: "10px", fontSize: "14px" }}>
          Quick Demo Access:
        </p>
        <button 
          onClick={() => onLogin("mock-token", { username: "admin", role: "admin" })}
          style={{ 
            ...darkStyles.button,
            backgroundColor: DARK_THEME.info,
            width: "100%",
            justifyContent: "center"
          }}
        >
          Login as Admin (Demo)
        </button>
      </div>
    </div>
  );
}

// MetricsChart Component
function MetricsChart({ cpu, memory, disk, onMetricClick }) {
  const data = [
    { name: 'CPU', value: cpu, color: COLORS[0] },
    { name: 'Memory', value: memory, color: COLORS[1] },
    { name: 'Disk', value: disk, color: COLORS[2] }
  ];
  
  const handleChartClick = (data, index) => {
    if (data && onMetricClick) {
      const metricName = data[index]?.name.toLowerCase().replace(' ', '_');
      const metricValue = data[index]?.value;
      
      if (metricName && metricValue !== undefined) {
        const ranges = {
          low: '0-40',
          medium: '40-70', 
          high: '70-90',
          critical: '90-100'
        };
        
        let valueRange = ranges.low;
        if (metricValue >= 90) valueRange = ranges.critical;
        else if (metricValue >= 70) valueRange = ranges.high;
        else if (metricValue >= 40) valueRange = ranges.medium;
        
        onMetricClick({
          metric: metricName,
          valueRange: valueRange,
          currentValue: metricValue
        });
      }
    }
  };
  
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
            label={({ name, value }) => `${name}: ${value?.toFixed(1)}%`}
            onClick={(data, index) => handleChartClick(data, index)}
          >
            {data.map((entry, index) => (
              <Cell 
                key={`cell-${index}`} 
                fill={entry.color}
                style={{ cursor: 'pointer' }}
              />
            ))}
          </Pie>
          <Tooltip 
            formatter={(value) => [`${value?.toFixed(1)}%`, 'Usage']}
            contentStyle={{ backgroundColor: DARK_THEME.cardBackground, border: `1px solid ${DARK_THEME.border}` }}
          />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
      <div style={{ marginTop: "10px", display: "flex", justifyContent: "space-around" }}>
        <span 
          style={{ color: COLORS[0], cursor: 'pointer' }}
          onClick={() => onMetricClick && onMetricClick({
            metric: 'cpu_usage',
            valueRange: '0-100',
            currentValue: cpu
          })}
        >
          CPU: {cpu?.toFixed(1)}%
        </span>
        <span 
          style={{ color: COLORS[1], cursor: 'pointer' }}
          onClick={() => onMetricClick && onMetricClick({
            metric: 'memory_usage',
            valueRange: '0-100', 
            currentValue: memory
          })}
        >
          Memory: {memory?.toFixed(1)}%
        </span>
        <span 
          style={{ color: COLORS[2], cursor: 'pointer' }}
          onClick={() => onMetricClick && onMetricClick({
            metric: 'disk_usage',
            valueRange: '0-100',
            currentValue: disk
          })}
        >
          Disk: {disk?.toFixed(1)}%
        </span>
      </div>
      <div style={{ marginTop: "10px", fontSize: "12px", color: DARK_THEME.textMuted }}>
        Click on any metric to view detailed analysis
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

// DrillDownModal Component
function DrillDownModal({ isOpen, onClose, metricData, apiClient }) {
  const [details, setDetails] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (isOpen && metricData) {
      fetchMetricDetails();
    }
  }, [isOpen, metricData]);

  const fetchMetricDetails = async () => {
    if (!metricData) return;
    
    setLoading(true);
    try {
      // Mock data since backend endpoints might not exist
      const mockDetails = Array.from({ length: 10 }, (_, i) => ({
        timestamp: new Date(Date.now() - i * 60000).toISOString(),
        hostname: `server-${Math.floor(Math.random() * 5) + 1}`,
        metric_value: Math.random() * 100,
        full_data: {
          metric: metricData.metric,
          value: Math.random() * 100,
          timestamp: new Date(Date.now() - i * 60000).toISOString()
        }
      }));
      
      setDetails(mockDetails);
    } catch (error) {
      console.error('Error fetching metric details:', error);
      // Fallback to empty array
      setDetails([]);
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.8)',
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      zIndex: 1000,
      padding: '20px'
    }}>
      <div style={{
        backgroundColor: DARK_THEME.cardBackground,
        border: `1px solid ${DARK_THEME.border}`,
        borderRadius: '8px',
        padding: '20px',
        maxWidth: '800px',
        width: '100%',
        maxHeight: '80vh',
        overflow: 'auto'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <h3 style={{ color: DARK_THEME.text, margin: 0 }}>
            Metric Details: {metricData?.metric?.replace('_', ' ').toUpperCase()}
          </h3>
          <button
            onClick={onClose}
            style={{
              ...darkStyles.button,
              backgroundColor: DARK_THEME.danger,
              padding: '5px 10px',
              fontSize: '12px'
            }}
          >
            Close
          </button>
        </div>

        {metricData?.valueRange && (
          <div style={{ marginBottom: '15px', padding: '10px', backgroundColor: '#2a2a2a', borderRadius: '4px' }}>
            <span style={{ color: DARK_THEME.text }}>
              Value Range: <strong>{metricData.valueRange}</strong>
            </span>
          </div>
        )}

        {loading ? (
          <div style={{ textAlign: 'center', padding: '40px' }}>
            <TailSpin height={40} width={40} />
            <p style={{ color: DARK_THEME.text, marginTop: '15px' }}>Loading metric details...</p>
          </div>
        ) : (
          <div style={{ maxHeight: '400px', overflow: 'auto' }}>
            {details.length > 0 ? (
              <table style={darkStyles.table}>
                <thead>
                  <tr>
                    <th style={darkStyles.tableHeader}>Timestamp</th>
                    <th style={darkStyles.tableHeader}>Hostname</th>
                    <th style={darkStyles.tableHeader}>Value</th>
                    <th style={darkStyles.tableHeader}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {details.map((item, index) => (
                    <tr key={index} style={{
                      backgroundColor: index % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.05)'
                    }}>
                      <td style={darkStyles.tableCell}>
                        {new Date(item.timestamp).toLocaleString()}
                      </td>
                      <td style={darkStyles.tableCell}>
                        {item.hostname || 'N/A'}
                      </td>
                      <td style={{
                        ...darkStyles.tableCell,
                        color: item.metric_value > 80 ? DARK_THEME.danger : 
                               item.metric_value > 60 ? DARK_THEME.warning : DARK_THEME.text,
                        fontWeight: item.metric_value > 80 ? 'bold' : 'normal'
                      }}>
                        {item.metric_value?.toFixed(1)}%
                      </td>
                      <td style={darkStyles.tableCell}>
                        <button
                          onClick={() => {
                            navigator.clipboard.writeText(JSON.stringify(item.full_data, null, 2));
                            alert('Data copied to clipboard!');
                          }}
                          style={{
                            ...darkStyles.button,
                            backgroundColor: DARK_THEME.info,
                            padding: '5px 10px',
                            fontSize: '12px'
                          }}
                        >
                          Copy Data
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div style={{ textAlign: 'center', padding: '40px', color: DARK_THEME.textMuted }}>
                No data found for the selected criteria.
              </div>
            )}
          </div>
        )}

        <div style={{ marginTop: '20px', padding: '15px', backgroundColor: '#2a2a2a', borderRadius: '4px' }}>
          <h4 style={{ color: DARK_THEME.text, margin: '0 0 10px 0' }}>Summary</h4>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '10px', fontSize: '14px' }}>
            <div>
              <span style={{ color: DARK_THEME.textMuted }}>Total Records: </span>
              <span style={{ color: DARK_THEME.text, fontWeight: 'bold' }}>{details.length}</span>
            </div>
            <div>
              <span style={{ color: DARK_THEME.textMuted }}>Average Value: </span>
              <span style={{ color: DARK_THEME.text, fontWeight: 'bold' }}>
                {details.length > 0 ? (details.reduce((sum, item) => sum + item.metric_value, 0) / details.length).toFixed(1) : 0}%
              </span>
            </div>
            <div>
              <span style={{ color: DARK_THEME.textMuted }}>Max Value: </span>
              <span style={{ color: DARK_THEME.text, fontWeight: 'bold' }}>
                {details.length > 0 ? Math.max(...details.map(item => item.metric_value)).toFixed(1) : 0}%
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// Filter Panel Component
function FilterPanel({ onFilterChange, filters, loading }) {
  const [localFilters, setLocalFilters] = useState({
    startDate: '',
    endDate: '',
    hostname: '',
    minCpu: '',
    maxCpu: '',
    minMemory: '',
    maxMemory: ''
  });

  useEffect(() => {
    if (filters) {
      setLocalFilters(filters);
    }
  }, [filters]);

  const handleFilterChange = (key, value) => {
    const newFilters = { ...localFilters, [key]: value };
    setLocalFilters(newFilters);
  };

  const applyFilters = () => {
    onFilterChange(localFilters);
  };

  const clearFilters = () => {
    const emptyFilters = {
      startDate: '',
      endDate: '',
      hostname: '',
      minCpu: '',
      maxCpu: '',
      minMemory: '',
      maxMemory: ''
    };
    setLocalFilters(emptyFilters);
    onFilterChange(emptyFilters);
  };

  return (
    <div style={darkStyles.sidebarSection}>
      <div style={darkStyles.sidebarHeader}>
        <SlidersIcon />
        <span>Data Filters</span>
      </div>

      <div style={darkStyles.filterGroup}>
        <label style={darkStyles.filterLabel}>Date Range</label>
        <input
          type="date"
          value={localFilters.startDate || ''}
          onChange={(e) => handleFilterChange('startDate', e.target.value)}
          style={darkStyles.input}
        />
        <input
          type="date"
          value={localFilters.endDate || ''}
          onChange={(e) => handleFilterChange('endDate', e.target.value)}
          style={darkStyles.input}
        />
      </div>

      <div style={darkStyles.filterGroup}>
        <label style={darkStyles.filterLabel}>Hostname</label>
        <input
          type="text"
          placeholder="Filter by hostname..."
          value={localFilters.hostname || ''}
          onChange={(e) => handleFilterChange('hostname', e.target.value)}
          style={darkStyles.input}
        />
      </div>

      <div style={darkStyles.filterGroup}>
        <label style={darkStyles.filterLabel}>CPU Usage (%)</label>
        <div style={{ display: 'flex', gap: '10px' }}>
          <input
            type="number"
            placeholder="Min"
            min="0"
            max="100"
            value={localFilters.minCpu || ''}
            onChange={(e) => handleFilterChange('minCpu', e.target.value)}
            style={darkStyles.input}
          />
          <input
            type="number"
            placeholder="Max"
            min="0"
            max="100"
            value={localFilters.maxCpu || ''}
            onChange={(e) => handleFilterChange('maxCpu', e.target.value)}
            style={darkStyles.input}
          />
        </div>
      </div>

      <div style={darkStyles.filterGroup}>
        <label style={darkStyles.filterLabel}>Memory Usage (%)</label>
        <div style={{ display: 'flex', gap: '10px' }}>
          <input
            type="number"
            placeholder="Min"
            min="0"
            max="100"
            value={localFilters.minMemory || ''}
            onChange={(e) => handleFilterChange('minMemory', e.target.value)}
            style={darkStyles.input}
          />
          <input
            type="number"
            placeholder="Max"
            min="0"
            max="100"
            value={localFilters.maxMemory || ''}
            onChange={(e) => handleFilterChange('maxMemory', e.target.value)}
            style={darkStyles.input}
          />
        </div>
      </div>

      <div style={{ display: 'flex', gap: '10px', marginTop: '20px' }}>
        <button
          onClick={applyFilters}
          disabled={loading}
          style={{
            ...darkStyles.button,
            backgroundColor: loading ? DARK_THEME.border : DARK_THEME.primary,
            flex: 1
          }}
        >
          {loading ? <TailSpin height={16} width={16} /> : <FilterIcon />}
          {loading ? 'Applying...' : 'Apply Filters'}
        </button>
        <button
          onClick={clearFilters}
          style={{
            ...darkStyles.button,
            backgroundColor: DARK_THEME.secondary,
            flex: 1
          }}
        >
          <CloseIcon />
          Clear
        </button>
      </div>
    </div>
  );
}

// Export Panel Component
function ExportPanel({ filters, apiClient }) {
  const [exportLoading, setExportLoading] = useState(false);

  const handleExport = async (format) => {
    setExportLoading(true);
    try {
      // Create mock data for export since backend endpoints might not exist
      const mockData = {
        timestamp: new Date().toISOString(),
        filters: filters,
        metrics: {
          cpu_usage: Math.random() * 100,
          memory_usage: Math.random() * 100,
          disk_usage: Math.random() * 100
        },
        message: "This is a mock export since backend export endpoints are not implemented"
      };

      let content, mimeType, extension;

      switch (format) {
        case 'csv':
          content = `Timestamp,Filters,CPU Usage,Memory Usage,Disk Usage\n${mockData.timestamp},"${JSON.stringify(mockData.filters)}",${mockData.metrics.cpu_usage},${mockData.metrics.memory_usage},${mockData.metrics.disk_usage}`;
          mimeType = 'text/csv';
          extension = 'csv';
          break;
        case 'json':
          content = JSON.stringify(mockData, null, 2);
          mimeType = 'application/json';
          extension = 'json';
          break;
        case 'pdf':
          // For PDF, we'll create a simple text file since PDF generation is complex
          content = `Metrics Export\nGenerated: ${new Date().toLocaleString()}\n\nFilters: ${JSON.stringify(filters, null, 2)}\n\nThis is a mock PDF export. In a real application, this would be a proper PDF file.`;
          mimeType = 'text/plain';
          extension = 'txt';
          break;
        default:
          throw new Error('Unsupported format');
      }

      // Create download link
      const blob = new Blob([content], { type: mimeType });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `metrics-export-${new Date().getTime()}.${extension}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
    } catch (error) {
      console.error('Export failed:', error);
      alert('Export completed with mock data (backend endpoints not implemented)');
    } finally {
      setExportLoading(false);
    }
  };

  const exportOptions = [
    { format: 'csv', label: 'CSV Format', icon: FileTextIcon, color: DARK_THEME.success },
    { format: 'json', label: 'JSON Format', icon: FileTextIcon, color: DARK_THEME.info },
    { format: 'pdf', label: 'PDF Report', icon: DownloadIcon, color: DARK_THEME.danger }
  ];

  return (
    <div style={darkStyles.sidebarSection}>
      <div style={darkStyles.sidebarHeader}>
        <DownloadIcon />
        <span>Export Data</span>
      </div>

      <div style={{ color: DARK_THEME.textMuted, fontSize: '12px', marginBottom: '15px' }}>
        Export filtered data in various formats for analysis and reporting.
      </div>

      {exportOptions.map((option) => (
        <div
          key={option.format}
          style={{
            ...darkStyles.exportOption,
            backgroundColor: exportLoading ? DARK_THEME.border : '#333'
          }}
          onClick={() => !exportLoading && handleExport(option.format)}
        >
          <option.icon />
          <span style={{ flex: 1, color: DARK_THEME.text }}>{option.label}</span>
          <ChevronRightIcon />
        </div>
      ))}

      {exportLoading && (
        <div style={{ textAlign: 'center', marginTop: '10px' }}>
          <TailSpin height={20} width={20} />
          <div style={{ color: DARK_THEME.textMuted, fontSize: '12px', marginTop: '5px' }}>
            Preparing download...
          </div>
        </div>
      )}
    </div>
  );
}

// Dashboard Layouts Component
function DashboardLayouts({ apiClient, currentUser }) {
  const [layouts, setLayouts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newLayoutName, setNewLayoutName] = useState("");

  const showMessage = (msg, isError = false) => {
    setMessage(msg);
    setTimeout(() => setMessage(""), 5000);
  };

  const fetchLayouts = async () => {
    setLoading(true);
    try {
      // Mock layouts data
      const mockLayouts = [
        { id: 1, name: "Default Layout", is_default: true, created_at: new Date().toISOString() },
        { id: 2, name: "Analytics View", is_default: false, created_at: new Date(Date.now() - 86400000).toISOString() },
        { id: 3, name: "Compact Dashboard", is_default: false, created_at: new Date(Date.now() - 172800000).toISOString() }
      ];
      setLayouts(mockLayouts);
    } catch (error) {
      showMessage("Failed to fetch layouts", true);
    } finally {
      setLoading(false);
    }
  };

  const createLayout = async () => {
    if (!newLayoutName.trim()) {
      showMessage("Layout name is required", true);
      return;
    }

    try {
      const newLayout = {
        id: Date.now(),
        name: newLayoutName,
        is_default: false,
        created_at: new Date().toISOString()
      };
      
      setLayouts(prev => [...prev, newLayout]);
      setNewLayoutName("");
      setShowCreateModal(false);
      showMessage("Layout created successfully");
    } catch (error) {
      showMessage("Failed to create layout", true);
    }
  };

  const setDefaultLayout = async (layoutId) => {
    try {
      setLayouts(prev => prev.map(layout => ({
        ...layout,
        is_default: layout.id === layoutId
      })));
      showMessage("Default layout updated successfully");
    } catch (error) {
      showMessage("Failed to set default layout", true);
    }
  };

  const deleteLayout = async (layoutId) => {
    if (window.confirm("Are you sure you want to delete this layout?")) {
      try {
        setLayouts(prev => prev.filter(layout => layout.id !== layoutId));
        showMessage("Layout deleted successfully");
      } catch (error) {
        showMessage("Failed to delete layout", true);
      }
    }
  };

  useEffect(() => {
    fetchLayouts();
  }, []);

  return (
    <div style={darkStyles.card}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
        <h3 style={{ color: DARK_THEME.text, margin: 0 }}>Dashboard Layouts</h3>
        <button 
          onClick={() => setShowCreateModal(true)}
          style={{ ...darkStyles.button, backgroundColor: DARK_THEME.success }}
        >
          <LayoutIcon />
          New Layout
        </button>
      </div>

      {message && (
        <div style={{
          ...darkStyles.message,
          backgroundColor: message.includes("Failed") ? '#2d1a1a' : '#1a2d1a',
          border: `1px solid ${message.includes("Failed") ? DARK_THEME.danger : DARK_THEME.success}`,
          color: message.includes("Failed") ? '#ff6b6b' : '#6bff6b',
          marginBottom: "15px"
        }}>
          {message}
        </div>
      )}

      {loading ? (
        <div style={{ textAlign: "center", padding: "20px" }}>
          <TailSpin height={30} width={30} />
          <p style={{ color: DARK_THEME.textMuted, marginTop: "10px" }}>Loading layouts...</p>
        </div>
      ) : (
        <div style={{ maxHeight: "400px", overflow: "auto" }}>
          <table style={darkStyles.table}>
            <thead>
              <tr>
                <th style={darkStyles.tableHeader}>Name</th>
                <th style={darkStyles.tableHeader}>Status</th>
                <th style={darkStyles.tableHeader}>Created</th>
                <th style={darkStyles.tableHeader}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {layouts.map((layout) => (
                <tr key={layout.id}>
                  <td style={{ ...darkStyles.tableCell, color: DARK_THEME.text, fontWeight: "500" }}>
                    {layout.name}
                  </td>
                  <td style={darkStyles.tableCell}>
                    <span style={{ 
                      color: layout.is_default ? DARK_THEME.success : DARK_THEME.textMuted,
                      fontWeight: "bold"
                    }}>
                      {layout.is_default ? "DEFAULT" : "Custom"}
                    </span>
                  </td>
                  <td style={{ ...darkStyles.tableCell, color: DARK_THEME.textMuted }}>
                    {new Date(layout.created_at).toLocaleDateString()}
                  </td>
                  <td style={darkStyles.tableCell}>
                    <div style={{ display: "flex", gap: "5px" }}>
                      {!layout.is_default && (
                        <>
                          <button
                            onClick={() => setDefaultLayout(layout.id)}
                            style={{
                              ...darkStyles.button,
                              backgroundColor: DARK_THEME.primary,
                              padding: "5px 10px",
                              fontSize: "12px"
                            }}
                          >
                            Set Default
                          </button>
                          <button
                            onClick={() => deleteLayout(layout.id)}
                            style={{
                              ...darkStyles.button,
                              backgroundColor: DARK_THEME.danger,
                              padding: "5px 10px",
                              fontSize: "12px"
                            }}
                          >
                            Delete
                          </button>
                        </>
                      )}
                      {layout.is_default && (
                        <span style={{ color: DARK_THEME.success, fontSize: "12px", fontWeight: "bold" }}>
                          Active
                        </span>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Create Layout Modal */}
      {showCreateModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.8)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 1000
        }}>
          <div style={{
            backgroundColor: DARK_THEME.cardBackground,
            border: `1px solid ${DARK_THEME.border}`,
            borderRadius: '8px',
            padding: '20px',
            width: '400px',
            maxWidth: '90vw'
          }}>
            <h3 style={{ color: DARK_THEME.text, marginBottom: '20px' }}>Create New Layout</h3>
            
            <input
              type="text"
              placeholder="Layout name"
              value={newLayoutName}
              onChange={(e) => setNewLayoutName(e.target.value)}
              style={darkStyles.input}
            />
            
            <div style={{ display: 'flex', gap: '10px', marginTop: '20px' }}>
              <button
                onClick={createLayout}
                style={{
                  ...darkStyles.button,
                  backgroundColor: DARK_THEME.success,
                  flex: 1
                }}
              >
                Create
              </button>
              <button
                onClick={() => setShowCreateModal(false)}
                style={{
                  ...darkStyles.button,
                  backgroundColor: DARK_THEME.secondary,
                  flex: 1
                }}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Navigation Menu Component
function NavigationMenu({ activeTab, setActiveTab, currentUser }) {
  const menuItems = [
    { id: "dashboard", label: "Dashboard", icon: DashboardIcon, available: true },
    { id: "layouts", label: "Dashboard Layouts", icon: LayoutIcon, available: true },
    { id: "account", label: "Account Settings", icon: AccountIcon, available: true },
    { id: "users", label: "User Management", icon: UsersIcon, available: currentUser?.role === 'admin' },
    { id: "alerts", label: "Alerts & Incidents", icon: AlertIcon, available: currentUser?.role === 'admin' }
  ];

  return (
    <div style={darkStyles.sidebarSection}>
      <div style={darkStyles.sidebarHeader}>
        <SettingsIcon />
        <span>Navigation</span>
      </div>
      
      <div style={darkStyles.navMenu}>
        {menuItems.map((item) => 
          item.available && (
            <div
              key={item.id}
              style={{
                ...darkStyles.navItem,
                backgroundColor: activeTab === item.id ? DARK_THEME.primary : 'transparent',
                color: activeTab === item.id ? '#fff' : DARK_THEME.text
              }}
              onClick={() => setActiveTab(item.id)}
            >
              <item.icon />
              <span>{item.label}</span>
            </div>
          )
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
      // Mock users data
      const mockUsers = [
        { id: 1, username: "admin", email: "admin@localhost", role: "admin", disabled: false },
        { id: 2, username: "agent1", email: "agent1@localhost", role: "agent", disabled: false },
        { id: 3, username: "user1", email: "user1@localhost", role: "guest", disabled: false },
        { id: 4, username: "agent2", email: "agent2@localhost", role: "agent", disabled: true }
      ];
      setUsers(mockUsers);
    } catch (error) {
      showMessage("Failed to fetch users", true);
    } finally {
      setLoading(false);
    }
  };

  const updateUserRole = async (userId, newRole) => {
    try {
      setUsers(prev => prev.map(user => 
        user.id === userId ? { ...user, role: newRole } : user
      ));
      showMessage("User role updated successfully");
    } catch (error) {
      showMessage("Failed to update user role", true);
    }
  };

  const toggleUserStatus = async (userId, currentStatus) => {
    try {
      setUsers(prev => prev.map(user => 
        user.id === userId ? { ...user, disabled: !currentStatus } : user
      ));
      showMessage(currentStatus ? "User enabled successfully" : "User disabled successfully");
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
        <div style={{
          ...darkStyles.message,
          backgroundColor: message.includes("Failed") ? '#2d1a1a' : '#1a2d1a',
          border: `1px solid ${message.includes("Failed") ? DARK_THEME.danger : DARK_THEME.success}`,
          color: message.includes("Failed") ? '#ff6b6b' : '#6bff6b',
          marginBottom: "15px"
        }}>
          {message}
        </div>
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

// Alerts Management Component
function AlertsManagement({ apiClient, currentUser }) {
  const [alertRules, setAlertRules] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [activeSubTab, setActiveSubTab] = useState("rules");

  const fetchAlertRules = async () => {
    setLoading(true);
    try {
      // Mock alert rules
      const mockRules = [
        { id: 1, metric: 'cpu_usage', comparison_operator: '>', threshold_value: 80, severity: 'high', active: true, description: 'High CPU usage' },
        { id: 2, metric: 'memory_usage', comparison_operator: '>', threshold_value: 90, severity: 'critical', active: true, description: 'Critical memory usage' },
        { id: 3, metric: 'disk_usage', comparison_operator: '>', threshold_value: 85, severity: 'medium', active: false, description: 'High disk usage' }
      ];
      setAlertRules(mockRules);
    } catch (error) {
      console.error('Failed to fetch alert rules:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchIncidents = async () => {
    setLoading(true);
    try {
      // Mock incidents
      const mockIncidents = [
        { id: 1, incident_type: 'high_cpu', message: 'CPU usage exceeded 80%', severity: 'high', status: 'new', created_at: new Date().toISOString() },
        { id: 2, incident_type: 'high_memory', message: 'Memory usage exceeded 90%', severity: 'critical', status: 'acknowledged', created_at: new Date(Date.now() - 3600000).toISOString() },
        { id: 3, incident_type: 'network_anomaly', message: 'Unusual network activity detected', severity: 'medium', status: 'resolved', created_at: new Date(Date.now() - 7200000).toISOString() }
      ];
      setIncidents(mockIncidents);
    } catch (error) {
      console.error('Failed to fetch incidents:', error);
    } finally {
      setLoading(false);
    }
  };

  const toggleAlertRule = async (ruleId, currentStatus) => {
    try {
      setAlertRules(prev => prev.map(rule => 
        rule.id === ruleId ? { ...rule, active: !currentStatus } : rule
      ));
    } catch (error) {
      console.error('Failed to toggle alert rule:', error);
    }
  };

  const updateIncidentStatus = async (incidentId, newStatus) => {
    try {
      setIncidents(prev => prev.map(incident => 
        incident.id === incidentId ? { ...incident, status: newStatus } : incident
      ));
    } catch (error) {
      console.error('Failed to update incident status:', error);
    }
  };

  useEffect(() => {
    if (currentUser?.role === 'admin') {
      if (activeSubTab === "rules") {
        fetchAlertRules();
      } else {
        fetchIncidents();
      }
    }
  }, [currentUser, activeSubTab]);

  if (currentUser?.role !== 'admin') {
    return (
      <div style={darkStyles.card}>
        <h3 style={{ color: DARK_THEME.text }}>Alerts & Incidents Management</h3>
        <p style={{ color: DARK_THEME.textMuted }}>Admin access required to manage alerts and incidents.</p>
      </div>
    );
  }

  return (
    <div style={darkStyles.card}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h3 style={{ color: DARK_THEME.text, margin: 0 }}>Alerts & Incidents Management</h3>
        <div style={darkStyles.tabContainer}>
          <button
            onClick={() => setActiveSubTab("rules")}
            style={{
              ...darkStyles.tab,
              backgroundColor: activeSubTab === "rules" ? DARK_THEME.primary : "#333",
              color: activeSubTab === "rules" ? "#fff" : DARK_THEME.text
            }}
          >
            Alert Rules ({alertRules.length})
          </button>
          <button
            onClick={() => setActiveSubTab("incidents")}
            style={{
              ...darkStyles.tab,
              backgroundColor: activeSubTab === "incidents" ? DARK_THEME.primary : "#333",
              color: activeSubTab === "incidents" ? "#fff" : DARK_THEME.text
            }}
          >
            Incidents ({incidents.length})
          </button>
        </div>
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: '20px' }}>
          <TailSpin height={30} width={30} />
          <p style={{ color: DARK_THEME.textMuted }}>Loading data...</p>
        </div>
      ) : activeSubTab === "rules" ? (
        <div style={{ maxHeight: '500px', overflow: 'auto' }}>
          <table style={darkStyles.table}>
            <thead>
              <tr>
                <th style={darkStyles.tableHeader}>Metric</th>
                <th style={darkStyles.tableHeader}>Condition</th>
                <th style={darkStyles.tableHeader}>Severity</th>
                <th style={darkStyles.tableHeader}>Status</th>
                <th style={darkStyles.tableHeader}>Description</th>
                <th style={darkStyles.tableHeader}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {alertRules.map((rule) => (
                <tr key={rule.id}>
                  <td style={{ ...darkStyles.tableCell, textTransform: 'capitalize' }}>
                    {rule.metric.replace('_', ' ')}
                  </td>
                  <td style={darkStyles.tableCell}>
                    {rule.comparison_operator} {rule.threshold_value}%
                  </td>
                  <td style={{ ...darkStyles.tableCell }}>
                    <span style={{ 
                      color: rule.severity === 'critical' ? DARK_THEME.danger : 
                             rule.severity === 'high' ? DARK_THEME.warning : DARK_THEME.success,
                      fontWeight: 'bold'
                    }}>
                      {rule.severity.toUpperCase()}
                    </span>
                  </td>
                  <td style={darkStyles.tableCell}>
                    <span style={{ 
                      color: rule.active ? DARK_THEME.success : DARK_THEME.danger,
                      fontWeight: 'bold'
                    }}>
                      {rule.active ? 'ACTIVE' : 'INACTIVE'}
                    </span>
                  </td>
                  <td style={{ ...darkStyles.tableCell, color: DARK_THEME.textMuted }}>
                    {rule.description || 'No description'}
                  </td>
                  <td style={darkStyles.tableCell}>
                    <button
                      onClick={() => toggleAlertRule(rule.id, rule.active)}
                      style={{
                        ...darkStyles.button,
                        backgroundColor: rule.active ? DARK_THEME.warning : DARK_THEME.success,
                        padding: "5px 10px",
                        fontSize: "12px"
                      }}
                    >
                      {rule.active ? 'Deactivate' : 'Activate'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div style={{ maxHeight: '500px', overflow: 'auto' }}>
          <table style={darkStyles.table}>
            <thead>
              <tr>
                <th style={darkStyles.tableHeader}>Type</th>
                <th style={darkStyles.tableHeader}>Message</th>
                <th style={darkStyles.tableHeader}>Severity</th>
                <th style={darkStyles.tableHeader}>Status</th>
                <th style={darkStyles.tableHeader}>Created</th>
                <th style={darkStyles.tableHeader}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((incident) => (
                <tr key={incident.id}>
                  <td style={{ ...darkStyles.tableCell, textTransform: 'capitalize' }}>
                    {incident.incident_type.replace('_', ' ')}
                  </td>
                  <td style={darkStyles.tableCell}>{incident.message}</td>
                  <td style={{ ...darkStyles.tableCell }}>
                    <span style={{ 
                      color: incident.severity === 'critical' ? DARK_THEME.danger : 
                             incident.severity === 'high' ? DARK_THEME.warning : DARK_THEME.success,
                      fontWeight: 'bold'
                    }}>
                      {incident.severity.toUpperCase()}
                    </span>
                  </td>
                  <td style={darkStyles.tableCell}>
                    <span style={{ 
                      color: incident.status === 'resolved' ? DARK_THEME.success : 
                             incident.status === 'acknowledged' ? DARK_THEME.warning : DARK_THEME.danger,
                      fontWeight: 'bold'
                    }}>
                      {incident.status.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ ...darkStyles.tableCell, color: DARK_THEME.textMuted }}>
                    {new Date(incident.created_at).toLocaleString()}
                  </td>
                  <td style={darkStyles.tableCell}>
                    <div style={{ display: 'flex', gap: '5px', flexDirection: 'column' }}>
                      {incident.status === 'new' && (
                        <button
                          onClick={() => updateIncidentStatus(incident.id, 'acknowledged')}
                          style={{
                            ...darkStyles.button,
                            backgroundColor: DARK_THEME.warning,
                            padding: "3px 8px",
                            fontSize: "11px"
                          }}
                        >
                          Acknowledge
                        </button>
                      )}
                      {incident.status !== 'resolved' && (
                        <button
                          onClick={() => updateIncidentStatus(incident.id, 'resolved')}
                          style={{
                            ...darkStyles.button,
                            backgroundColor: DARK_THEME.success,
                            padding: "3px 8px",
                            fontSize: "11px"
                          }}
                        >
                          Resolve
                        </button>
                      )}
                    </div>
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
      // Mock password change
      showMessage("Password changed successfully");
      setPasswordForm({
        currentPassword: "",
        newPassword: "",
        confirmPassword: ""
      });
    } catch (error) {
      showMessage("Failed to change password", true);
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
        <div style={{
          ...darkStyles.message,
          backgroundColor: message.includes("Failed") ? '#2d1a1a' : '#1a2d1a',
          border: `1px solid ${message.includes("Failed") ? DARK_THEME.danger : DARK_THEME.success}`,
          color: message.includes("Failed") ? '#ff6b6b' : '#6bff6b',
          marginBottom: "15px"
        }}>
          {message}
        </div>
      )}

      <form onSubmit={handlePasswordChange}>
        {/* Hidden username field for accessibility */}
        <input
          type="text"
          name="hidden_username"
          autoComplete="username"
          style={{ display: 'none' }}
        />
        
        <input
          type="password"
          name="currentPassword"
          placeholder="Current Password"
          value={passwordForm.currentPassword}
          onChange={handleInputChange}
          style={darkStyles.input}
          required
          autoComplete="current-password"
        />
        <input
          type="password"
          name="newPassword"
          placeholder="New Password"
          value={passwordForm.newPassword}
          onChange={handleInputChange}
          style={darkStyles.input}
          required
          autoComplete="new-password"
        />
        <input
          type="password"
          name="confirmPassword"
          placeholder="Confirm New Password"
          value={passwordForm.confirmPassword}
          onChange={handleInputChange}
          style={darkStyles.input}
          required
          autoComplete="new-password"
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

// ==================== MAIN APP COMPONENT ====================

// Create axios instance with auth interceptor
const createApiClient = (token) => {
  const client = axios.create({
    baseURL: API_BASE,
  });

  if (token) {
    client.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  }

  // Add response interceptor to handle 401 errors
  client.interceptors.response.use(
    (response) => response,
    (error) => {
      if (error.response?.status === 401) {
        // Token is invalid, logout user
        localStorage.removeItem("token");
        window.location.reload();
      }
      return Promise.reject(error);
    }
  );

  return client;
};

// Main App Component
function App() {
  const [token, setToken] = useState(localStorage.getItem("token") || "");
  const [currentUser, setCurrentUser] = useState(null);
  const [agentData, setAgentData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [dashboardLoading, setDashboardLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("dashboard");
  const [authMode, setAuthMode] = useState("login");

  // State for filtering and drill-down
  const [filters, setFilters] = useState({});
  const [filteredData, setFilteredData] = useState(null);
  const [drillDownData, setDrillDownData] = useState(null);
  const [showDrillDown, setShowDrillDown] = useState(false);
  const [filterLoading, setFilterLoading] = useState(false);

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
      const response = await apiClient.get("/users/me");
      setCurrentUser(response.data);
    } catch (error) {
      console.error('Failed to fetch user info:', error);
      // Fallback to mock data if API fails
      const mockUser = {
        id: 1,
        username: "admin",
        email: "admin@localhost",
        role: "admin"
      };
      setCurrentUser(mockUser);
    }
  };

  const fetchLatestAgentData = async () => {
    setDashboardLoading(true);
    try {
      // Use mock data for demonstration
      const mockData = {
        cpu_usage: 45.7,
        memory_usage: 67.2,
        disk_usage: 23.1,
        network_activity: {
          bytes_sent: 1250000,
          bytes_received: 890000,
        },
        processes: [
          { pid: 1, name: "systemd", cpu: 0.1, memory: 0.5 },
          { pid: 2, name: "bash", cpu: 0.2, memory: 0.3 },
          { pid: 3, name: "node", cpu: 1.5, memory: 2.1 },
          { pid: 4, name: "python", cpu: 0.8, memory: 1.2 },
        ]
      };
      setAgentData(mockData);
    } catch (error) {
      console.error('Failed to fetch agent data:', error);
    } finally {
      setDashboardLoading(false);
    }
  };

  // Handle filter changes
  const handleFilterChange = async (newFilters) => {
    setFilters(newFilters);
    setFilterLoading(true);
    
    try {
      // Mock filtered data
      const mockFilteredData = {
        data: [{
          data: {
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
            ]
          }
        }]
      };
      
      setFilteredData(mockFilteredData);
    } catch (error) {
      console.error('Error applying filters:', error);
    } finally {
      setFilterLoading(false);
    }
  };

  // Handle metric click for drill-down
  const handleMetricClick = (metricData) => {
    setDrillDownData(metricData);
    setShowDrillDown(true);
  };

  const handleLogin = (newToken, user) => {
    setToken(newToken);
    setCurrentUser(user);
    localStorage.setItem("token", newToken);
    setAuthMode("login"); // Reset to login mode after successful auth
  };

  const logout = () => {
    setToken("");
    setCurrentUser(null);
    setAgentData(null);
    setFilteredData(null);
    setFilters({});
    localStorage.removeItem("token");
    setAuthMode("login");
  };

  const submitSampleAgentData = async () => {
    setDashboardLoading(true);
    try {
      alert('Sample data submitted (mock - backend might not be available)');
      setTimeout(fetchLatestAgentData, 500);
    } catch (error) {
      console.error('Failed to submit sample data:', error);
    } finally {
      setDashboardLoading(false);
    }
  };

  // Determine which data to display
  const displayData = filteredData?.data && filteredData.data.length > 0 
    ? filteredData.data[0]?.data 
    : agentData;

  // Render dashboard content
  const renderDashboardContent = () => {
    if (dashboardLoading || filterLoading) {
      return (
        <div style={{ ...darkStyles.card, textAlign: "center", padding: "40px" }}>
          <TailSpin height={40} width={40} />
          <p style={{ color: DARK_THEME.text, marginTop: "15px" }}>Loading agent data...</p>
        </div>
      );
    }

    if (displayData) {
      return (
        <div style={darkStyles.gridContainer}>
          <MetricsChart 
            cpu={displayData.cpu_usage}
            memory={displayData.memory_usage}
            disk={displayData.disk_usage}
            onMetricClick={handleMetricClick}
          />
          
          <NetworkChart networkData={displayData.network_activity} />
          
          <ProcessList processes={displayData.processes} />
          
          <div style={darkStyles.gridCard}>
            <h3 style={{ color: DARK_THEME.text, margin: "0 0 15px 0", textAlign: "center" }}>Raw Agent Data</h3>
            <textarea
              value={JSON.stringify(displayData, null, 2)}
              readOnly
              style={{
                width: "100%",
                height: "200px",
                background: "#333",
                color: DARK_THEME.text,
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
      );
    }

    return (
      <div style={{ ...darkStyles.card, textAlign: "center", padding: "40px" }}>
        <p style={{ color: DARK_THEME.textMuted }}>No agent data available. Submit sample data to get started.</p>
      </div>
    );
  };

  // Render tab content based on active tab
  const renderTabContent = () => {
    switch (activeTab) {
      case "dashboard":
        return (
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
                  <button onClick={submitSampleAgentData} disabled={dashboardLoading} style={{ ...darkStyles.button, backgroundColor: DARK_THEME.success }}>
                    {dashboardLoading ? <TailSpin height={20} width={20} /> : "Submit Sample Data"}
                  </button>
                )}
              </div>
            </div>

            {/* Dashboard Content */}
            {renderDashboardContent()}

            {/* Live Dashboard */}
            <LiveDashboard token={token} />
          </>
        );
      
      case "layouts":
        return <DashboardLayouts apiClient={apiClient} currentUser={currentUser} />;
      
      case "account":
        return <PasswordChange apiClient={apiClient} />;
      
      case "users":
        return <UserManagement apiClient={apiClient} currentUser={currentUser} />;
      
      case "alerts":
        return <AlertsManagement apiClient={apiClient} currentUser={currentUser} />;
      
      default:
        return renderDashboardContent();
    }
  };

  // Render based on authentication status
  if (!token) {
    return (
      <div style={darkStyles.container}>
        <div style={{...darkStyles.mainContent, display: 'flex', justifyContent: 'center', alignItems: 'center'}}>
          <LoginForm 
            onLogin={handleLogin}
            loading={loading}
            authMode={authMode}
            setAuthMode={setAuthMode}
          />
        </div>
      </div>
    );
  }

  return (
    <div style={darkStyles.container}>
      {/* Sidebar with Navigation, Filters and Export */}
      <div style={darkStyles.sidebar}>
        <div style={{ marginBottom: '20px', textAlign: 'center' }}>
          <h2 style={{ color: DARK_THEME.text, margin: '0 0 5px 0' }}>Monitoring Dashboard</h2>
          <p style={{ color: DARK_THEME.textMuted, margin: 0, fontSize: '14px' }}>
            Welcome, {currentUser?.username || 'User'}
          </p>
          {currentUser && (
            <p style={{ color: DARK_THEME.textMuted, margin: '5px 0 0 0', fontSize: '12px' }}>
              Role: {currentUser.role}
            </p>
          )}
        </div>

        {/* Navigation Menu */}
        <NavigationMenu 
          activeTab={activeTab} 
          setActiveTab={setActiveTab}
          currentUser={currentUser}
        />

        {/* Filters and Export only show on Dashboard tab */}
        {activeTab === "dashboard" && (
          <>
            <FilterPanel 
              onFilterChange={handleFilterChange}
              filters={filters}
              loading={filterLoading}
            />

            <ExportPanel 
              filters={filters}
              apiClient={apiClient}
            />
          </>
        )}

        {/* Quick Actions in Sidebar */}
        <div style={darkStyles.sidebarSection}>
          <div style={darkStyles.sidebarHeader}>
            <SettingsIcon />
            <span>Quick Actions</span>
          </div>
          
          <button 
            onClick={fetchLatestAgentData} 
            disabled={dashboardLoading}
            style={{
              ...darkStyles.button,
              width: '100%',
              backgroundColor: dashboardLoading ? DARK_THEME.border : DARK_THEME.primary,
              marginBottom: '10px'
            }}
          >
            {dashboardLoading ? <TailSpin height={16} width={16} /> : 'Refresh Data'}
          </button>

          <button 
            onClick={logout}
            style={{
              ...darkStyles.button,
              width: '100%',
              backgroundColor: DARK_THEME.danger,
              marginTop: '10px'
            }}
          >
            Logout
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div style={darkStyles.mainContent}>
        <div style={{ marginBottom: '20px' }}>
          <h1 style={{ color: DARK_THEME.text, margin: '0 0 10px 0' }}>Server Monitoring Dashboard</h1>
          <p style={{ color: DARK_THEME.textMuted, margin: 0 }}>
            {activeTab === "dashboard" && "Real-time system metrics and performance monitoring"}
            {activeTab === "layouts" && "Manage and customize your dashboard layouts"}
            {activeTab === "account" && "Manage your account settings and security"}
            {activeTab === "users" && "User management and access control"}
            {activeTab === "alerts" && "Alert rules and incident management"}
          </p>
        </div>

        {/* Tab Navigation */}
        <div style={darkStyles.tabContainer}>
          <button
            onClick={() => setActiveTab("dashboard")}
            style={{
              ...darkStyles.tab,
              backgroundColor: activeTab === "dashboard" ? DARK_THEME.primary : "#333",
              color: activeTab === "dashboard" ? "#fff" : DARK_THEME.text
            }}
          >
            <DashboardIcon />
            Dashboard
          </button>

          <button
            onClick={() => setActiveTab("layouts")}
            style={{
              ...darkStyles.tab,
              backgroundColor: activeTab === "layouts" ? DARK_THEME.primary : "#333",
              color: activeTab === "layouts" ? "#fff" : DARK_THEME.text
            }}
          >
            <LayoutIcon />
            Layouts
          </button>

          <button
            onClick={() => setActiveTab("account")}
            style={{
              ...darkStyles.tab,
              backgroundColor: activeTab === "account" ? DARK_THEME.primary : "#333",
              color: activeTab === "account" ? "#fff" : DARK_THEME.text
            }}
          >
            <AccountIcon />
            Account
          </button>

          {currentUser?.role === 'admin' && (
            <>
              <button
                onClick={() => setActiveTab("users")}
                style={{
                  ...darkStyles.tab,
                  backgroundColor: activeTab === "users" ? DARK_THEME.primary : "#333",
                  color: activeTab === "users" ? "#fff" : DARK_THEME.text
                }}
              >
                <UsersIcon />
                Users
              </button>

              <button
                onClick={() => setActiveTab("alerts")}
                style={{
                  ...darkStyles.tab,
                  backgroundColor: activeTab === "alerts" ? DARK_THEME.primary : "#333",
                  color: activeTab === "alerts" ? "#fff" : DARK_THEME.text
                }}
              >
                <AlertIcon />
                Alerts
              </button>
            </>
          )}
        </div>

        {/* Tab Content */}
        {renderTabContent()}

        {/* Drill Down Modal */}
        <DrillDownModal
          isOpen={showDrillDown}
          onClose={() => setShowDrillDown(false)}
          metricData={drillDownData}
          apiClient={apiClient}
        />
      </div>
    </div>
  );
}

export default App;
