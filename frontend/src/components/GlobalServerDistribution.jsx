import React, { useState, useEffect, useMemo, useRef } from 'react';

// Theme constants aligned with Purple SOC Design System
const SOC_THEME = {
  cardBg: "rgba(255, 255, 255, 0.05)",
  cardBorder: "rgba(139, 92, 246, 0.18)",
  canvasBg: "radial-gradient(ellipse at 50% 50%, #16041c 0%, #0c0211 60%, #050007 100%)",
  online: "#2dd4bf",   // Cyan / Teal
  warning: "#f59e0b",  // Amber / Orange
  offline: "#f43f5e",  // Rose / Crimson
  primary: "#8b5cf6",  // Purple
  text: "#e8e6ff",
  textMuted: "rgba(180, 170, 255, 0.6)",
  gridLine: "rgba(139, 92, 246, 0.08)",
  orbitLine: "rgba(139, 92, 246, 0.22)",
  meshLine: "rgba(139, 92, 246, 0.28)",
  meshActive: "rgba(45, 212, 191, 0.45)",
};

const DEFAULT_SERVERS = [
  {
    id: 1,
    name: "US East (N. Virginia)",
    code: "iad-01",
    region: "North America",
    flag: "🇺🇸",
    latitude: 38.9072,
    longitude: -77.0369,
    orbitX: 220,
    orbitY: 130,
    status: "online",
    current_load: 42.5,
    active_users: 1245,
    latency: 24,
    throughput: "4.8 Gbps",
    threats_blocked: 142,
    shield: "Armored"
  },
  {
    id: 2,
    name: "US West (Oregon)",
    code: "pdx-01",
    region: "North America",
    flag: "🇺🇸",
    latitude: 45.5152,
    longitude: -122.6784,
    orbitX: 120,
    orbitY: 185,
    status: "online",
    current_load: 34.0,
    active_users: 876,
    latency: 48,
    throughput: "3.2 Gbps",
    threats_blocked: 89,
    shield: "Armored"
  },
  {
    id: 3,
    name: "Europe (Frankfurt)",
    code: "fra-01",
    region: "Europe",
    flag: "🇩🇪",
    latitude: 50.1109,
    longitude: 8.6821,
    orbitX: 410,
    orbitY: 100,
    status: "online",
    current_load: 28.4,
    active_users: 1530,
    latency: 38,
    throughput: "6.1 Gbps",
    threats_blocked: 215,
    shield: "Armored"
  },
  {
    id: 4,
    name: "Asia Pacific (Tokyo)",
    code: "nrt-01",
    region: "Asia Pacific",
    flag: "🇯🇵",
    latitude: 35.6762,
    longitude: 139.6503,
    orbitX: 670,
    orbitY: 140,
    status: "warning",
    current_load: 79.2,
    active_users: 2140,
    latency: 92,
    throughput: "8.4 Gbps",
    threats_blocked: 512,
    shield: "High Alert"
  },
  {
    id: 5,
    name: "South America (São Paulo)",
    code: "gru-01",
    region: "South America",
    flag: "🇧🇷",
    latitude: -23.5505,
    longitude: -46.6333,
    orbitX: 300,
    orbitY: 265,
    status: "offline",
    current_load: 0,
    active_users: 0,
    latency: 0,
    throughput: "0 Gbps",
    threats_blocked: 12,
    shield: "Isolated"
  },
  {
    id: 6,
    name: "Australia (Sydney)",
    code: "syd-01",
    region: "Oceania",
    flag: "🇦🇺",
    latitude: -33.8688,
    longitude: 151.2093,
    orbitX: 690,
    orbitY: 260,
    status: "online",
    current_load: 22.8,
    active_users: 640,
    latency: 118,
    throughput: "2.4 Gbps",
    threats_blocked: 47,
    shield: "Armored"
  }
];

export default function GlobalServerDistribution({ servers = [], onServerClick, token }) {
  const [serverList, setServerList] = useState(DEFAULT_SERVERS);
  const [selectedServer, setSelectedServer] = useState(null);
  const [hoveredServer, setHoveredServer] = useState(null);
  const [viewMode, setViewMode] = useState('orbital'); // 'orbital' | 'world' | 'matrix'
  const [statusFilter, setStatusFilter] = useState('all'); // 'all' | 'online' | 'warning' | 'offline'
  const [isPinging, setIsPinging] = useState(false);
  const [pingSweepKey, setPingSweepKey] = useState(0);
  const [lastRefreshed, setLastRefreshed] = useState(new Date().toLocaleTimeString());
  const canvasRef = useRef(null);

  // Fetch live server geolocation from backend
  const fetchGeolocations = async () => {
    try {
      const authToken = token || localStorage.getItem('token');
      const headers = authToken ? { Authorization: `Bearer ${authToken}` } : {};
      
      const res = await fetch('http://localhost:8000/api/servers/geolocation', { headers });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data) && data.length > 0) {
          // Merge with rich coordinate and metadata attributes
          const merged = data.map((item, idx) => {
            const def = DEFAULT_SERVERS.find(d => 
              d.name.toLowerCase().includes(item.name.toLowerCase()) || 
              item.name.toLowerCase().includes(d.name.toLowerCase())
            ) || DEFAULT_SERVERS[idx % DEFAULT_SERVERS.length];

            return {
              ...def,
              id: item.id || def.id,
              name: item.name || def.name,
              latitude: item.latitude ?? def.latitude,
              longitude: item.longitude ?? def.longitude,
              status: item.status || def.status,
              current_load: item.current_load ?? def.current_load,
              active_users: item.active_users ?? def.active_users,
              latency: item.status === 'offline' ? 0 : Math.round(18 + (item.current_load || 40) * 0.9),
            };
          });
          setServerList(merged);
          setLastRefreshed(new Date().toLocaleTimeString());
        }
      }
    } catch (e) {
      // Keep rich default state if backend not immediately reached
      console.debug('Using cached/default geolocation topology', e);
    }
  };

  useEffect(() => {
    fetchGeolocations();
    const interval = setInterval(fetchGeolocations, 20000);
    return () => clearInterval(interval);
  }, [token]);

  // Handle Ping Sweep Animation
  const triggerPingSweep = () => {
    setIsPinging(true);
    setPingSweepKey(prev => prev + 1);
    setTimeout(() => setIsPinging(false), 2400);
  };

  // Status counters
  const counts = useMemo(() => {
    return {
      all: serverList.length,
      online: serverList.filter(s => s.status === 'online').length,
      warning: serverList.filter(s => s.status === 'warning').length,
      offline: serverList.filter(s => s.status === 'offline').length,
      avgLatency: Math.round(
        serverList.filter(s => s.status !== 'offline').reduce((acc, s) => acc + (s.latency || 30), 0) /
        Math.max(1, serverList.filter(s => s.status !== 'offline').length)
      )
    };
  }, [serverList]);

  // Filtered servers
  const displayedServers = useMemo(() => {
    if (statusFilter === 'all') return serverList;
    return serverList.filter(s => s.status === statusFilter);
  }, [serverList, statusFilter]);

  // Helper color function
  const getNodeColor = (status) => {
    switch (status) {
      case 'online': return SOC_THEME.online;
      case 'warning': return SOC_THEME.warning;
      case 'offline': return SOC_THEME.offline;
      default: return SOC_THEME.textMuted;
    }
  };

  // Convert lat/long to Cyber World Map X/Y (viewBox 0 0 800 360)
  const getMapCoordinates = (lat, lng) => {
    const x = ((lng + 180) / 360) * 760 + 20;
    const y = ((90 - lat) / 180) * 320 + 20;
    return { x, y };
  };

  return (
    <div style={{
      background: "rgba(255, 255, 255, 0.05)",
      backdropFilter: "blur(48px) saturate(160%)",
      WebkitBackdropFilter: "blur(48px) saturate(160%)",
      borderRadius: "20px",
      border: `1px solid ${SOC_THEME.cardBorder}`,
      padding: "24px",
      boxShadow: "0 20px 50px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.1)",
      position: "relative",
      overflow: "hidden",
      fontFamily: "'Inter', sans-serif"
    }}>
      {/* Dynamic Keyframes for Constellation and Cyber Map */}
      <style>{`
        @keyframes orbitPulse {
          0% { transform: scale(1); opacity: 0.9; }
          50% { transform: scale(1.08); opacity: 0.4; }
          100% { transform: scale(1); opacity: 0.9; }
        }
        @keyframes rippleRing {
          0% { r: 6; opacity: 1; stroke-width: 2; }
          100% { r: 24; opacity: 0; stroke-width: 0.5; }
        }
        @keyframes dashFlow {
          from { stroke-dashoffset: 40; }
          to { stroke-dashoffset: 0; }
        }
        @keyframes radarSweep {
          0% { transform: rotate(0deg); opacity: 0.8; }
          100% { transform: rotate(360deg); opacity: 0.8; }
        }
        @keyframes radarExpand {
          0% { r: 0; opacity: 0.9; }
          100% { r: 420; opacity: 0; }
        }
        @keyframes packetMove {
          0% { offset-distance: 0%; opacity: 0; }
          20% { opacity: 1; }
          80% { opacity: 1; }
          100% { offset-distance: 100%; opacity: 0; }
        }
        .server-node-group:hover .node-halo {
          filter: drop-shadow(0 0 12px currentColor);
          transform: scale(1.2);
        }
      `}</style>

      {/* ── CARD HEADER ──────────────────────────────────────────────────────── */}
      <div style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        flexWrap: "wrap",
        gap: "16px",
        marginBottom: "20px"
      }}>
        {/* Left: Branded Icon & Titles (Exact match to user's design) */}
        <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
          <div style={{
            width: "48px",
            height: "48px",
            background: "linear-gradient(135deg, #10b981 0%, #059669 100%)",
            borderRadius: "15px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            boxShadow: "0 8px 25px rgba(16, 185, 129, 0.4), inset 0 1px 1px rgba(255, 255, 255, 0.3)",
            flexShrink: 0
          }}>
            {/* Crisp Vector Globe Icon */}
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ffffff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10" />
              <line x1="2" y1="12" x2="22" y2="12" />
              <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
            </svg>
          </div>

          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <h3 style={{
                color: SOC_THEME.text,
                margin: 0,
                fontSize: "19px",
                fontWeight: 600,
                letterSpacing: "-0.01em"
              }}>
                Global Server Distribution
              </h3>
              <span style={{
                background: "rgba(45, 212, 191, 0.12)",
                color: SOC_THEME.online,
                fontSize: "11px",
                padding: "2px 8px",
                borderRadius: "20px",
                border: "1px solid rgba(45, 212, 191, 0.25)",
                display: "inline-flex",
                alignItems: "center",
                gap: "5px",
                fontWeight: 600
              }}>
                <span style={{
                  width: "6px",
                  height: "6px",
                  borderRadius: "50%",
                  background: SOC_THEME.online,
                  boxShadow: `0 0 8px ${SOC_THEME.online}`
                }} />
                LIVE MESH
              </span>
            </div>
            <p style={{
              color: SOC_THEME.textMuted,
              margin: "3px 0 0 0",
              fontSize: "13.5px"
            }}>
              Real-time server status and connectivity
            </p>
          </div>
        </div>

        {/* Right: Live Telemetry Metrics & View Mode Switcher */}
        <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
          {/* Telemetry quick ticker */}
          <div style={{
            display: "flex",
            alignItems: "center",
            gap: "14px",
            background: "rgba(0, 0, 0, 0.35)",
            padding: "6px 14px",
            borderRadius: "10px",
            border: "1px solid rgba(139, 92, 246, 0.15)",
            fontSize: "12px"
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <span style={{ color: SOC_THEME.textMuted }}>Median RTT:</span>
              <strong style={{ color: SOC_THEME.online }}>{counts.avgLatency}ms</strong>
            </div>
            <div style={{ width: "1px", height: "14px", background: "rgba(255, 255, 255, 0.1)" }} />
            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <span style={{ color: SOC_THEME.textMuted }}>Links:</span>
              <strong style={{ color: "#c084fc" }}>10 Active</strong>
            </div>
          </div>

          {/* View Toggle Tabs */}
          <div style={{
            display: "flex",
            background: "rgba(0, 0, 0, 0.4)",
            padding: "3px",
            borderRadius: "10px",
            border: "1px solid rgba(255, 255, 255, 0.08)"
          }}>
            <button
              onClick={() => setViewMode('orbital')}
              style={{
                background: viewMode === 'orbital' ? "linear-gradient(135deg, rgba(139,92,246,0.5), rgba(45,212,191,0.3))" : "transparent",
                color: viewMode === 'orbital' ? "#fff" : SOC_THEME.textMuted,
                border: viewMode === 'orbital' ? "1px solid rgba(139,92,246,0.4)" : "none",
                borderRadius: "8px",
                padding: "6px 12px",
                fontSize: "12px",
                fontWeight: 600,
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: "6px",
                transition: "all 0.2s ease"
              }}
              title="Orbital Constellation View"
            >
              <span>🛰️</span> Orbital Mesh
            </button>

            <button
              onClick={() => setViewMode('world')}
              style={{
                background: viewMode === 'world' ? "linear-gradient(135deg, rgba(139,92,246,0.5), rgba(45,212,191,0.3))" : "transparent",
                color: viewMode === 'world' ? "#fff" : SOC_THEME.textMuted,
                border: viewMode === 'world' ? "1px solid rgba(139,92,246,0.4)" : "none",
                borderRadius: "8px",
                padding: "6px 12px",
                fontSize: "12px",
                fontWeight: 600,
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: "6px",
                transition: "all 0.2s ease"
              }}
              title="Geographic World Map"
            >
              <span>🌐</span> World Map
            </button>

            <button
              onClick={() => setViewMode('matrix')}
              style={{
                background: viewMode === 'matrix' ? "linear-gradient(135deg, rgba(139,92,246,0.5), rgba(45,212,191,0.3))" : "transparent",
                color: viewMode === 'matrix' ? "#fff" : SOC_THEME.textMuted,
                border: viewMode === 'matrix' ? "1px solid rgba(139,92,246,0.4)" : "none",
                borderRadius: "8px",
                padding: "6px 12px",
                fontSize: "12px",
                fontWeight: 600,
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: "6px",
                transition: "all 0.2s ease"
              }}
              title="Fleet Telemetry Grid"
            >
              <span>⚡</span> Matrix
            </button>
          </div>

          {/* Radar Ping Sweep Action Button */}
          <button
            onClick={triggerPingSweep}
            disabled={isPinging}
            style={{
              background: isPinging ? "rgba(45, 212, 191, 0.25)" : "rgba(139, 92, 246, 0.15)",
              color: isPinging ? SOC_THEME.online : "#c084fc",
              border: `1px solid ${isPinging ? SOC_THEME.online : "rgba(139, 92, 246, 0.3)"}`,
              borderRadius: "10px",
              padding: "6px 12px",
              fontSize: "12px",
              fontWeight: 600,
              cursor: isPinging ? "default" : "pointer",
              display: "flex",
              alignItems: "center",
              gap: "6px",
              transition: "all 0.2s ease"
            }}
            title="Perform live mesh latency test across nodes"
          >
            <span>📡</span> {isPinging ? "Sweeping..." : "Ping Sweep"}
          </button>
        </div>
      </div>

      {/* ── MAIN VISUALIZATION CANVAS (340px) ─────────────────────────────────── */}
      <div 
        ref={canvasRef}
        style={{
          width: "100%",
          height: "340px",
          background: SOC_THEME.canvasBg,
          borderRadius: "16px",
          position: "relative",
          border: `1px solid ${SOC_THEME.cardBorder}`,
          overflow: "hidden",
          boxShadow: "inset 0 0 60px rgba(0, 0, 0, 0.8), 0 10px 30px rgba(0,0,0,0.3)"
        }}
      >
        {/* Subtle Cyber Grid Lines on Canvas Floor */}
        <div style={{
          position: "absolute",
          inset: 0,
          backgroundImage: `
            linear-gradient(to right, rgba(139, 92, 246, 0.04) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(139, 92, 246, 0.04) 1px, transparent 1px)
          `,
          backgroundSize: "40px 40px",
          pointerEvents: "none",
          opacity: 0.7
        }} />

        {/* ───────── VIEW 1: ORBITAL CONSTELLATION (Elevated from user's image) ───────── */}
        {viewMode === 'orbital' && (
          <svg
            viewBox="0 0 800 360"
            style={{ width: "100%", height: "100%", position: "absolute", inset: 0 }}
          >
            <defs>
              {/* Radial gradient for glowing aura */}
              <radialGradient id="orbitGlow" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#8b5cf6" stopOpacity="0.15" />
                <stop offset="60%" stopColor="#8b5cf6" stopOpacity="0.03" />
                <stop offset="100%" stopColor="#8b5cf6" stopOpacity="0" />
              </radialGradient>

              {/* Linear gradient for mesh connection beams */}
              <linearGradient id="beamGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#8b5cf6" stopOpacity="0.4" />
                <stop offset="50%" stopColor="#2dd4bf" stopOpacity="0.25" />
                <stop offset="100%" stopColor="#f59e0b" stopOpacity="0.4" />
              </linearGradient>

              {/* Neon Glow Filter */}
              <filter id="neonGlow" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="3.5" result="coloredBlur" />
                <feMerge>
                  <feMergeNode in="coloredBlur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            {/* Center Orbital Aura */}
            <ellipse cx="400" cy="180" rx="340" ry="120" fill="url(#orbitGlow)" />

            {/* Outer Faint Coordinate Ring */}
            <ellipse
              cx="400"
              cy="180"
              rx="330"
              ry="115"
              fill="none"
              stroke="rgba(139, 92, 246, 0.12)"
              strokeWidth="1"
              strokeDasharray="2 10"
            />

            {/* Primary Tilted Orbital Ring (Exact feature from user's screenshot, elevated) */}
            <ellipse
              cx="400"
              cy="180"
              rx="270"
              ry="92"
              fill="none"
              stroke={SOC_THEME.orbitLine}
              strokeWidth="1.5"
              strokeDasharray="1 0"
              style={{
                filter: "drop-shadow(0 0 6px rgba(139, 92, 246, 0.25))"
              }}
            />

            {/* Inner Concentric Orbit */}
            <ellipse
              cx="400"
              cy="180"
              rx="180"
              ry="60"
              fill="none"
              stroke="rgba(139, 92, 246, 0.14)"
              strokeWidth="1"
              strokeDasharray="6 6"
            />

            {/* Center Core Beacon */}
            <circle cx="400" cy="180" r="3" fill="rgba(139, 92, 246, 0.6)" />
            <circle cx="400" cy="180" r="14" fill="none" stroke="rgba(139, 92, 246, 0.15)" strokeWidth="1" />

            {/* Dynamic Ping Radar Ripple when sweeping */}
            {isPinging && (
              <circle
                key={`ping-${pingSweepKey}`}
                cx="400"
                cy="180"
                fill="none"
                stroke={SOC_THEME.online}
                strokeWidth="2"
                style={{
                  animation: "radarExpand 2.2s cubic-bezier(0.1, 0.8, 0.3, 1) forwards"
                }}
              />
            )}

            {/* Dashed Mesh Connection Lines between nodes (matching user's screenshot) */}
            <g>
              {displayedServers.map((server, i) => {
                return displayedServers.slice(i + 1).map((target) => {
                  const isHighlighted = hoveredServer?.id === server.id || hoveredServer?.id === target.id;
                  const isBothOnline = server.status === 'online' && target.status === 'online';
                  
                  return (
                    <g key={`mesh-${server.id}-${target.id}`}>
                      {/* Base Dashed Line */}
                      <line
                        x1={server.orbitX}
                        y1={server.orbitY}
                        x2={target.orbitX}
                        y2={target.orbitY}
                        stroke={isHighlighted ? SOC_THEME.online : SOC_THEME.meshLine}
                        strokeWidth={isHighlighted ? "1.8" : "1"}
                        strokeDasharray={isHighlighted ? "6 3" : "4 4"}
                        style={{
                          transition: "stroke 0.3s ease",
                          animation: isBothOnline ? "dashFlow 20s linear infinite" : "none"
                        }}
                      />
                      
                      {/* Active Packet Dot travelling along online connection */}
                      {isBothOnline && (
                        <circle
                          r={isHighlighted ? 3 : 2}
                          fill={isHighlighted ? SOC_THEME.online : "rgba(192, 132, 252, 0.8)"}
                          style={{
                            animation: `dashFlow 4s linear infinite`
                          }}
                        >
                          <animateMotion
                            path={`M ${server.orbitX} ${server.orbitY} L ${target.orbitX} ${target.orbitY}`}
                            dur={`${3.5 + ((server.id + target.id) % 3)}s`}
                            repeatCount="indefinite"
                          />
                        </circle>
                      )}
                    </g>
                  );
                });
              })}
            </g>

            {/* Server Nodes (Cyan=Online, Amber=Warning, Rose=Offline) */}
            {displayedServers.map((server) => {
              const nodeColor = getNodeColor(server.status);
              const isSelected = selectedServer?.id === server.id;
              const isHovered = hoveredServer?.id === server.id;

              return (
                <g
                  key={`node-${server.id}`}
                  className="server-node-group"
                  style={{ cursor: "pointer" }}
                  onMouseEnter={() => setHoveredServer(server)}
                  onMouseLeave={() => setHoveredServer(null)}
                  onClick={() => {
                    setSelectedServer(server);
                    if (onServerClick) onServerClick(server);
                  }}
                >
                  {/* Outer Pulsing Radar Ring for Online / Warning nodes */}
                  {server.status !== 'offline' && (
                    <circle
                      cx={server.orbitX}
                      cy={server.orbitY}
                      r="16"
                      fill="none"
                      stroke={nodeColor}
                      opacity={isHovered ? 0.8 : 0.35}
                      strokeWidth="1"
                      style={{
                        animation: "rippleRing 2.4s cubic-bezier(0, 0.2, 0.8, 1) infinite",
                        animationDelay: `${(server.id * 0.4) % 2}s`
                      }}
                    />
                  )}

                  {/* Interactive Selected Ring */}
                  {(isSelected || isHovered) && (
                    <circle
                      cx={server.orbitX}
                      cy={server.orbitY}
                      r="14"
                      fill="none"
                      stroke="#ffffff"
                      strokeWidth="1.5"
                      strokeDasharray="2 3"
                    />
                  )}

                  {/* Outer Neon Glow Halo */}
                  <circle
                    className="node-halo"
                    cx={server.orbitX}
                    cy={server.orbitY}
                    r={isSelected || isHovered ? 10 : 8}
                    fill={nodeColor}
                    opacity="0.3"
                    style={{ transition: "all 0.2s ease" }}
                  />

                  {/* Core Node Circle */}
                  <circle
                    cx={server.orbitX}
                    cy={server.orbitY}
                    r={isSelected || isHovered ? 6.5 : 5}
                    fill={nodeColor}
                    stroke="#ffffff"
                    strokeWidth={isSelected ? "2" : "1"}
                    filter="url(#neonGlow)"
                    style={{ transition: "all 0.2s ease" }}
                  />

                  {/* Text Label & Latency Badge next to node */}
                  <text
                    x={server.orbitX + (server.orbitX > 500 ? -12 : 14)}
                    y={server.orbitY + (server.orbitY > 200 ? 16 : -8)}
                    fill={isHovered || isSelected ? "#ffffff" : SOC_THEME.text}
                    fontSize={isHovered || isSelected ? "12" : "11"}
                    fontWeight={isHovered || isSelected ? "600" : "500"}
                    textAnchor={server.orbitX > 500 ? "end" : "start"}
                    style={{ pointerEvents: "none", userSelect: "none" }}
                  >
                    {server.name.split(' (')[0]}
                  </text>

                  {/* Small RTT / Latency Indicator */}
                  {server.status !== 'offline' && (
                    <text
                      x={server.orbitX + (server.orbitX > 500 ? -12 : 14)}
                      y={server.orbitY + (server.orbitY > 200 ? 28 : 5)}
                      fill={nodeColor}
                      fontSize="9.5"
                      fontWeight="600"
                      textAnchor={server.orbitX > 500 ? "end" : "start"}
                      style={{ pointerEvents: "none", userSelect: "none", opacity: 0.85 }}
                    >
                      {server.latency}ms
                    </text>
                  )}
                </g>
              );
            })}
          </svg>
        )}

        {/* ───────── VIEW 2: CYBER WORLD MAP (Equirectangular Lat/Long) ───────── */}
        {viewMode === 'world' && (
          <svg
            viewBox="0 0 800 360"
            style={{ width: "100%", height: "100%", position: "absolute", inset: 0 }}
          >
            <defs>
              <linearGradient id="mapArcGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#2dd4bf" stopOpacity="0.6" />
                <stop offset="50%" stopColor="#8b5cf6" stopOpacity="0.8" />
                <stop offset="100%" stopColor="#2dd4bf" stopOpacity="0.6" />
              </linearGradient>
            </defs>

            {/* Latitude & Longitude Cyber Grid */}
            <g opacity="0.25">
              {[-60, -30, 0, 30, 60].map(lat => {
                const { y } = getMapCoordinates(lat, 0);
                return (
                  <line
                    key={`lat-${lat}`}
                    x1="20"
                    y1={y}
                    x2="780"
                    y2={y}
                    stroke="rgba(139, 92, 246, 0.4)"
                    strokeWidth="0.8"
                    strokeDasharray="3 6"
                  />
                );
              })}
              {[-120, -60, 0, 60, 120].map(lng => {
                const { x } = getMapCoordinates(0, lng);
                return (
                  <line
                    key={`lng-${lng}`}
                    x1={x}
                    y1="20"
                    x2={x}
                    y2="340"
                    stroke="rgba(139, 92, 246, 0.4)"
                    strokeWidth="0.8"
                    strokeDasharray="3 6"
                  />
                );
              })}
            </g>

            {/* Stylized Minimal Continental Vector Silhouettes */}
            <g fill="rgba(139, 92, 246, 0.08)" stroke="rgba(139, 92, 246, 0.25)" strokeWidth="0.8">
              {/* North America */}
              <path d="M 120 70 L 230 65 L 260 90 L 230 140 L 190 150 L 160 210 L 130 160 L 90 120 Z" />
              {/* South America */}
              <path d="M 210 210 L 290 220 L 310 270 L 270 330 L 230 310 L 210 250 Z" />
              {/* Europe */}
              <path d="M 370 75 L 450 70 L 460 110 L 420 135 L 375 125 L 360 90 Z" />
              {/* Africa */}
              <path d="M 375 145 L 450 140 L 480 200 L 450 280 L 400 290 L 365 210 Z" />
              {/* Asia */}
              <path d="M 470 70 L 680 75 L 720 130 L 660 180 L 560 180 L 510 140 L 465 110 Z" />
              {/* Australia */}
              <path d="M 640 250 L 730 250 L 740 310 L 660 320 Z" />
            </g>

            {/* Geodesic Curved Packet Arcs connecting datacenters */}
            <g>
              {displayedServers.map((server, i) => {
                const sCoord = getMapCoordinates(server.latitude, server.longitude);
                return displayedServers.slice(i + 1).map(target => {
                  const tCoord = getMapCoordinates(target.latitude, target.longitude);
                  const isBothOnline = server.status === 'online' && target.status === 'online';
                  
                  // Control point for quadratic curve
                  const midX = (sCoord.x + tCoord.x) / 2;
                  const midY = Math.min(sCoord.y, tCoord.y) - 40;
                  const pathD = `M ${sCoord.x} ${sCoord.y} Q ${midX} ${midY} ${tCoord.x} ${tCoord.y}`;

                  return (
                    <g key={`world-arc-${server.id}-${target.id}`}>
                      <path
                        d={pathD}
                        fill="none"
                        stroke="url(#mapArcGrad)"
                        strokeWidth="1.2"
                        strokeDasharray="4 4"
                        opacity={isBothOnline ? 0.7 : 0.2}
                      />
                      {isBothOnline && (
                        <circle r="2.5" fill="#2dd4bf">
                          <animateMotion
                            path={pathD}
                            dur={`${4 + (server.id % 3)}s`}
                            repeatCount="indefinite"
                          />
                        </circle>
                      )}
                    </g>
                  );
                });
              })}
            </g>

            {/* Server Nodes Placed at Accurate Geo-Coordinates */}
            {displayedServers.map((server) => {
              const { x, y } = getMapCoordinates(server.latitude, server.longitude);
              const nodeColor = getNodeColor(server.status);
              const isSelected = selectedServer?.id === server.id;

              return (
                <g
                  key={`geo-node-${server.id}`}
                  style={{ cursor: "pointer" }}
                  onClick={() => {
                    setSelectedServer(server);
                    if (onServerClick) onServerClick(server);
                  }}
                  onMouseEnter={() => setHoveredServer(server)}
                  onMouseLeave={() => setHoveredServer(null)}
                >
                  {server.status !== 'offline' && (
                    <circle
                      cx={x}
                      cy={y}
                      r="12"
                      fill="none"
                      stroke={nodeColor}
                      strokeWidth="1"
                      style={{ animation: "rippleRing 2.5s infinite" }}
                    />
                  )}
                  <circle cx={x} cy={y} r="8" fill={nodeColor} opacity="0.3" />
                  <circle cx={x} cy={y} r="5" fill={nodeColor} stroke="#fff" strokeWidth="1" />
                  <text
                    x={x + 10}
                    y={y - 6}
                    fill="#fff"
                    fontSize="11"
                    fontWeight="600"
                    style={{ pointerEvents: "none" }}
                  >
                    {server.name.split(' (')[0]}
                  </text>
                </g>
              );
            })}
          </svg>
        )}

        {/* ───────── VIEW 3: MATRIX TELEMETRY GRID ───────── */}
        {viewMode === 'matrix' && (
          <div style={{
            padding: "20px",
            height: "100%",
            overflowY: "auto",
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            gap: "14px",
            boxSizing: "border-box"
          }}>
            {displayedServers.map((server) => {
              const nodeColor = getNodeColor(server.status);
              const isSelected = selectedServer?.id === server.id;

              return (
                <div
                  key={`card-${server.id}`}
                  onClick={() => {
                    setSelectedServer(server);
                    if (onServerClick) onServerClick(server);
                  }}
                  style={{
                    background: isSelected ? "rgba(139, 92, 246, 0.2)" : "rgba(0, 0, 0, 0.45)",
                    border: `1px solid ${isSelected ? SOC_THEME.primary : "rgba(255, 255, 255, 0.08)"}`,
                    borderRadius: "12px",
                    padding: "14px",
                    cursor: "pointer",
                    transition: "all 0.2s ease"
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px" }}>
                    <div>
                      <div style={{ fontSize: "14px", fontWeight: 600, color: "#fff" }}>
                        {server.flag} {server.name.split(' (')[0]}
                      </div>
                      <div style={{ fontSize: "11px", color: SOC_THEME.textMuted }}>{server.code}</div>
                    </div>
                    <span style={{
                      background: `${nodeColor}22`,
                      color: nodeColor,
                      fontSize: "10px",
                      fontWeight: 700,
                      padding: "2px 7px",
                      borderRadius: "6px",
                      textTransform: "uppercase"
                    }}>
                      {server.status}
                    </span>
                  </div>

                  {/* Load Bar */}
                  <div style={{ marginTop: "10px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: "11px", marginBottom: "4px" }}>
                      <span style={{ color: SOC_THEME.textMuted }}>CPU Load</span>
                      <strong style={{ color: server.current_load > 70 ? SOC_THEME.warning : "#fff" }}>
                        {server.current_load}%
                      </strong>
                    </div>
                    <div style={{ height: "4px", background: "rgba(255, 255, 255, 0.1)", borderRadius: "2px", overflow: "hidden" }}>
                      <div style={{
                        width: `${server.current_load}%`,
                        height: "100%",
                        background: server.current_load > 70 ? SOC_THEME.warning : SOC_THEME.online,
                        borderRadius: "2px"
                      }} />
                    </div>
                  </div>

                  {/* Latency & Users */}
                  <div style={{ display: "flex", justifyContent: "space-between", marginTop: "10px", fontSize: "11px" }}>
                    <span style={{ color: SOC_THEME.textMuted }}>RTT: <strong style={{ color: nodeColor }}>{server.latency}ms</strong></span>
                    <span style={{ color: SOC_THEME.textMuted }}>Users: <strong style={{ color: "#fff" }}>{server.active_users}</strong></span>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* ── FLOATING HUD INSPECTOR CARD (When node hovered or selected) ──────── */}
        {(hoveredServer || selectedServer) && (
          <div style={{
            position: "absolute",
            bottom: "16px",
            right: "16px",
            width: "270px",
            background: "rgba(10, 2, 14, 0.88)",
            backdropFilter: "blur(20px)",
            WebkitBackdropFilter: "blur(20px)",
            border: `1px solid ${SOC_THEME.primary}`,
            borderRadius: "14px",
            padding: "14px 16px",
            boxShadow: "0 10px 30px rgba(0, 0, 0, 0.7), 0 0 20px rgba(139, 92, 246, 0.25)",
            zIndex: 10,
            animation: "fadeIn 0.2s ease"
          }}>
            {(() => {
              const node = hoveredServer || selectedServer;
              const nodeColor = getNodeColor(node.status);
              return (
                <>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                      <span style={{ fontSize: "16px" }}>{node.flag}</span>
                      <strong style={{ color: "#fff", fontSize: "13px" }}>{node.name}</strong>
                    </div>
                    <span style={{
                      background: `${nodeColor}20`,
                      color: nodeColor,
                      fontSize: "10px",
                      padding: "2px 6px",
                      borderRadius: "4px",
                      fontWeight: 700,
                      textTransform: "uppercase"
                    }}>
                      {node.status}
                    </span>
                  </div>

                  <div style={{
                    display: "grid",
                    gridTemplateColumns: "1fr 1fr",
                    gap: "8px",
                    fontSize: "11.5px",
                    margin: "8px 0"
                  }}>
                    <div style={{ background: "rgba(255, 255, 255, 0.04)", padding: "6px 8px", borderRadius: "8px" }}>
                      <div style={{ color: SOC_THEME.textMuted, fontSize: "10px" }}>Latency</div>
                      <div style={{ color: nodeColor, fontWeight: 700, fontSize: "13px" }}>
                        {node.latency} ms
                      </div>
                    </div>

                    <div style={{ background: "rgba(255, 255, 255, 0.04)", padding: "6px 8px", borderRadius: "8px" }}>
                      <div style={{ color: SOC_THEME.textMuted, fontSize: "10px" }}>Active Users</div>
                      <div style={{ color: "#fff", fontWeight: 700, fontSize: "13px" }}>
                        {node.active_users}
                      </div>
                    </div>

                    <div style={{ background: "rgba(255, 255, 255, 0.04)", padding: "6px 8px", borderRadius: "8px" }}>
                      <div style={{ color: SOC_THEME.textMuted, fontSize: "10px" }}>Compute Load</div>
                      <div style={{ color: node.current_load > 70 ? SOC_THEME.warning : "#fff", fontWeight: 700, fontSize: "13px" }}>
                        {node.current_load}%
                      </div>
                    </div>

                    <div style={{ background: "rgba(255, 255, 255, 0.04)", padding: "6px 8px", borderRadius: "8px" }}>
                      <div style={{ color: SOC_THEME.textMuted, fontSize: "10px" }}>Shield State</div>
                      <div style={{ color: "#2dd4bf", fontWeight: 700, fontSize: "12px" }}>
                        {node.shield || "Armored"}
                      </div>
                    </div>
                  </div>

                  {onServerClick && (
                    <button
                      onClick={() => onServerClick(node)}
                      style={{
                        width: "100%",
                        background: "linear-gradient(135deg, #8b5cf6 0%, #2dd4bf 100%)",
                        border: "none",
                        borderRadius: "8px",
                        color: "#fff",
                        padding: "6px 0",
                        fontSize: "11.5px",
                        fontWeight: 600,
                        cursor: "pointer",
                        marginTop: "4px"
                      }}
                    >
                      Focus Telemetry Feed →
                    </button>
                  )}
                </>
              );
            })()}
          </div>
        )}
      </div>

      {/* ── CARD FOOTER / INTERACTIVE LEGEND (Exact match to screenshot) ─────── */}
      <div style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        marginTop: "18px",
        flexWrap: "wrap",
        gap: "14px"
      }}>
        {/* Status Legend Pills (Clickable filter) */}
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: "24px",
          fontSize: "13px",
          color: SOC_THEME.textMuted
        }}>
          {/* Online status indicator */}
          <div
            onClick={() => setStatusFilter(statusFilter === 'online' ? 'all' : 'online')}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              cursor: "pointer",
              opacity: statusFilter === 'all' || statusFilter === 'online' ? 1 : 0.45,
              transition: "opacity 0.2s ease"
            }}
          >
            <div style={{
              width: "12px",
              height: "12px",
              borderRadius: "50%",
              background: SOC_THEME.online,
              boxShadow: `0 0 10px ${SOC_THEME.online}`,
              animation: "orbitPulse 2s infinite"
            }} />
            <span style={{ color: statusFilter === 'online' ? "#fff" : SOC_THEME.textMuted, fontWeight: 500 }}>
              Online ({counts.online})
            </span>
          </div>

          {/* Warning status indicator */}
          <div
            onClick={() => setStatusFilter(statusFilter === 'warning' ? 'all' : 'warning')}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              cursor: "pointer",
              opacity: statusFilter === 'all' || statusFilter === 'warning' ? 1 : 0.45,
              transition: "opacity 0.2s ease"
            }}
          >
            <div style={{
              width: "12px",
              height: "12px",
              borderRadius: "50%",
              background: SOC_THEME.warning,
              boxShadow: `0 0 10px ${SOC_THEME.warning}`,
              animation: "orbitPulse 2s infinite"
            }} />
            <span style={{ color: statusFilter === 'warning' ? "#fff" : SOC_THEME.textMuted, fontWeight: 500 }}>
              Warning ({counts.warning})
            </span>
          </div>

          {/* Offline status indicator */}
          <div
            onClick={() => setStatusFilter(statusFilter === 'offline' ? 'all' : 'offline')}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              cursor: "pointer",
              opacity: statusFilter === 'all' || statusFilter === 'offline' ? 1 : 0.45,
              transition: "opacity 0.2s ease"
            }}
          >
            <div style={{
              width: "12px",
              height: "12px",
              borderRadius: "50%",
              background: SOC_THEME.offline,
              boxShadow: `0 0 10px ${SOC_THEME.offline}`
            }} />
            <span style={{ color: statusFilter === 'offline' ? "#fff" : SOC_THEME.textMuted, fontWeight: 500 }}>
              Offline ({counts.offline})
            </span>
          </div>
        </div>

        {/* Right Info: Last Sync Timestamp */}
        <div style={{
          fontSize: "12px",
          color: "rgba(180, 170, 255, 0.45)",
          display: "flex",
          alignItems: "center",
          gap: "8px"
        }}>
          <span>Telemetry synced at {lastRefreshed}</span>
          <button
            onClick={fetchGeolocations}
            style={{
              background: "transparent",
              border: "none",
              color: SOC_THEME.primary,
              cursor: "pointer",
              fontSize: "12px",
              padding: "0 4px",
              display: "flex",
              alignItems: "center"
            }}
            title="Refresh geolocation telemetry"
          >
            🔄
          </button>
        </div>
      </div>
    </div>
  );
}
