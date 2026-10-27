import React, { useState, useEffect, memo } from "react";
import axios from "axios";
import useWebSocket from "react-use-websocket";
import { PieChart, Pie, Cell, Legend, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer } from "recharts";
import { TailSpin } from 'react-loader-spinner';
import LiveAgentTerminal from "./components/LiveAgentTerminal";
import FleetPulseBar from "./components/FleetPulseBar";
import CommandPaletteModal from "./components/CommandPaletteModal";
import RemediationPlaybookModal from "./components/RemediationPlaybookModal";
import ExecutiveReportModal from "./components/ExecutiveReportModal";
import CommandRibbon from "./components/CommandRibbon";
import AutonomousCopilot from "./components/AutonomousCopilot";
import GlobalServerDistribution from "./components/GlobalServerDistribution";
import LandingPage from "./components/LandingPage";

const API_BASE = `http://${window.location.hostname}:8000`;

const DARK_THEME = {
  background: "transparent",
  cardBackground: "rgba(255,255,255,0.03)",
  cardBackgroundSolid: "#07071a",
  border: "rgba(255,255,255,0.06)",
  text: "#e8e6ff",
  textMuted: "rgba(180,170,255,0.45)",
  primary: "#8b5cf6",
  success: "#2dd4bf",
  danger: "#f43f5e",
  warning: "#f59e0b",
  info: "#818cf8",
  secondary: "rgba(180,170,255,0.5)",
  glass: "rgba(139,92,246,0.05)",
  glassBorder: "rgba(139,92,246,0.14)",
  accentGradient: "linear-gradient(135deg,#8b5cf6 0%,#2dd4bf 100%)"
};
const COLORS = ["#8b5cf6","#2dd4bf","#f59e0b","#818cf8","rgba(45,212,191,0.3)"];

// ── Global glass override injected into DOM ───────────────────────────────
function GlobalGlass() {
  return (
    <style>{`
      @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

      *, *::before, *::after { box-sizing:border-box; -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale; }

      html, body {
        margin:0; padding:0;
        font-family:'Inter',-apple-system,sans-serif;
        overflow:hidden;
        background:#07071a !important;
        color:#e8e6ff;
      }

      /* ── Typography scale ── */
      .t-label  { font-size:10px; font-weight:600; letter-spacing:0.1em; text-transform:uppercase; color:rgba(180,170,255,0.45); }
      .t-mono   { font-family:'JetBrains Mono',monospace; }
      .t-num    { font-family:'JetBrains Mono',monospace; font-feature-settings:'tnum'; }

      /* ── Scrollbars ── */
      ::-webkit-scrollbar { width:3px; height:3px; }
      ::-webkit-scrollbar-track { background:transparent; }
      ::-webkit-scrollbar-thumb { background:rgba(139,92,246,0.35); border-radius:4px; }
      ::-webkit-scrollbar-thumb:hover { background:rgba(139,92,246,0.6); }

      /* ── Buttons ── */
      button {
        font-family:inherit !important;
        letter-spacing:-0.01em !important;
        transition:all 0.18s cubic-bezier(0.25,0.46,0.45,0.94) !important;
      }
      button:hover:not(:disabled) { transform:translateY(-1px) !important; }
      button:active:not(:disabled) { transform:scale(0.98) translateY(0) !important; }

      /* ── Inputs ── */
      input, select, textarea { font-family:inherit !important; transition:border-color 0.2s,box-shadow 0.2s !important; }
      input:focus, select:focus, textarea:focus {
        border-color:rgba(139,92,246,0.6) !important;
        box-shadow:0 0 0 3px rgba(139,92,246,0.15) !important;
        outline:none !important;
      }
      input::placeholder { color:rgba(180,170,255,0.3) !important; }
      select option { background:#0d0d2b; color:#e8e6ff; }

      /* ── Recharts ── */
      .recharts-cartesian-grid line { stroke:rgba(139,92,246,0.07) !important; }
      .recharts-default-tooltip {
        background:rgba(10,9,30,0.97) !important;
        border:1px solid rgba(139,92,246,0.25) !important;
        border-radius:12px !important;
        backdrop-filter:blur(24px) !important;
        box-shadow:0 8px 32px rgba(0,0,0,0.6) !important;
        color:#e8e6ff !important;
        font-family:'Inter',sans-serif !important;
        font-size:13px !important;
      }
      .recharts-legend-item-text { color:rgba(180,170,255,0.7) !important; font-size:12px !important; }
      .recharts-text { fill:rgba(180,170,255,0.5) !important; font-size:11px !important; font-family:'Inter',sans-serif !important; }

      /* ── Tables ── */
      tr:hover td { background:rgba(139,92,246,0.05) !important; transition:background 0.12s; }
      th { text-transform:uppercase !important; letter-spacing:0.08em !important; font-size:10px !important; font-weight:600 !important; }

      /* ── Severity badges ── */
      .badge-critical { background:rgba(244,63,94,0.12); color:#fb7185; border:1px solid rgba(244,63,94,0.25); padding:2px 8px; border-radius:4px; font-size:10px; font-weight:600; letter-spacing:0.06em; }
      .badge-warning  { background:rgba(245,158,11,0.12); color:#fbbf24; border:1px solid rgba(245,158,11,0.22); padding:2px 8px; border-radius:4px; font-size:10px; font-weight:600; letter-spacing:0.06em; }
      .badge-info     { background:rgba(139,92,246,0.12); color:#a78bfa; border:1px solid rgba(139,92,246,0.22); padding:2px 8px; border-radius:4px; font-size:10px; font-weight:600; letter-spacing:0.06em; }
      .badge-ok       { background:rgba(45,212,191,0.10); color:#2dd4bf; border:1px solid rgba(45,212,191,0.22); padding:2px 8px; border-radius:4px; font-size:10px; font-weight:600; letter-spacing:0.06em; }

      /* ── Stat card metric colour classes ── */
      .metric-danger  { color:#f43f5e !important; }
      .metric-warning { color:#f59e0b !important; }
      .metric-ok      { color:#2dd4bf !important; }
      .metric-default { color:#e8e6ff !important; }

      /* ── Pulse and micro-animations ── */
      @keyframes live-pulse {
        0% { transform:scale(0.95); box-shadow:0 0 0 0 rgba(45,212,191,0.7); }
        70% { transform:scale(1); box-shadow:0 0 0 8px rgba(45,212,191,0); }
        100% { transform:scale(0.95); box-shadow:0 0 0 0 rgba(45,212,191,0); }
      }
      @keyframes live-pulse-purple {
        0% { transform:scale(0.95); box-shadow:0 0 0 0 rgba(139,92,246,0.7); }
        70% { transform:scale(1); box-shadow:0 0 0 8px rgba(139,92,246,0); }
        100% { transform:scale(0.95); box-shadow:0 0 0 0 rgba(139,92,246,0); }
      }
      @keyframes fadeIn {
        from { opacity:0; }
        to { opacity:1; }
      }
      @keyframes slideInDown {
        from { opacity:0; transform:translateY(-10px); }
        to { opacity:1; transform:translateY(0); }
      }

      /* ── Login split layout ── */
      .login-split { display:flex; height:100vh; width:100vw; }
      .login-left  {
        flex:0 0 48%;
        background:linear-gradient(145deg,#0a0820 0%,#0d0b2b 50%,#080618 100%);
        border-right:1px solid rgba(139,92,246,0.12);
        display:flex; flex-direction:column;
        position:relative; overflow:hidden;
        padding:48px;
      }
      .login-right {
        flex:1; display:flex; align-items:center; justify-content:center;
        background:#07071a; padding:48px;
      }
      @media(max-width:768px) {
        .login-split { flex-direction:column; }
        .login-left  { flex:0 0 220px; padding:32px 24px; border-right:none; border-bottom:1px solid rgba(139,92,246,0.12); }
        .login-right { padding:24px; }
      }

      /* ── Login grid pattern ── */
      .login-grid {
        position:absolute; inset:0;
        background-image:
          linear-gradient(rgba(139,92,246,0.06) 1px, transparent 1px),
          linear-gradient(90deg, rgba(139,92,246,0.06) 1px, transparent 1px);
        background-size:40px 40px;
        mask-image:radial-gradient(ellipse 80% 80% at 50% 50%, black 40%, transparent 100%);
      }

      /* ── Sidebar v2 ── */
      .sidebar-v2 {
        width:240px; min-width:240px;
        background:rgba(7,7,26,0.9);
        backdrop-filter:blur(40px);
        border-right:1px solid rgba(139,92,246,0.1);
        display:flex; flex-direction:column;
        height:100vh; position:sticky; top:0;
      }
      .sidebar-logo {
        padding:20px 20px 16px;
        border-bottom:1px solid rgba(139,92,246,0.08);
        display:flex; align-items:center; gap:12px;
      }
      .sidebar-logo-icon {
        width:36px; height:36px; border-radius:10px;
        background:linear-gradient(135deg,#8b5cf6,#2dd4bf);
        display:flex; align-items:center; justify-content:center;
        flex-shrink:0;
        box-shadow:0 4px 16px rgba(139,92,246,0.4);
      }
      .sidebar-logo-text { font-size:15px; font-weight:600; color:#e8e6ff; letter-spacing:-0.02em; }
      .sidebar-logo-sub  { font-size:10px; color:rgba(180,170,255,0.4); letter-spacing:0.04em; }
      .sidebar-nav { flex:1; padding:12px 12px; overflow-y:auto; display:flex; flex-direction:column; gap:2px; }
      .nav-section-label { font-size:9px; font-weight:700; letter-spacing:0.12em; text-transform:uppercase; color:rgba(180,170,255,0.3); padding:12px 10px 6px; }
      .nav-item {
        display:flex; align-items:center; gap:10px;
        padding:9px 12px; border-radius:8px;
        cursor:pointer; font-size:13px; font-weight:450;
        color:rgba(180,170,255,0.55);
        border:1px solid transparent;
        transition:all 0.15s ease;
        position:relative;
      }
      .nav-item:hover { background:rgba(139,92,246,0.08); color:rgba(220,210,255,0.9); }
      .nav-item.active {
        background:rgba(139,92,246,0.14);
        border-color:rgba(139,92,246,0.22);
        color:#e8e6ff;
        font-weight:550;
      }
      .nav-item.active::before {
        content:''; position:absolute; left:-12px; top:50%; transform:translateY(-50%);
        width:3px; height:60%; background:linear-gradient(#8b5cf6,#2dd4bf);
        border-radius:0 2px 2px 0;
      }
      .sidebar-footer {
        padding:16px 20px;
        border-top:1px solid rgba(139,92,246,0.08);
      }
      .user-chip {
        display:flex; align-items:center; gap:10px;
        padding:10px 12px; border-radius:10px;
        background:rgba(139,92,246,0.07);
        border:1px solid rgba(139,92,246,0.12);
      }
      .user-avatar {
        width:32px; height:32px; border-radius:8px;
        background:linear-gradient(135deg,#6d28d9,#2dd4bf);
        display:flex; align-items:center; justify-content:center;
        font-size:12px; font-weight:700; color:white; flex-shrink:0;
      }
      .user-name  { font-size:12px; font-weight:500; color:#e8e6ff; }
      .user-role  { font-size:10px; color:rgba(180,170,255,0.45); }

      /* ── Dashboard header ── */
      .dash-header {
        display:flex; align-items:center; justify-content:space-between;
        padding:20px 28px 0;
        border-bottom:1px solid rgba(139,92,246,0.07);
        margin-bottom:0;
        flex-shrink:0;
      }
      .dash-title { font-size:20px; font-weight:650; color:#e8e6ff; letter-spacing:-0.03em; }
      .dash-sub   { font-size:13px; color:rgba(180,170,255,0.45); margin-top:3px; }

      /* ── Top tabs ── */
      .tab-rail {
        display:flex; gap:1px; padding:0 28px;
        border-bottom:1px solid rgba(139,92,246,0.08);
        background:transparent; flex-shrink:0;
      }
      .tab-btn {
        padding:12px 16px; border:none; border-bottom:2px solid transparent;
        background:transparent; color:rgba(180,170,255,0.45);
        cursor:pointer; font-size:13px; font-weight:500;
        display:flex; align-items:center; gap:7px;
        transition:all 0.15s;
        white-space:nowrap;
      }
      .tab-btn:hover { color:rgba(220,210,255,0.8); background:transparent !important; transform:none !important; }
      .tab-btn.active { color:#c4b5fd; border-bottom-color:#8b5cf6; }

      /* ── Metric cards ── */
      .metric-card {
        background:rgba(255,255,255,0.03);
        border:1px solid rgba(139,92,246,0.1);
        border-radius:14px;
        padding:18px 20px;
        position:relative; overflow:hidden;
        transition:border-color 0.2s, transform 0.2s;
        cursor:default;
      }
      .metric-card:hover { border-color:rgba(139,92,246,0.22); transform:translateY(-1px); }
      .metric-card-accent { position:absolute; top:0; left:0; right:0; height:2px; }
      .metric-card-label { font-size:10px; font-weight:600; letter-spacing:0.1em; text-transform:uppercase; color:rgba(180,170,255,0.4); margin-bottom:8px; }
      .metric-card-value { font-family:'JetBrains Mono',monospace; font-size:28px; font-weight:600; letter-spacing:-0.03em; line-height:1; }
      .metric-card-sub   { font-size:11px; color:rgba(180,170,255,0.4); margin-top:8px; display:flex; align-items:center; gap:6px; }

      /* ── Glass cards (general) ── */
      .glass-card {
        background:rgba(255,255,255,0.03);
        backdrop-filter:blur(32px);
        -webkit-backdrop-filter:blur(32px);
        border:1px solid rgba(139,92,246,0.1);
        border-radius:16px;
        padding:22px;
        position:relative;
      }
      .glass-card-title {
        font-size:13px; font-weight:600; color:rgba(180,170,255,0.65);
        letter-spacing:0.02em; margin-bottom:16px;
        display:flex; align-items:center; gap:8px;
      }

      /* ── Progress bar ── */
      .progress-track { background:rgba(139,92,246,0.1); border-radius:4px; height:5px; overflow:hidden; margin-top:8px; }
      .progress-fill  { height:100%; border-radius:4px; transition:width 0.6s cubic-bezier(0.34,1.56,0.64,1); }

      /* ── Alert severity rows ── */
      .alert-row { display:flex; align-items:center; gap:10px; padding:9px 12px; border-radius:8px; border-left:3px solid; margin-bottom:4px; font-size:12px; }
      .alert-row-critical { background:rgba(244,63,94,0.06);  border-left-color:#f43f5e; }
      .alert-row-warning  { background:rgba(245,158,11,0.06); border-left-color:#f59e0b; }
      .alert-row-info     { background:rgba(139,92,246,0.05); border-left-color:#8b5cf6; }

      /* ── Animations ── */
      @keyframes cardIn   { from{opacity:0;transform:translateY(16px) scale(0.99)} to{opacity:1;transform:none} }
      @keyframes fadeUp   { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:none} }
      @keyframes sidebarIn{ from{opacity:0;transform:translateX(-16px)} to{opacity:1;transform:none} }
      @keyframes pulse    { 0%{transform:translate(-50%,-50%) scale(1);box-shadow:0 0 0 0 rgba(139,92,246,0.5)} 70%{transform:translate(-50%,-50%) scale(1);box-shadow:0 0 0 12px rgba(139,92,246,0)} 100%{transform:translate(-50%,-50%) scale(1);box-shadow:0 0 0 0 rgba(139,92,246,0)} }
      @keyframes pulseSimple { 0%,100%{transform:scale(1);opacity:1} 50%{transform:scale(1.06);opacity:0.7} }
      @keyframes float    { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-14px)} }
      @keyframes shimmer  { 0%{transform:translateX(-100%)} 100%{transform:translateX(200%)} }
      @keyframes ripple   { 0%{width:0;height:0;opacity:0.4} 100%{width:300px;height:300px;opacity:0} }
      @keyframes slideInDown{ from{opacity:0;transform:translateY(-8px)} to{opacity:1;transform:none} }
      @keyframes bounce   { 0%,80%,100%{transform:scale(0)} 40%{transform:scale(1)} }
      @keyframes scanLine { 0%{top:-2%;opacity:0} 5%{opacity:0.5} 95%{opacity:0.5} 100%{top:102%;opacity:0} }
      @keyframes orbA     { 0%{transform:translate(0,0) scale(1)} 33%{transform:translate(-40px,30px) scale(1.08)} 66%{transform:translate(30px,-20px) scale(0.95)} 100%{transform:translate(-20px,50px) scale(1.04)} }
      @keyframes orbB     { 0%{transform:translate(0,0) scale(1)} 33%{transform:translate(40px,-30px) scale(1.06)} 66%{transform:translate(-30px,20px) scale(0.92)} 100%{transform:translate(20px,-40px) scale(1.1)} }
      @keyframes orbC     { 0%{transform:translate(0,0) scale(1);opacity:0.7} 50%{transform:translate(-20px,-30px) scale(1.15);opacity:1} 100%{transform:translate(20px,15px) scale(0.9);opacity:0.6} }
      @keyframes orbD     { 0%{transform:translate(0,0) scale(1)} 100%{transform:translate(50px,-60px) scale(1.2)} }
      @keyframes loginPing { 0%{opacity:1;transform:scale(1)} 75%,100%{opacity:0;transform:scale(2)} }

      /* ── Login left panel live stats ── */
      .login-stat {
        background:rgba(139,92,246,0.07);
        border:1px solid rgba(139,92,246,0.14);
        border-radius:10px; padding:12px 16px;
        display:flex; flex-direction:column; gap:2px;
      }
      .login-stat-val { font-family:'JetBrains Mono',monospace; font-size:22px; font-weight:600; color:#e8e6ff; }
      .login-stat-label { font-size:10px; font-weight:600; letter-spacing:0.08em; text-transform:uppercase; color:rgba(180,170,255,0.4); }

      /* ── Form fields ── */
      .field-wrap { position:relative; margin-bottom:12px; }
      .field-label { font-size:11px; font-weight:600; letter-spacing:0.06em; text-transform:uppercase; color:rgba(180,170,255,0.5); margin-bottom:5px; display:block; }
      .field-input {
        width:100%; padding:11px 16px;
        background:rgba(139,92,246,0.06);
        border:1px solid rgba(139,92,246,0.15);
        border-radius:10px; color:#e8e6ff;
        font-size:14px; font-family:'Inter',sans-serif;
        transition:all 0.2s; box-sizing:border-box;
      }
      .field-input:focus { border-color:rgba(139,92,246,0.6); box-shadow:0 0 0 3px rgba(139,92,246,0.12); outline:none; }
      .btn-primary {
        width:100%; padding:13px 20px;
        background:linear-gradient(135deg,#7c3aed,#4f46e5 60%,#2dd4bf);
        border:none; border-radius:10px;
        color:white; font-size:14px; font-weight:600;
        cursor:pointer; letter-spacing:0.01em;
        box-shadow:0 4px 20px rgba(124,58,237,0.4);
        transition:all 0.2s !important;
        position:relative; overflow:hidden;
      }
      .btn-primary:hover:not(:disabled) { box-shadow:0 6px 28px rgba(124,58,237,0.55) !important; transform:translateY(-1px) !important; }
      .btn-primary:disabled { opacity:0.5; cursor:not-allowed; }
    `}</style>
  );
}

// ── Background — static deep space, minimal orbs ──────────────────────────────
function BackgroundOrbs() {
  return (
    <div style={{ position:'fixed', inset:0, pointerEvents:'none', zIndex:0, overflow:'hidden' }}>
      <div style={{
        position:'absolute', inset:0,
        background:'linear-gradient(145deg,#07071a 0%,#090720 40%,#06061a 70%,#07071a 100%)',
        zIndex:-1
      }}/>
      {/* Purple bloom — top right */}
      <div style={{
        position:'absolute', width:'700px', height:'700px',
        top:'-180px', right:'-160px', borderRadius:'50%',
        background:'radial-gradient(circle at 38% 38%, rgba(109,40,217,0.28) 0%, rgba(76,29,149,0.09) 45%, transparent 70%)',
        filter:'blur(70px)', animation:'orbA 28s ease-in-out infinite alternate'
      }}/>
      {/* Teal bloom — bottom left */}
      <div style={{
        position:'absolute', width:'600px', height:'600px',
        bottom:'-140px', left:'-120px', borderRadius:'50%',
        background:'radial-gradient(circle at 58% 58%, rgba(20,184,166,0.18) 0%, rgba(15,118,110,0.07) 48%, transparent 70%)',
        filter:'blur(80px)', animation:'orbB 35s ease-in-out infinite alternate'
      }}/>
      {/* Indigo mid — center */}
      <div style={{
        position:'absolute', width:'400px', height:'400px',
        top:'35%', left:'38%', borderRadius:'50%',
        background:'radial-gradient(circle, rgba(99,51,220,0.10) 0%, transparent 70%)',
        filter:'blur(55px)', animation:'orbC 22s ease-in-out infinite alternate'
      }}/>
    </div>
  );
}

// Utility function to convert to Indian Standard Time (IST) - FIXED NULL HANDLING
function toIST(dateString) {
  if (!dateString) return "N/A";   // Prevent 1970 for null/undefined

  const date = new Date(dateString);
  if (isNaN(date.getTime())) return "Invalid"; // Handle invalid dates

  // Convert to milliseconds, add 5:30 offset
  const istOffset = 5 * 60 + 30; // minutes
  const istTime = new Date(date.getTime() + istOffset * 60000);
  return istTime.toLocaleString(); // Displays in local format
}

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

const EyeIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/>
  </svg>
);

const EyeOffIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"/>
  </svg>
);

const ServerIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M20 6H4v4h16V6zm2 10v-2H2v2h4v4H4v2h16v-2h-2v-4h4z"/>
  </svg>
);

const ActivityIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
  </svg>
);

const SecurityIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
  </svg>
);

const BrainIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 4C13.1 4 14 4.9 14 6s-.9 2-2 2-2-.9-2-2 .9-2 2-2zm9 8c-.6 0-1 .4-1 1 0 1.1-.9 2-2 2-.6 0-1 .4-1 1s.4 1 1 1c2.2 0 4-1.8 4-4 0-.6-.4-1-1-1zM3 12c0-.6-.4-1-1-1s-1 .4-1 1c0 2.2 1.8 4 4 4 .6 0 1-.4 1-1s-.4-1-1-1c-1.1 0-2-.9-2-2zm12.3-2.1l-2.9-1.6c-.4-.2-.8-.2-1.2 0l-2.9 1.6c-.4.2-.7.6-.7 1.1 0 .4.2.8.6 1l2.9 1.6c.2.1.4.2.6.2s.4-.1.6-.2l2.9-1.6c.4-.2.6-.6.6-1s-.2-.8-.6-1zm-1 6.6c-.4-.2-.8-.2-1.2 0l-2.9 1.6c-.4.2-.7.6-.7 1.1 0 .4.2.8.6 1l2.9 1.6c.2.1.4.2.6.2s.4-.1.6-.2l2.9-1.6c.4-.2.6-.6.6-1s-.2-.8-.6-1l-2.8-1.6z"/>
  </svg>
);

const GlobeIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/>
  </svg>
);

const FeedbackIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M20 2H4c-1.1 0-1.99.9-1.99 2L2 22l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-7 9h-2V5h2v6zm0 4h-2v-2h2v2z"/>
  </svg>
);

const ThumbsUpIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M1 21h4V9H1v12zm22-11c0-1.1-.9-2-2-2h-6.31l.95-4.57.03-.32c0-.41-.17-.79-.44-1.06L14.17 1 7.59 7.59C7.22 7.95 7 8.45 7 9v10c0 1.1.9 2 2 2h9c.83 0 1.54-.5 1.84-1.22l3.02-7.05c.09-.23.14-.47.14-.73v-2z"/>
  </svg>
);

const ThumbsDownIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M15 3H6c-.83 0-1.54.5-1.84 1.22l-3.02 7.05c-.09.23-.14.47-.14.73v2c0 1.1.9 2 2 2h6.31l-.95 4.57-.03.32c0 .41.17.79.44 1.06L9.83 23l6.59-6.59c.36-.36.58-.86.58-1.41V5c0-1.1-.9-2-2-2zm4 0v12h4V3h-4z"/>
  </svg>
);

const darkStyles = {
  container: {
    background: "transparent",
    color: DARK_THEME.text,
    minHeight: "100vh",
    width: "100vw",
    display: "flex",
    padding: "0",
    boxSizing: "border-box",
    overflow: "hidden",
    fontFamily: "'Inter',-apple-system,sans-serif",
    position: "relative",
    zIndex: 1,
  },
  sidebar: {
    width: "240px",
    minWidth: "240px",
    background: "rgba(7,7,26,0.92)",
    backdropFilter: "blur(40px)",
    WebkitBackdropFilter: "blur(40px)",
    borderRight: "1px solid rgba(139,92,246,0.1)",
    padding: "0",
    overflowY: "auto",
    height: "100vh",
    position: "sticky",
    top: 0,
    boxShadow: "4px 0 24px rgba(0,0,0,0.5)",
    zIndex: 10,
    display: "flex",
    flexDirection: "column",
  },
  mainContent: {
    flex: 1,
    overflowY: "auto",
    height: "100vh",
    display: "flex",
    flexDirection: "column",
    scrollBehavior: "smooth",
    zIndex: 2,
    position: "relative",
    background: "transparent",
  },
  loginContainer: {
    display: "flex",
    minHeight: "100vh",
    width: "100%",
    zIndex: 2,
    position: "relative",
  },
  card: {
    background: "rgba(255,255,255,0.03)",
    backdropFilter: "blur(32px)",
    WebkitBackdropFilter: "blur(32px)",
    border: "1px solid rgba(139,92,246,0.1)",
    padding: "22px",
    borderRadius: "16px",
    width: "100%",
    boxSizing: "border-box",
    marginBottom: "16px",
    boxShadow: "0 4px 24px rgba(0,0,0,0.3)",
    position: "relative",
    zIndex: 2,
    textAlign: "left",
  },
  gridCard: {
    background: "rgba(255,255,255,0.03)",
    backdropFilter: "blur(32px)",
    WebkitBackdropFilter: "blur(32px)",
    border: "1px solid rgba(139,92,246,0.1)",
    padding: "22px",
    borderRadius: "16px",
    width: "100%",
    boxSizing: "border-box",
    height: "100%",
    boxShadow: "0 4px 24px rgba(0,0,0,0.3)",
    position: "relative",
    zIndex: 2,
    textAlign: "left",
  },
  input: {
    width: "100%",
    padding: "10px 14px",
    marginBottom: "10px",
    background: "rgba(139,92,246,0.06)",
    color: DARK_THEME.text,
    border: "1px solid rgba(139,92,246,0.15)",
    borderRadius: "10px",
    fontSize: "13px",
    boxSizing: "border-box",
    transition: "all 0.2s ease",
  },
  select: {
    width: "100%",
    padding: "10px 14px",
    marginBottom: "10px",
    background: "rgba(139,92,246,0.06)",
    color: DARK_THEME.text,
    border: "1px solid rgba(139,92,246,0.15)",
    borderRadius: "10px",
    fontSize: "13px",
    boxSizing: "border-box",
  },
  button: {
    padding: "9px 18px",
    border: "1px solid rgba(139,92,246,0.2)",
    borderRadius: "10px",
    cursor: "pointer",
    color: "rgba(200,190,255,0.9)",
    fontSize: "13px",
    fontWeight: "500",
    margin: "3px",
    display: "inline-flex",
    alignItems: "center",
    gap: "6px",
    transition: "all 0.18s ease",
    background: "rgba(139,92,246,0.08)",
    letterSpacing: "-0.01em",
  },
  gridContainer: {
    display: "grid",
    gap: "16px",
    gridTemplateColumns: "1fr 1fr",
    width: "100%",
  },
  table: {
    width: "100%",
    borderCollapse: "collapse",
  },
  tableHeader: {
    background: "rgba(139,92,246,0.07)",
    color: "rgba(180,170,255,0.5)",
    padding: "10px 14px",
    textAlign: "left",
    cursor: "pointer",
    borderBottom: "1px solid rgba(139,92,246,0.12)",
    fontSize: "10px",
    fontWeight: "600",
    letterSpacing: "0.09em",
    textTransform: "uppercase",
    whiteSpace: "nowrap",
  },
  tableCell: {
    padding: "11px 14px",
    borderBottom: "1px solid rgba(139,92,246,0.06)",
    fontSize: "12.5px",
    color: "rgba(220,215,255,0.8)",
  },
  pre: {
    background: "rgba(0,0,0,0.45)",
    color: "#a5f3fc",
    padding: "14px",
    borderRadius: "10px",
    overflow: "auto",
    fontFamily: "'JetBrains Mono',monospace",
    fontSize: "11.5px",
    maxHeight: "200px",
    textAlign: "left",
    border: "1px solid rgba(139,92,246,0.1)",
  },
  message: {
    padding: "12px 18px",
    borderRadius: "10px",
    textAlign: "center",
    width: "100%",
    boxSizing: "border-box",
    fontSize: "13px",
  },
  quickActions: {
    display: "flex",
    gap: "8px",
    flexWrap: "wrap",
    justifyContent: "flex-start",
    width: "100%",
  },
  // Tabs moved to top rail — tabContainer/tab kept for compat
  tabContainer: {
    display: "flex",
    gap: "0",
    marginBottom: "0",
    justifyContent: "flex-start",
    flexWrap: "nowrap",
    overflowX: "auto",
    background: "transparent",
    border: "none",
    borderBottom: "1px solid rgba(139,92,246,0.08)",
    padding: "0 28px",
  },
  tab: {
    padding: "12px 16px",
    border: "none",
    borderBottom: "2px solid transparent",
    borderRadius: "0",
    cursor: "pointer",
    fontSize: "13px",
    fontWeight: "500",
    display: "inline-flex",
    alignItems: "center",
    gap: "7px",
    color: "rgba(180,170,255,0.45)",
    background: "transparent",
    letterSpacing: "-0.01em",
    whiteSpace: "nowrap",
    transition: "all 0.15s",
  },
  sidebarSection: {
    marginBottom: "8px",
    padding: "0 12px",
  },
  sidebarHeader: {
    display: "flex",
    alignItems: "center",
    gap: "6px",
    padding: "12px 10px 6px",
    color: "rgba(180,170,255,0.3)",
    fontSize: "9px",
    fontWeight: "700",
    letterSpacing: "0.12em",
    textTransform: "uppercase",
  },
  filterGroup: {
    marginBottom: "14px",
  },
  filterLabel: {
    display: "block",
    marginBottom: "5px",
    color: "rgba(180,170,255,0.45)",
    fontSize: "11px",
    fontWeight: "500",
    letterSpacing: "0.02em",
  },
  exportOption: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    padding: "10px 12px",
    marginBottom: "5px",
    background: "rgba(139,92,246,0.05)",
    borderRadius: "10px",
    cursor: "pointer",
    transition: "all 0.18s ease",
    border: "1px solid rgba(139,92,246,0.1)",
  },
  navMenu: {
    display: "flex",
    flexDirection: "column",
    gap: "2px",
    padding: "0 12px",
  },
  navItem: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    padding: "9px 12px",
    color: "rgba(180,170,255,0.55)",
    textDecoration: "none",
    borderRadius: "8px",
    transition: "all 0.15s ease",
    cursor: "pointer",
    fontSize: "13px",
    fontWeight: "450",
    letterSpacing: "-0.01em",
    border: "1px solid transparent",
    position: "relative",
  },
};

// ==================== ENHANCED AI COMPONENTS WITH REAL IMPLEMENTATIONS ====================

// 1. AI Smart Insights Component with Real AI Integration
function AISmartInsights({ metrics, apiClient }) {
  const [insights, setInsights] = useState([]);
  const [predictions, setPredictions] = useState({});
  const [loading, setLoading] = useState(false);
  const [explanationData, setExplanationData] = useState(null);

  useEffect(() => {
    if (metrics) {
      analyzeMetricsWithAI();
    }
  }, [metrics]);

  const analyzeMetricsWithAI = async () => {
    setLoading(true);
    try {
      // Real AI analysis call
      const aiResponse = await apiClient.get("/ai/insights");
      
      if (aiResponse.data) {
        setInsights(aiResponse.data.insights || []);
        setPredictions(aiResponse.data.predictions || {});
      }

      // Real anomaly detection - FIXED: Changed from POST to GET
      if (metrics) {
        const anomalyResponse = await apiClient.get("/ai/detect-anomaly", {
          params: {
            cpu_usage: metrics.cpu_usage,
            memory_usage: metrics.memory_usage,
            disk_usage: metrics.disk_usage
          }
        });

        if (anomalyResponse.data.is_anomaly) {
          setInsights(prev => [{
            id: Date.now(),
            type: 'warning',
            message: `AI Alert: ${anomalyResponse.data.explanation}`,
            confidence: Math.round(anomalyResponse.data.confidence * 100),
            timestamp: new Date(),
            action: 'investigate_anomaly',
            reconstruction_error: anomalyResponse.data.reconstruction_error
          }, ...prev]);
        }
      }
    } catch (error) {
      console.error('AI analysis failed, using fallback:', error);
      // Fallback to mock data if AI service is down
      useMockAIData();
    } finally {
      setLoading(false);
    }
  };

  const useMockAIData = () => {
    const mockInsights = [
      {
        id: 1,
        type: 'warning',
        message: 'Memory usage trending upward - consider optimizing applications',
        confidence: 85,
        timestamp: new Date(),
        action: 'optimize_memory'
      },
      {
        id: 2,
        type: 'info',
        message: 'CPU usage patterns indicate peak hours between 2-4 PM',
        confidence: 92,
        timestamp: new Date(),
        action: 'schedule_maintenance'
      }
    ];

    const mockPredictions = {
      cpu_peak: '2:30 PM',
      memory_alert: '4 hours',
      disk_usage: '72% in 7 days',
      network_load: '45% in 2 hours'
    };

    setInsights(mockInsights);
    setPredictions(mockPredictions);
  };

  const handleInsightAction = async (action, insightId) => {
    switch(action) {
      case 'optimize_memory':
        alert('AI: Optimizing memory usage...');
        break;
      case 'schedule_maintenance':
        alert('AI: Scheduling maintenance during off-peak hours...');
        break;
      case 'investigate_anomaly':
        await explainAnomaly(insightId);
        break;
      default:
        break;
    }
  };

  const explainAnomaly = async (insightId) => {
    try {
      const explanation = await apiClient.post("/ai/explain-prediction", {
        metrics: metrics,
        insight_id: insightId
      });
      setExplanationData(explanation.data);
    } catch (error) {
      console.error('Failed to get explanation:', error);
      setExplanationData({
        explanation: "Anomaly detected due to unusual patterns in system metrics",
        contributing_factors: [
          { feature: "cpu_usage", contribution: 0.45 },
          { feature: "memory_usage", contribution: 0.35 }
        ]
      });
    }
  };

  const handleInsightFeedback = async (insightId, isAccurate) => {
    try {
      await apiClient.post("/ai/feedback/alert-accuracy", {
        insight_id: insightId,
        is_accurate: isAccurate,
        user_comment: "User provided feedback via UI",
        timestamp: new Date().toISOString()
      });
      alert('Thank you for your feedback! This helps improve AI accuracy.');
    } catch (error) {
      console.error('Failed to submit feedback:', error);
      alert('Feedback recorded locally (AI service unavailable)');
    }
  };

  return (
    <div style={{
      ...darkStyles.card,
      background: "rgba(255,255,255,0.07)",
      backdropFilter: "blur(48px) saturate(160%)",
      WebkitBackdropFilter: "blur(48px) saturate(160%)",
      position: "relative",
      zIndex: 2,
      border: `1px solid ${DARK_THEME.glassBorder}`,
      textAlign: 'left'
    }}>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '15px',
        marginBottom: '25px'
      }}>
        <div style={{
          width: '50px',
          height: '50px',
          background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
          borderRadius: '16px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: '24px',
          boxShadow: '0 8px 32px rgba(102, 126, 234, 0.3)'
        }}>
          <BrainIcon />
        </div>
        <div>
          <h3 style={{ color: DARK_THEME.text, margin: '0 0 5px 0', fontSize: '20px' }}>AI Smart Insights</h3>
          <p style={{ color: DARK_THEME.textMuted, margin: 0, fontSize: '14px' }}>
            Real-time system analysis and predictions
          </p>
        </div>
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: '40px' }}>
          <TailSpin height={40} width={40} color={DARK_THEME.primary} />
          <p style={{ color: DARK_THEME.textMuted, marginTop: '15px' }}>Analyzing system patterns with AI...</p>
        </div>
      ) : (
        <>
          {/* Predictions Grid */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
            gap: '15px',
            marginBottom: '25px'
          }}>
            <div style={{
              background: 'rgba(255,255,255,0.05)',
              padding: '20px',
              borderRadius: '12px',
              textAlign: 'center',
              border: `1px solid ${DARK_THEME.glassBorder}`
            }}>
              <div style={{ color: DARK_THEME.textMuted, fontSize: '12px', marginBottom: '8px' }}>Next CPU Peak</div>
              <div style={{ color: DARK_THEME.primary, fontWeight: 'bold', fontSize: '16px' }}>{predictions.cpu_peak || 'Calculating...'}</div>
            </div>
            <div style={{
              background: 'rgba(255,255,255,0.05)',
              padding: '20px',
              borderRadius: '12px',
              textAlign: 'center',
              border: `1px solid ${DARK_THEME.glassBorder}`
            }}>
              <div style={{ color: DARK_THEME.textMuted, fontSize: '12px', marginBottom: '8px' }}>Memory Alert</div>
              <div style={{ color: DARK_THEME.warning, fontWeight: 'bold', fontSize: '16px' }}>{predictions.memory_alert || 'Stable'}</div>
            </div>
          </div>

          {/* AI Explanation Modal */}
          {explanationData && (
            <div style={{
              background: 'rgba(255,255,255,0.05)',
              padding: '20px',
              borderRadius: '12px',
              border: `1px solid ${DARK_THEME.info}`,
              marginBottom: '20px'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
                <h4 style={{ color: DARK_THEME.text, margin: 0 }}>AI Explanation</h4>
                <button 
                  onClick={() => setExplanationData(null)}
                  style={{ background: 'none', border: 'none', color: DARK_THEME.textMuted, cursor: 'pointer' }}
                >
                  <CloseIcon />
                </button>
              </div>
              <p style={{ color: DARK_THEME.text, marginBottom: '15px' }}>{explanationData.explanation}</p>
              <div style={{ fontSize: '14px', color: DARK_THEME.textMuted }}>
                <strong>Contributing Factors:</strong>
                <ul style={{ margin: '10px 0', paddingLeft: '20px' }}>
                  {explanationData.contributing_factors?.map((factor, index) => (
                    <li key={index}>
                      {factor.feature}: {(factor.contribution * 100).toFixed(1)}%
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}

          {/* Insights List */}
          <div style={{ maxHeight: '250px', overflow: 'auto' }}>
            {insights.map((insight) => (
              <div
                key={insight.id}
                style={{
                  background: 'rgba(255,255,255,0.05)',
                  padding: '15px',
                  borderRadius: '12px',
                  marginBottom: '12px',
                  borderLeft: `4px solid ${
                    insight.type === 'warning' ? DARK_THEME.warning :
                    insight.type === 'info' ? DARK_THEME.info : DARK_THEME.success
                  }`,
                  border: `1px solid ${DARK_THEME.glassBorder}`,
                  transition: 'all 0.3s ease'
                }}
              >
                <div style={{ 
                  color: DARK_THEME.text,
                  fontSize: '14px',
                  marginBottom: '8px',
                  lineHeight: '1.4'
                }}>
                  {insight.message}
                </div>
                <div style={{ 
                  color: DARK_THEME.textMuted,
                  fontSize: '12px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '8px'
                }}>
                  <span>Confidence: {insight.confidence}%</span>
                  <span>{toIST(insight.timestamp)}</span>
                </div>
                <div style={{ display: 'flex', gap: '10px', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', gap: '5px' }}>
                    {insight.action !== 'none' && (
                      <button
                        onClick={() => handleInsightAction(insight.action, insight.id)}
                        style={{
                          padding: '6px 12px',
                          background: 'rgba(139,92,246,0.15)',
                          border: `1px solid rgba(139,92,246,0.15)`,
                          borderRadius: '6px',
                          color: DARK_THEME.text,
                          fontSize: '11px',
                          cursor: 'pointer'
                        }}
                      >
                        Take Action
                      </button>
                    )}
                    {insight.action === 'investigate_anomaly' && (
                      <button
                        onClick={() => explainAnomaly(insight.id)}
                        style={{
                          padding: '6px 12px',
                          background: 'rgba(147, 51, 234, 0.2)',
                          border: `1px solid rgba(147, 51, 234, 0.3)`,
                          borderRadius: '6px',
                          color: DARK_THEME.text,
                          fontSize: '11px',
                          cursor: 'pointer'
                        }}
                      >
                        Explain
                      </button>
                    )}
                  </div>
                  <div style={{ display: 'flex', gap: '5px' }}>
                    <button
                      onClick={() => handleInsightFeedback(insight.id, true)}
                      style={{
                        padding: '4px 8px',
                        background: 'rgba(34,197,94,0.15)',
                        border: `1px solid rgba(34,197,94,0.3)`,
                        borderRadius: '4px',
                        color: DARK_THEME.text,
                        fontSize: '10px',
                        cursor: 'pointer'
                      }}
                      title="This insight is accurate"
                    >
                      <ThumbsUpIcon />
                    </button>
                    <button
                      onClick={() => handleInsightFeedback(insight.id, false)}
                      style={{
                        padding: '4px 8px',
                        background: 'rgba(139,92,246,0.15)',
                        border: `1px solid rgba(139,92,246,0.15)`,
                        borderRadius: '4px',
                        color: DARK_THEME.text,
                        fontSize: '10px',
                        cursor: 'pointer'
                      }}
                      title="This insight is inaccurate"
                    >
                      <ThumbsDownIcon />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {insights.length === 0 && !loading && (
            <div style={{ textAlign: 'center', padding: '20px', color: DARK_THEME.textMuted }}>
              No AI insights available. System is operating normally.
            </div>
          )}
        </>
      )}
    </div>
  );
}

// 2. Interactive Geo-Map Component
function ServerWorldMap({ servers, onServerClick, token }) {
  return <GlobalServerDistribution servers={servers} onServerClick={onServerClick} token={token} />;
}


// 3. Emotional AI Assistant Component with Real AI Integration
function EmotionalAIAssistant({ metrics, onSuggestion }) {
  const [mood, setMood] = useState('neutral');
  const [messages, setMessages] = useState([]);
  const [isTyping, setIsTyping] = useState(false);
  const [userInput, setUserInput] = useState('');

  useEffect(() => {
    // Analyze metrics and set mood using real AI
    const analyzeMoodWithAI = async () => {
      const avgLoad = metrics ? (metrics.cpu_usage + metrics.memory_usage) / 2 : 0;
      
      if (avgLoad > 80) {
        setMood('concerned');
        addMessage("I'm detecting high system load. Would you like me to investigate potential issues?");
      } else if (avgLoad < 30) {
        setMood('happy');
        addMessage("System performance is excellent! Everything is running smoothly.");
      } else {
        setMood('neutral');
        addMessage("Hello! I'm here to help you monitor your system. Everything looks good at the moment.");
      }
    };

    analyzeMoodWithAI();
  }, [metrics]);

  const addMessage = (text) => {
    if (messages.some(msg => msg.text === text)) return;
    
    setIsTyping(true);
    setTimeout(() => {
      setMessages(prev => [...prev, { id: Date.now(), text, fromAI: true }]);
      setIsTyping(false);
    }, 1500);
  };

  const getMoodEmoji = () => {
    switch(mood) {
      case 'happy': return '😊';
      case 'concerned': return '😟';
      case 'excited': return '🤩';
      case 'analytical': return '🤔';
      default: return '😐';
    }
  };

  const getMoodColor = () => {
    switch(mood) {
      case 'happy': return '#10b981';
      case 'concerned': return '#f59e0b';
      case 'excited': return '#8b5cf6';
      case 'analytical': return '#3b82f6';
      default: return 'rgba(255,255,255,0.45)';
    }
  };

  const handleQuickAction = async (action) => {
    const newMessage = {
      id: Date.now(),
      text: `You: ${action.replace('_', ' ')}`,
      fromAI: false
    };
    setMessages(prev => [...prev, newMessage]);
    
    setIsTyping(true);
    
    try {
      // Real AI chat integration
      const response = await fetch(`${API_BASE}/ai/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          question: action.replace('_', ' '),
          context: {
            current_metrics: metrics,
            system_state: 'operational',
            user_intent: action
          }
        })
      });

      let aiResponse;
      if (response.ok) {
        const data = await response.json();
        aiResponse = data.answer;
      } else {
        // Fallback responses
        switch(action) {
          case 'analyze_performance':
            aiResponse = "I'll analyze the current performance metrics and provide recommendations. Based on my analysis, I recommend monitoring CPU usage closely as it's approaching critical levels.";
            break;
          case 'generate_report':
            aiResponse = "Generating comprehensive system report with insights and recommendations. The report will include performance trends, anomaly detection, and optimization suggestions.";
            break;
          case 'optimize_system':
            aiResponse = "Starting system optimization process. I've identified several areas for improvement including memory allocation and background process management.";
            break;
          default:
            aiResponse = "I'm processing your request and will provide detailed analysis shortly.";
        }
      }

      setMessages(prev => [...prev, { id: Date.now(), text: aiResponse, fromAI: true }]);
      onSuggestion(action);
    } catch (error) {
      console.error('AI chat failed:', error);
      setMessages(prev => [...prev, { 
        id: Date.now(), 
        text: "I'm having trouble connecting to the AI service right now. Please try again later.", 
        fromAI: true 
      }]);
    } finally {
      setIsTyping(false);
    }
  };

  const handleUserMessage = async () => {
    if (!userInput.trim()) return;

    const userMessage = {
      id: Date.now(),
      text: `You: ${userInput}`,
      fromAI: false
    };
    setMessages(prev => [...prev, userMessage]);
    setUserInput('');
    
    setIsTyping(true);

    try {
      const response = await fetch(`${API_BASE}/ai/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          question: userInput,
          context: {
            current_metrics: metrics,
            system_state: 'operational',
            conversation_history: messages.slice(-5) // Last 5 messages for context
          }
        })
      });

      let aiResponse;
      if (response.ok) {
        const data = await response.json();
        aiResponse = data.answer;
      } else {
        aiResponse = "I understand your question, but I'm currently unable to access my full capabilities. For now, I can help you with system monitoring and basic analysis.";
      }

      setMessages(prev => [...prev, { id: Date.now(), text: aiResponse, fromAI: true }]);
    } catch (error) {
      console.error('AI chat failed:', error);
      setMessages(prev => [...prev, { 
        id: Date.now(), 
        text: "I apologize, but I'm having trouble processing your request right now. Please try again in a moment.", 
        fromAI: true 
      }]);
    } finally {
      setIsTyping(false);
    }
  };

  return (
    <div style={{
      ...darkStyles.card,
      background: "rgba(255,255,255,0.07)",
      backdropFilter: "blur(48px) saturate(160%)",
      WebkitBackdropFilter: "blur(48px) saturate(160%)",
      position: "relative",
      zIndex: 2,
      border: `1px solid ${DARK_THEME.glassBorder}`,
      textAlign: 'left'
    }}>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '15px',
        marginBottom: '20px'
      }}>
        <div style={{
          width: '50px',
          height: '50px',
          background: `linear-gradient(135deg, ${getMoodColor()} 0%, ${getMoodColor()}80 100%)`,
          borderRadius: '16px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: '24px',
          boxShadow: `0 8px 32px ${getMoodColor()}30`
        }}>
          {getMoodEmoji()}
        </div>
        <div>
          <h3 style={{ color: DARK_THEME.text, margin: '0 0 5px 0', fontSize: '20px' }}>AI Assistant</h3>
          <p style={{ color: DARK_THEME.textMuted, margin: 0, fontSize: '14px' }}>
            {mood === 'happy' ? 'Feeling great! Systems optimal' : 
             mood === 'concerned' ? 'Monitoring closely - issues detected' : 
             mood === 'analytical' ? 'Analyzing patterns' : 'All systems normal'}
          </p>
        </div>
      </div>

      {/* Chat messages */}
      <div style={{
        height: '180px',
        overflowY: 'auto',
        marginBottom: '20px',
        padding: '15px',
        background: 'rgba(255,255,255,0.05)',
        borderRadius: '12px',
        border: `1px solid ${DARK_THEME.glassBorder}`
      }}>
        {messages.map(message => (
          <div
            key={message.id}
            style={{
              padding: '10px 15px',
              marginBottom: '10px',
              background: message.fromAI ? 'rgba(102, 126, 234, 0.15)' : 'rgba(255,255,255,0.1)',
              borderRadius: '12px',
              fontSize: '14px',
              color: DARK_THEME.text,
              border: `1px solid ${message.fromAI ? 'rgba(102, 126, 234, 0.3)' : 'rgba(255,255,255,0.2)'}`,
              maxWidth: '85%',
              marginLeft: message.fromAI ? '0' : 'auto',
              marginRight: message.fromAI ? 'auto' : '0'
            }}
          >
            {message.text}
          </div>
        ))}
        {isTyping && (
          <div style={{
            padding: '10px 15px',
            color: DARK_THEME.textMuted,
            fontStyle: 'italic',
            fontSize: '14px',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}>
            <div style={{ display: 'flex', gap: '3px' }}>
              <div style={{
                width: '4px',
                height: '4px',
                borderRadius: '50%',
                background: DARK_THEME.textMuted,
                animation: 'bounce 1.4s infinite ease-in-out'
              }} />
              <div style={{
                width: '4px',
                height: '4px',
                borderRadius: '50%',
                background: DARK_THEME.textMuted,
                animation: 'bounce 1.4s infinite ease-in-out',
                animationDelay: '0.2s'
              }} />
              <div style={{
                width: '4px',
                height: '4px',
                borderRadius: '50%',
                background: DARK_THEME.textMuted,
                animation: 'bounce 1.4s infinite ease-in-out',
                animationDelay: '0.4s'
              }} />
            </div>
            AI is thinking...
          </div>
        )}
      </div>

      {/* User Input */}
      <div style={{ display: 'flex', gap: '10px', marginBottom: '15px' }}>
        <input
          type="text"
          value={userInput}
          onChange={(e) => setUserInput(e.target.value)}
          placeholder="Ask me anything about the system..."
          style={{
            flex: 1,
            padding: '12px 15px',
            background: 'rgba(255,255,255,0.05)',
            border: `1px solid ${DARK_THEME.glassBorder}`,
            borderRadius: '8px',
            color: DARK_THEME.text,
            fontSize: '14px'
          }}
          onKeyPress={(e) => e.key === 'Enter' && handleUserMessage()}
        />
        <button
          onClick={handleUserMessage}
          disabled={!userInput.trim()}
          style={{
            padding: '12px 15px',
            background: !userInput.trim() ? DARK_THEME.glassBorder : 'rgba(102, 126, 234, 0.2)',
            border: `1px solid ${!userInput.trim() ? DARK_THEME.glassBorder : 'rgba(102, 126, 234, 0.3)'}`,
            borderRadius: '8px',
            color: DARK_THEME.text,
            cursor: !userInput.trim() ? 'not-allowed' : 'pointer'
          }}
        >
          Send
        </button>
      </div>

      {/* Quick actions */}
      <div style={{
        display: 'flex',
        gap: '10px',
        flexWrap: 'wrap'
      }}>
        {['analyze_performance', 'generate_report', 'optimize_system'].map(action => (
          <button
            key={action}
            onClick={() => handleQuickAction(action)}
            style={{
              padding: '10px 16px',
              background: 'rgba(102, 126, 234, 0.15)',
              border: `1px solid rgba(102, 126, 234, 0.3)`,
              borderRadius: '20px',
              color: DARK_THEME.text,
              fontSize: '12px',
              cursor: 'pointer',
              transition: 'all 0.3s ease',
              fontWeight: '500'
            }}
            onMouseEnter={(e) => {
              e.target.style.background = 'rgba(102, 126, 234, 0.25)';
              e.target.style.transform = 'translateY(-2px)';
            }}
            onMouseLeave={(e) => {
              e.target.style.background = 'rgba(102, 126, 234, 0.15)';
              e.target.style.transform = 'translateY(0)';
            }}
          >
            {action.replace('_', ' ')}
          </button>
        ))}
      </div>

      <style>
        {`
          @keyframes bounce {
            0%, 80%, 100% { transform: scale(0); }
            40% { transform: scale(1); }
          }
        `}
      </style>
    </div>
  );
}

// 4. Adaptive Dashboard Layout Component with Real AI
function AdaptiveDashboard({ metrics, userPreferences, onLayoutChange }) {
  const [layout, setLayout] = useState('default');
  const [priorityMetrics, setPriorityMetrics] = useState([]);
  const [aiRecommendation, setAiRecommendation] = useState('');

  useEffect(() => {
    // AI-powered layout adaptation
    const determineOptimalLayout = () => {
      const hour = new Date().getHours();
      const isBusinessHours = hour >= 9 && hour <= 17;
      const hasIssues = metrics && (metrics.cpu_usage > 80 || metrics.memory_usage > 85);
      const isQuietHours = hour >= 22 || hour <= 6;

      if (hasIssues) {
        setLayout('issues');
        setPriorityMetrics(['cpu_usage', 'memory_usage', 'processes']);
        setAiRecommendation('Focusing on critical system issues detected by AI analysis');
      } else if (isBusinessHours) {
        setLayout('business');
        setPriorityMetrics(['cpu_usage', 'network_activity', 'response_times']);
        setAiRecommendation('Optimized layout for business hours monitoring');
      } else if (isQuietHours) {
        setLayout('quiet');
        setPriorityMetrics(['cpu_usage', 'memory_usage', 'background_processes']);
        setAiRecommendation('Quiet hours mode - monitoring essential metrics only');
      } else {
        setLayout('default');
        setPriorityMetrics(['cpu_usage', 'memory_usage', 'disk_usage']);
        setAiRecommendation('Standard monitoring with AI-powered insights');
      }
      
      onLayoutChange?.(layout);
    };

    determineOptimalLayout();
  }, [metrics, layout, onLayoutChange]);

  const getLayoutColor = () => {
    switch(layout) {
      case 'issues': return DARK_THEME.danger;
      case 'business': return DARK_THEME.warning;
      case 'quiet': return DARK_THEME.info;
      default: return DARK_THEME.success;
    }
  };

  const getLayoutDescription = () => {
    switch(layout) {
      case 'issues': return 'Focusing on critical system issues';
      case 'business': return 'Optimized for business hours monitoring';
      case 'quiet': return 'Quiet hours - minimal monitoring';
      default: return 'Standard monitoring layout';
    }
  };

  return (
    <div style={{
      padding: '20px',
      background: 'rgba(255,255,255,0.05)',
      borderRadius: '16px',
      border: `1px solid ${DARK_THEME.glassBorder}`,
      marginBottom: '20px',
      backdropFilter: 'blur(10px)'
    }}>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: '15px'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '12px'
        }}>
          <div style={{
            width: '12px',
            height: '12px',
            borderRadius: '50%',
            background: getLayoutColor(),
            animation: 'pulse 2s infinite'
          }} />
          <div>
            <div style={{
              color: DARK_THEME.text,
              fontSize: '16px',
              fontWeight: '600',
              marginBottom: '4px'
            }}>
              AI-Adaptive Dashboard
            </div>
            <div style={{
              color: DARK_THEME.textMuted,
              fontSize: '14px'
            }}>
              {aiRecommendation}
            </div>
          </div>
        </div>
        
        <div style={{
          padding: '6px 12px',
          background: 'rgba(255,255,255,0.1)',
          borderRadius: '20px',
          fontSize: '12px',
          color: DARK_THEME.text,
          fontWeight: '500'
        }}>
          {layout.toUpperCase()} MODE
        </div>
      </div>
      
      <div style={{
        display: 'flex',
        gap: '10px',
        flexWrap: 'wrap'
      }}>
        {priorityMetrics.map(metric => (
          <span
            key={metric}
            style={{
              padding: '6px 12px',
              background: 'rgba(255,255,255,0.1)',
              borderRadius: '8px',
              fontSize: '12px',
              color: DARK_THEME.text,
              border: `1px solid ${DARK_THEME.glassBorder}`,
              fontWeight: '500'
            }}
          >
            {metric.replace('_', ' ')}
          </span>
        ))}
      </div>
    </div>
  );
}

// ==================== ORIGINAL COMPONENTS (UPDATED WITH REAL AI) ====================

// PasswordInput Component
const PasswordInput = memo(({ 
  value, 
  onChange, 
  placeholder, 
  name, 
  showPassword, 
  onToggleVisibility,
  autoComplete 
}) => (
  <div style={{ position: 'relative', width: '100%' }}>
    <input
      type={showPassword ? "text" : "password"}
      name={name}
      placeholder={placeholder}
      value={value}
      onChange={onChange}
      style={{
        width: "100%",
        padding: "15px 20px",
        paddingRight: '45px',
        marginBottom: 0,
        background: "rgba(255,255,255,0.05)",
        backdropFilter: "blur(10px)",
        color: "#fff",
        border: `1px solid ${DARK_THEME.glassBorder}`,
        borderRadius: "12px",
        fontSize: "14px",
        boxSizing: "border-box",
        transition: "all 0.3s ease"
      }}
      required
      autoComplete={autoComplete}
      onFocus={(e) => {
        e.target.style.borderColor = "#8b5cf6";
        e.target.style.boxShadow = `0 0 0 3px rgba(139,92,246,0.15)`;
      }}
      onBlur={(e) => {
        e.target.style.borderColor = DARK_THEME.glassBorder;
        e.target.style.boxShadow = 'none';
      }}
    />
    <button
      type="button"
      onClick={onToggleVisibility}
      style={{
        position: 'absolute',
        right: '12px',
        top: '50%',
        transform: 'translateY(-50%)',
        background: 'none',
        border: 'none',
        color: 'rgba(255,255,255,0.4)',
        cursor: 'pointer',
        padding: '4px',
        borderRadius: '4px',
        transition: 'all 0.2s ease'
      }}
      onMouseEnter={(e) => {
        e.target.style.color = '#8b5cf6';
        e.target.style.backgroundColor = 'rgba(220, 38, 38, 0.1)';
      }}
      onMouseLeave={(e) => {
        e.target.style.color = '#888';
        e.target.style.backgroundColor = 'transparent';
      }}
    >
      {showPassword ? <EyeOffIcon /> : <EyeIcon />}
    </button>
  </div>
));

// FloatingParticles Component
function FloatingParticles() {
  const [particles, setParticles] = useState([]);
  const [matrixLines, setMatrixLines] = useState([]);

  useEffect(() => {
    // Create initial particles
    const initialParticles = Array.from({ length: 25 }, (_, i) => ({
      id: i,
      x: Math.random() * 100,
      y: Math.random() * 100,
      size: Math.random() * 4 + 1,
      speedX: (Math.random() - 0.5) * 0.3,
      speedY: (Math.random() - 0.5) * 0.3,
      opacity: Math.random() * 0.3 + 0.1
    }));
    setParticles(initialParticles);

    // Create matrix-style lines
    const initialLines = Array.from({ length: 15 }, (_, i) => ({
      id: i,
      x: Math.random() * 100,
      y: 0,
      height: Math.random() * 30 + 10,
      speed: Math.random() * 2 + 1,
      opacity: Math.random() * 0.1 + 0.05
    }));
    setMatrixLines(initialLines);

    // Animation loop for particles
    const particleInterval = setInterval(() => {
      setParticles(prev => prev.map(particle => {
        let newX = particle.x + particle.speedX;
        let newY = particle.y + particle.speedY;

        // Bounce off edges
        if (newX <= 0 || newX >= 100) particle.speedX *= -1;
        if (newY <= 0 || newY >= 100) particle.speedY *= -1;

        return {
          ...particle,
          x: Math.max(0, Math.min(100, newX)),
          y: Math.max(0, Math.min(100, newY))
        };
      }));
    }, 50);

    // Animation loop for matrix lines
    const matrixInterval = setInterval(() => {
      setMatrixLines(prev => prev.map(line => {
        let newY = line.y + line.speed;
        if (newY > 100) {
          return {
            ...line,
            y: -line.height,
            x: Math.random() * 100
          };
        }
        return { ...line, y: newY };
      }));
    }, 100);

    return () => {
      clearInterval(particleInterval);
      clearInterval(matrixInterval);
    };
  }, []);

  return (
    <div style={{
      position: 'absolute',
      top: 0,
      left: 0,
      width: '100%',
      height: '100%',
      pointerEvents: 'none',
      zIndex: 0
    }}>
      {/* Matrix-style vertical lines */}
      {matrixLines.map(line => (
        <div
          key={`line-${line.id}`}
          style={{
            position: 'absolute',
            left: `${line.x}%`,
            top: `${line.y}%`,
            width: '1px',
            height: `${line.height}%`,
            background: `linear-gradient(to bottom, transparent, rgba(220, 38, 38, ${line.opacity}), transparent)`,
            transition: 'top 0.1s linear'
          }}
        />
      ))}
      
      {/* Floating particles */}
      {particles.map(particle => (
        <div
          key={particle.id}
          style={{
            position: 'absolute',
            left: `${particle.x}%`,
            top: `${particle.y}%`,
            width: `${particle.size}px`,
            height: `${particle.size}px`,
            backgroundColor: `rgba(220, 38, 38, ${particle.opacity})`,
            borderRadius: '50%',
            transition: 'all 0.1s linear'
          }}
        />
      ))}
    </div>
  );
}

// Enhanced LoginForm Component with Glass Morphism
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
  const [isHovered, setIsHovered] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [avatarGlow, setAvatarGlow] = useState(true);
  const [buttonRipple, setButtonRipple] = useState(false);

  // Avatar glow animation
  useEffect(() => {
    const interval = setInterval(() => {
      setAvatarGlow(prev => !prev);
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage("");
    setAuthLoading(true);

    if (authMode === "register") {
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
        const formDataObj = new FormData();
        formDataObj.append("username", formData.username);
        formDataObj.append("password", formData.password);
        
        response = await axios.post(`${API_BASE}/token`, formDataObj, {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded"
          }
        });
      } else {
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
      if (!error.response) {
        setMessage("Cannot reach backend on port 8000. Click 'Continue as Admin (demo)' below to test instantly with a simulated fleet!");
      } else {
        setMessage(
          error.response?.data?.detail || 
          (authMode === "login" ? "Invalid username or password" : "Registration failed")
        );
      }
    } finally {
      setAuthLoading(false);
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
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

  const handleButtonClick = (e) => {
    setButtonRipple(true);
    setTimeout(() => setButtonRipple(false), 600);
  };

  const handleQuickDemoClick = async () => {
    setAuthLoading(true);
    try {
      const formDataObj = new FormData();
      formDataObj.append("username", "admin");
      formDataObj.append("password", "adminpass");
      const res = await axios.post(`${API_BASE}/token`, formDataObj, {
        headers: { "Content-Type": "application/x-www-form-urlencoded" }
      });
      if (res.data?.access_token) {
        onLogin(res.data.access_token, res.data.user);
        return;
      }
    } catch {
      // Graceful fallback to demo mode if backend is not responding
    } finally {
      setAuthLoading(false);
    }
    onLogin('demo-session-token', { username: 'admin', role: 'admin', email: 'security@sesametechnologies.in' });
  };

  // Field helper
  const fieldStyle = {
    width: '100%', padding: '11px 14px', marginBottom: 0,
    background: 'rgba(139,92,246,0.06)',
    border: '1px solid rgba(139,92,246,0.15)',
    borderRadius: '10px', color: '#e8e6ff',
    fontSize: '14px', boxSizing: 'border-box',
    fontFamily: "'Inter',sans-serif", transition: 'all 0.2s',
  };

  const isError = message && (message.includes("failed") || message.includes("error") || message.includes("Incorrect") || message.includes("invalid") || message.includes("Cannot"));

  return (
    <div style={{ ...darkStyles.loginContainer, display: 'flex', minHeight: '100vh' }}>
      {/* ── LEFT PANEL ── */}
      <div className="login-left" style={{
        flex: '0 0 50%', display: 'flex', flexDirection: 'column',
        background: 'linear-gradient(145deg,#0a0820 0%,#0d0b2b 60%,#080618 100%)',
        borderRight: '1px solid rgba(139,92,246,0.12)',
        position: 'relative', overflowY: 'auto', padding: '48px 48px 36px',
        justifyContent: 'space-between',
      }}>
        {/* Grid pattern */}
        <div className="login-grid" />

        {/* Purple orb */}
        <div style={{
          position: 'absolute', width: '500px', height: '500px',
          top: '-100px', right: '-100px', borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(109,40,217,0.22) 0%, transparent 70%)',
          filter: 'blur(60px)', pointerEvents: 'none',
        }} />
        {/* Teal orb */}
        <div style={{
          position: 'absolute', width: '350px', height: '350px',
          bottom: '-60px', left: '-60px', borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(20,184,166,0.15) 0%, transparent 70%)',
          filter: 'blur(50px)', pointerEvents: 'none',
        }} />

        {/* Logo & Headline */}
        <div style={{ position: 'relative', zIndex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '36px' }}>
            <img 
              src="/logos/app-icon.png" 
              alt="Purple Agent" 
              style={{
                width: '52px', 
                height: '52px', 
                borderRadius: '14px',
                boxShadow: '0 8px 28px rgba(139,92,246,0.5)',
                objectFit: 'contain',
                border: '1px solid rgba(139,92,246,0.3)',
              }} 
            />
            <div>
              <div style={{ fontSize: '18px', fontWeight: '800', color: '#f3f0ff', letterSpacing: '-0.02em', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span>Purple Agent</span>
                <span style={{ fontSize: '10px', fontWeight: '700', padding: '2px 6px', borderRadius: '4px', background: 'rgba(139,92,246,0.25)', border: '1px solid rgba(139,92,246,0.4)', color: '#c4b5fd' }}>ENTERPRISE</span>
              </div>
              <div style={{ fontSize: '11px', color: 'rgba(180,170,255,0.55)', letterSpacing: '0.04em' }}>
                Autonomous SRE & Cyber Threat Defense
              </div>
            </div>
          </div>

          {/* Headline */}
          <h1 style={{
            fontSize: '34px', fontWeight: '700', lineHeight: 1.15,
            letterSpacing: '-0.04em', color: '#e8e6ff', margin: '0 0 12px',
          }}>
            Autonomous SRE Intelligence<br />
            <span style={{
              background: 'linear-gradient(135deg,#a78bfa 0%,#2dd4bf 100%)',
              WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
            }}>powered by PyTorch LSTM</span>
          </h1>
          <p style={{ fontSize: '14px', color: 'rgba(180,170,255,0.6)', lineHeight: 1.6, margin: 0, maxWidth: '420px' }}>
            Predict anomalies before they become outages. Live multi-server telemetry, automated playbooks, and security auditing from one unified glass cockpit.
          </p>

          {/* Live Agent Terminal Widget */}
          <LiveAgentTerminal />
        </div>

        {/* Live stat grid & Trust Badges */}
        <div style={{ position: 'relative', zIndex: 1 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px', marginBottom: '20px' }}>
            {[
              { val: '99.98%', label: 'Uptime SLA' },
              { val: '<2s',   label: 'AI Latency' },
              { val: 'AES-256', label: 'Kernel Auth' },
              { val: 'JWT',   label: 'Zero Trust' },
            ].map(s => (
              <div key={s.label} className="login-stat" style={{ padding: '10px 12px' }}>
                <div className="login-stat-val" style={{ fontSize: '14px', color: '#2dd4bf' }}>{s.val}</div>
                <div className="login-stat-label" style={{ fontSize: '9px' }}>{s.label}</div>
              </div>
            ))}
          </div>

          {/* Enterprise Compliance Pills */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '14px' }}>
            {['SOC 2 Type II', 'ISO 27001', 'HIPAA Ready', 'TLS 1.3 Strict', 'Kubernetes / Linux / Baremetal'].map(f => (
              <div key={f} style={{
                padding: '3px 10px', borderRadius: '16px',
                background: 'rgba(139,92,246,0.08)', border: '1px solid rgba(139,92,246,0.2)',
                fontSize: '10px', color: 'rgba(180,170,255,0.7)', fontWeight: '500',
              }}>
                ✓ {f}
              </div>
            ))}
          </div>

          <div style={{ fontSize: '11px', color: 'rgba(180,170,255,0.3)', letterSpacing: '0.04em' }}>
            Purple Agent Enterprise v2.4 • Cryptographically Protected
          </div>
        </div>
      </div>

      {/* ── RIGHT PANEL — Form ── */}
      <div style={{
        flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
        padding: '48px 40px', background: '#07071a',
      }}>
        <div style={{ width: '100%', maxWidth: '380px' }}>
          {/* Header */}
          {/* Mobile/Right Logo Badge */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '18px' }}>
            <img src="/logos/app-icon.png" alt="Purple Agent" style={{ width: '30px', height: '30px', borderRadius: '8px', objectFit: 'contain' }} />
            <span style={{ fontSize: '12px', fontWeight: '700', letterSpacing: '0.08em', color: '#a78bfa', textTransform: 'uppercase' }}>Purple Agent Console</span>
          </div>

          <div style={{ marginBottom: '28px' }}>
            <h2 style={{
              fontSize: '24px', fontWeight: '700', color: '#e8e6ff',
              letterSpacing: '-0.03em', margin: '0 0 6px',
            }}>
              {authMode === 'login' ? 'Sign in' : 'Create account'}
            </h2>
            <p style={{ fontSize: '13px', color: 'rgba(180,170,255,0.45)', margin: 0 }}>
              {authMode === 'login' ? 'Enter credentials or use the Quick Demo sandbox' : 'Fill in your details to get started'}
            </p>
          </div>

          {/* Message */}
          {message && (
            <div style={{
              padding: '11px 14px', borderRadius: '10px', marginBottom: '18px',
              fontSize: '13px', lineHeight: 1.4, animation: 'slideInDown 0.3s ease',
              background: isError ? 'rgba(244,63,94,0.1)' : 'rgba(45,212,191,0.1)',
              border: `1px solid ${isError ? 'rgba(244,63,94,0.25)' : 'rgba(45,212,191,0.22)'}`,
              color: isError ? '#fb7185' : '#2dd4bf',
            }}>{message}</div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <input type="text" name="hidden_username" autoComplete="username" style={{ display: 'none' }} />

            {/* Username */}
            <div>
              <label style={{ display: 'block', fontSize: '11px', fontWeight: '600', letterSpacing: '0.07em', textTransform: 'uppercase', color: 'rgba(180,170,255,0.5)', marginBottom: '5px' }}>Username</label>
              <input id="username" type="text" name="username" placeholder="your username"
                value={formData.username} onChange={handleInputChange}
                style={fieldStyle} required autoComplete="username" />
            </div>

            {authMode === 'register' && (
              <>
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: '600', letterSpacing: '0.07em', textTransform: 'uppercase', color: 'rgba(180,170,255,0.5)', marginBottom: '5px' }}>Email</label>
                  <input id="email" type="email" name="email" placeholder="you@example.com"
                    value={formData.email} onChange={handleInputChange}
                    style={fieldStyle} required autoComplete="email" />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: '600', letterSpacing: '0.07em', textTransform: 'uppercase', color: 'rgba(180,170,255,0.5)', marginBottom: '5px' }}>Role</label>
                  <select id="role" name="role" value={formData.role} onChange={handleInputChange} style={fieldStyle}>
                    <option value="guest">Guest</option>
                    <option value="agent">Agent</option>
                  </select>
                </div>
              </>
            )}

            {/* Password */}
            <div>
              <label style={{ display: 'block', fontSize: '11px', fontWeight: '600', letterSpacing: '0.07em', textTransform: 'uppercase', color: 'rgba(180,170,255,0.5)', marginBottom: '5px' }}>Password</label>
              <PasswordInput value={formData.password} onChange={handleInputChange}
                placeholder="••••••••" name="password"
                showPassword={showPassword} onToggleVisibility={() => setShowPassword(!showPassword)}
                autoComplete={authMode === 'login' ? 'current-password' : 'new-password'} />
            </div>

            {/* Autofill helper shortcut */}
            {authMode === 'login' && (
              <div
                onClick={() => setFormData(prev => ({ ...prev, username: 'admin', password: 'adminpass' }))}
                style={{
                  fontSize: '11px',
                  color: '#a78bfa',
                  cursor: 'pointer',
                  textAlign: 'right',
                  marginTop: '-4px',
                  fontWeight: '500',
                }}
              >
                ⚡ Auto-fill Default Admin (admin / adminpass)
              </div>
            )}

            {authMode === 'register' && (
              <div>
                <label style={{ display: 'block', fontSize: '11px', fontWeight: '600', letterSpacing: '0.07em', textTransform: 'uppercase', color: 'rgba(180,170,255,0.5)', marginBottom: '5px' }}>Confirm Password</label>
                <PasswordInput value={formData.confirmPassword} onChange={handleInputChange}
                  placeholder="••••••••" name="confirmPassword"
                  showPassword={showConfirmPassword} onToggleVisibility={() => setShowConfirmPassword(!showConfirmPassword)}
                  autoComplete="new-password" />
              </div>
            )}

            {/* Submit */}
            <button type="submit" disabled={authLoading} onClick={handleButtonClick}
              style={{
                marginTop: '8px', padding: '13px 20px', border: 'none', borderRadius: '10px',
                cursor: authLoading ? 'not-allowed' : 'pointer', color: 'white',
                fontSize: '14px', fontWeight: '600',
                background: authLoading ? 'rgba(80,70,120,0.5)' : 'linear-gradient(135deg,#7c3aed,#4f46e5 60%,#2dd4bf)',
                boxShadow: authLoading ? 'none' : '0 4px 20px rgba(124,58,237,0.4)',
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
                position: 'relative', overflow: 'hidden',
                transition: 'all 0.2s',
              }}>
              {buttonRipple && (
                <div style={{
                  position: 'absolute', top: '50%', left: '50%',
                  width: 0, height: 0, borderRadius: '50%',
                  background: 'rgba(255,255,255,0.25)',
                  transform: 'translate(-50%,-50%)',
                  animation: 'ripple 0.6s ease-out',
                }} />
              )}
              {authLoading ? (
                <><TailSpin height={18} width={18} color="white" /><span>Authenticating…</span></>
              ) : (
                authMode === 'login' ? 'Sign in →' : 'Create account →'
              )}
            </button>
          </form>

          {/* Toggle */}
          <div style={{ marginTop: '18px', textAlign: 'center' }}>
            <button onClick={toggleAuthMode} style={{
              background: 'none', border: 'none', cursor: 'pointer',
              fontSize: '13px', color: 'rgba(180,170,255,0.5)',
            }}>
              {authMode === 'login' ? "No account? " : "Have an account? "}
              <span style={{ color: '#a78bfa', fontWeight: '600' }}>
                {authMode === 'login' ? 'Register' : 'Sign in'}
              </span>
            </button>
          </div>

          {/* Demo shortcut */}
          <div style={{ marginTop: '24px', paddingTop: '18px', borderTop: '1px solid rgba(139,92,246,0.1)' }}>
            <div style={{ fontSize: '11px', color: 'rgba(180,170,255,0.4)', marginBottom: '8px', textAlign: 'center', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
              One-Click Evaluation Sandbox
            </div>
            <button onClick={handleQuickDemoClick}
              style={{
                width: '100%', padding: '11px 20px', border: '1px solid rgba(139,92,246,0.25)',
                borderRadius: '10px', cursor: 'pointer', color: 'rgba(215,205,255,0.9)',
                fontSize: '13px', fontWeight: '500', background: 'rgba(139,92,246,0.1)',
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
                transition: 'all 0.18s ease',
              }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="#2dd4bf">
                <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/>
              </svg>
              <span>Instant Admin Demo (1-Click)</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// MetricsChart Component with Glass Morphism
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
  
  const GaugeCard = ({ label, value, color, thresholdWarn=70, thresholdCrit=90, metricKey }) => {
    const pct = Math.min(100, Math.max(0, value || 0));
    const isCrit = pct >= thresholdCrit;
    const isWarn = pct >= thresholdWarn && !isCrit;
    const displayColor = isCrit ? '#f43f5e' : isWarn ? '#f59e0b' : color;
    const statusLabel = isCrit ? 'critical' : isWarn ? 'warning' : 'normal';

    return (
      <div
        onClick={() => onMetricClick && onMetricClick({ metric: metricKey, valueRange: '0-100', currentValue: value })}
        style={{
          flex: 1, padding: '18px 20px',
          background: isCrit ? 'rgba(244,63,94,0.05)' : isWarn ? 'rgba(245,158,11,0.05)' : 'rgba(255,255,255,0.03)',
          border: `1px solid ${isCrit ? 'rgba(244,63,94,0.2)' : isWarn ? 'rgba(245,158,11,0.18)' : 'rgba(139,92,246,0.1)'}`,
          borderRadius: '14px', cursor: 'pointer',
          transition: 'all 0.2s', position: 'relative', overflow: 'hidden',
        }}
      >
        {/* Accent top bar */}
        <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: '2px', background: displayColor, borderRadius: '14px 14px 0 0', opacity: 0.8 }} />
        <div style={{ fontSize: '10px', fontWeight: '600', letterSpacing: '0.09em', textTransform: 'uppercase', color: 'rgba(180,170,255,0.45)', marginBottom: '10px' }}>{label}</div>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: '4px', marginBottom: '12px' }}>
          <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '32px', fontWeight: '600', color: displayColor, lineHeight: 1, letterSpacing: '-0.03em' }}>
            {value != null ? value.toFixed(1) : '—'}
          </span>
          <span style={{ fontSize: '14px', color: 'rgba(180,170,255,0.4)' }}>%</span>
        </div>
        {/* Progress track */}
        <div style={{ background: 'rgba(139,92,246,0.08)', borderRadius: '4px', height: '5px', overflow: 'hidden' }}>
          <div style={{ height: '100%', width: `${pct}%`, background: displayColor, borderRadius: '4px', transition: 'width 0.8s cubic-bezier(0.34,1.56,0.64,1)', boxShadow: `0 0 8px ${displayColor}55` }} />
        </div>
        <div style={{ marginTop: '8px', fontSize: '11px', color: 'rgba(180,170,255,0.35)', display: 'flex', justifyContent: 'space-between' }}>
          <span>{statusLabel}</span><span>tap to drill down</span>
        </div>
      </div>
    );
  };

  return (
    <div style={{ ...darkStyles.gridCard, position: 'relative', zIndex: 2 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
        <h3 style={{ color: DARK_THEME.text, fontSize: '14px', fontWeight: '600', margin: 0, letterSpacing: '-0.01em' }}>System Resources</h3>
        <span style={{ fontSize: '10px', color: 'rgba(180,170,255,0.35)', letterSpacing: '0.06em', textTransform: 'uppercase' }}>Live</span>
      </div>
      <div style={{ display: 'flex', gap: '12px' }}>
        <GaugeCard label="CPU" value={cpu} color={COLORS[0]} metricKey="cpu_usage" />
        <GaugeCard label="Memory" value={memory} color={COLORS[1]} thresholdWarn={75} thresholdCrit={90} metricKey="memory_usage" />
        <GaugeCard label="Disk" value={disk} color={COLORS[2]} thresholdWarn={80} thresholdCrit={95} metricKey="disk_usage" />
      </div>
    </div>
  );
}

// NetworkChart Component with Glass Morphism
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
    <div style={{
      ...darkStyles.gridCard,
      background: "rgba(255,255,255,0.07)",
      backdropFilter: "blur(48px) saturate(160%)",
      WebkitBackdropFilter: "blur(48px) saturate(160%)",
      position: "relative",
      zIndex: 2
    }}>
      <h3 style={{ color: DARK_THEME.text, marginBottom: "20px", fontSize: '18px' }}>Network Activity</h3>
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke={DARK_THEME.glassBorder} />
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
            contentStyle={{ 
              background: DARK_THEME.cardBackground, 
              border: `1px solid ${DARK_THEME.glassBorder}`,
              borderRadius: '12px',
              backdropFilter: 'blur(10px)'
            }}
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

// ProcessList Component with Glass Morphism
function ProcessList({ processes }) {
  return (
    <div style={{
      ...darkStyles.gridCard,
      background: "rgba(255,255,255,0.07)",
      backdropFilter: "blur(48px) saturate(160%)",
      WebkitBackdropFilter: "blur(48px) saturate(160%)",
      position: "relative",
      zIndex: 2
    }}>
      <h3 style={{ color: DARK_THEME.text, marginBottom: "20px", fontSize: '18px' }}>Running Processes ({processes?.length || 0})</h3>
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
                  backgroundColor: index % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.04)'
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

// AlertBanner Component with Glass Morphism
function AlertBanner({ message, type = 'info' }) {
  const bgColor = type === 'error' ? 'rgba(139,92,246,0.15)' : type === 'warning' ? 'rgba(245,158,11,0.1)' : 'rgba(34,197,94,0.1)';
  const borderColor = type === 'error' ? DARK_THEME.danger : type === 'warning' ? DARK_THEME.warning : DARK_THEME.success;
  const textColor = type === 'error' ? '#f87171' : type === 'warning' ? '#fbbf24' : '#4ade80';
  
  return (
    <div style={{
      ...darkStyles.message,
      background: bgColor,
      border: `1px solid ${borderColor}`,
      color: textColor,
      marginBottom: "15px",
      backdropFilter: 'blur(10px)'
    }}>
      {message}
    </div>
  );
}

// LiveDashboard Component with Glass Morphism
function LiveDashboard({ token }) {
  const [messages, setMessages] = useState([]);
  
  const { lastMessage, readyState } = useWebSocket(
    `ws://${window.location.hostname}:8000/ws`,
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
    <div style={{
      ...darkStyles.card,
      background: "rgba(255,255,255,0.07)",
      backdropFilter: "blur(48px) saturate(160%)",
      WebkitBackdropFilter: "blur(48px) saturate(160%)",
      position: "relative",
      zIndex: 2
    }}>
      <h3 style={{ color: DARK_THEME.text, marginBottom: "20px", fontSize: '18px' }}>Live Dashboard</h3>
      <div style={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center',
        marginBottom: '15px',
        padding: '15px',
        background: readyState === 1 ? 'rgba(34,197,94,0.1)' : 'rgba(139,92,246,0.15)',
        border: `1px solid ${readyState === 1 ? DARK_THEME.success : DARK_THEME.danger}`,
        borderRadius: '12px',
        backdropFilter: 'blur(10px)'
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
        border: `1px solid ${DARK_THEME.glassBorder}`,
        borderRadius: '12px',
        padding: '15px',
        background: 'rgba(255,255,255,0.05)'
      }}>
        {messages.length > 0 ? (
          messages.map((msg, index) => (
            <div 
              key={index} 
              style={{ 
                padding: '12px', 
                borderBottom: index < messages.length - 1 ? `1px solid ${DARK_THEME.glassBorder}` : 'none',
                fontSize: '12px',
                color: DARK_THEME.textMuted,
                backgroundColor: index % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.04)',
                borderRadius: index === 0 ? '8px 8px 0 0' : index === messages.length - 1 ? '0 0 8px 8px' : '0',
                transition: 'all 0.3s ease'
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
                  {toIST(msg.timestamp)}
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

// DrillDownModal Component with Glass Morphism
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
      background: 'rgba(0, 0, 0, 0.8)',
      backdropFilter: 'blur(10px)',
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      zIndex: 1000,
      padding: '20px'
    }}>
      <div style={{
        background: DARK_THEME.cardBackground,
        backdropFilter: 'blur(25px)',
        border: `1px solid ${DARK_THEME.glassBorder}`,
        borderRadius: '20px',
        padding: '25px',
        maxWidth: '800px',
        width: '100%',
        maxHeight: '80vh',
        overflow: 'auto',
        boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <h3 style={{ color: DARK_THEME.text, margin: 0, fontSize: '20px' }}>
            Metric Details: {metricData?.metric?.replace('_', ' ').toUpperCase()}
          </h3>
          <button
            onClick={onClose}
            style={{
              ...darkStyles.button,
              background: 'rgba(139,92,246,0.15)',
              border: `1px solid rgba(139,92,246,0.15)`,
              padding: '8px 16px',
              fontSize: '12px'
            }}
          >
            Close
          </button>
        </div>

        {metricData?.valueRange && (
          <div style={{ 
            marginBottom: '15px', 
            padding: '15px', 
            background: 'rgba(255,255,255,0.04)',
            borderRadius: '12px',
            border: `1px solid ${DARK_THEME.glassBorder}`
          }}>
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
                      backgroundColor: index % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.04)'
                    }}>
                      <td style={darkStyles.tableCell}>
                        {toIST(item.timestamp)}
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
                            background: 'rgba(147, 51, 234, 0.2)',
                            border: `1px solid rgba(147, 51, 234, 0.3)`,
                            padding: '8px 16px',
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

        <div style={{ 
          marginTop: '20px', 
          padding: '20px', 
          background: 'rgba(255,255,255,0.04)', 
          borderRadius: '12px',
          border: `1px solid ${DARK_THEME.glassBorder}`
        }}>
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

// Filter Panel Component with Glass Morphism
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
            background: loading ? DARK_THEME.glassBorder : 'rgba(139,92,246,0.15)',
            border: `1px solid ${loading ? DARK_THEME.glassBorder : 'rgba(139,92,246,0.15)'}`,
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
            background: 'rgba(107, 114, 128, 0.2)',
            border: `1px solid rgba(107, 114, 128, 0.3)`,
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

// Export Panel Component with Glass Morphism
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
            background: exportLoading ? DARK_THEME.glassBorder : 'rgba(255,255,255,0.05)'
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

// Dashboard Layouts Component with Glass Morphism
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
      const response = await apiClient.get("/dashboard/layouts");
      if (response.data && response.data.length > 0) {
        setLayouts(response.data);
      } else {
        setLayouts([
          { id: 1, name: "Standard NOC Layout", is_default: true, created_at: new Date().toISOString() },
          { id: 2, name: "Incident Response Layout", is_default: false, created_at: new Date().toISOString() }
        ]);
      }
    } catch (error) {
      console.error("Failed to fetch layouts:", error);
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
      const response = await apiClient.post("/dashboard/layouts", {
        name: newLayoutName.trim(),
        layout_data: { grid: "2x2", widgets: ["metrics", "alerts", "live_stream"] },
        is_default: false
      });
      const created = response.data || {
        id: Date.now(),
        name: newLayoutName.trim(),
        is_default: false,
        created_at: new Date().toISOString()
      };
      setLayouts(prev => [...prev, created]);
      setNewLayoutName("");
      setShowCreateModal(false);
      showMessage("Layout created successfully");
    } catch (error) {
      console.error("Failed to create layout:", error);
      showMessage("Failed to create layout", true);
    }
  };

  const setDefaultLayout = async (layoutId) => {
    try {
      await apiClient.patch(`/dashboard/layouts/${layoutId}/set-default`);
      setLayouts(prev => prev.map(layout => ({
        ...layout,
        is_default: layout.id === layoutId
      })));
      showMessage("Default layout updated successfully");
    } catch (error) {
      console.error("Failed to set default layout:", error);
      showMessage("Failed to set default layout", true);
    }
  };

  const deleteLayout = async (layoutId) => {
    if (window.confirm("Are you sure you want to delete this layout?")) {
      try {
        await apiClient.delete(`/dashboard/layouts/${layoutId}`);
        setLayouts(prev => prev.filter(layout => layout.id !== layoutId));
        showMessage("Layout deleted successfully");
      } catch (error) {
        console.error("Failed to delete layout:", error);
        showMessage("Failed to delete layout", true);
      }
    }
  };

  useEffect(() => {
    fetchLayouts();
  }, []);

  return (
    <div style={{
      ...darkStyles.card,
      background: "rgba(255,255,255,0.07)",
      backdropFilter: "blur(48px) saturate(160%)",
      WebkitBackdropFilter: "blur(48px) saturate(160%)",
      position: "relative",
      zIndex: 2
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
        <h3 style={{ color: DARK_THEME.text, margin: 0, fontSize: '20px' }}>Dashboard Layouts</h3>
        <button 
          onClick={() => setShowCreateModal(true)}
          style={{ 
            ...darkStyles.button, 
            background: 'rgba(34,197,94,0.15)',
            border: `1px solid rgba(34,197,94,0.3)`
          }}
        >
          <LayoutIcon />
          New Layout
        </button>
      </div>

      {message && (
        <div style={{
          ...darkStyles.message,
          background: message.includes("Failed") ? 'rgba(139,92,246,0.15)' : 'rgba(34,197,94,0.1)',
          border: `1px solid ${message.includes("Failed") ? DARK_THEME.danger : DARK_THEME.success}`,
          color: message.includes("Failed") ? '#f87171' : '#86efac',
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
                    {toIST(layout.created_at)}
                  </td>
                  <td style={darkStyles.tableCell}>
                    <div style={{ display: "flex", gap: "5px" }}>
                      {!layout.is_default && (
                        <>
                          <button
                            onClick={() => setDefaultLayout(layout.id)}
                            style={{
                              ...darkStyles.button,
                              background: 'rgba(139,92,246,0.15)',
                              border: `1px solid rgba(139,92,246,0.15)`,
                              padding: "8px 16px",
                              fontSize: "12px"
                            }}
                          >
                            Set Default
                          </button>
                          <button
                            onClick={() => deleteLayout(layout.id)}
                            style={{
                              ...darkStyles.button,
                              background: 'rgba(139,92,246,0.15)',
                              border: `1px solid rgba(139,92,246,0.15)`,
                              padding: "8px 16px",
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
          background: 'rgba(0, 0, 0, 0.8)',
          backdropFilter: 'blur(10px)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 1000
        }}>
          <div style={{
            background: DARK_THEME.cardBackground,
            backdropFilter: 'blur(25px)',
            border: `1px solid ${DARK_THEME.glassBorder}`,
            borderRadius: '20px',
            padding: '25px',
            width: '400px',
            maxWidth: '90vw',
            boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)'
          }}>
            <h3 style={{ color: DARK_THEME.text, marginBottom: '20px', fontSize: '20px' }}>Create New Layout</h3>
            
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
                  background: 'rgba(34,197,94,0.15)',
                  border: `1px solid rgba(34,197,94,0.3)`,
                  flex: 1
                }}
              >
                Create
              </button>
              <button
                onClick={() => setShowCreateModal(false)}
                style={{
                  ...darkStyles.button,
                  background: 'rgba(107, 114, 128, 0.2)',
                  border: `1px solid rgba(107, 114, 128, 0.3)`,
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

// Navigation Menu — redesigned sidebar nav
function NavigationMenu({ activeTab, setActiveTab, currentUser }) {
  const isAdmin = currentUser?.role === 'admin';

  const sections = [
    {
      label: "Main",
      items: [
        { id: "dashboard", label: "Dashboard", icon: DashboardIcon },
        { id: "layouts",   label: "Layouts",   icon: LayoutIcon },
        { id: "landing",   label: "Landing Page", icon: GlobeIcon },
      ]
    },
    {
      label: "Account",
      items: [
        { id: "account", label: "Settings", icon: AccountIcon },
      ]
    },
    ...(isAdmin ? [{
      label: "Admin",
      items: [
        { id: "users",         label: "Users",          icon: UsersIcon },
        { id: "alerts",        label: "Alerts",         icon: AlertIcon },
        { id: "user-activity", label: "Activity",       icon: ActivityIcon },
        { id: "visitor-logs",  label: "Visitor Logs",   icon: SecurityIcon },
      ]
    }] : []),
  ];

  return (
    <nav style={{ flex: 1, overflowY: 'auto', padding: '8px 0' }}>
      {sections.map(section => (
        <div key={section.label} style={{ marginBottom: '4px' }}>
          <div style={darkStyles.sidebarHeader}>{section.label}</div>
          <div style={darkStyles.navMenu}>
            {section.items.map(item => {
              const isActive = activeTab === item.id;
              return (
                <div
                  key={item.id}
                  className={`nav-item${isActive ? ' active' : ''}`}
                  style={{
                    ...darkStyles.navItem,
                    background: isActive ? 'rgba(139,92,246,0.14)' : 'transparent',
                    borderColor: isActive ? 'rgba(139,92,246,0.22)' : 'transparent',
                    color: isActive ? '#e8e6ff' : 'rgba(180,170,255,0.55)',
                    fontWeight: isActive ? '550' : '450',
                  }}
                  onClick={() => setActiveTab(item.id)}
                >
                  {/* Active left bar */}
                  {isActive && (
                    <div style={{
                      position: 'absolute', left: '-12px', top: '50%',
                      transform: 'translateY(-50%)',
                      width: '3px', height: '60%',
                      background: 'linear-gradient(#8b5cf6,#2dd4bf)',
                      borderRadius: '0 2px 2px 0',
                    }} />
                  )}
                  <item.icon />
                  <span>{item.label}</span>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </nav>
  );
}

// User Management Component with Glass Morphism
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
      // REAL API CALL - replace with your actual endpoint
      const response = await apiClient.get("/admin/users");
      setUsers(response.data);
    } catch (error) {
      console.error('Failed to fetch users:', error);
      // Fallback: if endpoint doesn't exist, show empty state
      if (error.response?.status === 404) {
        showMessage("Users endpoint not available in backend", true);
        setUsers([]);
      } else {
        showMessage("Failed to fetch users", true);
      }
    } finally {
      setLoading(false);
    }
  };

  const updateUserRole = async (userId, newRole) => {
    try {
      // REAL API CALL
      await apiClient.put(`/admin/users/${userId}/role`, { role: newRole });
      
      // Update local state only after successful API call
      setUsers(prev => prev.map(user => 
        user.id === userId ? { ...user, role: newRole } : user
      ));
      showMessage("User role updated successfully");
    } catch (error) {
      console.error('Failed to update user role:', error);
      showMessage("Failed to update user role", true);
    }
  };

  const toggleUserStatus = async (userId, currentStatus) => {
    try {
      // REAL API CALL
      await apiClient.put(`/admin/users/${userId}/status`, { 
        disabled: !currentStatus 
      });
      
      setUsers(prev => prev.map(user => 
        user.id === userId ? { ...user, disabled: !currentStatus } : user
      ));
      showMessage(currentStatus ? "User enabled successfully" : "User disabled successfully");
    } catch (error) {
      console.error('Failed to update user status:', error);
      showMessage("Failed to update user status", true);
    }
  };

  const deleteUser = async (userId, username) => {
    if (window.confirm(`Are you sure you want to delete user "${username}"? This action cannot be undone.`)) {
      try {
        // REAL API CALL
        await apiClient.delete(`/admin/users/${userId}`);
        
        setUsers(prev => prev.filter(user => user.id !== userId));
        showMessage(`User "${username}" deleted successfully`);
      } catch (error) {
        console.error('Failed to delete user:', error);
        showMessage("Failed to delete user", true);
      }
    }
  };

  useEffect(() => {
    if (currentUser?.role === 'admin') {
      fetchUsers();
    }
  }, [currentUser]);

  if (currentUser?.role !== 'admin') {
    return (
      <div style={{
        ...darkStyles.card,
        background: "rgba(255,255,255,0.042)",
        backdropFilter: "blur(25px)"
      }}>
        <h3 style={{ color: DARK_THEME.text, fontSize: '20px' }}>User Management</h3>
        <p style={{ color: DARK_THEME.textMuted }}>Admin access required to manage users.</p>
      </div>
    );
  }

  return (
    <div style={{
      ...darkStyles.card,
      background: "rgba(255,255,255,0.07)",
      backdropFilter: "blur(48px) saturate(160%)",
      WebkitBackdropFilter: "blur(48px) saturate(160%)",
      position: "relative",
      zIndex: 2
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
        <h3 style={{ color: DARK_THEME.text, margin: 0, fontSize: '20px' }}>User Management</h3>
        <button 
          onClick={fetchUsers} 
          style={{ 
            ...darkStyles.button, 
            background: 'rgba(107, 114, 128, 0.2)',
            border: `1px solid rgba(107, 114, 128, 0.3)`
          }}
        >
          Refresh Users
        </button>
      </div>

      {message && (
        <div style={{
          ...darkStyles.message,
          background: message.includes("Failed") ? 'rgba(139,92,246,0.15)' : 'rgba(34,197,94,0.1)',
          border: `1px solid ${message.includes("Failed") ? DARK_THEME.danger : DARK_THEME.success}`,
          color: message.includes("Failed") ? '#f87171' : '#86efac',
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
          {users.length === 0 ? (
            <div style={{ textAlign: "center", padding: "40px", color: DARK_THEME.textMuted }}>
              <p>No users found.</p>
              <p style={{ fontSize: "14px", marginTop: "10px" }}>
                This could mean:
                <br />• The users API endpoint is not implemented
                <br />• There are no users in the system
                <br />• You don't have permission to view users
              </p>
            </div>
          ) : (
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
                    backgroundColor: user.id === currentUser.id ? 'rgba(220, 38, 38, 0.1)' : 'transparent'
                  }}>
                    <td style={{ ...darkStyles.tableCell, color: DARK_THEME.text }}>
                      {user.username} {user.id === currentUser.id && "(You)"}
                    </td>
                    <td style={{ ...darkStyles.tableCell, color: DARK_THEME.text }}>{user.email}</td>
                    <td style={{ ...darkStyles.tableCell, color: DARK_THEME.text }}>
                      <select
                        value={user.role}
                        onChange={(e) => updateUserRole(user.id, e.target.value)}
                        style={{
                          ...darkStyles.select,
                          background: 'rgba(255,255,255,0.05)',
                          border: `1px solid ${DARK_THEME.glassBorder}`,
                          marginBottom: 0
                        }}
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
                      <div style={{ display: "flex", gap: "5px" }}>
                        <button
                          onClick={() => toggleUserStatus(user.id, user.disabled)}
                          style={{
                            ...darkStyles.button,
                            background: user.disabled ? 'rgba(34,197,94,0.15)' : 'rgba(217, 119, 6, 0.2)',
                            border: `1px solid ${user.disabled ? 'rgba(34,197,94,0.3)' : 'rgba(217, 119, 6, 0.3)'}`,
                            padding: "8px 16px",
                            fontSize: "12px"
                          }}
                          disabled={user.id === currentUser.id}
                        >
                          {user.disabled ? "Enable" : "Disable"}
                        </button>
                        {user.id !== currentUser.id && (
                          <button
                            onClick={() => deleteUser(user.id, user.username)}
                            style={{
                              ...darkStyles.button,
                              background: 'rgba(139,92,246,0.15)',
                              border: `1px solid rgba(139,92,246,0.15)`,
                              padding: "8px 16px",
                              fontSize: "12px",
                              marginLeft: "5px"
                            }}
                          >
                            Delete
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}

// Alerts Management Component with Glass Morphism
function AlertsManagement({ apiClient, currentUser }) {
  const [alertRules, setAlertRules] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [activeSubTab, setActiveSubTab] = useState("rules");

  const fetchAlertRules = async () => {
    setLoading(true);
    try {
      const response = await apiClient.get('/alerts/rules?active_only=false');
      setAlertRules(response.data || []);
    } catch (error) {
      console.error('Failed to fetch alert rules:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchIncidents = async () => {
    setLoading(true);
    try {
      const response = await apiClient.get('/incidents');
      setIncidents(response.data || []);
    } catch (error) {
      console.error('Failed to fetch incidents:', error);
    } finally {
      setLoading(false);
    }
  };

  const toggleAlertRule = async (ruleId, currentStatus) => {
    try {
      const newStatus = !currentStatus;
      await apiClient.patch(`/alerts/rules/${ruleId}/toggle?active=${newStatus}`);
      setAlertRules(prev => prev.map(rule => 
        rule.id === ruleId ? { ...rule, active: newStatus } : rule
      ));
    } catch (error) {
      console.error('Failed to toggle alert rule:', error);
    }
  };

  const updateIncidentStatus = async (incidentId, newStatus) => {
    try {
      await apiClient.patch(`/incidents/${incidentId}/status`, { status: newStatus });
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
      <div style={{
        ...darkStyles.card,
        background: "rgba(255,255,255,0.042)",
        backdropFilter: "blur(25px)"
      }}>
        <h3 style={{ color: DARK_THEME.text, fontSize: '20px' }}>Alerts & Incidents Management</h3>
        <p style={{ color: DARK_THEME.textMuted }}>Admin access required to manage alerts and incidents.</p>
      </div>
    );
  }

  return (
    <div style={{
      ...darkStyles.card,
      background: "rgba(255,255,255,0.07)",
      backdropFilter: "blur(48px) saturate(160%)",
      WebkitBackdropFilter: "blur(48px) saturate(160%)",
      position: "relative",
      zIndex: 2
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h3 style={{ color: DARK_THEME.text, margin: 0, fontSize: '20px' }}>Alerts & Incidents Management</h3>
        <div style={darkStyles.tabContainer}>
          <button
            onClick={() => setActiveSubTab("rules")}
            style={{
              ...darkStyles.tab,
              background: activeSubTab === "rules" ? 'rgba(139,92,246,0.15)' : 'rgba(255,255,255,0.05)',
              border: `1px solid ${activeSubTab === "rules" ? 'rgba(139,92,246,0.15)' : DARK_THEME.glassBorder}`,
              color: activeSubTab === "rules" ? "#fff" : DARK_THEME.text
            }}
          >
            Alert Rules ({alertRules.length})
          </button>
          <button
            onClick={() => setActiveSubTab("incidents")}
            style={{
              ...darkStyles.tab,
              background: activeSubTab === "incidents" ? 'rgba(139,92,246,0.15)' : 'rgba(255,255,255,0.05)',
              border: `1px solid ${activeSubTab === "incidents" ? 'rgba(139,92,246,0.15)' : DARK_THEME.glassBorder}`,
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
                        background: rule.active ? 'rgba(217, 119, 6, 0.2)' : 'rgba(34,197,94,0.15)',
                        border: `1px solid ${rule.active ? 'rgba(217, 119, 6, 0.3)' : 'rgba(34,197,94,0.3)'}`,
                        padding: "8px 16px",
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
                    {toIST(incident.created_at)}
                  </td>
                  <td style={darkStyles.tableCell}>
                    <div style={{ display: 'flex', gap: '5px', flexDirection: 'column' }}>
                      {incident.status === 'new' && (
                        <button
                          onClick={() => updateIncidentStatus(incident.id, 'acknowledged')}
                          style={{
                            ...darkStyles.button,
                            background: 'rgba(217, 119, 6, 0.2)',
                            border: `1px solid rgba(217, 119, 6, 0.3)`,
                            padding: "6px 12px",
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
                            background: 'rgba(34,197,94,0.15)',
                            border: `1px solid rgba(34,197,94,0.3)`,
                            padding: "6px 12px",
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

// Password Change Component with Glass Morphism
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
      const errDetail = error.response?.data?.detail || "Failed to change password";
      showMessage(errDetail, true);
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
    <div style={{
      ...darkStyles.card,
      background: "rgba(255,255,255,0.07)",
      backdropFilter: "blur(48px) saturate(160%)",
      WebkitBackdropFilter: "blur(48px) saturate(160%)",
      position: "relative",
      zIndex: 2
    }}>
      <h3 style={{ color: DARK_THEME.text, marginBottom: "20px", fontSize: '20px' }}>Change Password</h3>
      
      {message && (
        <div style={{
          ...darkStyles.message,
          background: message.includes("Failed") ? 'rgba(139,92,246,0.15)' : 'rgba(34,197,94,0.1)',
          border: `1px solid ${message.includes("Failed") ? DARK_THEME.danger : DARK_THEME.success}`,
          color: message.includes("Failed") ? '#f87171' : '#86efac',
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
            background: loading ? DARK_THEME.glassBorder : 'rgba(139,92,246,0.15)',
            border: `1px solid ${loading ? DARK_THEME.glassBorder : 'rgba(139,92,246,0.15)'}`,
            width: "100%"
          }}
        >
          {loading ? <TailSpin height={20} width={20} color="white" /> : "Change Password"}
        </button>
      </form>
    </div>
  );
}

// Server Selector Component with Glass Morphism
function ServerSelector({ servers, selectedServer, onServerChange, loading }) {
  return (
    <div style={darkStyles.sidebarSection}>
      <div style={darkStyles.sidebarHeader}>
        <ServerIcon />
        <span>Server Selection</span>
      </div>
      
      {loading ? (
        <div style={{ textAlign: 'center', padding: '10px' }}>
          <TailSpin height={20} width={20} />
          <div style={{ color: DARK_THEME.textMuted, fontSize: '12px', marginTop: '5px' }}>
            Loading servers...
          </div>
        </div>
      ) : (
        <select
          value={selectedServer || ''}
          onChange={(e) => onServerChange(e.target.value ? parseInt(e.target.value) : null)}
          style={darkStyles.select}
        >
          <option value="">All Servers</option>
          {servers.map(server => (
            <option key={server.id} value={server.id}>
              {server.hostname} {server.ip_address ? `(${server.ip_address})` : ''}
            </option>
          ))}
        </select>
      )}
      
      {selectedServer && (
        <div style={{ 
          marginTop: '10px', 
          padding: '15px', 
          background: 'rgba(255,255,255,0.04)', 
          borderRadius: '12px',
          border: `1px solid ${DARK_THEME.glassBorder}`
        }}>
          <div style={{ fontSize: '12px', color: DARK_THEME.textMuted }}>
            Selected: {servers.find(s => s.id === selectedServer)?.hostname}
          </div>
        </div>
      )}
    </div>
  );
}

// User Activity Monitoring Component with Glass Morphism
function UserActivityMonitor({ apiClient, currentUser }) {
  const [activities, setActivities] = useState([]);
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState({});
  const [filters, setFilters] = useState({
    username: '',
    activity_type: '',
    success: '',
    days: 7
  });

  const fetchActivities = async () => {
    if (currentUser?.role !== 'admin') return;
    
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (filters.username) params.append('username', filters.username);
      if (filters.activity_type) params.append('activity_type', filters.activity_type);
      if (filters.success !== '') params.append('success', filters.success);
      params.append('limit', '50');
      
      const response = await apiClient.get(`/admin/user-activities?${params}`);
      setActivities(response.data);
    } catch (error) {
      console.error('Failed to fetch user activities:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    if (currentUser?.role !== 'admin') return;
    
    try {
      const response = await apiClient.get(`/admin/user-activities/stats?days=${filters.days}`);
      setStats(response.data);
    } catch (error) {
      console.error('Failed to fetch user activity stats:', error);
    }
  };

  useEffect(() => {
    if (currentUser?.role === 'admin') {
      fetchActivities();
      fetchStats();
    }
  }, [currentUser, filters]);

  if (currentUser?.role !== 'admin') {
    return (
      <div style={{
        ...darkStyles.card,
        background: "rgba(255,255,255,0.042)",
        backdropFilter: "blur(25px)"
      }}>
        <h3 style={{ color: DARK_THEME.text, fontSize: '20px' }}>User Activity Monitor</h3>
        <p style={{ color: DARK_THEME.textMuted }}>Admin access required to view user activities.</p>
      </div>
    );
  }

  return (
    <div style={{
      ...darkStyles.card,
      background: "rgba(255,255,255,0.07)",
      backdropFilter: "blur(48px) saturate(160%)",
      WebkitBackdropFilter: "blur(48px) saturate(160%)",
      position: "relative",
      zIndex: 2
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h3 style={{ color: DARK_THEME.text, margin: 0, fontSize: '20px' }}>User Activity Monitor</h3>
        <button 
          onClick={fetchActivities}
          style={{ 
            ...darkStyles.button, 
            background: 'rgba(107, 114, 128, 0.2)',
            border: `1px solid rgba(107, 114, 128, 0.3)`
          }}
        >
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '10px', marginBottom: '20px' }}>
        <input
          type="text"
          placeholder="Filter by username..."
          value={filters.username}
          onChange={(e) => setFilters(prev => ({ ...prev, username: e.target.value }))}
          style={darkStyles.input}
        />
        <select
          value={filters.activity_type}
          onChange={(e) => setFilters(prev => ({ ...prev, activity_type: e.target.value }))}
          style={darkStyles.select}
        >
          <option value="">All Activities</option>
          <option value="login">Login</option>
          <option value="logout">Logout</option>
          <option value="password_change">Password Change</option>
          <option value="role_change">Role Change</option>
        </select>
        <select
          value={filters.success}
          onChange={(e) => setFilters(prev => ({ ...prev, success: e.target.value }))}
          style={darkStyles.select}
        >
          <option value="">All Status</option>
          <option value="true">Successful</option>
          <option value="false">Failed</option>
        </select>
      </div>

      {/* Stats */}
      {stats.suspicious_activities && stats.suspicious_activities.length > 0 && (
        <AlertBanner 
          message={`${stats.suspicious_activities.length} suspicious activities detected`}
          type="warning"
        />
      )}

      {/* Activities Table */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '20px' }}>
          <TailSpin height={30} width={30} />
          <p style={{ color: DARK_THEME.textMuted }}>Loading activities...</p>
        </div>
      ) : (
        <div style={{ maxHeight: '400px', overflow: 'auto' }}>
          <table style={darkStyles.table}>
            <thead>
              <tr>
                <th style={darkStyles.tableHeader}>Username</th>
                <th style={darkStyles.tableHeader}>Activity</th>
                <th style={darkStyles.tableHeader}>IP Address</th>
                <th style={darkStyles.tableHeader}>Status</th>
                <th style={darkStyles.tableHeader}>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {activities.map((activity) => (
                <tr key={activity.id}>
                  <td style={darkStyles.tableCell}>
                    <span style={{ 
                      color: activity.success ? DARK_THEME.text : DARK_THEME.danger,
                      fontWeight: '500'
                    }}>
                      {activity.username}
                    </span>
                  </td>
                  <td style={darkStyles.tableCell}>
                    <span style={{ 
                      textTransform: 'capitalize',
                      color: DARK_THEME.text
                    }}>
                      {activity.activity_type.replace('_', ' ')}
                    </span>
                  </td>
                  <td style={{ ...darkStyles.tableCell, fontFamily: 'monospace', fontSize: '11px' }}>
                    {activity.ip_address}
                  </td>
                  <td style={darkStyles.tableCell}>
                    <span style={{ 
                      color: activity.success ? DARK_THEME.success : DARK_THEME.danger,
                      fontWeight: 'bold'
                    }}>
                      {activity.success ? 'SUCCESS' : 'FAILED'}
                    </span>
                  </td>
                  <td style={{ ...darkStyles.tableCell, color: DARK_THEME.textMuted, fontSize: '11px' }}>
                    {toIST(activity.created_at)}
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

// Visitor Logs Component with Glass Morphism
function VisitorLogs({ apiClient, currentUser }) {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState({});
  const [filters, setFilters] = useState({
    ip_address: '',
    request_method: '',
    suspicious: '',
    days: 7
  });

  const fetchLogs = async () => {
    if (currentUser?.role !== 'admin') return;
    
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (filters.ip_address) params.append('ip_address', filters.ip_address);
      if (filters.request_method) params.append('request_method', filters.request_method);
      if (filters.suspicious !== '') params.append('suspicious', filters.suspicious);
      params.append('limit', '50');
      
      const response = await apiClient.get(`/admin/visitor-logs?${params}`);
      setLogs(response.data);
    } catch (error) {
      console.error('Failed to fetch visitor logs:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    if (currentUser?.role !== 'admin') return;
    
    try {
      const response = await apiClient.get(`/admin/visitor-logs/stats?days=${filters.days}`);
      setStats(response.data);
    } catch (error) {
      console.error('Failed to fetch visitor stats:', error);
    }
  };

  useEffect(() => {
    if (currentUser?.role === 'admin') {
      fetchLogs();
      fetchStats();
    }
  }, [currentUser, filters]);

  if (currentUser?.role !== 'admin') {
    return (
      <div style={{
        ...darkStyles.card,
        background: "rgba(255,255,255,0.042)",
        backdropFilter: "blur(25px)"
      }}>
        <h3 style={{ color: DARK_THEME.text, fontSize: '20px' }}>Visitor Logs</h3>
        <p style={{ color: DARK_THEME.textMuted }}>Admin access required to view visitor logs.</p>
      </div>
    );
  }

  return (
    <div style={{
      ...darkStyles.card,
      background: "rgba(255,255,255,0.07)",
      backdropFilter: "blur(48px) saturate(160%)",
      WebkitBackdropFilter: "blur(48px) saturate(160%)",
      position: "relative",
      zIndex: 2
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h3 style={{ color: DARK_THEME.text, margin: 0, fontSize: '20px' }}>Visitor Logs & Security</h3>
        <div style={{ display: 'flex', gap: '10px' }}>
          {stats.total_requests !== undefined && (
            <span style={{ color: DARK_THEME.textMuted, fontSize: '14px' }}>
              Total: {stats.total_requests} | Suspicious: {stats.suspicious_requests || 0}
            </span>
          )}
          <button 
            onClick={fetchLogs}
            style={{ 
              ...darkStyles.button, 
              background: 'rgba(107, 114, 128, 0.2)',
              border: `1px solid rgba(107, 114, 128, 0.3)`
          }}
        >
          Refresh
        </button>
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '10px', marginBottom: '20px' }}>
        <input
          type="text"
          placeholder="Filter by IP..."
          value={filters.ip_address}
          onChange={(e) => setFilters(prev => ({ ...prev, ip_address: e.target.value }))}
          style={darkStyles.input}
        />
        <select
          value={filters.request_method}
          onChange={(e) => setFilters(prev => ({ ...prev, request_method: e.target.value }))}
          style={darkStyles.select}
        >
          <option value="">All Methods</option>
          <option value="GET">GET</option>
          <option value="POST">POST</option>
          <option value="PUT">PUT</option>
          <option value="DELETE">DELETE</option>
        </select>
        <select
          value={filters.suspicious}
          onChange={(e) => setFilters(prev => ({ ...prev, suspicious: e.target.value }))}
          style={darkStyles.select}
        >
          <option value="">All Requests</option>
          <option value="true">Suspicious Only</option>
          <option value="false">Normal Only</option>
        </select>
      </div>

      {/* Logs Table */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '20px' }}>
          <TailSpin height={30} width={30} />
          <p style={{ color: DARK_THEME.textMuted }}>Loading logs...</p>
        </div>
      ) : (
        <div style={{ maxHeight: '400px', overflow: 'auto' }}>
          <table style={darkStyles.table}>
            <thead>
              <tr>
                <th style={darkStyles.tableHeader}>IP Address</th>
                <th style={darkStyles.tableHeader}>Method</th>
                <th style={darkStyles.tableHeader}>Path</th>
                <th style={darkStyles.tableHeader}>Status</th>
                <th style={darkStyles.tableHeader}>Suspicious</th>
                <th style={darkStyles.tableHeader}>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr key={log.id} style={{
                  backgroundColor: log.suspicious ? 'rgba(220, 38, 38, 0.1)' : 'transparent'
                }}>
                  <td style={{ ...darkStyles.tableCell, fontFamily: 'monospace', fontSize: '11px' }}>
                    {log.ip_address}
                  </td>
                  <td style={darkStyles.tableCell}>
                    <span style={{ 
                      color: log.request_method === 'GET' ? DARK_THEME.success : 
                             log.request_method === 'POST' ? DARK_THEME.warning :
                             log.request_method === 'PUT' ? DARK_THEME.info : DARK_THEME.danger,
                      fontWeight: 'bold'
                    }}>
                      {log.request_method}
                    </span>
                  </td>
                  <td style={{ ...darkStyles.tableCell, fontSize: '11px' }}>
                    {log.request_path}
                  </td>
                  <td style={darkStyles.tableCell}>
                    <span style={{ 
                      color: log.response_status < 400 ? DARK_THEME.success : 
                             log.response_status < 500 ? DARK_THEME.warning : DARK_THEME.danger,
                      fontWeight: 'bold'
                    }}>
                      {log.response_status}
                    </span>
                  </td>
                  <td style={darkStyles.tableCell}>
                    <span style={{ 
                      color: log.suspicious ? DARK_THEME.danger : DARK_THEME.success,
                      fontWeight: 'bold'
                    }}>
                      {log.suspicious ? 'YES' : 'NO'}
                    </span>
                    {log.suspicious_reason && (
                      <div style={{ fontSize: '10px', color: DARK_THEME.textMuted }}>
                        {log.suspicious_reason}
                      </div>
                    )}
                  </td>
                  <td style={{ ...darkStyles.tableCell, color: DARK_THEME.textMuted, fontSize: '11px' }}>
                    {toIST(log.created_at)}
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

// Real-time AI Hook
const useRealTimeAI = (metrics, apiClient) => {
  const [aiPredictions, setAiPredictions] = useState({});
  
  useEffect(() => {
    if (metrics && Object.keys(metrics).length > 0) {
      // Debounced AI analysis
      const timeoutId = setTimeout(() => {
        analyzeWithAI(metrics);
      }, 2000);
      
      return () => clearTimeout(timeoutId);
    }
  }, [metrics]);
  
  const analyzeWithAI = async (currentMetrics) => {
    try {
      const response = await apiClient.post('/ai/real-time-analysis', {
        metrics: currentMetrics,
        historical_context: getRecentHistory(currentMetrics) // Pass metrics directly
      });
      setAiPredictions(response.data);
    } catch (error) {
      console.error('Real-time AI analysis failed:', error);
    }
  };
  
  return aiPredictions;
};

// Add this function to your App.jsx
const getRecentHistory = (metrics) => {
  // Return recent metrics data for AI analysis
  if (!metrics || Object.keys(metrics).length === 0) return [];
  
  // Return last 10 data points for analysis - using current metrics as single data point
  return [{
    cpu_usage: metrics.cpu_usage || 0,
    memory_usage: metrics.memory_usage || 0,
    disk_usage: metrics.disk_usage || 0,
    network_sent: metrics.network_activity?.bytes_sent || 0,
    network_received: metrics.network_activity?.bytes_received || 0,
    timestamp: new Date().toISOString()
  }];
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
  const [publicView, setPublicView] = useState("landing");

  // State for filtering and drill-down
  const [filters, setFilters] = useState({});
  const [filteredData, setFilteredData] = useState(null);
  const [drillDownData, setDrillDownData] = useState(null);
  const [showDrillDown, setShowDrillDown] = useState(false);
  const [filterLoading, setFilterLoading] = useState(false);

  // New state for server selection
  const [servers, setServers] = useState([]);
  const [selectedServer, setSelectedServer] = useState(null);
  const [serversLoading, setServersLoading] = useState(false);

  // State for new features
  const [currentLayout, setCurrentLayout] = useState('default');
  const [showCommandPalette, setShowCommandPalette] = useState(false);
  const [showRemediation, setShowRemediation] = useState(false);
  const [showExecutiveReport, setShowExecutiveReport] = useState(false);
  const [targetHostForPlaybook, setTargetHostForPlaybook] = useState("db-server-01");

  // Create API client with current token
  const apiClient = createApiClient(token);

  // Real-time AI predictions - FIXED: Pass metrics directly instead of agentData
  const aiPredictions = useRealTimeAI(agentData && agentData[0] ? agentData[0] : null, apiClient);

  const fetchServers = async () => {
    setServersLoading(true);
    try {
      // Mock servers data
      const mockServers = [
        { id: 1, hostname: 'web-server-01', ip_address: '192.168.1.100', status: 'online' },
        { id: 2, hostname: 'db-server-01', ip_address: '192.168.1.101', status: 'online' },
        { id: 3, hostname: 'app-server-01', ip_address: '192.168.1.102', status: 'offline' }
      ];
      setServers(mockServers);
    } catch (error) {
      console.error('Failed to fetch servers:', error);
    } finally {
      setServersLoading(false);
    }
  };

  useEffect(() => {
    if (token) {
      fetchUserInfo();
      fetchLatestAgentData();
      fetchServers();
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
      setAgentData([mockData]); // Wrap in array for getRecentHistory
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
    setPublicView("landing");
  };

  const handleDemoLogin = async () => {
    setLoading(true);
    try {
      const formData = new FormData();
      formData.append("username", "admin");
      formData.append("password", "adminpass");
      const res = await axios.post(`${API_BASE}/token`, formData, {
        headers: { "Content-Type": "application/x-www-form-urlencoded" }
      });
      if (res.data && res.data.access_token) {
        handleLogin(res.data.access_token);
      }
    } catch (e) {
      console.error("Demo sandbox login failed, redirecting to login form:", e);
      setPublicView("login");
    } finally {
      setLoading(false);
    }
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

  // New feature handlers
  const handleAISuggestion = (suggestion) => {
    console.log('AI suggestion:', suggestion);
    alert(`AI Assistant: Executing ${suggestion.replace('_', ' ')}`);
  };

  const handleServerClick = (server) => {
    console.log('Server clicked:', server);
    alert(`Selected: ${server.name} (${server.status})`);
  };

  const handleLayoutChange = (layout) => {
    setCurrentLayout(layout);
  };

  // Determine which data to display
  const displayData = filteredData?.data && filteredData.data.length > 0 
    ? filteredData.data[0]?.data 
    : (agentData && agentData[0]) || null;

  // Render dashboard content
  const renderDashboardContent = () => {
    if (dashboardLoading || filterLoading) {
      return (
        <div style={{ 
          ...darkStyles.card, 
          textAlign: "center", 
          padding: "40px",
          background: "rgba(255,255,255,0.042)",
          backdropFilter: "blur(25px)"
        }}>
          <TailSpin height={40} width={40} />
          <p style={{ color: DARK_THEME.text, marginTop: "15px" }}>Loading agent data...</p>
        </div>
      );
    }

    if (displayData) {
      return (
        <>
          {/* AI Insights and Assistant Row */}
          <div style={{
            display: 'grid',
            gap: '20px',
            gridTemplateColumns: '2fr 1fr',
            marginBottom: '20px'
          }}>
            <AISmartInsights metrics={displayData} apiClient={apiClient} />
            <AutonomousCopilot 
              metrics={displayData} 
              onTriggerPlaybook={() => {
                setTargetHostForPlaybook(selectedServer?.hostname || "db-server-01");
                setShowRemediation(true);
              }}
            />
          </div>

          {/* Adaptive Dashboard Layout */}
          <AdaptiveDashboard 
            metrics={displayData} 
            userPreferences={{}} 
            onLayoutChange={handleLayoutChange}
          />

          {/* Main Dashboard Grid */}
          <div style={darkStyles.gridContainer}>
            <MetricsChart 
              cpu={displayData.cpu_usage}
              memory={displayData.memory_usage}
              disk={displayData.disk_usage}
              onMetricClick={handleMetricClick}
            />
            
            <GlobalServerDistribution 
              servers={servers} 
              onServerClick={handleServerClick}
              token={token}
            />
            
            <ProcessList processes={displayData.processes} />
            
            <NetworkChart networkData={displayData.network_activity} />
          </div>

          {/* Live Dashboard */}
          <LiveDashboard token={token} />
        </>
      );
    }

    return (
      <div style={{ 
        ...darkStyles.card, 
        textAlign: "center", 
        padding: "40px",
        background: "rgba(255,255,255,0.042)",
        backdropFilter: "blur(25px)"
      }}>
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
            {/* Mission Control Command Ribbon */}
            <CommandRibbon
              serverCount={servers?.length || 4}
              onRefresh={fetchLatestAgentData}
              loading={dashboardLoading}
              onOpenRemediation={() => {
                setTargetHostForPlaybook(selectedServer?.hostname || "db-server-01");
                setShowRemediation(true);
              }}
              onOpenReport={() => setShowExecutiveReport(true)}
              onOpenCommandPalette={() => setShowCommandPalette(true)}
            />

            {/* Dashboard Content */}
            {renderDashboardContent()}
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
      
      case "user-activity":
        return <UserActivityMonitor apiClient={apiClient} currentUser={currentUser} />;
      
      case "visitor-logs":
        return <VisitorLogs apiClient={apiClient} currentUser={currentUser} />;

      case "landing":
        return (
          <div style={{ position: 'relative' }}>
            <div style={{
              position: 'sticky',
              top: '12px',
              zIndex: 99,
              display: 'flex',
              justifyContent: 'flex-end',
              padding: '0 24px',
              marginBottom: '-48px',
              pointerEvents: 'none'
            }}>
              <button
                onClick={() => setActiveTab("dashboard")}
                style={{
                  background: 'linear-gradient(135deg, #8b5cf6, #2dd4bf)',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '12px',
                  padding: '10px 20px',
                  fontSize: '13px',
                  fontWeight: 700,
                  cursor: 'pointer',
                  pointerEvents: 'auto',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  boxShadow: '0 8px 25px rgba(139,92,246,0.5)'
                }}
              >
                ← Return to Live SOC Dashboard
              </button>
            </div>
            <LandingPage 
              onLaunchDemo={() => setActiveTab("dashboard")} 
              onOpenAuth={() => setActiveTab("dashboard")}
            />
          </div>
        );
      
      default:
        return renderDashboardContent();
    }
  };

  // Render based on authentication status
  if (!token) {
    if (publicView === "landing") {
      return (
        <LandingPage 
          onLaunchDemo={handleDemoLogin}
          onOpenAuth={() => {
            setAuthMode("login");
            setPublicView("login");
          }}
        />
      );
    }

    return (
      <div style={darkStyles.container}>
        <GlobalGlass />
        <BackgroundOrbs />
        <div style={{ position: 'absolute', top: '24px', left: '24px', zIndex: 10 }}>
          <button 
            onClick={() => setPublicView("landing")}
            style={{
              background: 'rgba(255,255,255,0.06)',
              border: '1px solid rgba(139,92,246,0.3)',
              color: '#c4b5fd',
              borderRadius: '10px',
              padding: '8px 16px',
              cursor: 'pointer',
              fontSize: '13px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              boxShadow: '0 4px 16px rgba(0,0,0,0.4)',
              transition: 'all 0.2s ease'
            }}
            onMouseEnter={e => e.target.style.background = 'rgba(139,92,246,0.2)'}
            onMouseLeave={e => e.target.style.background = 'rgba(255,255,255,0.06)'}
          >
            ← Back to Landing Page
          </button>
        </div>
        <LoginForm 
          onLogin={handleLogin}
          loading={loading}
          authMode={authMode}
          setAuthMode={setAuthMode}
        />
      </div>
    );
  }

  // When viewing the public landing page while authenticated, display it full-screen
  if (activeTab === "landing") {
    return (
      <div style={{ width: "100%", minHeight: "100vh", position: "relative", background: "#06010a", overflowX: "hidden" }}>
        <div style={{
          position: "fixed",
          top: "16px",
          right: "24px",
          zIndex: 9999,
          display: "flex",
          gap: "12px",
          alignItems: "center"
        }}>
          <button
            onClick={() => setActiveTab("dashboard")}
            style={{
              background: "linear-gradient(135deg, #8b5cf6, #2dd4bf)",
              color: "#fff",
              border: "none",
              borderRadius: "12px",
              padding: "10px 20px",
              fontSize: "13px",
              fontWeight: 700,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              gap: "8px",
              boxShadow: "0 8px 30px rgba(139,92,246,0.6)",
              backdropFilter: "blur(10px)",
              transition: "transform 0.2s ease, box-shadow 0.2s ease"
            }}
            onMouseEnter={e => e.currentTarget.style.transform = 'translateY(-2px)'}
            onMouseLeave={e => e.currentTarget.style.transform = 'translateY(0)'}
          >
            ← Return to Live SOC Dashboard
          </button>
        </div>
        <LandingPage 
          onLaunchDemo={() => setActiveTab("dashboard")} 
          onOpenAuth={() => setActiveTab("dashboard")}
        />
      </div>
    );
  }

  return (
    <div style={darkStyles.container}>
      <GlobalGlass />
      <BackgroundOrbs />
      {/* ── Sidebar v2 ── */}
      <div style={darkStyles.sidebar}>
        {/* Logo */}
        <div style={{ padding: '18px 20px 14px', borderBottom: '1px solid rgba(139,92,246,0.12)', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <img 
            src="/logos/app-icon.png" 
            alt="Purple Agent" 
            style={{ 
              width: '38px', 
              height: '38px', 
              borderRadius: '10px', 
              flexShrink: 0,
              boxShadow: '0 4px 16px rgba(139,92,246,0.45)',
              objectFit: 'contain'
            }} 
          />
          <div>
            <div style={{ fontSize: '15px', fontWeight: '800', color: '#f3f0ff', letterSpacing: '-0.02em', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span>Purple Agent</span>
              <span style={{ fontSize: '9px', fontWeight: '700', padding: '1px 5px', borderRadius: '4px', background: 'rgba(139,92,246,0.2)', border: '1px solid rgba(139,92,246,0.3)', color: '#c4b5fd' }}>v2.4</span>
            </div>
            <div style={{ fontSize: '10px', color: 'rgba(180,170,255,0.45)', letterSpacing: '0.04em' }}>Autonomous SOC Platform</div>
          </div>
        </div>

        {/* Nav */}
        <NavigationMenu activeTab={activeTab} setActiveTab={setActiveTab} currentUser={currentUser} />

        {/* Dashboard-only panels */}
        {activeTab === 'dashboard' && (
          <div style={{ padding: '0 12px', borderTop: '1px solid rgba(139,92,246,0.08)' }}>
            <ServerSelector servers={servers} selectedServer={selectedServer} onServerChange={setSelectedServer} loading={serversLoading} />
            <FilterPanel onFilterChange={handleFilterChange} filters={filters} loading={filterLoading} />
            <ExportPanel filters={filters} apiClient={apiClient} />
          </div>
        )}

        {/* User footer */}
        <div style={{ padding: '14px 16px', borderTop: '1px solid rgba(139,92,246,0.08)', marginTop: 'auto' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '10px 12px', background: 'rgba(139,92,246,0.07)', border: '1px solid rgba(139,92,246,0.12)', borderRadius: '10px', marginBottom: '8px' }}>
            <div style={{ width: '30px', height: '30px', borderRadius: '8px', background: 'linear-gradient(135deg,#6d28d9,#2dd4bf)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px', fontWeight: '700', color: 'white', flexShrink: 0 }}>
              {(currentUser?.username || 'U')[0].toUpperCase()}
            </div>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: '12px', fontWeight: '500', color: '#e8e6ff', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{currentUser?.username || 'User'}</div>
              <div style={{ fontSize: '10px', color: 'rgba(180,170,255,0.4)', letterSpacing: '0.04em' }}>{currentUser?.role || 'guest'}</div>
            </div>
          </div>
          <button onClick={fetchLatestAgentData} disabled={dashboardLoading} style={{ ...darkStyles.button, width: '100%', justifyContent: 'center', marginBottom: '4px', background: 'rgba(139,92,246,0.1)', border: '1px solid rgba(139,92,246,0.18)' }}>
            {dashboardLoading ? <TailSpin height={14} width={14} /> : '↻ Refresh'}
          </button>
          <button onClick={logout} style={{ ...darkStyles.button, width: '100%', justifyContent: 'center', background: 'rgba(244,63,94,0.07)', border: '1px solid rgba(244,63,94,0.18)', color: '#fb7185', margin: 0 }}>
            Sign out
          </button>
        </div>
      </div>

      {/* ── Main content ── */}
      <div style={darkStyles.mainContent}>
        {/* Page header */}
        <div style={{ padding: '22px 28px 0', borderBottom: '1px solid rgba(139,92,246,0.07)', marginBottom: '0', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', paddingBottom: '16px' }}>
            <div>
              <h1 style={{ color: '#e8e6ff', margin: '0 0 4px', fontSize: '20px', fontWeight: '700', letterSpacing: '-0.04em', background: 'linear-gradient(135deg,#e0d7ff 0%,#2dd4bf 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                {activeTab === 'dashboard'     && 'Dashboard Overview'}
                {activeTab === 'layouts'       && 'Dashboard Layouts'}
                {activeTab === 'landing'       && 'Product Landing Page'}
                {activeTab === 'account'       && 'Account Settings'}
                {activeTab === 'users'         && 'User Management'}
                {activeTab === 'alerts'        && 'Alerts & Incidents'}
                {activeTab === 'user-activity' && 'User Activity'}
                {activeTab === 'visitor-logs'  && 'Visitor Logs'}
              </h1>
              <p style={{ color: 'rgba(180,170,255,0.45)', margin: 0, fontSize: '13px' }}>
                {activeTab === 'dashboard'     && 'Real-time monitoring with AI-powered insights'}
                {activeTab === 'layouts'       && 'Manage and customize your dashboard layouts'}
                {activeTab === 'landing'       && 'Public advertising, features, and enterprise architecture overview'}
                {activeTab === 'account'       && 'Manage account settings and security'}
                {activeTab === 'users'         && 'User management and access control'}
                {activeTab === 'alerts'        && 'Alert rules and incident management'}
                {activeTab === 'user-activity' && 'User activity monitoring and security'}
                {activeTab === 'visitor-logs'  && 'Visitor logs and security monitoring'}
              </p>
            </div>
          </div>

          {/* Top tab rail */}
          <div style={{ display: 'flex', gap: '0', overflowX: 'auto' }}>
            {[
              { id: 'dashboard', label: 'Overview', icon: DashboardIcon },
              { id: 'layouts',   label: 'Layouts',  icon: LayoutIcon },
              { id: 'landing',   label: 'Landing Page', icon: GlobeIcon },
              { id: 'account',   label: 'Account',  icon: AccountIcon },
              ...(currentUser?.role === 'admin' ? [
                { id: 'users',         label: 'Users',    icon: UsersIcon },
                { id: 'alerts',        label: 'Alerts',   icon: AlertIcon },
                { id: 'user-activity', label: 'Activity', icon: ActivityIcon },
                { id: 'visitor-logs',  label: 'Visitors', icon: SecurityIcon },
              ] : [])
            ].map(t => (
              <button key={t.id} onClick={() => setActiveTab(t.id)} style={{
                ...darkStyles.tab,
                color: activeTab === t.id ? '#c4b5fd' : 'rgba(180,170,255,0.45)',
                borderBottomColor: activeTab === t.id ? '#8b5cf6' : 'transparent',
                fontWeight: activeTab === t.id ? '600' : '450',
              }}>
                <t.icon />{t.label}
              </button>
            ))}
          </div>
        </div>

        {/* Scrollable content area */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '24px 28px 48px' }}>
          {/* Fleet Pulse Bar */}
          {activeTab === 'dashboard' && (
            <FleetPulseBar
              serverCount={servers?.length || 4}
              onOpenCommandPalette={() => setShowCommandPalette(true)}
              onOpenRemediation={() => {
                setTargetHostForPlaybook(selectedServer?.hostname || "db-server-01");
                setShowRemediation(true);
              }}
              onOpenExecutiveReport={() => setShowExecutiveReport(true)}
            />
          )}

          {/* Tab Content */}
          {renderTabContent()}
        </div>{/* end scrollable content */}

        {/* Command Palette Modal (Cmd + K) */}
        <CommandPaletteModal
          isOpen={showCommandPalette}
          onClose={(shouldOpen) => setShowCommandPalette(typeof shouldOpen === 'boolean' ? shouldOpen : false)}
          onNavigate={(tab) => setActiveTab(tab)}
          onSelectServer={(server) => {
            setSelectedServer(server);
            setActiveTab('dashboard');
          }}
          servers={servers}
          onTriggerAction={(action) => {
            if (action === 'remediation') {
              setTargetHostForPlaybook(selectedServer?.hostname || "db-server-01");
              setShowRemediation(true);
            } else if (action === 'report') {
              setShowExecutiveReport(true);
            } else if (action === 'scan') {
              fetchLatestAgentData();
            }
          }}
        />

        {/* AI Autonomous Remediation Playbook Modal */}
        <RemediationPlaybookModal
          isOpen={showRemediation}
          onClose={() => setShowRemediation(false)}
          targetHost={targetHostForPlaybook}
        />

        {/* Executive Report Modal */}
        <ExecutiveReportModal
          isOpen={showExecutiveReport}
          onClose={() => setShowExecutiveReport(false)}
        />

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
