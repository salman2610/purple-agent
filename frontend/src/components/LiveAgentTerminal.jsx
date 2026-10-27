import React, { useState, useEffect } from 'react';

const SAMPLE_LOGS = [
  { time: "12:44:01", tag: "NODE-01", type: "ok", msg: "agent-us-east-01 · Heartbeat nominal [CPU: 22.4%, MEM: 38.1%]" },
  { time: "12:44:03", tag: "AI-LSTM", type: "ai", msg: "PyTorch LSTM inference: 3.4ms · Anomaly score 0.012 [NOMINAL]" },
  { time: "12:44:05", tag: "INTEGRITY", type: "ok", msg: "File integrity scan: 4,120 critical hashes verified [CLEAN]" },
  { time: "12:44:07", tag: "NETWORK", type: "info", msg: "Socket buffer sync · 1,480 packets/sec · Zero packet loss" },
  { time: "12:44:09", tag: "ZERO-TRUST", type: "ok", msg: "JWT auth token rotation verified for agent daemon #38" },
  { time: "12:44:11", tag: "NODE-02", type: "ok", msg: "agent-eu-central-02 · Telemetry synced via TLS 1.3" },
  { time: "12:44:13", tag: "THREAT-INTEL", type: "info", msg: "Visitor IP correlation: 0 malicious signatures matched" },
  { time: "12:44:15", tag: "AUTONOMOUS", type: "ai", msg: "Predictive memory model: Nominal pressure for next 48h" },
];

export default function LiveAgentTerminal() {
  const [logs, setLogs] = useState(SAMPLE_LOGS.slice(0, 5));

  useEffect(() => {
    let index = 5;
    const interval = setInterval(() => {
      const nextLog = SAMPLE_LOGS[index % SAMPLE_LOGS.length];
      const now = new Date();
      const timeStr = now.toTimeString().split(' ')[0];
      setLogs(prev => [...prev.slice(1), { ...nextLog, time: timeStr }]);
      index++;
    }, 2400);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{
      borderRadius: '12px',
      background: 'rgba(5, 4, 18, 0.85)',
      border: '1px solid rgba(139, 92, 246, 0.25)',
      boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.05)',
      overflow: 'hidden',
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: '11px',
      marginTop: '20px',
      marginBottom: '24px',
    }}>
      {/* Terminal Titlebar */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '8px 12px',
        background: 'rgba(139, 92, 246, 0.08)',
        borderBottom: '1px solid rgba(139, 92, 246, 0.15)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#f43f5e', opacity: 0.8 }} />
          <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#f59e0b', opacity: 0.8 }} />
          <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#2dd4bf', opacity: 0.8 }} />
          <span style={{ marginLeft: '6px', fontSize: '10px', color: 'rgba(180, 170, 255, 0.7)', letterSpacing: '0.04em' }}>
            purple-agent-daemon :: stream
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <div style={{
            width: '6px',
            height: '6px',
            borderRadius: '50%',
            background: '#2dd4bf',
            boxShadow: '0 0 8px #2dd4bf',
            animation: 'live-pulse 1.8s infinite',
          }} />
          <span style={{ fontSize: '9px', fontWeight: '600', color: '#2dd4bf', letterSpacing: '0.08em' }}>
            LIVE FEED
          </span>
        </div>
      </div>

      {/* Terminal Body */}
      <div style={{ padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: '6px', minHeight: '110px' }}>
        {logs.map((log, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'baseline', gap: '8px', lineHeight: 1.4 }}>
            <span style={{ color: 'rgba(180, 170, 255, 0.35)', fontSize: '10px', flexShrink: 0 }}>
              {log.time}
            </span>
            <span style={{
              fontSize: '9px',
              padding: '1px 5px',
              borderRadius: '4px',
              fontWeight: '600',
              flexShrink: 0,
              background: log.type === 'ai' ? 'rgba(139, 92, 246, 0.2)' : log.type === 'ok' ? 'rgba(45, 212, 191, 0.15)' : 'rgba(56, 189, 248, 0.15)',
              color: log.type === 'ai' ? '#c4b5fd' : log.type === 'ok' ? '#2dd4bf' : '#38bdf8',
              border: `1px solid ${log.type === 'ai' ? 'rgba(139, 92, 246, 0.3)' : log.type === 'ok' ? 'rgba(45, 212, 191, 0.3)' : 'rgba(56, 189, 248, 0.3)'}`,
            }}>
              {log.tag}
            </span>
            <span style={{
              color: log.type === 'ai' ? '#e2d9ff' : 'rgba(230, 225, 255, 0.85)',
              wordBreak: 'break-all',
              fontSize: '11px',
            }}>
              {log.msg}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
