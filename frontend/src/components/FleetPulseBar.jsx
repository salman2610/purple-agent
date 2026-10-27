import React from 'react';

export default function FleetPulseBar({ onOpenCommandPalette, onOpenRemediation, onOpenExecutiveReport, serverCount = 4 }) {
  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      flexWrap: 'wrap',
      gap: '12px',
      padding: '12px 18px',
      marginBottom: '20px',
      background: 'linear-gradient(135deg, rgba(139, 92, 246, 0.08) 0%, rgba(45, 212, 191, 0.05) 50%, rgba(7, 7, 26, 0.8) 100%)',
      backdropFilter: 'blur(20px)',
      border: '1px solid rgba(139, 92, 246, 0.2)',
      borderRadius: '14px',
      boxShadow: '0 8px 32px rgba(0, 0, 0, 0.35)',
    }}>
      {/* Left: Telemetry & Engine Status Chips */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
        {/* Fleet Health Badge */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '6px 12px',
          borderRadius: '8px',
          background: 'rgba(45, 212, 191, 0.1)',
          border: '1px solid rgba(45, 212, 191, 0.25)',
        }}>
          <div style={{
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            background: '#2dd4bf',
            boxShadow: '0 0 10px #2dd4bf',
            animation: 'live-pulse 2s infinite',
          }} />
          <span style={{ fontSize: '12px', fontWeight: '600', color: '#2dd4bf' }}>
            FLEET NOMINAL
          </span>
          <span style={{ fontSize: '11px', color: 'rgba(45, 212, 191, 0.7)' }}>
            ({serverCount} Nodes Online)
          </span>
        </div>

        {/* AI Engine Status */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          padding: '6px 12px',
          borderRadius: '8px',
          background: 'rgba(139, 92, 246, 0.12)',
          border: '1px solid rgba(139, 92, 246, 0.25)',
        }}>
          <span style={{ fontSize: '13px' }}>🧠</span>
          <span style={{ fontSize: '11px', fontWeight: '600', color: '#c4b5fd' }}>
            PyTorch LSTM v2.4
          </span>
          <span style={{
            fontSize: '9px',
            padding: '1px 5px',
            borderRadius: '4px',
            background: 'rgba(139, 92, 246, 0.3)',
            color: '#e9d5ff',
            fontWeight: '600',
          }}>
            3.4ms INFERENCE
          </span>
        </div>

        {/* WebSocket Stream Badge */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          padding: '6px 10px',
          borderRadius: '8px',
          background: 'rgba(56, 189, 248, 0.08)',
          border: '1px solid rgba(56, 189, 248, 0.2)',
          fontSize: '11px',
          color: '#38bdf8',
        }}>
          <span style={{ display: 'inline-block', width: '6px', height: '6px', borderRadius: '50%', background: '#38bdf8' }} />
          <span>Real-time WS (14ms)</span>
        </div>
      </div>

      {/* Right: High-Value Executive & SRE Action Buttons */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
        {/* Command Palette Trigger */}
        <button
          onClick={onOpenCommandPalette}
          title="Open Quick Command Palette (Cmd + K)"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '7px 12px',
            borderRadius: '8px',
            background: 'rgba(255, 255, 255, 0.04)',
            border: '1px solid rgba(139, 92, 246, 0.25)',
            color: 'rgba(220, 215, 255, 0.9)',
            fontSize: '12px',
            fontWeight: '500',
            cursor: 'pointer',
            transition: 'all 0.15s ease',
          }}
        >
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="8"></circle>
            <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
          </svg>
          <span>Search / Actions</span>
          <span style={{
            fontSize: '10px',
            fontFamily: "'JetBrains Mono', monospace",
            padding: '2px 5px',
            borderRadius: '4px',
            background: 'rgba(139, 92, 246, 0.2)',
            color: '#c4b5fd',
          }}>
            ⌘K
          </span>
        </button>

        {/* AI Autonomous Remediation Trigger */}
        <button
          onClick={onOpenRemediation}
          title="Trigger AI Autonomous Remediation Playbook"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '7px 14px',
            borderRadius: '8px',
            background: 'linear-gradient(135deg, rgba(124, 58, 237, 0.35) 0%, rgba(45, 212, 191, 0.25) 100%)',
            border: '1px solid rgba(139, 92, 246, 0.4)',
            color: '#e8e6ff',
            fontSize: '12px',
            fontWeight: '600',
            cursor: 'pointer',
            boxShadow: '0 2px 12px rgba(124, 58, 237, 0.25)',
            transition: 'all 0.15s ease',
          }}
        >
          <span style={{ color: '#2dd4bf' }}>⚡</span>
          <span>AI Playbook</span>
        </button>

        {/* Executive Report Button */}
        <button
          onClick={onOpenExecutiveReport}
          title="Generate Executive SRE Briefing"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '7px 12px',
            borderRadius: '8px',
            background: 'rgba(139, 92, 246, 0.12)',
            border: '1px solid rgba(139, 92, 246, 0.25)',
            color: '#c4b5fd',
            fontSize: '12px',
            fontWeight: '500',
            cursor: 'pointer',
            transition: 'all 0.15s ease',
          }}
        >
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
            <polyline points="14 2 14 8 20 8"></polyline>
            <line x1="16" y1="13" x2="8" y2="13"></line>
            <line x1="16" y1="17" x2="8" y2="17"></line>
          </svg>
          <span>Executive Brief</span>
        </button>
      </div>
    </div>
  );
}
