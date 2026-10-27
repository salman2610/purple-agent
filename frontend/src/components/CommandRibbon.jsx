import React from 'react';

export default function CommandRibbon({
  onRefresh,
  loading,
  onOpenRemediation,
  onOpenReport,
  onOpenCommandPalette,
  serverCount = 4
}) {
  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
      gap: '14px',
      marginBottom: '20px',
    }}>
      {/* KPI 1: Fleet Availability */}
      <div style={{
        padding: '16px 18px',
        borderRadius: '14px',
        background: 'linear-gradient(135deg, rgba(139, 92, 246, 0.08) 0%, rgba(7, 7, 26, 0.7) 100%)',
        border: '1px solid rgba(139, 92, 246, 0.2)',
        boxShadow: '0 8px 24px rgba(0, 0, 0, 0.4)',
        position: 'relative',
        overflow: 'hidden',
      }}>
        <div style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '2px', background: 'linear-gradient(90deg, #8b5cf6, #2dd4bf)' }} />
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
          <span style={{ fontSize: '11px', fontWeight: '600', letterSpacing: '0.07em', textTransform: 'uppercase', color: 'rgba(180, 170, 255, 0.5)' }}>
            Fleet Posture
          </span>
          <span style={{
            fontSize: '9px', fontWeight: '700', padding: '2px 6px', borderRadius: '4px',
            background: 'rgba(45, 212, 191, 0.15)', color: '#2dd4bf', border: '1px solid rgba(45, 212, 191, 0.3)'
          }}>
            OPTIMAL
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
          <span style={{ fontSize: '26px', fontWeight: '700', color: '#f3f0ff', fontFamily: "'JetBrains Mono', monospace" }}>
            99.98%
          </span>
          <span style={{ fontSize: '11px', color: '#2dd4bf' }}>↑ 0.02%</span>
        </div>
        <div style={{ fontSize: '11px', color: 'rgba(180, 170, 255, 0.45)', marginTop: '4px' }}>
          {serverCount} Monitored Hosts in Sync
        </div>
      </div>

      {/* KPI 2: AI LSTM Anomaly Engine */}
      <div style={{
        padding: '16px 18px',
        borderRadius: '14px',
        background: 'linear-gradient(135deg, rgba(45, 212, 191, 0.08) 0%, rgba(7, 7, 26, 0.7) 100%)',
        border: '1px solid rgba(45, 212, 191, 0.2)',
        boxShadow: '0 8px 24px rgba(0, 0, 0, 0.4)',
        position: 'relative',
        overflow: 'hidden',
      }}>
        <div style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '2px', background: 'linear-gradient(90deg, #2dd4bf, #38bdf8)' }} />
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
          <span style={{ fontSize: '11px', fontWeight: '600', letterSpacing: '0.07em', textTransform: 'uppercase', color: 'rgba(180, 170, 255, 0.5)' }}>
            AI Anomaly Score
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
            <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#2dd4bf', animation: 'live-pulse 2s infinite' }} />
            <span style={{ fontSize: '9px', fontWeight: '700', color: '#2dd4bf' }}>ACTIVE</span>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
          <span style={{ fontSize: '26px', fontWeight: '700', color: '#2dd4bf', fontFamily: "'JetBrains Mono', monospace" }}>
            0.014
          </span>
          <span style={{ fontSize: '11px', color: 'rgba(180, 170, 255, 0.5)' }}>/ 1.00 max</span>
        </div>
        <div style={{ fontSize: '11px', color: 'rgba(180, 170, 255, 0.45)', marginTop: '4px' }}>
          LSTM Recurrent Neural Net Nominal
        </div>
      </div>

      {/* KPI 3: Telemetry Stream Throughput */}
      <div style={{
        padding: '16px 18px',
        borderRadius: '14px',
        background: 'linear-gradient(135deg, rgba(56, 189, 248, 0.08) 0%, rgba(7, 7, 26, 0.7) 100%)',
        border: '1px solid rgba(56, 189, 248, 0.2)',
        boxShadow: '0 8px 24px rgba(0, 0, 0, 0.4)',
        position: 'relative',
        overflow: 'hidden',
      }}>
        <div style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '2px', background: 'linear-gradient(90deg, #38bdf8, #818cf8)' }} />
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
          <span style={{ fontSize: '11px', fontWeight: '600', letterSpacing: '0.07em', textTransform: 'uppercase', color: 'rgba(180, 170, 255, 0.5)' }}>
            Ingestion Velocity
          </span>
          <span style={{
            fontSize: '9px', fontWeight: '700', padding: '2px 6px', borderRadius: '4px',
            background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.3)'
          }}>
            14ms WS
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
          <span style={{ fontSize: '26px', fontWeight: '700', color: '#f3f0ff', fontFamily: "'JetBrains Mono', monospace" }}>
            1,480
          </span>
          <span style={{ fontSize: '11px', color: '#38bdf8' }}>events/s</span>
        </div>
        <div style={{ fontSize: '11px', color: 'rgba(180, 170, 255, 0.45)', marginTop: '4px' }}>
          Zero Buffer Loss • E2E Encrypted
        </div>
      </div>

      {/* KPI 4: Interactive Mission Control Actions */}
      <div style={{
        padding: '14px 16px',
        borderRadius: '14px',
        background: 'linear-gradient(135deg, rgba(139, 92, 246, 0.12) 0%, rgba(7, 7, 26, 0.8) 100%)',
        border: '1px solid rgba(139, 92, 246, 0.25)',
        boxShadow: '0 8px 24px rgba(0, 0, 0, 0.4)',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        gap: '8px',
      }}>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            onClick={onOpenRemediation}
            style={{
              flex: 1,
              padding: '8px 10px',
              borderRadius: '8px',
              border: 'none',
              background: 'linear-gradient(135deg, #7c3aed 0%, #0d9488 100%)',
              color: 'white',
              fontSize: '11px',
              fontWeight: '600',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '6px',
              boxShadow: '0 4px 12px rgba(124, 58, 237, 0.3)',
            }}
          >
            <span>⚡ AI Playbook</span>
          </button>
          <button
            onClick={onOpenReport}
            style={{
              flex: 1,
              padding: '8px 10px',
              borderRadius: '8px',
              border: '1px solid rgba(139, 92, 246, 0.3)',
              background: 'rgba(139, 92, 246, 0.15)',
              color: '#c4b5fd',
              fontSize: '11px',
              fontWeight: '600',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '4px',
            }}
          >
            <span>📄 CISO Brief</span>
          </button>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            onClick={onOpenCommandPalette}
            style={{
              flex: 1,
              padding: '7px 10px',
              borderRadius: '8px',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              background: 'rgba(255, 255, 255, 0.04)',
              color: 'rgba(220, 215, 255, 0.85)',
              fontSize: '11px',
              fontWeight: '500',
              cursor: 'pointer',
            }}
          >
            ⌘K Palette
          </button>
          <button
            onClick={onRefresh}
            disabled={loading}
            style={{
              padding: '7px 12px',
              borderRadius: '8px',
              border: '1px solid rgba(139, 92, 246, 0.25)',
              background: 'rgba(139, 92, 246, 0.1)',
              color: '#a78bfa',
              fontSize: '11px',
              fontWeight: '500',
              cursor: loading ? 'wait' : 'pointer',
            }}
          >
            {loading ? '...' : '↻ Sync'}
          </button>
        </div>
      </div>
    </div>
  );
}
