import React from 'react';

export default function ExecutiveReportModal({ isOpen, onClose }) {
  if (!isOpen) return null;

  const handlePrint = () => {
    window.print();
  };

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 9999,
        background: 'rgba(5, 4, 18, 0.8)',
        backdropFilter: 'blur(16px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '24px',
        animation: 'fadeIn 0.15s ease-out',
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: '680px',
          maxHeight: '90vh',
          background: '#0d0b26',
          border: '1px solid rgba(139, 92, 246, 0.35)',
          borderRadius: '18px',
          boxShadow: '0 24px 64px rgba(0, 0, 0, 0.85), 0 0 40px rgba(139, 92, 246, 0.2)',
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          animation: 'slideInDown 0.2s ease-out',
        }}
      >
        {/* Header */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '20px 24px',
          borderBottom: '1px solid rgba(139, 92, 246, 0.15)',
          background: 'rgba(139, 92, 246, 0.08)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <img 
              src="/logos/app-icon.png" 
              alt="Purple Agent" 
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '9px',
                objectFit: 'contain',
                boxShadow: '0 4px 14px rgba(139, 92, 246, 0.4)',
              }} 
            />
            <div>
              <div style={{ fontSize: '16px', fontWeight: '700', color: '#f3f0ff', letterSpacing: '-0.01em' }}>
                Executive SRE & Security Briefing
              </div>
              <div style={{ fontSize: '11px', color: 'rgba(180, 170, 255, 0.6)' }}>
                Purple Agent Autonomous Defense • Report Period: Last 7 Days
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'rgba(180, 170, 255, 0.6)',
              fontSize: '18px',
              cursor: 'pointer',
              padding: '4px 8px',
            }}
          >
            ✕
          </button>
        </div>

        {/* Scrollable Report Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Executive KPI Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
            {[
              { val: '99.98%', label: 'Fleet Availability', color: '#2dd4bf' },
              { val: '38s', label: 'Mean Time to Mitigate', color: '#8b5cf6' },
              { val: '0', label: 'Critical Zero-Days', color: '#2dd4bf' },
              { val: '99.4%', label: 'AI Anomaly Precision', color: '#38bdf8' },
            ].map(k => (
              <div key={k.label} style={{
                padding: '14px 12px',
                borderRadius: '12px',
                background: 'rgba(139, 92, 246, 0.06)',
                border: '1px solid rgba(139, 92, 246, 0.16)',
                textAlign: 'center',
              }}>
                <div style={{ fontSize: '20px', fontWeight: '700', color: k.color, fontFamily: "'JetBrains Mono', monospace" }}>{k.val}</div>
                <div style={{ fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'rgba(180, 170, 255, 0.5)', marginTop: '4px' }}>{k.label}</div>
              </div>
            ))}
          </div>

          {/* AI Executive Analysis */}
          <div style={{
            padding: '16px 20px',
            borderRadius: '12px',
            background: 'linear-gradient(135deg, rgba(139, 92, 246, 0.1) 0%, rgba(45, 212, 191, 0.05) 100%)',
            border: '1px solid rgba(139, 92, 246, 0.22)',
          }}>
            <div style={{ fontSize: '11px', fontWeight: '700', letterSpacing: '0.08em', textTransform: 'uppercase', color: '#c4b5fd', marginBottom: '6px' }}>
              ✦ Autonomous Defense Summary
            </div>
            <p style={{ margin: 0, fontSize: '13px', color: '#e8e6ff', lineHeight: 1.6 }}>
              All <strong>4 distributed server nodes</strong> remained nominal throughout the observation cycle. The LSTM anomaly detection engine screened <strong>14,290 telemetry samples</strong> and auto-mitigated 2 minor thread pressure anomalies on <code>db-server-01</code> before user-facing SLA impact occurred. Zero brute-force login attempts breached JWT gatekeepers.
            </p>
          </div>

          {/* Fleet Nodes Breakdown */}
          <div>
            <div style={{ fontSize: '12px', fontWeight: '700', letterSpacing: '0.06em', textTransform: 'uppercase', color: 'rgba(180, 170, 255, 0.6)', marginBottom: '10px' }}>
              Monitored Nodes Health & Posture
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {[
                { host: 'default-server', ip: '127.0.0.1', cpu: '18%', mem: '42%', status: 'Nominal', score: '99.9%' },
                { host: 'web-server-01', ip: '192.168.1.101', cpu: '26%', mem: '51%', status: 'Nominal', score: '99.8%' },
                { host: 'db-server-01', ip: '192.168.1.102', cpu: '34%', mem: '68%', status: 'Optimized', score: '99.6%' },
                { host: 'app-server-01', ip: '192.168.1.103', cpu: '21%', mem: '45%', status: 'Nominal', score: '99.9%' },
              ].map(n => (
                <div key={n.host} style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '10px 14px',
                  borderRadius: '10px',
                  background: 'rgba(255, 255, 255, 0.02)',
                  border: '1px solid rgba(139, 92, 246, 0.1)',
                  fontSize: '12px',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#2dd4bf' }} />
                    <span style={{ fontWeight: '600', color: '#e8e6ff' }}>{n.host}</span>
                    <span style={{ color: 'rgba(180, 170, 255, 0.4)', fontFamily: "'JetBrains Mono', monospace", fontSize: '11px' }}>{n.ip}</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px', fontFamily: "'JetBrains Mono', monospace", fontSize: '11px' }}>
                    <span style={{ color: 'rgba(180, 170, 255, 0.7)' }}>CPU: {n.cpu}</span>
                    <span style={{ color: 'rgba(180, 170, 255, 0.7)' }}>MEM: {n.mem}</span>
                    <span style={{ color: '#2dd4bf', fontWeight: '600' }}>SLA: {n.score}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div style={{
          padding: '16px 24px',
          borderTop: '1px solid rgba(139, 92, 246, 0.15)',
          background: 'rgba(139, 92, 246, 0.05)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}>
          <span style={{ fontSize: '11px', color: 'rgba(180, 170, 255, 0.4)' }}>
            Cryptographically signed by Purple Agent AI Kernel
          </span>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              onClick={handlePrint}
              style={{
                padding: '9px 18px',
                borderRadius: '8px',
                background: 'linear-gradient(135deg, #7c3aed, #4f46e5)',
                border: 'none',
                color: 'white',
                fontWeight: '600',
                fontSize: '13px',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
              }}
            >
              <span>🖨️ Print / Save as PDF</span>
            </button>
            <button
              onClick={onClose}
              style={{
                padding: '9px 16px',
                borderRadius: '8px',
                background: 'rgba(139, 92, 246, 0.15)',
                border: '1px solid rgba(139, 92, 246, 0.25)',
                color: '#c4b5fd',
                fontSize: '13px',
                cursor: 'pointer',
              }}
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
