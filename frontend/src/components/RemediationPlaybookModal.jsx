import React, { useState } from 'react';

export default function RemediationPlaybookModal({ isOpen, onClose, targetHost = "db-server-01" }) {
  const [status, setStatus] = useState('idle'); // idle | running | success
  const [progress, setProgress] = useState(0);
  const [stepLogs, setStepLogs] = useState([]);

  if (!isOpen) return null;

  const handleExecutePlaybook = () => {
    setStatus('running');
    setProgress(15);
    setStepLogs(["[INIT] AI Autonomous Incident Remediation v2.4 initialized"]);

    setTimeout(() => {
      setProgress(40);
      setStepLogs(prev => [...prev, `[1/3] Draining idle connection pool on ${targetHost} ... OK`]);
    }, 600);

    setTimeout(() => {
      setProgress(75);
      setStepLogs(prev => [...prev, `[2/3] Applied dynamic rate-limit filter (15 req/sec) to IP subnet 192.168.1.0/24 ... OK`]);
    }, 1300);

    setTimeout(() => {
      setProgress(100);
      setStepLogs(prev => [
        ...prev,
        `[3/3] Python garbage collection triggered (freed 420 MB RAM) ... OK`,
        `[SUCCESS] Node nominal latency restored (14ms). Incident marked as RESOLVED.`
      ]);
      setStatus('success');
    }, 2100);
  };

  const handleReset = () => {
    setStatus('idle');
    setProgress(0);
    setStepLogs([]);
  };

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 9999,
        background: 'rgba(5, 4, 18, 0.78)',
        backdropFilter: 'blur(16px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '20px',
        animation: 'fadeIn 0.15s ease-out',
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: '620px',
          background: '#0d0b26',
          border: '1px solid rgba(139, 92, 246, 0.35)',
          borderRadius: '18px',
          boxShadow: '0 24px 64px rgba(0, 0, 0, 0.8), 0 0 40px rgba(139, 92, 246, 0.2)',
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          animation: 'slideInDown 0.2s ease-out',
        }}
      >
        {/* Title Header */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '18px 24px',
          borderBottom: '1px solid rgba(139, 92, 246, 0.15)',
          background: 'rgba(139, 92, 246, 0.08)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{
              width: '32px',
              height: '32px',
              borderRadius: '8px',
              background: 'linear-gradient(135deg, #8b5cf6, #2dd4bf)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '16px',
            }}>
              ⚡
            </div>
            <div>
              <div style={{ fontSize: '15px', fontWeight: '700', color: '#f3f0ff' }}>
                AI Autonomous Remediation Playbook
              </div>
              <div style={{ fontSize: '11px', color: 'rgba(180, 170, 255, 0.6)' }}>
                Target Host: <code style={{ color: '#2dd4bf' }}>{targetHost}</code> • Trigger: Anomaly Spike Correlated
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

        {/* Content Body */}
        <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Incident Diagnosis Card */}
          <div style={{
            padding: '14px 18px',
            borderRadius: '12px',
            background: 'rgba(244, 63, 94, 0.08)',
            border: '1px solid rgba(244, 63, 94, 0.25)',
            display: 'flex',
            flexDirection: 'column',
            gap: '6px',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: '11px', fontWeight: '700', color: '#fb7185', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
                ● Active Anomaly Signature
              </span>
              <span style={{ fontSize: '10px', padding: '2px 6px', borderRadius: '4px', background: 'rgba(244, 63, 94, 0.2)', color: '#fb7185', fontWeight: '600' }}>
                CONFIDENCE: 98.4%
              </span>
            </div>
            <div style={{ fontSize: '13px', color: '#ffe4e6', lineHeight: 1.5 }}>
              LSTM model detected <strong>Memory Pressure + Latency Spike (92%)</strong> on <code style={{ color: '#fb7185' }}>{targetHost}</code> correlated with a sudden burst of unindexed requests from subnet <code>192.168.1.0/24</code>.
            </div>
          </div>

          {/* Planned Playbook Steps */}
          <div>
            <div style={{ fontSize: '11px', fontWeight: '700', letterSpacing: '0.08em', textTransform: 'uppercase', color: 'rgba(180, 170, 255, 0.5)', marginBottom: '8px' }}>
              Autonomous Action Sequence
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {[
                { num: '01', title: 'Drain Stale Connection Buffer', desc: 'Isolates runaway worker connections to free pinned thread pools.' },
                { num: '02', title: 'Dynamic Adaptive Rate-Limiter', desc: 'Caps suspicious IP traffic burst without disrupting verified users.' },
                { num: '03', title: 'Trigger In-Memory Garbage Collection', desc: 'Reclaims ~400MB memory and notifies Slack channel #sre-alerts.' },
              ].map(step => (
                <div key={step.num} style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '12px',
                  padding: '10px 14px',
                  borderRadius: '10px',
                  background: 'rgba(139, 92, 246, 0.06)',
                  border: '1px solid rgba(139, 92, 246, 0.14)',
                }}>
                  <span style={{
                    fontSize: '11px',
                    fontWeight: '700',
                    color: '#c4b5fd',
                    fontFamily: "'JetBrains Mono', monospace",
                    padding: '2px 6px',
                    borderRadius: '4px',
                    background: 'rgba(139, 92, 246, 0.2)',
                  }}>
                    {step.num}
                  </span>
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: '600', color: '#e8e6ff' }}>{step.title}</div>
                    <div style={{ fontSize: '11px', color: 'rgba(180, 170, 255, 0.55)' }}>{step.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Execution Progress & Terminal */}
          {status !== 'idle' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: '#2dd4bf', fontWeight: '600' }}>
                <span>{status === 'running' ? 'Executing Playbook Steps...' : 'Playbook Completed Successfully'}</span>
                <span>{progress}%</span>
              </div>
              {/* Progress bar */}
              <div style={{ width: '100%', height: '6px', borderRadius: '3px', background: 'rgba(255, 255, 255, 0.08)', overflow: 'hidden' }}>
                <div style={{
                  width: `${progress}%`,
                  height: '100%',
                  background: 'linear-gradient(90deg, #8b5cf6, #2dd4bf)',
                  transition: 'width 0.4s ease',
                }} />
              </div>
              {/* Log stream */}
              <div style={{
                padding: '10px 12px',
                borderRadius: '8px',
                background: '#050412',
                border: '1px solid rgba(139, 92, 246, 0.2)',
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '11px',
                color: 'rgba(220, 215, 255, 0.85)',
                display: 'flex',
                flexDirection: 'column',
                gap: '4px',
                maxHeight: '120px',
                overflowY: 'auto',
              }}>
                {stepLogs.map((log, i) => (
                  <div key={i} style={{ color: log.includes('SUCCESS') ? '#2dd4bf' : 'rgba(200, 195, 255, 0.8)' }}>
                    {log}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div style={{
          padding: '16px 24px',
          borderTop: '1px solid rgba(139, 92, 246, 0.15)',
          background: 'rgba(139, 92, 246, 0.05)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}>
          <button
            onClick={onClose}
            style={{
              padding: '9px 16px',
              borderRadius: '8px',
              background: 'transparent',
              border: '1px solid rgba(180, 170, 255, 0.2)',
              color: 'rgba(180, 170, 255, 0.7)',
              fontSize: '13px',
              cursor: 'pointer',
            }}
          >
            Cancel
          </button>

          {status === 'idle' ? (
            <button
              onClick={handleExecutePlaybook}
              style={{
                padding: '10px 22px',
                borderRadius: '8px',
                background: 'linear-gradient(135deg, #7c3aed 0%, #0d9488 100%)',
                border: 'none',
                color: 'white',
                fontSize: '13px',
                fontWeight: '600',
                cursor: 'pointer',
                boxShadow: '0 4px 16px rgba(124, 58, 237, 0.4)',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <span>⚡ Execute Self-Healing Playbook</span>
            </button>
          ) : status === 'running' ? (
            <button disabled style={{
              padding: '10px 22px',
              borderRadius: '8px',
              background: 'rgba(124, 58, 237, 0.3)',
              border: 'none',
              color: 'rgba(255, 255, 255, 0.7)',
              fontSize: '13px',
              fontWeight: '600',
              cursor: 'wait',
            }}>
              Remediating...
            </button>
          ) : (
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                onClick={handleReset}
                style={{
                  padding: '9px 16px',
                  borderRadius: '8px',
                  background: 'rgba(139, 92, 246, 0.15)',
                  border: '1px solid rgba(139, 92, 246, 0.3)',
                  color: '#c4b5fd',
                  fontSize: '13px',
                  cursor: 'pointer',
                }}
              >
                Reset
              </button>
              <button
                onClick={onClose}
                style={{
                  padding: '9px 20px',
                  borderRadius: '8px',
                  background: 'linear-gradient(135deg, #2dd4bf, #059669)',
                  border: 'none',
                  color: '#07071a',
                  fontWeight: '700',
                  fontSize: '13px',
                  cursor: 'pointer',
                }}
              >
                ✓ Done (Resolved)
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
