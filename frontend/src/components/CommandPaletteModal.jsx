import React, { useState, useEffect, useRef } from 'react';

export default function CommandPaletteModal({
  isOpen,
  onClose,
  onNavigate,
  onSelectServer,
  servers = [],
  onTriggerAction,
}) {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef(null);

  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  // Global Cmd+K / Ctrl+K listener
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (isOpen) onClose();
        else onClose(true); // open trigger
      }
      if (isOpen && e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  // Base list of commands
  const allItems = [
    // Navigation
    { id: 'nav-dashboard', category: 'Navigation', label: 'Go to Dashboard Overview', icon: '📊', action: () => { onNavigate('dashboard'); onClose(); } },
    { id: 'nav-alerts', category: 'Navigation', label: 'Go to Alerts & Incidents', icon: '🚨', action: () => { onNavigate('alerts'); onClose(); } },
    { id: 'nav-visitors', category: 'Navigation', label: 'Go to Visitor & Threat Logs', icon: '🛡️', action: () => { onNavigate('visitor-logs'); onClose(); } },
    { id: 'nav-activity', category: 'Navigation', label: 'Go to User Audit Activity', icon: '👥', action: () => { onNavigate('user-activity'); onClose(); } },
    { id: 'nav-layouts', category: 'Navigation', label: 'Customize Dashboard Layouts', icon: '🎛️', action: () => { onNavigate('layouts'); onClose(); } },

    // Servers
    ...(servers.map(s => ({
      id: `server-${s.hostname}`,
      category: 'Monitored Servers',
      label: `Switch to server: ${s.hostname} (${s.ip_address || '127.0.0.1'})`,
      icon: '🖥️',
      action: () => { onSelectServer(s); onClose(); }
    }))),

    // Quick Actions
    { id: 'act-remediate', category: 'Autonomous Actions', label: 'Execute AI Remediation Playbook', icon: '⚡', action: () => { onTriggerAction('remediation'); onClose(); } },
    { id: 'act-report', category: 'Autonomous Actions', label: 'Generate Executive Security Brief', icon: '📄', action: () => { onTriggerAction('report'); onClose(); } },
    { id: 'act-scan', category: 'Autonomous Actions', label: 'Trigger Full Anomaly Scan', icon: '🔍', action: () => { onTriggerAction('scan'); onClose(); } },
  ];

  const filteredItems = allItems.filter(item =>
    item.label.toLowerCase().includes(query.toLowerCase()) ||
    item.category.toLowerCase().includes(query.toLowerCase())
  );

  const handleKeyDown = (e) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex(prev => (prev + 1) % (filteredItems.length || 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex(prev => (prev - 1 + filteredItems.length) % (filteredItems.length || 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (filteredItems[selectedIndex]) {
        filteredItems[selectedIndex].action();
      }
    }
  };

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 9999,
        background: 'rgba(5, 4, 18, 0.75)',
        backdropFilter: 'blur(16px)',
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'center',
        paddingTop: '12vh',
        animation: 'fadeIn 0.15s ease-out',
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: '560px',
          background: '#0d0b26',
          border: '1px solid rgba(139, 92, 246, 0.35)',
          borderRadius: '16px',
          boxShadow: '0 24px 64px rgba(0, 0, 0, 0.8), 0 0 32px rgba(139, 92, 246, 0.15)',
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          animation: 'slideInDown 0.2s ease-out',
        }}
      >
        {/* Search Input Bar */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          padding: '16px 20px',
          borderBottom: '1px solid rgba(139, 92, 246, 0.15)',
          background: 'rgba(139, 92, 246, 0.05)',
        }}>
          <img 
            src="/logos/app-icon.png" 
            alt="Purple Agent" 
            style={{ width: '22px', height: '22px', borderRadius: '6px', objectFit: 'contain' }} 
          />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={e => { setQuery(e.target.value); setSelectedIndex(0); }}
            onKeyDown={handleKeyDown}
            placeholder="Type a command, server name, or action..."
            style={{
              flex: 1,
              background: 'transparent',
              border: 'none',
              outline: 'none',
              color: '#f3f0ff',
              fontSize: '15px',
              fontFamily: "'Inter', sans-serif",
            }}
          />
          <span style={{
            fontSize: '11px',
            color: 'rgba(180, 170, 255, 0.4)',
            padding: '2px 6px',
            borderRadius: '4px',
            border: '1px solid rgba(180, 170, 255, 0.2)',
          }}>
            ESC to close
          </span>
        </div>

        {/* Results List */}
        <div style={{ maxHeight: '340px', overflowY: 'auto', padding: '8px' }}>
          {filteredItems.length === 0 ? (
            <div style={{ padding: '32px 20px', textAlign: 'center', color: 'rgba(180, 170, 255, 0.4)', fontSize: '13px' }}>
              No matching commands or servers found for "{query}"
            </div>
          ) : (
            filteredItems.map((item, idx) => {
              const isSelected = idx === selectedIndex;
              return (
                <div
                  key={item.id}
                  onClick={item.action}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '10px 14px',
                    borderRadius: '10px',
                    cursor: 'pointer',
                    background: isSelected ? 'rgba(139, 92, 246, 0.2)' : 'transparent',
                    border: isSelected ? '1px solid rgba(139, 92, 246, 0.35)' : '1px solid transparent',
                    color: isSelected ? '#ffffff' : '#d1c9f3',
                    transition: 'all 0.1s ease',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span style={{ fontSize: '16px' }}>{item.icon}</span>
                    <span style={{ fontSize: '13px', fontWeight: isSelected ? '600' : '450' }}>
                      {item.label}
                    </span>
                  </div>
                  <span style={{
                    fontSize: '10px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                    color: isSelected ? '#c4b5fd' : 'rgba(180, 170, 255, 0.35)',
                    fontWeight: '600',
                  }}>
                    {item.category}
                  </span>
                </div>
              );
            })
          )}
        </div>

        {/* Footer shortcuts */}
        <div style={{
          padding: '10px 18px',
          borderTop: '1px solid rgba(139, 92, 246, 0.12)',
          background: 'rgba(5, 4, 18, 0.5)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          fontSize: '11px',
          color: 'rgba(180, 170, 255, 0.45)',
        }}>
          <span>Use <strong>↑</strong> <strong>↓</strong> to navigate</span>
          <span>Press <strong>↵ Enter</strong> to select</span>
        </div>
      </div>
    </div>
  );
}
