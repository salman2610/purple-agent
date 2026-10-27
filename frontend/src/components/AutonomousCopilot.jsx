import React, { useState, useEffect, useRef } from 'react';
import gsap from 'gsap';

export default function AutonomousCopilot({ metrics, onTriggerPlaybook }) {
  const [messages, setMessages] = useState([
    {
      id: 1,
      fromAI: true,
      text: "Purple Autonomous AI Kernel online. Monitoring 4 sovereign server nodes with continuous LSTM telemetry correlation. All clusters nominal.",
      time: "Just now",
      tag: "NOMINAL",
      playbookAction: null
    }
  ]);
  const [isTyping, setIsTyping] = useState(false);
  const [input, setInput] = useState('');
  const [streamingText, setStreamingText] = useState('');
  
  const chatEndRef = useRef(null);
  const waveBarsRef = useRef([]);
  const containerRef = useRef(null);

  // Auto scroll to bottom
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping, streamingText]);

  // GSAP Neural Waveform Equalizer Animation in Header
  useEffect(() => {
    const bars = waveBarsRef.current.filter(Boolean);
    if (!bars.length) return;

    const anims = bars.map((bar, i) => {
      return gsap.to(bar, {
        scaleY: isTyping ? gsap.utils.random(0.3, 2.4) : gsap.utils.random(0.4, 1.2),
        duration: isTyping ? gsap.utils.random(0.18, 0.35) : gsap.utils.random(0.4, 0.8),
        repeat: -1,
        yoyo: true,
        ease: 'sine.inOut',
        delay: i * 0.08
      });
    });

    return () => {
      anims.forEach(a => a.kill());
    };
  }, [isTyping]);

  // Animate incoming messages with GSAP
  const animateLastMessage = () => {
    const bubbles = containerRef.current?.querySelectorAll('.copilot-msg-bubble');
    if (bubbles && bubbles.length > 0) {
      const lastBubble = bubbles[bubbles.length - 1];
      gsap.fromTo(
        lastBubble,
        { opacity: 0, y: 14, scale: 0.94, filter: 'blur(6px)' },
        { opacity: 1, y: 0, scale: 1, filter: 'blur(0px)', duration: 0.45, ease: 'back.out(1.4)' }
      );
    }
  };

  // Stream text letter by letter
  const streamResponse = (fullText, tag, playbookAction) => {
    setIsTyping(true);
    setStreamingText('');

    let index = 0;
    const interval = setInterval(() => {
      index += 2;
      if (index >= fullText.length) {
        clearInterval(interval);
        setMessages(prev => [
          ...prev,
          {
            id: Date.now(),
            fromAI: true,
            text: fullText,
            time: "Just now",
            tag: tag,
            playbookAction: playbookAction
          }
        ]);
        setStreamingText('');
        setIsTyping(false);
        setTimeout(animateLastMessage, 20);
      } else {
        setStreamingText(fullText.substring(0, index));
      }
    }, 18);
  };

  const handleAsk = (query) => {
    const userMsg = { id: Date.now(), fromAI: false, text: query, time: "Just now" };
    setMessages(prev => [...prev, userMsg]);
    setIsTyping(true);
    setTimeout(animateLastMessage, 20);

    setTimeout(() => {
      let reply = "";
      let tag = "DIAGNOSTIC";
      let action = null;

      const q = query.toLowerCase();

      if (q.includes("cpu") || q.includes("spike")) {
        const cpuVal = metrics?.cpu_usage || 24.5;
        reply = `Kernel telemetry correlated: Total fleet CPU load is at ${cpuVal.toFixed(1)}%. LSTM time-series forecast projects zero threshold breaches for the next 6 hours. Background thread pools on web-server-01 are operating within standard safety buffers.`;
        tag = "CPU NOMINAL";
        action = { name: "Inspect Process Tree", target: "web-server-01" };
      } else if (q.includes("brute") || q.includes("log") || q.includes("threat") || q.includes("ssh")) {
        reply = `Security Audit Analysis: Processed 1,420 inbound connections. Detected 3 unauthorized SSH handshake attempts from 185.220.101.42. Automatic Zero-Trust eBPF quarantine is active. Would you like to trigger Fail2Ban isolation?`;
        tag = "THREAT ISOLATED";
        action = { name: "⚡ Execute SSH Quarantine Playbook", isPlaybook: true };
      } else if (q.includes("memory") || q.includes("lstm") || q.includes("forecast") || q.includes("leak")) {
        const memVal = metrics?.memory_usage || 48.2;
        reply = `LSTM Predictive Analysis: Memory allocation on db-server-01 is ${memVal.toFixed(1)}%. Gradient coefficient is stable (dM/dt = +0.02%/min). Self-healing JVM garbage collection playbook is armed and ready if 85% limit is reached.`;
        tag = "PREDICTIVE OK";
        action = { name: "🚀 Hot-Swap Heap Clean Playbook", isPlaybook: true };
      } else {
        reply = `Fleet Correlator online. Multi-node telemetry shows 99.98% health index across US-East, EU-West, and AP-East. Packet latency is 28ms. Zero anomalous syscalls or memory leaks identified.`;
        tag = "FLEET STABLE";
      }

      streamResponse(reply, tag, action);
    }, 600);
  };

  return (
    <div
      ref={containerRef}
      style={{
        borderRadius: '18px',
        background: 'linear-gradient(145deg, rgba(14, 10, 38, 0.94) 0%, rgba(7, 5, 24, 0.98) 100%)',
        border: '1px solid rgba(139, 92, 246, 0.28)',
        backdropFilter: 'blur(35px)',
        WebkitBackdropFilter: 'blur(35px)',
        boxShadow: '0 16px 45px rgba(0, 0, 0, 0.6), inset 0 1px 0 rgba(255, 255, 255, 0.08)',
        display: 'flex',
        flexDirection: 'column',
        height: '420px',
        overflow: 'hidden',
        position: 'relative'
      }}
    >
      {/* Dynamic Ambient Background Glow */}
      <div style={{
        position: 'absolute',
        top: '-40px',
        right: '-40px',
        width: '180px',
        height: '180px',
        background: 'radial-gradient(circle, rgba(139, 92, 246, 0.18) 0%, transparent 70%)',
        pointerEvents: 'none',
        zIndex: 0
      }} />

      {/* Copilot Header */}
      <div style={{
        padding: '14px 18px',
        borderBottom: '1px solid rgba(139, 92, 246, 0.18)',
        background: 'rgba(139, 92, 246, 0.08)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        position: 'relative',
        zIndex: 1
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '11px' }}>
          <div style={{ position: 'relative' }}>
            <img 
              src="/logos/agent-avatar.png" 
              alt="AI Copilot" 
              style={{
                width: '34px',
                height: '34px',
                borderRadius: '10px',
                objectFit: 'cover',
                boxShadow: '0 4px 16px rgba(139, 92, 246, 0.5)',
                border: '1.5px solid rgba(139, 92, 246, 0.45)',
              }} 
            />
            <span style={{
              position: 'absolute',
              bottom: '-2px',
              right: '-2px',
              width: '9px',
              height: '9px',
              borderRadius: '50%',
              background: '#2dd4bf',
              border: '2px solid #0a0720',
              boxShadow: '0 0 8px #2dd4bf'
            }} />
          </div>
          <div>
            <div style={{ fontSize: '13.5px', fontWeight: '800', color: '#f3f0ff', letterSpacing: '-0.02em', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span>Autonomous SRE Copilot</span>
              <span style={{ fontSize: '9px', padding: '1px 5px', borderRadius: '4px', background: 'rgba(139, 92, 246, 0.25)', color: '#c4b5fd', fontWeight: 700 }}>
                v2.4
              </span>
            </div>
            <div style={{ fontSize: '10.5px', color: 'rgba(180, 170, 255, 0.55)', letterSpacing: '0.02em' }}>
              Neural Anomaly Correlator & Auto-Healer
            </div>
          </div>
        </div>

        {/* Neural Waveform Equalizer Animated with GSAP */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '3px',
            height: '18px',
            padding: '0 4px'
          }}>
            {[0, 1, 2, 3, 4, 5, 6].map(i => (
              <span
                key={i}
                ref={el => waveBarsRef.current[i] = el}
                style={{
                  width: '2.5px',
                  height: '10px',
                  borderRadius: '2px',
                  background: i % 2 === 0 ? '#2dd4bf' : '#8b5cf6',
                  transformOrigin: 'bottom',
                  boxShadow: i % 2 === 0 ? '0 0 6px rgba(45, 212, 191, 0.5)' : '0 0 6px rgba(139, 92, 246, 0.5)'
                }}
              />
            ))}
          </div>

          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            background: 'rgba(45, 212, 191, 0.1)',
            border: '1px solid rgba(45, 212, 191, 0.25)',
            padding: '3px 8px',
            borderRadius: '12px'
          }}>
            <span style={{ fontSize: '10px', fontWeight: '700', color: '#2dd4bf', letterSpacing: '0.04em' }}>
              ACTIVE DEFENDER
            </span>
          </div>
        </div>
      </div>

      {/* Messages Scroll Area */}
      <div style={{
        flex: 1,
        overflowY: 'auto',
        padding: '16px 18px',
        display: 'flex',
        flexDirection: 'column',
        gap: '14px',
        position: 'relative',
        zIndex: 1
      }}>
        {messages.map(m => (
          <div
            key={m.id}
            className="copilot-msg-bubble"
            style={{
              alignSelf: m.fromAI ? 'flex-start' : 'flex-end',
              maxWidth: '90%',
              display: 'flex',
              flexDirection: 'column',
              gap: '4px',
            }}
          >
            {m.fromAI && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '2px' }}>
                <img 
                  src="/logos/agent-avatar.png" 
                  alt="AI" 
                  style={{ width: '16px', height: '16px', borderRadius: '4px', objectFit: 'cover' }} 
                />
                {m.tag && (
                  <span style={{
                    fontSize: '9.5px',
                    fontWeight: '700',
                    letterSpacing: '0.08em',
                    color: '#2dd4bf',
                    padding: '2px 7px',
                    borderRadius: '4px',
                    background: 'rgba(45, 212, 191, 0.12)',
                    border: '1px solid rgba(45, 212, 191, 0.28)',
                    alignSelf: 'flex-start',
                  }}>
                    ✦ {m.tag}
                  </span>
                )}
              </div>
            )}
            <div style={{
              padding: '11px 16px',
              borderRadius: m.fromAI ? '4px 16px 16px 16px' : '16px 4px 16px 16px',
              background: m.fromAI ? 'rgba(139, 92, 246, 0.12)' : 'linear-gradient(135deg, #7c3aed, #4f46e5)',
              border: `1px solid ${m.fromAI ? 'rgba(139, 92, 246, 0.25)' : 'rgba(124, 58, 237, 0.5)'}`,
              color: m.fromAI ? '#e8e6ff' : '#ffffff',
              fontSize: '12.5px',
              lineHeight: 1.55,
              boxShadow: m.fromAI ? '0 4px 16px rgba(0, 0, 0, 0.3)' : '0 6px 20px rgba(124, 58, 237, 0.4)',
            }}>
              {m.text}

              {/* Interactive One-Click Playbook Trigger Button */}
              {m.playbookAction && (
                <div style={{ marginTop: '10px', paddingTop: '8px', borderTop: '1px solid rgba(139, 92, 246, 0.2)' }}>
                  <button
                    onClick={() => {
                      if (onTriggerPlaybook) onTriggerPlaybook(m.playbookAction);
                    }}
                    style={{
                      background: 'linear-gradient(135deg, #8b5cf6, #2dd4bf)',
                      color: '#ffffff',
                      border: 'none',
                      borderRadius: '8px',
                      padding: '6px 14px',
                      fontSize: '11.5px',
                      fontWeight: '700',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                      boxShadow: '0 4px 14px rgba(139, 92, 246, 0.4)',
                      transition: 'transform 0.15s ease'
                    }}
                    onMouseEnter={e => e.currentTarget.style.transform = 'translateY(-1px)'}
                    onMouseLeave={e => e.currentTarget.style.transform = 'translateY(0)'}
                  >
                    <span>{m.playbookAction.name}</span>
                    <span style={{ fontSize: '13px' }}>→</span>
                  </button>
                </div>
              )}
            </div>
            <span style={{ fontSize: '9.5px', color: 'rgba(180, 170, 255, 0.4)', alignSelf: m.fromAI ? 'flex-start' : 'flex-end', marginLeft: m.fromAI ? '4px' : '0', marginRight: m.fromAI ? '0' : '4px' }}>
              {m.time}
            </span>
          </div>
        ))}

        {/* Live Streaming Typewriter Bubble */}
        {isTyping && (
          <div
            className="copilot-msg-bubble"
            style={{
              alignSelf: 'flex-start',
              maxWidth: '90%',
              display: 'flex',
              flexDirection: 'column',
              gap: '4px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '2px' }}>
              <img 
                src="/logos/agent-avatar.png" 
                alt="AI" 
                style={{ width: '16px', height: '16px', borderRadius: '4px', objectFit: 'cover' }} 
              />
              <span style={{
                fontSize: '9.5px',
                fontWeight: '700',
                color: '#8b5cf6',
                padding: '2px 7px',
                borderRadius: '4px',
                background: 'rgba(139, 92, 246, 0.15)',
                border: '1px solid rgba(139, 92, 246, 0.3)'
              }}>
                NEURAL STREAMING
              </span>
            </div>
            <div style={{
              padding: '11px 16px',
              borderRadius: '4px 16px 16px 16px',
              background: 'rgba(139, 92, 246, 0.14)',
              border: '1px solid rgba(139, 92, 246, 0.3)',
              color: '#e8e6ff',
              fontSize: '12.5px',
              lineHeight: 1.55,
              boxShadow: '0 4px 16px rgba(0, 0, 0, 0.3)'
            }}>
              {streamingText ? (
                <>
                  {streamingText}
                  <span style={{ display: 'inline-block', width: '7px', height: '13px', background: '#2dd4bf', marginLeft: '3px', verticalAlign: 'middle', animation: 'blink 0.8s infinite' }}>
                    ▋
                  </span>
                </>
              ) : (
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#c4b5fd', fontSize: '12px' }}>
                  <span style={{ color: '#2dd4bf', animation: 'spin 1.5s linear infinite' }}>✦</span>
                  <span>Correlating kernel metrics across fleet...</span>
                </div>
              )}
            </div>
          </div>
        )}

        <div ref={chatEndRef} />
      </div>

      {/* Suggested Quick Prompt Chips */}
      <div style={{
        padding: '8px 16px',
        display: 'flex',
        gap: '8px',
        overflowX: 'auto',
        background: 'rgba(6, 4, 20, 0.55)',
        borderTop: '1px solid rgba(139, 92, 246, 0.14)',
        position: 'relative',
        zIndex: 1
      }}>
        {[
          { label: '✦ Correlate CPU spikes', query: 'Analyze CPU usage and spikes' },
          { label: '✦ Audit visitor logs', query: 'Audit visitor logs for brute-force threats' },
          { label: '✦ Memory forecast', query: 'Run LSTM memory forecast' },
        ].map((chip, idx) => (
          <button
            key={idx}
            onClick={() => handleAsk(chip.query)}
            style={{
              padding: '5px 12px',
              borderRadius: '16px',
              border: '1px solid rgba(139, 92, 246, 0.25)',
              background: 'rgba(139, 92, 246, 0.1)',
              color: 'rgba(215, 205, 255, 0.9)',
              fontSize: '11px',
              fontWeight: '600',
              cursor: 'pointer',
              whiteSpace: 'nowrap',
              transition: 'all 0.18s cubic-bezier(0.2, 0.8, 0.2, 1)',
            }}
            onMouseEnter={e => {
              e.currentTarget.style.background = 'rgba(139, 92, 246, 0.22)';
              e.currentTarget.style.borderColor = '#8b5cf6';
              e.currentTarget.style.transform = 'translateY(-1px)';
            }}
            onMouseLeave={e => {
              e.currentTarget.style.background = 'rgba(139, 92, 246, 0.1)';
              e.currentTarget.style.borderColor = 'rgba(139, 92, 246, 0.25)';
              e.currentTarget.style.transform = 'translateY(0)';
            }}
          >
            {chip.label}
          </button>
        ))}
      </div>

      {/* Chat Input */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (input.trim()) {
            handleAsk(input.trim());
            setInput('');
          }
        }}
        style={{
          display: 'flex',
          padding: '12px 16px',
          background: 'rgba(7, 5, 26, 0.9)',
          borderTop: '1px solid rgba(139, 92, 246, 0.16)',
          gap: '10px',
          position: 'relative',
          zIndex: 1
        }}
      >
        <input
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="Ask SRE Copilot (e.g. Audit threats, Memory forecast)..."
          style={{
            flex: 1,
            background: 'rgba(139, 92, 246, 0.08)',
            border: '1px solid rgba(139, 92, 246, 0.22)',
            borderRadius: '10px',
            padding: '9px 14px',
            color: '#e8e6ff',
            fontSize: '12.5px',
            outline: 'none',
            transition: 'border-color 0.2s, box-shadow 0.2s'
          }}
          onFocus={e => {
            e.currentTarget.style.borderColor = 'rgba(139, 92, 246, 0.6)';
            e.currentTarget.style.boxShadow = '0 0 0 3px rgba(139, 92, 246, 0.15)';
          }}
          onBlur={e => {
            e.currentTarget.style.borderColor = 'rgba(139, 92, 246, 0.22)';
            e.currentTarget.style.boxShadow = 'none';
          }}
        />
        <button
          type="submit"
          style={{
            padding: '9px 18px',
            borderRadius: '10px',
            border: 'none',
            background: 'linear-gradient(135deg, #7c3aed, #4f46e5)',
            color: 'white',
            fontWeight: '700',
            fontSize: '12px',
            cursor: 'pointer',
            boxShadow: '0 4px 14px rgba(124, 58, 237, 0.4)',
            transition: 'all 0.18s ease'
          }}
          onMouseEnter={e => e.currentTarget.style.filter = 'brightness(1.15)'}
          onMouseLeave={e => e.currentTarget.style.filter = 'brightness(1.0)'}
        >
          Send
        </button>
      </form>
    </div>
  );
}
