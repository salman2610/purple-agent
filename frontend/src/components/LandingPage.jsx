import React, { useState, useEffect, useRef } from 'react';
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';

gsap.registerPlugin(ScrollTrigger);

export default function LandingPage({ onLaunchDemo, onOpenAuth }) {
  // Simulator State
  const [activeVec, setActiveVec] = useState('ssh');
  const [simLines, setSimLines] = useState([]);
  const [simStatus, setSimStatus] = useState('ANALYZING');
  const simTimersRef = useRef([]);

  // ROI Calculator State
  const [servers, setServers] = useState(25);
  const [minutes, setMinutes] = useState(20);

  // Root Ref for GSAP scoping
  const rootRef = useRef(null);

  const incidents = servers * 2;
  const hoursSaved = Math.round((incidents * minutes) / 60);
  const dollarSaved = '$' + (hoursSaved * 60).toLocaleString('en-US');

  const vectors = [
    {
      id: 'ssh',
      label: 'SSH brute force',
      sev: 'CRITICAL',
      pill: 'p4',
      lines: [
        { t: 'scan', cls: 'ac', x: 'auth.log: 214 failed logins from 31 hosts in 60 seconds' },
        { t: 'correlate', cls: 'ac', x: 'pattern matches credential stuffing, not a typo storm' },
        { t: 'insight', cls: 'wn', x: 'SSH is exposed on port 22 with no rate limiting' },
        { t: 'suggest', cls: 'ok', x: 'enable key-only auth, add fail2ban, block the offending ranges' },
        { t: 'status', cls: 'ok', x: 'incident opened, severity CRITICAL' }
      ]
    },
    {
      id: 'mem',
      label: 'Memory pressure',
      sev: 'HIGH',
      pill: 'p3',
      lines: [
        { t: 'scan', cls: 'ac', x: 'memory at 91% and rising for 12 minutes' },
        { t: 'correlate', cls: 'ac', x: 'one worker process is growing steadily, traffic is flat' },
        { t: 'insight', cls: 'wn', x: 'looks like a memory leak, not a load spike' },
        { t: 'suggest', cls: 'ok', x: 'restart the worker and inspect the latest deploy' },
        { t: 'status', cls: 'ok', x: 'alert fired, severity HIGH' }
      ]
    },
    {
      id: 'req',
      label: 'Suspicious request burst',
      sev: 'MEDIUM',
      pill: 'p2',
      lines: [
        { t: 'scan', cls: 'ac', x: '1.8k requests per minute to /login from 3 IPs' },
        { t: 'correlate', cls: 'ac', x: 'visitor log: none of these IPs were seen before' },
        { t: 'insight', cls: 'wn', x: 'looks like automated probing' },
        { t: 'suggest', cls: 'ok', x: 'rate-limit /login and review the visitor log' },
        { t: 'status', cls: 'ok', x: 'incident opened, severity MEDIUM' }
      ]
    }
  ];

  const runSim = (id) => {
    simTimersRef.current.forEach(clearTimeout);
    simTimersRef.current = [];

    const vec = vectors.find(x => x.id === id);
    if (!vec) return;

    setActiveVec(id);
    setSimLines([]);
    setSimStatus('ANALYZING');

    vec.lines.forEach((ln, i) => {
      const timer = setTimeout(() => {
        setSimLines(vec.lines.slice(0, i + 1));
        if (i === vec.lines.length - 1) {
          setSimStatus('RESOLVED');
        }
      }, 450 + i * 650);
      simTimersRef.current.push(timer);
    });
  };

  // Run initial simulation on mount
  useEffect(() => {
    runSim('ssh');
    return () => {
      simTimersRef.current.forEach(clearTimeout);
    };
  }, []);

  // GSAP Animations and Interactions
  useEffect(() => {
    const r = rootRef.current;
    if (!r) return;

    const ctx = gsap.context(() => {
      const q = (sel) => r.querySelectorAll(sel);

      // Scroll Progress Bar
      gsap.to(q('.bar'), {
        scaleX: 1,
        ease: 'none',
        scrollTrigger: {
          trigger: r,
          start: 'top top',
          end: 'bottom bottom',
          scrub: 0.3
        }
      });

      // Floating Ambient Orbs
      gsap.to(q('.o1'), { x: -120, y: 70, duration: 9, repeat: -1, yoyo: true, ease: 'sine.inOut' });
      gsap.to(q('.hero .o2'), { x: 140, y: -60, duration: 11, repeat: -1, yoyo: true, ease: 'sine.inOut' });

      // Hero Timeline
      const card = q('.c3d')[0];
      const tl = gsap.timeline({ defaults: { ease: 'power4.out' } });

      tl.from(q('.liquid-glass-nav'), { autoAlpha: 0, y: -24, duration: 0.8 }, 0)
        .from(q('.hero .eyebrow'), { autoAlpha: 0, y: 20, duration: 0.6 }, '-=0.4')
        .from(q('.hero .w'), { yPercent: 120, rotate: 6, duration: 1.1, stagger: 0.07 }, '-=0.3')
        .from(q('.hero .fu'), { autoAlpha: 0, y: 28, duration: 0.8, stagger: 0.12 }, '-=0.6')
        .from(card, { autoAlpha: 0, y: 60, rotationX: -18, scale: 0.94, duration: 1.2 }, '-=1')
        .from(q('.ins'), { autoAlpha: 0, x: 40, duration: 0.8, stagger: 0.18 }, '-=0.5');

      tl.eventCallback('onComplete', () => {
        gsap.to(card, { y: -10, duration: 3, repeat: -1, yoyo: true, ease: 'sine.inOut' });

        const rx = gsap.quickTo(card, 'rotationX', { duration: 0.8, ease: 'power3' });
        const ry = gsap.quickTo(card, 'rotationY', { duration: 0.8, ease: 'power3' });

        const heroEl = q('.hero')[0];
        if (heroEl) {
          heroEl.addEventListener('mousemove', (e) => {
            const b = heroEl.getBoundingClientRect();
            ry(((e.clientX - b.left) / b.width - 0.5) * 14);
            rx(-((e.clientY - b.top) / b.height - 0.5) * 12);
          });
          heroEl.addEventListener('mouseleave', () => {
            rx(0);
            ry(0);
          });
        }
      });

      // Headings Word-Mask entrance on scroll
      q('.hd').forEach((h) => {
        gsap.from(h.querySelectorAll('.w'), {
          yPercent: 120,
          rotate: 5,
          duration: 1,
          ease: 'power4.out',
          stagger: 0.05,
          scrollTrigger: { trigger: h, start: 'top 88%', once: true }
        });
      });

      // Reveal elements on scroll
      gsap.set(q('.rv'), { autoAlpha: 0 });
      ScrollTrigger.batch(q('.rv'), {
        start: 'top 92%',
        once: true,
        onEnter: (batch) => gsap.fromTo(batch, 
          { y: 50, scale: 0.97 }, 
          { autoAlpha: 1, y: 0, scale: 1, duration: 0.9, stagger: 0.12, ease: 'power3.out', clearProps: 'transform' }
        )
      });

      // Line progress indicators
      q('.ln i').forEach((i) => {
        gsap.from(i, {
          scaleX: 0,
          duration: 1.3,
          ease: 'power3.inOut',
          scrollTrigger: { trigger: i, start: 'top 92%', once: true }
        });
      });

      // SVG Draw animations
      q('.draw').forEach((p) => {
        gsap.from(p, {
          strokeDashoffset: 1,
          duration: 2,
          ease: 'power2.inOut',
          scrollTrigger: { trigger: p, start: 'top 90%', once: true }
        });
      });

      // SVG Gauge Ring animations
      q('.ring').forEach((c) => {
        gsap.from(c, {
          strokeDasharray: '0 100',
          duration: 1.6,
          ease: 'power3.out',
          scrollTrigger: { trigger: c, start: 'top 92%', once: true }
        });
      });

      // Radial mouse highlight on cards
      r.addEventListener('pointermove', (e) => {
        const c = e.target.closest && e.target.closest('.card');
        if (c) {
          const b = c.getBoundingClientRect();
          c.style.setProperty('--mx', (e.clientX - b.left) + 'px');
          c.style.setProperty('--my', (e.clientY - b.top) + 'px');
        }
      });

      // Magnetic buttons
      q('.mag').forEach((b) => {
        const mx = gsap.quickTo(b, 'x', { duration: 0.5, ease: 'power3' });
        const my = gsap.quickTo(b, 'y', { duration: 0.5, ease: 'power3' });
        b.addEventListener('mousemove', (e) => {
          const k = b.getBoundingClientRect();
          mx((e.clientX - k.left - k.width / 2) * 0.25);
          my((e.clientY - k.top - k.height / 2) * 0.35);
        });
        b.addEventListener('mouseleave', () => {
          mx(0);
          my(0);
        });
      });

      // Fallback reveal in case user is already scrolled
      gsap.delayedCall(1.5, () => {
        if (ScrollTrigger.maxScroll(window) < 50) {
          gsap.to(q('.rv'), { autoAlpha: 1, y: 0, scale: 1, duration: 0.5, overwrite: true });
          gsap.to(q('.hd .w'), { yPercent: 0, rotate: 0, duration: 0.5, overwrite: true });
        }
      });
    }, rootRef);

    return () => ctx.revert();
  }, []);

  return (
    <div
      ref={rootRef}
      className="pa"
      style={{
        '--accent': '#A78BFA',
        width: '100%',
        minWidth: '100%',
        margin: 0,
        padding: 0,
        background: '#0F0B17',
        color: '#EDE9F6',
        fontFamily: "'Inter', sans-serif",
        fontSize: '18px',
        lineHeight: 1.7,
        overflowX: 'hidden',
        position: 'relative'
      }}
    >
      {/* ── Embedded CSS from Design ────────────────────────────────────── */}
      <style>{`
        .pa * { box-sizing: border-box; }
        .wrap { max-width: 1160px; margin: 0 auto; padding: 0 32px; position: relative; }
        .pa a { color: inherit; text-decoration: none; }
        .h { font-family: 'Bricolage Grotesque', sans-serif; font-weight: 700; letter-spacing: -0.02em; line-height: 1.05; margin: 0; }
        .mono { font-family: 'JetBrains Mono', monospace; }
        .muted { color: #C4BBD8; }
        .acc { color: var(--accent); }
        .wm { display: inline-block; overflow: hidden; vertical-align: top; padding-bottom: 0.14em; margin-bottom: -0.14em; }
        .w { display: inline-block; will-change: transform; }
        .eyebrow { font-family: 'JetBrains Mono', monospace; font-size: 13px; letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); margin: 0 0 16px; display: flex; align-items: center; gap: 10px; }
        .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--accent); animation: pulse 1.8s infinite; }
        @keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(167, 139, 250, 0.6); } 100% { box-shadow: 0 0 0 12px rgba(167, 139, 250, 0); } }
        .bar { position: fixed; top: 0; left: 0; right: 0; height: 3px; background: var(--accent); transform: scaleX(0); transform-origin: left; z-index: 9999; }
        .btn { position: relative; overflow: hidden; display: inline-flex; align-items: center; min-height: 48px; padding: 0 26px; border-radius: 8px; font-weight: 500; border: 1px solid #3A2F52; transition: border-color .3s, box-shadow .3s; cursor: pointer; text-decoration: none; }
        .btn.p { background: var(--accent); color: #130E1F; border-color: var(--accent); font-weight: 700; }
        .btn:hover { border-color: var(--accent); box-shadow: 0 0 32px rgba(167, 139, 250, 0.35); }
        .btn.p::before { content: ""; position: absolute; top: 0; left: -60%; width: 40%; height: 100%; background: rgba(255, 255, 255, 0.45); transform: skewX(-20deg); transition: left .6s; }
        .btn.p:hover::before { left: 130%; }
        .hero { position: relative; overflow: hidden; padding: 104px 0 96px; }
        .grid { position: absolute; inset: 0; background-image: linear-gradient(rgba(167, 139, 250, 0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(167, 139, 250, 0.08) 1px, transparent 1px); background-size: 56px 56px; -webkit-mask-image: radial-gradient(ellipse at 50% 30%, #000 20%, transparent 75%); mask-image: radial-gradient(ellipse at 50% 30%, #000 20%, transparent 75%); animation: gd 12s linear infinite; }
        @keyframes gd { to { background-position: 0 56px, 56px 0; } }
        .orb { position: absolute; border-radius: 50%; filter: blur(90px); opacity: 0.38; pointer-events: none; }
        .o1 { width: 420px; height: 420px; background: #7C3AED; top: -120px; right: -60px; }
        .o2 { width: 320px; height: 320px; background: #A78BFA; bottom: -100px; left: -80px; opacity: 0.22; }
        .big { font-size: 76px; letter-spacing: -0.03em; }
        .grid3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }
        .card { background: #171122; border: 1px solid #2A2040; border-radius: 12px; padding: 28px; transition: transform .35s, border-color .35s, box-shadow .35s; position: relative; overflow: hidden; }
        .card:hover { transform: translateY(-8px); border-color: var(--accent); box-shadow: 0 18px 48px rgba(124, 58, 237, 0.25); }
        .card::before { content: ""; position: absolute; inset: 0; pointer-events: none; opacity: 0; transition: opacity .3s; background: radial-gradient(260px circle at var(--mx, 50%) var(--my, 50%), rgba(167, 139, 250, 0.16), transparent 70%); }
        .card:hover::before { opacity: 1; }
        .card > * { position: relative; }
        .card h3 { font-family: 'Bricolage Grotesque', sans-serif; font-size: 22px; margin: 0 0 10px; }
        .card p, .card li { color: #C4BBD8; font-size: 16.5px; }
        .card ul { margin: 16px 0 0; padding: 0; list-style: none; display: flex; flex-direction: column; gap: 8px; }
        .card li { font-size: 15px; color: #B3AAC7; padding-left: 18px; position: relative; }
        .card li::before { content: ""; position: absolute; left: 0; top: 0.62em; width: 7px; height: 7px; border-radius: 2px; background: var(--accent); }
        .tag { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--accent); margin-bottom: 14px; display: block; }
        .code { background: #0A0711; border: 1px solid #2A2040; border-radius: 12px; padding: 24px; font-family: 'JetBrains Mono', monospace; font-size: 14px; line-height: 1.8; overflow-x: auto; white-space: pre; color: #D9D2EA; }
        .sec { padding: 120px 0; }
        .split { display: grid; grid-template-columns: 1.1fr 0.9fr; gap: 56px; align-items: center; }
        .ln { height: 1px; background: #3A2F52; margin-bottom: 20px; }
        .ln i { display: block; height: 1px; background: var(--accent); transform-origin: left; }
        .step b { font-family: 'JetBrains Mono', monospace; color: var(--accent); font-weight: 500; }
        .rm { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
        .rm span { border: 1px solid #2A2040; border-radius: 8px; padding: 14px 16px; font-size: 15px; color: #B3AAC7; transition: border-color .3s, color .3s; }
        .rm span:hover { border-color: var(--accent); color: #EDE9F6; }
        .mq { overflow: hidden; border-top: 1px solid #2A2040; border-bottom: 1px solid #2A2040; padding: 20px 0; background: #130E1D; }
        .mqt { display: flex; gap: 56px; width: max-content; animation: mq 28s linear infinite; font-family: 'JetBrains Mono', monospace; font-size: 15px; color: #B3AAC7; white-space: nowrap; }
        @keyframes mq { to { transform: translateX(-50%); } }
        .ty { display: inline-block; overflow: hidden; white-space: nowrap; width: 0; border-right: 2px solid var(--accent); animation: ty 2.2s steps(26) 1.5s forwards, bl 0.8s step-end infinite; }
        @keyframes ty { to { width: 26ch; } }
        @keyframes bl { 50% { border-color: transparent; } }
        .cmp { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 40px; }
        .cmp .card h3 { font-size: 20px; }
        .quote { font-family: 'Bricolage Grotesque', sans-serif; font-size: 34px; line-height: 1.2; max-width: 760px; margin: 0 auto; text-align: center; font-weight: 500; }
        .shots { display: grid; grid-template-columns: 1.5fr 1fr; gap: 20px; }
        .shots .col { display: flex; flex-direction: column; gap: 20px; }
        .win { background: #0A0711; border: 1px solid #2A2040; border-radius: 12px; overflow: hidden; }
        .win .tb { display: flex; align-items: center; gap: 8px; padding: 12px 16px; border-bottom: 1px solid #2A2040; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #B3AAC7; }
        .win .tb i { width: 9px; height: 9px; border-radius: 50%; background: #3A2F52; }
        .win .tb span { margin-left: auto; }
        .win .bd { padding: 20px; }
        .cap { font-size: 14px; color: #B3AAC7; margin: 12px 4px 0; }
        .rings { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 16px; }
        .rg { text-align: center; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #B3AAC7; }
        .rg svg { width: 84px; height: 84px; transform: rotate(-90deg); }
        .pt { width: 100%; border-collapse: collapse; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #D9D2EA; margin-top: 12px; }
        .pt td { padding: 8px 4px; border-top: 1px solid #2A2040; }
        .bt { display: block; height: 6px; border-radius: 3px; background: #2A2040; overflow: hidden; }
        .bt b { display: block; height: 100%; background: var(--accent); border-radius: 3px; }
        .sev { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 10px 0; border-top: 1px solid #2A2040; font-size: 14px; color: #D9D2EA; }
        .sev:first-child { border-top: 0; }
        .pill { font-family: 'JetBrains Mono', monospace; font-size: 11px; padding: 3px 9px; border-radius: 99px; border: 1px solid; }
        .p1 { color: #8EC5FF; border-color: #8EC5FF; }
        .p2 { color: #F2D066; border-color: #F2D066; }
        .p3 { color: #FFA060; border-color: #FFA060; }
        .p4 { color: #FF7A8A; border-color: #FF7A8A; }
        .arch { display: grid; grid-template-columns: 1fr 60px 1fr 60px 1fr 60px 1fr; align-items: center; gap: 0; margin: 8px 0 48px; }
        .node { background: #171122; border: 1px solid #3A2F52; border-radius: 12px; padding: 20px 14px; text-align: center; }
        .node b { display: block; font-family: 'Bricolage Grotesque', sans-serif; font-size: 18px; }
        .node span { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #B3AAC7; }
        .conn { height: 2px; background: repeating-linear-gradient(90deg, var(--accent) 0 8px, transparent 8px 16px); background-size: 16px 2px; animation: flow 1s linear infinite; }
        @keyframes flow { to { background-position: 16px 0; } }
        .mon { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
        .mon .card { padding: 22px; }
        .mon .card h3 { font-size: 18px; }
        details { background: #171122; border: 1px solid #2A2040; border-radius: 12px; padding: 0 24px; margin-bottom: 12px; transition: border-color .3s; }
        details[open], details:hover { border-color: var(--accent); }
        summary { cursor: pointer; padding: 20px 0; font-family: 'Bricolage Grotesque', sans-serif; font-size: 20px; list-style: none; display: flex; justify-content: space-between; gap: 16px; }
        summary::-webkit-details-marker { display: none; }
        summary::after { content: "+"; color: var(--accent); font-size: 24px; line-height: 1; }
        details[open] summary::after { content: "\u2212"; }
        details p, details ul { margin: 0 0 20px; color: #B3AAC7; font-size: 16px; }
        details code, .ic { font-family: 'JetBrains Mono', monospace; font-size: 14px; color: #D9D2EA; background: #0A0711; padding: 2px 6px; border-radius: 4px; }
        .cd2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .lbl { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--accent); margin: 0 0 10px; letter-spacing: 0.08em; }
        .tagx { display: inline-block; font-family: 'JetBrains Mono', monospace; font-size: 11px; letter-spacing: 0.1em; padding: 4px 10px; border: 1px solid #4A3A6E; border-radius: 99px; color: var(--accent); margin-bottom: 16px; }
        .vecs { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; }
        .vec { font: inherit; font-size: 15px; color: #EDE9F6; background: #171122; border: 1px solid #2A2040; border-radius: 10px; padding: 12px 16px; cursor: pointer; display: inline-flex; gap: 12px; align-items: center; transition: border-color .3s, background .3s; }
        .vec:hover, .vec.on { border-color: var(--accent); background: #1E1530; }
        .term { background: #0A0711; border: 1px solid #2A2040; border-radius: 12px; overflow: hidden; }
        .term .tb { display: flex; justify-content: space-between; padding: 14px 20px; border-bottom: 1px solid #2A2040; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #C4BBD8; }
        .term .bd { padding: 20px; min-height: 230px; font-size: 14px; line-height: 1.9; color: #D9D2EA; }
        .ok { color: #8EE0B0; }
        .wn { color: #F2B866; }
        .ac { color: var(--accent); }
        .roi { display: grid; grid-template-columns: 1.1fr 0.9fr; gap: 40px; padding: 40px; }
        .roi label { display: flex; justify-content: space-between; font-size: 15px; margin-bottom: 10px; }
        .roi input[type=range] { width: 100%; accent-color: var(--accent); margin-bottom: 28px; cursor: pointer; }
        .out { border-top: 1px solid #2A2040; padding: 16px 0; display: flex; justify-content: space-between; align-items: baseline; gap: 12px; }
        .out b { font-family: 'Bricolage Grotesque', sans-serif; font-size: 32px; font-weight: 700; }
        .price { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; max-width: 880px; }
        .price .card { padding: 36px; }
        .price .big2 { font-family: 'Bricolage Grotesque', sans-serif; font-size: 48px; font-weight: 700; margin: 8px 0 6px; }
        .price .btn { margin-top: 28px; }

        /* ── Apple Liquid Glass Pinned Navigation ─────────────────────────── */
        .nav-pin-wrap {
          position: fixed;
          top: 16px;
          left: 0;
          right: 0;
          display: flex;
          justify-content: center;
          padding: 0 24px;
          z-index: 1000;
          pointer-events: none;
        }
        .liquid-glass-nav {
          pointer-events: auto;
          width: 100%;
          max-width: 1440px;
          height: 66px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 0 20px 0 22px;
          border-radius: 20px;
          position: relative;
          background: rgba(15, 11, 23, 0.72);
          backdrop-filter: blur(28px) saturate(190%) contrast(105%);
          -webkit-backdrop-filter: blur(28px) saturate(190%) contrast(105%);
          border: 1px solid rgba(255, 255, 255, 0.13);
          box-shadow:
            0 24px 48px -12px rgba(0, 0, 0, 0.7),
            0 8px 20px -4px rgba(0, 0, 0, 0.45),
            inset 0 1px 1.5px 0 rgba(255, 255, 255, 0.32),
            inset 0 -1px 1px 0 rgba(0, 0, 0, 0.35),
            0 0 0 1px rgba(167, 139, 250, 0.12);
          transition: border-color 0.3s ease, box-shadow 0.3s ease, background 0.3s ease;
        }
        .liquid-glass-nav::before {
          content: "";
          position: absolute;
          inset: 0;
          border-radius: inherit;
          background: radial-gradient(900px circle at 50% 0%, rgba(255, 255, 255, 0.08), transparent 70%);
          pointer-events: none;
        }
        .liquid-glass-nav:hover {
          border-color: rgba(167, 139, 250, 0.35);
          box-shadow:
            0 28px 56px -12px rgba(0, 0, 0, 0.8),
            0 8px 26px -4px rgba(124, 58, 237, 0.25),
            inset 0 1px 2px 0 rgba(255, 255, 255, 0.42),
            inset 0 -1px 1px 0 rgba(0, 0, 0, 0.35),
            0 0 0 1px rgba(167, 139, 250, 0.25);
        }
        .nav-links-wrap {
          display: flex;
          align-items: center;
          gap: 6px;
        }
        .nav-item-link {
          position: relative;
          display: inline-flex;
          align-items: center;
          padding: 8px 15px;
          border-radius: 999px;
          font-size: 14.5px;
          font-weight: 500;
          color: #C4BBD8;
          transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
          text-decoration: none;
          white-space: nowrap;
        }
        .nav-item-link:hover {
          color: #FFFFFF;
          background: rgba(255, 255, 255, 0.08);
          box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.14);
        }
        .nav-btn-demo {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          min-height: 40px;
          padding: 0 20px;
          border-radius: 999px;
          font-size: 14px;
          font-weight: 600;
          background: linear-gradient(135deg, rgba(167, 139, 250, 0.28) 0%, rgba(124, 58, 237, 0.5) 100%);
          border: 1px solid rgba(167, 139, 250, 0.55);
          color: #FFFFFF;
          box-shadow: inset 0 1px 1.5px rgba(255, 255, 255, 0.35), 0 4px 18px rgba(124, 58, 237, 0.35);
          cursor: pointer;
          transition: all 0.25s ease;
          white-space: nowrap;
        }
        .nav-btn-demo:hover {
          background: linear-gradient(135deg, rgba(167, 139, 250, 0.42) 0%, rgba(124, 58, 237, 0.7) 100%);
          border-color: rgba(167, 139, 250, 0.85);
          box-shadow: inset 0 1px 2px rgba(255, 255, 255, 0.5), 0 6px 26px rgba(124, 58, 237, 0.6);
          transform: translateY(-1px);
        }
        .nav-btn-gh {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          min-height: 40px;
          padding: 0 16px;
          border-radius: 999px;
          font-size: 14px;
          font-weight: 500;
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid rgba(255, 255, 255, 0.12);
          color: #D9D2EA;
          box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.12);
          cursor: pointer;
          transition: all 0.25s ease;
          text-decoration: none;
          white-space: nowrap;
        }
        .nav-btn-gh:hover {
          background: rgba(255, 255, 255, 0.12);
          border-color: rgba(255, 255, 255, 0.25);
          box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.2);
          color: #FFFFFF;
          transform: translateY(-1px);
        }
        [id] { scroll-margin-top: 104px; }

        @media (max-width: 1180px) {
          .nav-item-link { padding: 6px 11px; font-size: 13.5px; }
          .nav-links-wrap { gap: 2px; }
        }
        @media (max-width: 980px) {
          .nav-links-wrap { display: none; }
          .liquid-glass-nav { height: 60px; padding: 0 16px; }
        }
        @media (max-width: 900px) {
          .grid3, .split, .rm, .cmp, .shots, .cd2, .roi, .price { grid-template-columns: 1fr; }
          .mon { grid-template-columns: 1fr 1fr; }
          .arch { grid-template-columns: 1fr; gap: 8px; }
          .conn { width: 2px; height: 28px; margin: 0 auto; background: repeating-linear-gradient(180deg, var(--accent) 0 6px, transparent 6px 12px); }
          .sec { padding: 72px 0; }
          .big { font-size: 52px; }
          .quote { font-size: 26px; }
        }
        @media (max-width: 600px) {
          .mon { grid-template-columns: 1fr; }
          .big { font-size: 40px; }
        }
      `}</style>

      {/* ── Scroll Progress Bar ─────────────────────────────────────────── */}
      <div className="bar"></div>

      {/* ── PINNED APPLE LIQUID GLASS NAVIGATION BAR ────────────────────── */}
      <header className="nav-pin-wrap">
        <nav className="liquid-glass-nav" aria-label="Main Navigation">
          {/* Brand Logo & Version Badge */}
          <a
            href="#top"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              textDecoration: 'none'
            }}
          >
            <img
              src="/logos/app-icon.png"
              alt="Purple Agent Logo"
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '10px',
                boxShadow: '0 0 20px rgba(167, 139, 250, 0.4)',
                objectFit: 'contain'
              }}
            />
            <span
              className="h"
              style={{
                fontSize: '21px',
                letterSpacing: '-0.02em',
                color: '#EDE9F6',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}
            >
              <span>Purple Agent</span>
              <span
                style={{
                  fontSize: '10px',
                  fontWeight: '700',
                  padding: '2px 8px',
                  borderRadius: '12px',
                  background: 'rgba(167, 139, 250, 0.16)',
                  border: '1px solid rgba(167, 139, 250, 0.35)',
                  color: '#C4B5FD',
                  fontFamily: "'JetBrains Mono', monospace",
                  boxShadow: 'inset 0 1px 0 rgba(255, 255, 255, 0.15)'
                }}
              >
                v2.4
              </span>
            </span>
          </a>

          {/* Navigation Links with Glass Pills */}
          <div className="nav-links-wrap">
            <a href="#features" className="nav-item-link">Features</a>
            <a href="#preview" className="nav-item-link">Dashboard</a>
            <a href="#how" className="nav-item-link">How it works</a>
            <a href="#sim" className="nav-item-link">Simulator</a>
            <a href="#roi" className="nav-item-link">ROI Calculator</a>
            <a href="#quickstart" className="nav-item-link">Quick start</a>
            <a href="#pricing" className="nav-item-link">Pricing</a>
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button
              onClick={onLaunchDemo}
              className="nav-btn-demo mag"
              aria-label="Launch interactive demo"
            >
              <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor">
                <polygon points="5 3 19 12 5 21 5 3" />
              </svg>
              <span>Launch Demo</span>
            </button>
            <a
              href="https://github.com/salman2610/purple-agent"
              target="_blank"
              rel="noreferrer"
              className="nav-btn-gh mag"
              aria-label="GitHub Repository"
            >
              <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
              </svg>
              <span>GitHub</span>
            </a>
          </div>
        </nav>
      </header>

      {/* ── HERO SECTION ─────────────────────────────────────────────────── */}
      <div className="hero" id="top">
        <div className="grid"></div>
        <div className="orb o1"></div>
        <div className="orb o2"></div>

        {/* Hero Split Content */}
        <div className="wrap split">
          <div>
            <p className="eyebrow">
              <span className="dot"></span>
              AI SRE agent
            </p>
            <h1 className="h big">
              <span className="wm"><span className="w">Monitor</span></span>{' '}
              <span className="wm"><span className="w">your</span></span>{' '}
              <span className="wm"><span className="w">servers.</span></span>{' '}
              <span className="wm"><span className="w">Understand</span></span>{' '}
              <span className="wm"><span className="w">what's</span></span>{' '}
              <span className="wm"><span className="w acc">wrong.</span></span>
            </h1>
            <p className="muted fu" style={{ fontSize: '20px', margin: '24px 0 36px', maxWidth: '540px' }}>
              Most tools show you a CPU spike and leave you to work it out. Purple Agent correlates events across your metrics and tells you, in plain English, what is happening and why.
            </p>
            <div className="fu" style={{ display: 'flex', gap: '14px', flexWrap: 'wrap' }}>
              <button
                onClick={onLaunchDemo}
                className="btn p mag"
                style={{ fontSize: '16px', fontWeight: '700' }}
              >
                🚀 Get started / Demo
              </button>
              {onOpenAuth && (
                <button
                  onClick={onOpenAuth}
                  className="btn mag"
                  style={{ fontSize: '16px' }}
                >
                  Sign In
                </button>
              )}
              <a
                href="https://github.com/salman2610/purple-agent"
                target="_blank"
                rel="noreferrer"
                className="btn mag"
                style={{ fontSize: '16px' }}
              >
                View on GitHub
              </a>
            </div>
            <p className="mono muted fu" style={{ fontSize: '13.5px', marginTop: '28px' }}>
              Open source · MIT license · Docker ready · Designed and built by{' '}
              <a
                href="https://salman2610.github.io"
                target="_blank"
                rel="noreferrer"
                className="acc"
                style={{ textDecoration: 'underline', color: 'var(--accent)' }}
              >
                P Salmanul Faris
              </a>
            </p>
          </div>

          {/* 3D Interactive Floating Cockpit Card */}
          <div style={{ perspective: '1000px' }}>
            <div
              className="card c3d"
              style={{
                padding: 0,
                overflow: 'hidden',
                boxShadow: '0 30px 80px rgba(0,0,0,.6), 0 0 50px rgba(124, 58, 237, 0.25)',
                transformStyle: 'preserve-3d',
                borderColor: 'rgba(167, 139, 250, 0.3)'
              }}
            >
              {/* Window Title Bar with AI Avatar */}
              <div
                className="mono"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '14px 20px',
                  borderBottom: '1px solid #2A2040',
                  fontSize: '12px',
                  color: '#B3AAC7',
                  background: 'rgba(255, 255, 255, 0.02)'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <img
                    src="/logos/agent-avatar.png"
                    alt="AI Avatar"
                    style={{ width: '18px', height: '18px', borderRadius: '4px', objectFit: 'cover' }}
                  />
                  <span style={{ color: '#EDE9F6', fontWeight: '600' }}>AI Smart Insights</span>
                </div>
                <span>example telemetry</span>
              </div>

              {/* Insights Body */}
              <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
                <div className="ins" style={{ border: '1px solid #4A3A6E', borderRadius: '10px', padding: '16px', background: 'rgba(167, 139, 250, 0.05)' }}>
                  <span className="tag" style={{ marginBottom: '6px' }}>PREDICTIVE ALERT</span>
                  <p style={{ margin: 0, fontSize: '16px', color: '#EDE9F6' }}>
                    CPU is trending toward a peak. Recent load looks driven by a growing set of worker processes.
                  </p>
                </div>
                <div className="ins" style={{ border: '1px solid #2A2040', borderRadius: '10px', padding: '16px', background: 'rgba(0,0,0,0.2)' }}>
                  <span className="tag" style={{ marginBottom: '6px', color: '#F2B866' }}>MEDIUM · MEMORY</span>
                  <p style={{ margin: 0, fontSize: '16px', color: '#B3AAC7' }}>
                    Memory pressure is rising. Review the top processes in the table below.
                  </p>
                </div>
                <div className="mono ins" style={{ fontSize: '13.5px', color: '#B3AAC7', borderTop: '1px solid #2A2040', paddingTop: '16px' }}>
                  &gt; <span className="ty">why is this server slow?</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── TECH STACK MARQUEE ───────────────────────────────────────────── */}
      <div className="mq">
        <div className="mqt">
          <span>React 18</span><span>FastAPI</span><span>PostgreSQL</span><span>WebSockets</span><span>JWT</span><span>PyTorch LSTM</span><span>Docker</span><span>systemd</span>
          <span>React 18</span><span>FastAPI</span><span>PostgreSQL</span><span>WebSockets</span><span>JWT</span><span>PyTorch LSTM</span><span>Docker</span><span>systemd</span>
        </div>
      </div>

      {/* ── WHAT MAKES THIS DIFFERENT ─────────────────────────────────────── */}
      <div className="sec" id="why" style={{ background: '#130E1D' }}>
        <div className="wrap">
          <p className="eyebrow">What makes this different</p>
          <h2 className="h hd" style={{ fontSize: '44px', maxWidth: '760px', marginBottom: '40px' }}>
            <span className="wm"><span className="w">Most</span></span>{' '}
            <span className="wm"><span className="w">tools</span></span>{' '}
            <span className="wm"><span className="w">show</span></span>{' '}
            <span className="wm"><span className="w">you</span></span>{' '}
            <span className="wm"><span className="w">a</span></span>{' '}
            <span className="wm"><span className="w">spike.</span></span>{' '}
            <span className="wm"><span className="w">We</span></span>{' '}
            <span className="wm"><span className="w acc">tell</span></span>{' '}
            <span className="wm"><span className="w acc">you</span></span>{' '}
            <span className="wm"><span className="w acc">why.</span></span>
          </h2>
          <div className="cmp">
            <div className="card rv">
              <span className="tag">A TYPICAL MONITORING TOOL</span>
              <h3>"CPU hit 94%."</h3>
              <p>A graph, a red line, and you left to work out what caused it, at 2 a.m., across five tabs.</p>
            </div>
            <div className="card rv" style={{ borderColor: '#4A3A6E', background: 'rgba(124, 58, 237, 0.08)' }}>
              <span className="tag">PURPLE AGENT</span>
              <h3>Here is what's wrong, and why.</h3>
              <p>The AI engine analyzes your system in real time, correlates events across metrics, and explains it in plain English, before it becomes an outage.</p>
            </div>
          </div>
          <p className="quote rv">
            "It's like having a junior sysadmin that <span className="acc">never sleeps</span>."
          </p>
        </div>
      </div>

      {/* ── INSIDE THE DASHBOARD PREVIEW ─────────────────────────────────── */}
      <div className="sec" id="preview">
        <div className="wrap">
          <p className="eyebrow">Inside the dashboard</p>
          <h2 className="h hd" style={{ fontSize: '44px', maxWidth: '760px', marginBottom: '12px' }}>
            <span className="wm"><span className="w">Dashboard,</span></span>{' '}
            <span className="wm"><span className="w">alerts</span></span>{' '}
            <span className="wm"><span className="w">and</span></span>{' '}
            <span className="wm"><span className="w acc">visitor</span></span>{' '}
            <span className="wm"><span className="w acc">logs.</span></span>
          </h2>
          <p className="muted rv" style={{ margin: '0 0 40px', maxWidth: '640px' }}>
            Illustrative preview of the three main views, drawn from the project's own screenshot descriptions.
          </p>

          <div className="shots">
            <div className="rv">
              <div className="win shotmain">
                <div className="tb">
                  <i></i><i></i><i></i><span>Dashboard Overview</span>
                </div>
                <div className="bd">
                  {/* Gauge Rings */}
                  <div className="rings">
                    <div className="rg">
                      <svg viewBox="0 0 100 100">
                        <circle cx="50" cy="50" r="40" fill="none" stroke="#2A2040" strokeWidth="10" />
                        <circle className="ring" cx="50" cy="50" r="40" fill="none" stroke="#A78BFA" strokeWidth="10" strokeLinecap="round" pathLength="100" strokeDasharray="62 100" />
                      </svg>
                      <br />CPU 62%
                    </div>
                    <div className="rg">
                      <svg viewBox="0 0 100 100">
                        <circle cx="50" cy="50" r="40" fill="none" stroke="#2A2040" strokeWidth="10" />
                        <circle className="ring" cx="50" cy="50" r="40" fill="none" stroke="#A78BFA" strokeWidth="10" strokeLinecap="round" pathLength="100" strokeDasharray="74 100" />
                      </svg>
                      <br />MEMORY 74%
                    </div>
                    <div className="rg">
                      <svg viewBox="0 0 100 100">
                        <circle cx="50" cy="50" r="40" fill="none" stroke="#2A2040" strokeWidth="10" />
                        <circle className="ring" cx="50" cy="50" r="40" fill="none" stroke="#A78BFA" strokeWidth="10" strokeLinecap="round" pathLength="100" strokeDasharray="48 100" />
                      </svg>
                      <br />DISK 48%
                    </div>
                  </div>

                  {/* SVG Network Graph */}
                  <svg viewBox="0 0 600 150" style={{ width: '100%', height: 'auto', display: 'block' }} role="img" aria-label="Network activity chart">
                    <path d="M0 120 L50 100 L100 108 L150 70 L200 84 L250 50 L300 78 L350 40 L400 62 L450 30 L500 54 L550 24 L600 38 L600 150 L0 150Z" fill="rgba(167,139,250,.12)" />
                    <path className="draw" pathLength="1" strokeDasharray="1" d="M0 120 L50 100 L100 108 L150 70 L200 84 L250 50 L300 78 L350 40 L400 62 L450 30 L500 54 L550 24 L600 38" fill="none" stroke="#A78BFA" strokeWidth="2.5" strokeLinejoin="round" />
                  </svg>

                  {/* Process Table */}
                  <table className="pt">
                    <tbody>
                      <tr><td>nginx</td><td style={{ width: '34%' }}><span className="bt"><b style={{ width: '46%' }}></b></span></td><td style={{ width: '22%' }}><span className="bt"><b style={{ width: '30%' }}></b></span></td></tr>
                      <tr><td>postgres</td><td><span className="bt"><b style={{ width: '28%' }}></b></span></td><td><span className="bt"><b style={{ width: '62%' }}></b></span></td></tr>
                      <tr><td>uvicorn</td><td><span className="bt"><b style={{ width: '36%' }}></b></span></td><td><span className="bt"><b style={{ width: '40%' }}></b></span></td></tr>
                    </tbody>
                  </table>
                </div>
              </div>
              <p className="cap">AI insights, process table, network chart</p>
            </div>

            <div className="col">
              <div className="rv">
                <div className="win">
                  <div className="tb"><i></i><i></i><i></i><span>Alerts & Rules</span></div>
                  <div className="bd" style={{ paddingTop: '8px', paddingBottom: '8px' }}>
                    <div className="sev"><span>Disk usage above 85%</span><span className="pill p2">MEDIUM</span></div>
                    <div className="sev"><span>Memory above 90%</span><span className="pill p3">HIGH</span></div>
                    <div className="sev"><span>CPU above 80%</span><span className="pill p1">LOW</span></div>
                    <div className="sev"><span>Suspicious request burst</span><span className="pill p4">CRITICAL</span></div>
                  </div>
                </div>
                <p className="cap">Alert rules with severity levels</p>
              </div>

              <div className="rv">
                <div className="win">
                  <div className="tb"><i></i><i></i><i></i><span>Visitor Logs</span></div>
                  <div className="bd" style={{ paddingTop: '8px', paddingBottom: '8px', fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', color: '#D9D2EA' }}>
                    <div className="sev"><span>203.0.113.14</span><span className="muted">GET /api/metrics</span></div>
                    <div className="sev"><span>198.51.100.7</span><span className="muted">POST /login</span></div>
                    <div className="sev"><span>192.0.2.88</span><span className="muted">GET /dashboard</span></div>
                  </div>
                </div>
                <p className="cap">Real-time IP tracking</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── LIVE SIMULATOR SANDBOX ───────────────────────────────────────── */}
      <div className="sec" id="sim" style={{ background: '#130E1D' }}>
        <div className="wrap">
          <span className="tagx">ILLUSTRATIVE SIMULATION</span>
          <h2 className="h hd" style={{ fontSize: '48px', maxWidth: '780px', marginBottom: '16px' }}>
            <span className="wm"><span className="w">Pick</span></span>{' '}
            <span className="wm"><span className="w">an</span></span>{' '}
            <span className="wm"><span className="w">incident.</span></span>{' '}
            <span className="wm"><span className="w">Watch</span></span>{' '}
            <span className="wm"><span className="w">it</span></span>{' '}
            <span className="wm"><span className="w acc">get</span></span>{' '}
            <span className="wm"><span className="w acc">explained.</span></span>
          </h2>
          <p className="muted rv" style={{ margin: '0 0 36px', maxWidth: '640px' }}>
            The terminal below is scripted so you can see the idea. The real agent reports from your own logs and metrics.
          </p>

          <div className="vecs rv">
            {vectors.map(v => (
              <button
                key={v.id}
                className={`vec ${activeVec === v.id ? 'on' : ''}`}
                onClick={() => runSim(v.id)}
              >
                <span>{v.label}</span>
                <span className={`pill ${v.pill}`}>{v.sev}</span>
              </button>
            ))}
          </div>

          <div className="term rv">
            <div className="tb">
              <span>agent / incident-log</span>
              <span className="acc" style={{ fontWeight: '700' }}>STATUS: {simStatus}</span>
            </div>
            <div className="bd mono">
              {simLines.map((l, idx) => (
                <div key={idx} style={{ marginBottom: '6px' }}>
                  <span className={l.cls}>[{l.t}]</span> {l.x}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ── FEATURES GRID ────────────────────────────────────────────────── */}
      <div className="sec" id="features" style={{ background: '#130E1D' }}>
        <div className="wrap">
          <p className="eyebrow">Features</p>
          <h2 className="h hd" style={{ fontSize: '44px', maxWidth: '760px', marginBottom: '48px' }}>
            <span className="wm"><span className="w">Everything</span></span>{' '}
            <span className="wm"><span className="w">a</span></span>{' '}
            <span className="wm"><span className="w">junior</span></span>{' '}
            <span className="wm"><span className="w">sysadmin</span></span>{' '}
            <span className="wm"><span className="w">would</span></span>{' '}
            <span className="wm"><span className="w">watch,</span></span>{' '}
            <span className="wm"><span className="w">without</span></span>{' '}
            <span className="wm"><span className="w">the</span></span>{' '}
            <span className="wm"><span className="w acc">sleep.</span></span>
          </h2>

          <div className="grid3">
            <div className="card rv">
              <span className="tag">01 / AI-POWERED INTELLIGENCE</span>
              <h3>AI insights</h3>
              <ul>
                <li>Smart insights across CPU, memory, disk and network patterns</li>
                <li>Predictive alerts for CPU peaks and memory pressure</li>
                <li>Plain-English diagnostics with actionable recommendations</li>
                <li>AI assistant: chat with your system</li>
              </ul>
            </div>

            <div className="card rv">
              <span className="tag">02 / REAL-TIME MONITORING</span>
              <h3>Live, zero refresh</h3>
              <ul>
                <li>CPU, memory and disk with live charts</li>
                <li>Process table with per-process CPU and memory</li>
                <li>Network bytes sent and received, with history</li>
                <li>WebSocket-powered live dashboard</li>
              </ul>
            </div>

            <div className="card rv">
              <span className="tag">03 / SECURITY AND ACCESS</span>
              <h3>Know who touched what</h3>
              <ul>
                <li>JWT authentication with admin and user roles</li>
                <li>Visitor log of every IP that hits your backend</li>
                <li>User activity monitor: audit trail of logins and actions</li>
                <li>Suspicious request detection</li>
              </ul>
            </div>

            <div className="card rv">
              <span className="tag">04 / ALERTS AND INCIDENTS</span>
              <h3>Rules that fit you</h3>
              <ul>
                <li>Configurable rules such as CPU above 80%, memory above 90%, disk above 85%</li>
                <li>Severity levels: LOW, MEDIUM, HIGH, CRITICAL</li>
                <li>Incident tracking and history</li>
                <li>Toggle rules active or inactive</li>
              </ul>
            </div>

            <div className="card rv">
              <span className="tag">05 / DASHBOARD</span>
              <h3>Your layout</h3>
              <ul>
                <li>Default, Analytics View and Compact layouts</li>
                <li>Global server distribution map</li>
                <li>System metrics pie chart</li>
                <li>Business and focus mode toggle</li>
              </ul>
            </div>

            <div className="card rv">
              <span className="tag">06 / AGENT ARCHITECTURE</span>
              <h3>Built for fleets</h3>
              <ul>
                <li>Lightweight Python agent, deployable as a systemd service</li>
                <li>Monitors metrics, logs, connections and file integrity</li>
                <li>Secure JWT-authenticated link to the backend</li>
                <li>Designed for multi-server deployments</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* ── INTERACTIVE ROI CALCULATOR ───────────────────────────────────── */}
      <div className="sec" id="roi">
        <div className="wrap">
          <span className="tagx">YOUR ASSUMPTIONS, NOT MEASURED RESULTS</span>
          <h2 className="h hd" style={{ fontSize: '48px', maxWidth: '780px', marginBottom: '40px' }}>
            <span className="wm"><span className="w">Estimate</span></span>{' '}
            <span className="wm"><span className="w">the</span></span>{' '}
            <span className="wm"><span className="w">time</span></span>{' '}
            <span className="wm"><span className="w">you</span></span>{' '}
            <span className="wm"><span className="w acc">could</span></span>{' '}
            <span className="wm"><span className="w acc">win</span></span>{' '}
            <span className="wm"><span className="w acc">back.</span></span>
          </h2>

          <div className="card roi rv">
            <div>
              <label htmlFor="sv">
                <span>Servers you run</span>
                <b className="acc">{servers} servers</b>
              </label>
              <input
                id="sv"
                type="range"
                min="1"
                max="200"
                value={servers}
                onChange={e => setServers(Number(e.target.value))}
              />

              <label htmlFor="mn">
                <span>Triage minutes saved per incident</span>
                <b className="acc">{minutes} mins</b>
              </label>
              <input
                id="mn"
                type="range"
                min="5"
                max="60"
                step="5"
                value={minutes}
                onChange={e => setMinutes(Number(e.target.value))}
              />

              <p className="muted" style={{ fontSize: '14px', margin: 0 }}>
                Model assumes 2 incidents per server per month and an engineer cost of $60 per hour. Change the sliders to match your reality.
              </p>
            </div>

            <div>
              <div className="out">
                <span className="muted">Incidents per month</span>
                <b>{incidents}</b>
              </div>
              <div className="out">
                <span className="muted">Engineer hours saved per month</span>
                <b className="acc">{hoursSaved} hrs</b>
              </div>
              <div className="out">
                <span className="muted">Estimated value per month</span>
                <b>{dollarSaved}</b>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── HOW IT WORKS & ARCHITECTURE ─────────────────────────────────── */}
      <div className="sec" id="how">
        <div className="wrap">
          <p className="eyebrow">How it works</p>
          <h2 className="h hd" style={{ fontSize: '44px', maxWidth: '760px', marginBottom: '48px' }}>
            <span className="wm"><span className="w">One</span></span>{' '}
            <span className="wm"><span className="w">agent</span></span>{' '}
            <span className="wm"><span className="w">per</span></span>{' '}
            <span className="wm"><span className="w">server.</span></span>{' '}
            <span className="wm"><span className="w">One</span></span>{' '}
            <span className="wm"><span className="w">place</span></span>{' '}
            <span className="wm"><span className="w acc">to</span></span>{' '}
            <span className="wm"><span className="w acc">look.</span></span>
          </h2>

          {/* Architecture Node Diagram with Logo Shield */}
          <div className="arch rv">
            <div className="node">
              <b>React</b>
              <span>Vite frontend</span>
            </div>
            <div className="conn"></div>
            <div className="node">
              <b>FastAPI</b>
              <span>Python 3.8+</span>
            </div>
            <div className="conn"></div>
            <div className="node">
              <b>PostgreSQL</b>
              <span>metrics and logs</span>
            </div>
            <div className="conn"></div>
            <div className="node" style={{ borderColor: 'rgba(167, 139, 250, 0.5)', background: 'rgba(124, 58, 237, 0.15)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px', marginBottom: '4px' }}>
                <img src="/logos/logo-shield.png" alt="Shield" style={{ width: '18px', height: '18px', objectFit: 'contain' }} />
                <b>Purple Agent</b>
              </div>
              <span className="acc">per server daemon</span>
            </div>
          </div>

          <p className="muted rv mono" style={{ fontSize: '13px', margin: '-24px 0 56px', textAlign: 'center' }}>
            WebSocket and REST between frontend and backend · JWT between agent and backend
          </p>

          <div className="grid3">
            <div className="step rv">
              <div className="ln"><i></i></div>
              <b>01</b>
              <h3 className="h" style={{ fontSize: '24px', margin: '8px 0 10px' }}>Install the agent</h3>
              <p className="muted" style={{ margin: 0 }}>
                Run it as a systemd service on each server you want to watch. It authenticates to your backend with a JWT.
              </p>
            </div>
            <div className="step rv">
              <div className="ln"><i></i></div>
              <b>02</b>
              <h3 className="h" style={{ fontSize: '24px', margin: '8px 0 10px' }}>Collect and correlate</h3>
              <p className="muted" style={{ margin: 0 }}>
                The FastAPI backend stores everything in PostgreSQL and an LSTM model looks for patterns across metrics.
              </p>
            </div>
            <div className="step rv">
              <div className="ln"><i></i></div>
              <b>03</b>
              <h3 className="h" style={{ fontSize: '24px', margin: '8px 0 10px' }}>Read the answer</h3>
              <p className="muted" style={{ margin: 0 }}>
                The React dashboard turns it into live charts, alerts and recommendations you can act on.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* ── WHAT THE AGENT WATCHES ───────────────────────────────────────── */}
      <div className="sec" style={{ background: '#130E1D' }}>
        <div className="wrap">
          <p className="eyebrow">What the agent watches</p>
          <h2 className="h hd" style={{ fontSize: '44px', maxWidth: '760px', marginBottom: '40px' }}>
            <span className="wm"><span className="w">Four</span></span>{' '}
            <span className="wm"><span className="w">signals,</span></span>{' '}
            <span className="wm"><span className="w">every</span></span>{' '}
            <span className="wm"><span className="w acc">scan</span></span>{' '}
            <span className="wm"><span className="w acc">interval.</span></span>
          </h2>
          <div className="mon">
            <div className="card rv"><span className="tag">METRICS</span><h3>System metrics</h3><p>CPU, memory, disk and network usage.</p></div>
            <div className="card rv"><span className="tag">LOGS</span><h3>Log files</h3><p>Such as /var/log/auth.log and /var/log/syslog.</p></div>
            <div className="card rv"><span className="tag">NETWORK</span><h3>Connections</h3><p>Network connections on the monitored host.</p></div>
            <div className="card rv"><span className="tag">INTEGRITY</span><h3>File integrity</h3><p>Watches directories like /etc, /var/www and /usr/bin.</p></div>
          </div>
        </div>
      </div>

      {/* ── QUICK START ─────────────────────────────────────────────────── */}
      <div className="sec" id="quickstart">
        <div className="wrap">
          <p className="eyebrow">Quick start</p>
          <h2 className="h hd" style={{ fontSize: '44px', maxWidth: '760px', marginBottom: '20px' }}>
            <span className="wm"><span className="w">Running</span></span>{' '}
            <span className="wm"><span className="w">in</span></span>{' '}
            <span className="wm"><span className="w">three</span></span>{' '}
            <span className="wm"><span className="w acc">commands.</span></span>
          </h2>
          <p className="muted rv" style={{ margin: '0 0 36px', maxWidth: '640px' }}>
            Docker is the recommended path. Open the frontend, sign in with the default admin login, and change it straight away.
          </p>

          <div className="cd2">
            <div className="rv">
              <p className="lbl">OPTION 1 / DOCKER (RECOMMENDED)</p>
              <div className="code">git clone https://github.com/salman2610/purple-agent.git
cd purple-agent
docker-compose up -d

# frontend  http://localhost:5173
# backend   http://localhost:8000</div>
            </div>

            <div className="rv">
              <p className="lbl">OPTION 2 / MANUAL SETUP</p>
              <div className="code"># backend
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# frontend
cd frontend &amp;&amp; npm install &amp;&amp; npm run dev</div>
            </div>

            <div className="rv">
              <p className="lbl">AGENT / CONFIG (config/config.json)</p>
              <div className="code">&#123;
  "server_url": "https://your-backend.example.com/api/agent",
  "agent_id": "server-001",
  "auth_token": "your-jwt-token-here",
  "scan_interval": 60,
  "log_paths": ["/var/log/auth.log", "/var/log/syslog"],
  "integrity_dirs": ["/etc", "/var/www", "/usr/bin"]
&#125;</div>
            </div>

            <div className="rv">
              <p className="lbl">AGENT / SYSTEMD SERVICE</p>
              <div className="code">[Unit]
Description=Purple Agent Monitoring Service
After=network.target

[Service]
User=root
WorkingDirectory=/path/to/purple-agent
ExecStart=/path/to/purple-agent/venv/bin/python -m agent.main
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target</div>
            </div>
          </div>
        </div>
      </div>

      {/* ── TROUBLESHOOTING ──────────────────────────────────────────────── */}
      <div className="sec" style={{ background: '#130E1D' }}>
        <div className="wrap split" style={{ alignItems: 'start' }}>
          <div>
            <p className="eyebrow">Troubleshooting</p>
            <h2 className="h hd" style={{ fontSize: '44px', marginBottom: '20px' }}>
              <span className="wm"><span className="w">Stuck?</span></span>{' '}
              <span className="wm"><span className="w">Start</span></span>{' '}
              <span className="wm"><span className="w acc">here.</span></span>
            </h2>
            <p className="muted rv" style={{ margin: 0 }}>
              The three problems people hit first, and the fix for each.
            </p>
          </div>
          <div className="rv">
            <details>
              <summary>Agent not connecting?</summary>
              <ul>
                <li>Check <code>config/config.json</code>: verify <code>server_url</code> and <code>auth_token</code></li>
                <li>Make sure the backend is reachable from the agent server</li>
                <li>Check logs: <code>journalctl -u purple-agent -f</code></li>
              </ul>
            </details>
            <details>
              <summary>CORS errors in the browser?</summary>
              <p>Add your frontend origin to <code>ALLOWED_ORIGINS</code> in <code>backend/main.py</code>.</p>
            </details>
            <details>
              <summary>Database warnings?</summary>
              <p>Run <code>ALTER DATABASE purpleteam_db REFRESH COLLATION VERSION;</code> in psql.</p>
            </details>
          </div>
        </div>
      </div>

      {/* ── ROADMAP ──────────────────────────────────────────────────────── */}
      <div className="sec">
        <div className="wrap">
          <p className="eyebrow">Roadmap</p>
          <h2 className="h hd" style={{ fontSize: '44px', marginBottom: '40px' }}>
            <span className="wm"><span className="w">What's</span></span>{' '}
            <span className="wm"><span className="w acc">next.</span></span>
          </h2>
          <div className="rm">
            <span className="rv">One-line agent install (curl | bash)</span>
            <span className="rv">Email and SMS alerts</span>
            <span className="rv">Windows agent support</span>
            <span className="rv">Docker container monitoring</span>
            <span className="rv">Multi-tenant and team support</span>
            <span className="rv">Mobile-responsive UI</span>
            <span className="rv">Stripe billing for a hosted version</span>
            <span className="rv">Kubernetes pod monitoring</span>
          </div>
        </div>
      </div>

      {/* ── CONTRIBUTING ─────────────────────────────────────────────────── */}
      <div className="sec" style={{ background: '#130E1D' }}>
        <div className="wrap split">
          <div>
            <p className="eyebrow">Contributing</p>
            <h2 className="h hd" style={{ fontSize: '44px', marginBottom: '20px' }}>
              <span className="wm"><span className="w">Contributions</span></span>{' '}
              <span className="wm"><span className="w">are</span></span>{' '}
              <span className="wm"><span className="w acc">welcome.</span></span>
            </h2>
            <p className="muted rv" style={{ margin: '0 0 28px' }}>
              Please open an issue before submitting a PR so the change can be discussed first.
            </p>
            <a href="https://github.com/salman2610/purple-agent/issues" target="_blank" rel="noreferrer" className="btn mag">
              Open an issue
            </a>
          </div>
          <div className="code rv">git checkout -b feature/your-feature
git commit -m "feat: add your feature"
git push origin feature/your-feature
# Open a Pull Request</div>
        </div>
      </div>

      {/* ── PRICING ──────────────────────────────────────────────────────── */}
      <div className="sec" id="pricing" style={{ background: '#130E1D' }}>
        <div className="wrap">
          <p className="eyebrow">Pricing</p>
          <h2 className="h hd" style={{ fontSize: '48px', maxWidth: '780px', marginBottom: '40px' }}>
            <span className="wm"><span className="w">Free</span></span>{' '}
            <span className="wm"><span className="w">to</span></span>{' '}
            <span className="wm"><span className="w acc">self-host</span></span>{' '}
            <span className="wm"><span className="w acc">today.</span></span>
          </h2>
          <div className="price">
            <div className="card rv" style={{ borderColor: '#4A3A6E', background: 'rgba(124, 58, 237, 0.08)' }}>
              <span className="tag">AVAILABLE NOW</span>
              <h3>Self-host</h3>
              <div className="big2">Free</div>
              <p>MIT licensed. Run it on your own infrastructure.</p>
              <ul>
                <li>The full dashboard, backend and agent</li>
                <li>Docker Compose quick start</li>
                <li>One agent per monitored server</li>
                <li>Community support through GitHub issues</li>
              </ul>
              <a href="https://github.com/salman2610/purple-agent" target="_blank" rel="noreferrer" className="btn p mag">
                Get it on GitHub
              </a>
            </div>

            <div className="card rv">
              <span className="tag">ROADMAP</span>
              <h3>Hosted</h3>
              <div className="big2">Coming soon</div>
              <p>A managed version, so you can skip the setup.</p>
              <ul>
                <li>Hosted backend and database</li>
                <li>Multi-tenant and team support</li>
                <li>Email and SMS alerts</li>
              </ul>
              <a href="https://github.com/salman2610/purple-agent/issues" target="_blank" rel="noreferrer" className="btn mag">
                Follow progress
              </a>
            </div>
          </div>
        </div>
      </div>

      {/* ── FINAL CALL TO ACTION ─────────────────────────────────────────── */}
      <div className="sec" style={{ textAlign: 'center', position: 'relative', overflow: 'hidden' }}>
        <div className="orb o2" style={{ left: '50%', bottom: '-200px', marginLeft: '-160px', opacity: 0.3 }}></div>
        <div className="wrap">
          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '24px' }}>
            <img
              src="/logos/logo-shield.png"
              alt="Purple Agent Shield"
              style={{ width: '64px', height: '64px', objectFit: 'contain', filter: 'drop-shadow(0 0 24px rgba(167, 139, 250, 0.6))' }}
            />
          </div>
          <h2 className="h hd" style={{ fontSize: '56px', maxWidth: '760px', margin: '0 auto 20px' }}>
            <span className="wm"><span className="w">Stop</span></span>{' '}
            <span className="wm"><span className="w">staring</span></span>{' '}
            <span className="wm"><span className="w">at</span></span>{' '}
            <span className="wm"><span className="w acc">graphs.</span></span>
          </h2>
          <p className="muted rv" style={{ margin: '0 0 32px', fontSize: '19px' }}>
            Use it, fork it, build on it. MIT licensed. If it helps you, star the repo.
          </p>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '14px', flexWrap: 'wrap' }}>
            <button
              onClick={onLaunchDemo}
              className="btn p mag"
              style={{ fontSize: '16px', fontWeight: '700' }}
            >
              🚀 Launch SOC Console
            </button>
            <a
              href="https://github.com/salman2610/purple-agent"
              target="_blank"
              rel="noreferrer"
              className="btn mag"
              style={{ fontSize: '16px' }}
            >
              Star on GitHub ★
            </a>
          </div>
        </div>
      </div>

      {/* ── FOOTER WITH BRAND LOGO ───────────────────────────────────────── */}
      <div
        className="wrap"
        style={{
          paddingTop: '32px',
          paddingBottom: '32px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '12px',
          fontSize: '14px',
          borderTop: '1px solid #2A2040'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <img
            src="/logos/app-icon.png"
            alt="Purple Agent"
            style={{ width: '22px', height: '22px', borderRadius: '5px' }}
          />
          <span className="muted">
            Designed and built by{' '}
            <a
              href="https://salman2610.github.io"
              target="_blank"
              rel="noreferrer"
              className="acc"
              style={{ textDecoration: 'underline' }}
            >
              P Salmanul Faris
            </a>
          </span>
        </div>
        <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
          <span className="muted">MIT License</span>
          <span className="muted">·</span>
          <a href="https://github.com/salman2610/purple-agent" target="_blank" rel="noreferrer" className="muted" style={{ textDecoration: 'none' }}>GitHub Repo</a>
        </div>
      </div>
    </div>
  );
}
