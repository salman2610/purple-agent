import React, { useState, useEffect, useRef } from 'react';
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';

gsap.registerPlugin(ScrollTrigger);

export default function LandingPage({ onLaunchDemo, onOpenAuth }) {
  // ── State for Interactive Elements ───────────────────────────────────────
  // ROI Calculator
  const [servers, setServers] = useState(14);
  const [hoursPerInc, setHoursPerInc] = useState(2);
  const [incidentsPerMonth, setIncidentsPerMonth] = useState(4);
  const hoursSaved = Math.round(servers * hoursPerInc * (incidentsPerMonth / 2) * 1.4);
  const dollarSaved = (hoursSaved * 40).toLocaleString('en-US');

  // Animated counters for ROI
  const hoursNumRef = useRef(null);
  const dollarNumRef = useRef(null);

  // Incident tabs
  const [activeIncidentTab, setActiveIncidentTab] = useState('explanation');

  // Terminal OS selector
  const [selectedOS, setSelectedOS] = useState('linux');
  const [copiedCode, setCopiedCode] = useState(false);

  // FAQ Accordions
  const [openFaq, setOpenFaq] = useState(null);

  // Root Ref for GSAP scoping
  const rootRef = useRef(null);
  const heroCardRef = useRef(null);
  const cube1Ref = useRef(null);
  const cube2Ref = useRef(null);

  // ── Code snippets per OS ──────────────────────────────────────────────────
  const codeSnippets = {
    linux: `# 1. Download the agent\n$ curl -sSL https://get.purpleagent.dev | bash\n\n# 2. Connect to your account\n$ purpleagent connect --key YOUR_API_KEY\n\n# 3. Start monitoring\n$ purpleagent start /purpleagent`,
    macos: `# 1. Install via Homebrew\n$ brew install purpleagent/tap/agent\n\n# 2. Connect to your account\n$ purpleagent connect --key YOUR_API_KEY\n\n# 3. Start background daemon\n$ brew services start purpleagent`,
    windows: `# 1. Install via PowerShell\nPS> iwr -useb https://get.purpleagent.dev/install.ps1 | iex\n\n# 2. Connect to your account\nPS> purpleagent connect --key YOUR_API_KEY\n\n# 3. Register and start service\nPS> purpleagent service install && purpleagent service start`
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(codeSnippets[selectedOS] || codeSnippets.linux);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2200);
  };

  // ── GSAP Scroll-Triggered & Typographic Animations ────────────────────────
  useEffect(() => {
    const r = rootRef.current;
    if (!r) return;

    const ctx = gsap.context(() => {
      const q = (sel) => r.querySelectorAll(sel);

      // 1. Top Scroll Progress Bar
      gsap.to(q('.scroll-progress'), {
        scaleX: 1,
        ease: 'none',
        scrollTrigger: {
          trigger: r,
          start: 'top top',
          end: 'bottom bottom',
          scrub: 0.15
        }
      });

      // 2. Parallax Ambient Glow Orbs
      gsap.to(q('.ambient-orb-1'), {
        yPercent: -45,
        ease: 'none',
        scrollTrigger: {
          trigger: r,
          start: 'top top',
          end: 'bottom bottom',
          scrub: 1
        }
      });
      gsap.to(q('.ambient-orb-2'), {
        yPercent: 40,
        ease: 'none',
        scrollTrigger: {
          trigger: r,
          start: 'top top',
          end: 'bottom bottom',
          scrub: 1
        }
      });

      // 3. Floating 3D Cubes continuous yoyo
      if (cube1Ref.current) {
        gsap.to(cube1Ref.current, {
          y: -16,
          rotationY: '+=25',
          rotationX: '-=12',
          duration: 3.6,
          repeat: -1,
          yoyo: true,
          ease: 'sine.inOut'
        });
      }
      if (cube2Ref.current) {
        gsap.to(cube2Ref.current, {
          y: -12,
          rotationZ: '+=15',
          duration: 4,
          repeat: -1,
          yoyo: true,
          ease: 'sine.inOut'
        });
      }

      // 4. Hero Section Timeline
      const heroTl = gsap.timeline({ defaults: { ease: 'power4.out' } });
      heroTl
        .from(q('.nav-container'), { autoAlpha: 0, y: -24, duration: 0.8 }, 0)
        .from(q('.hero-eyebrow'), { autoAlpha: 0, x: -30, duration: 0.7 }, '-=0.4')
        .from(q('.hero-title .w'), { yPercent: 120, rotate: 5, duration: 1.1, stagger: 0.06 }, '-=0.3')
        .from(q('.hero-sub'), { autoAlpha: 0, y: 24, duration: 0.8 }, '-=0.5')
        .from(q('.hero-actions'), { autoAlpha: 0, y: 22, duration: 0.7 }, '-=0.6')
        .from(q('.hero-trust-item'), { autoAlpha: 0, y: 15, duration: 0.6, stagger: 0.1 }, '-=0.4')
        .from(heroCardRef.current, { autoAlpha: 0, y: 60, scale: 0.93, rotationX: -12, duration: 1.2 }, '-=0.8')
        .from(q('.floating-alert-badge'), { autoAlpha: 0, scale: 0.75, x: 30, duration: 0.8, ease: 'back.out(1.7)' }, '-=0.4');

      // 5. 3D Tilt for Hero Dashboard on Mouse Move
      const heroCard = heroCardRef.current;
      const heroSection = q('.hero-section')[0];
      if (heroCard && heroSection) {
        const setRotX = gsap.quickTo(heroCard, 'rotationX', { duration: 0.7, ease: 'power3' });
        const setRotY = gsap.quickTo(heroCard, 'rotationY', { duration: 0.7, ease: 'power3' });

        const handleHeroMouse = (e) => {
          const rect = heroSection.getBoundingClientRect();
          const xNorm = (e.clientX - rect.left) / rect.width - 0.5;
          const yNorm = (e.clientY - rect.top) / rect.height - 0.5;
          setRotY(xNorm * 12);
          setRotX(-yNorm * 10);
        };
        const handleHeroLeave = () => {
          setRotX(0);
          setRotY(0);
        };

        heroSection.addEventListener('mousemove', handleHeroMouse);
        heroSection.addEventListener('mouseleave', handleHeroLeave);
      }

      // 6. Typographic Word Split animations for all section titles (.sec-h)
      q('.sec-h').forEach((heading) => {
        gsap.from(heading.querySelectorAll('.w'), {
          yPercent: 120,
          rotate: 4,
          duration: 0.95,
          ease: 'power4.out',
          stagger: 0.045,
          scrollTrigger: {
            trigger: heading,
            start: 'top 85%',
            once: true
          }
        });
      });

      // 7. Section Eyebrows slide in on scroll
      q('.sec-eyebrow').forEach((eyebrow) => {
        gsap.from(eyebrow, {
          x: -25,
          autoAlpha: 0,
          duration: 0.7,
          ease: 'power3.out',
          scrollTrigger: {
            trigger: eyebrow,
            start: 'top 88%',
            once: true
          }
        });
      });

      // 8. General Card Reveals (.card-anim) with stagger
      q('.card-grid-anim').forEach((grid) => {
        const cards = grid.querySelectorAll('.card-anim');
        gsap.from(cards, {
          autoAlpha: 0,
          y: 55,
          scale: 0.94,
          duration: 0.85,
          stagger: 0.12,
          ease: 'power3.out',
          clearProps: 'transform',
          scrollTrigger: {
            trigger: grid,
            start: 'top 82%',
            once: true
          }
        });
      });

      // 9. Real-Time Servers Table Rows Sequenced Stagger
      const serverRows = q('.server-row-anim');
      if (serverRows.length > 0) {
        gsap.from(serverRows, {
          x: -30,
          autoAlpha: 0,
          duration: 0.6,
          stagger: 0.14,
          ease: 'power3.out',
          scrollTrigger: {
            trigger: '.servers-table-card',
            start: 'top 80%',
            once: true
          }
        });
      }

      // 10. Sparklines and Charts Path Draw
      q('.chart-stroke').forEach((path) => {
        gsap.from(path, {
          strokeDashoffset: 1,
          duration: 2.2,
          ease: 'power2.inOut',
          scrollTrigger: { trigger: path, start: 'top 88%', once: true }
        });
      });

      // 11. Workflow 4-Step Cards cascading trigger
      const workflowSteps = q('.workflow-step-anim');
      if (workflowSteps.length > 0) {
        gsap.from(workflowSteps, {
          y: 45,
          scale: 0.92,
          autoAlpha: 0,
          duration: 0.75,
          stagger: 0.15,
          ease: 'power3.out',
          scrollTrigger: {
            trigger: '.workflow-grid-anim',
            start: 'top 82%',
            once: true
          }
        });
      }

      // 12. Incident Evidence Log Lines cascade
      const logLines = q('.log-line-anim');
      if (logLines.length > 0) {
        gsap.from(logLines, {
          y: 18,
          autoAlpha: 0,
          duration: 0.5,
          stagger: 0.16,
          ease: 'power3.out',
          scrollTrigger: {
            trigger: '.incident-card-anim',
            start: 'top 78%',
            once: true
          }
        });
      }

      // 13. Terminal Window slide up
      const termWindow = q('.terminal-window-anim')[0];
      if (termWindow) {
        gsap.from(termWindow, {
          y: 60,
          autoAlpha: 0,
          duration: 0.9,
          ease: 'power3.out',
          scrollTrigger: {
            trigger: termWindow,
            start: 'top 82%',
            once: true
          }
        });
      }

      // 14. CTA Banner Entrance
      const ctaBanner = q('.cta-banner-anim')[0];
      if (ctaBanner) {
        gsap.from(ctaBanner, {
          scale: 0.92,
          y: 40,
          autoAlpha: 0,
          duration: 1,
          ease: 'power3.out',
          scrollTrigger: {
            trigger: ctaBanner,
            start: 'top 85%',
            once: true
          }
        });
      }

      // 15. Radial Glow tracking mouse on cards (.interactive-card)
      r.addEventListener('pointermove', (e) => {
        const card = e.target.closest && e.target.closest('.interactive-card');
        if (card) {
          const b = card.getBoundingClientRect();
          card.style.setProperty('--card-mx', `${e.clientX - b.left}px`);
          card.style.setProperty('--card-my', `${e.clientY - b.top}px`);
        }
      });

      // 16. Magnetic Button Hover effect (.magnetic-btn)
      q('.magnetic-btn').forEach((btn) => {
        const xTo = gsap.quickTo(btn, 'x', { duration: 0.4, ease: 'power3' });
        const yTo = gsap.quickTo(btn, 'y', { duration: 0.4, ease: 'power3' });

        btn.addEventListener('mousemove', (e) => {
          const b = btn.getBoundingClientRect();
          xTo((e.clientX - b.left - b.width / 2) * 0.24);
          yTo((e.clientY - b.top - b.height / 2) * 0.3);
        });
        btn.addEventListener('mouseleave', () => {
          xTo(0);
          yTo(0);
        });
      });
    }, rootRef);

    return () => ctx.revert();
  }, []);

  // ── Animate numbers when ROI sliders update ───────────────────────────────
  useEffect(() => {
    if (hoursNumRef.current) {
      gsap.fromTo(
        hoursNumRef.current,
        { scale: 1.18, color: '#C084FC' },
        { scale: 1, color: '#EDE9F6', duration: 0.4, ease: 'power2.out' }
      );
    }
    if (dollarNumRef.current) {
      gsap.fromTo(
        dollarNumRef.current,
        { scale: 1.18, color: '#34D399' },
        { scale: 1, color: '#EDE9F6', duration: 0.4, ease: 'power2.out' }
      );
    }
  }, [hoursSaved, dollarSaved]);

  return (
    <div
      ref={rootRef}
      className="purple-landing-root"
      style={{
        '--pa-accent': '#8B5CF6',
        '--pa-accent-light': '#A78BFA',
        '--pa-accent-glow': 'rgba(139, 92, 246, 0.45)',
        '--pa-bg': '#070311',
        '--pa-card-bg': '#0D081D',
        '--pa-card-border': '#22163B',
        '--pa-card-hover': '#381E6E',
        '--pa-text-main': '#EDE9F6',
        '--pa-text-muted': '#9E94B8',
        '--pa-text-sub': '#776E91',
        backgroundColor: '#070311',
        color: '#EDE9F6',
        fontFamily: "'Inter', -apple-system, sans-serif",
        fontSize: '16px',
        lineHeight: 1.6,
        minHeight: '100vh',
        width: '100%',
        overflowX: 'hidden',
        position: 'relative',
        WebkitFontSmoothing: 'antialiased'
      }}
    >
      {/* ── Custom CSS Styles ────────────────────────────────────────────── */}
      <style>{`
        .purple-landing-root * { box-sizing: border-box; }
        .purple-landing-root a { text-decoration: none; color: inherit; }
        .section-wrap { max-width: 1220px; margin: 0 auto; padding: 0 28px; position: relative; }
        
        /* Typography */
        .font-display { font-family: 'Bricolage Grotesque', sans-serif; letter-spacing: -0.025em; line-height: 1.08; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
        .text-accent { color: var(--pa-accent-light); }
        .text-accent-gradient {
          background: linear-gradient(135deg, #C084FC 0%, #8B5CF6 100%);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
        }

        /* Word Mask for Typographic Entrances */
        .wm { display: inline-block; overflow: hidden; vertical-align: top; padding-bottom: 0.12em; margin-bottom: -0.12em; }
        .w { display: inline-block; will-change: transform; }

        /* Scroll Progress Bar */
        .scroll-progress {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          height: 3px;
          background: linear-gradient(90deg, #7C3AED, #A78BFA, #2DD4BF);
          transform: scaleX(0);
          transform-origin: left;
          z-index: 99999;
        }

        /* Ambient Glow & Grid */
        .bg-grid-pattern {
          position: absolute;
          inset: 0;
          background-image: 
            linear-gradient(rgba(139, 92, 246, 0.05) 1px, transparent 1px),
            linear-gradient(90deg, rgba(139, 92, 246, 0.05) 1px, transparent 1px);
          background-size: 54px 54px;
          mask-image: radial-gradient(ellipse at 50% 25%, #000 30%, transparent 80%);
          -webkit-mask-image: radial-gradient(ellipse at 50% 25%, #000 30%, transparent 80%);
          pointer-events: none;
        }
        .ambient-orb {
          position: absolute;
          border-radius: 50%;
          filter: blur(120px);
          pointer-events: none;
          opacity: 0.35;
        }
        .ambient-orb-1 { width: 550px; height: 550px; background: #6D28D9; top: -120px; right: 5%; }
        .ambient-orb-2 { width: 480px; height: 480px; background: #8B5CF6; top: 400px; left: -100px; opacity: 0.24; }

        /* Interactive Card Base */
        .interactive-card {
          background: var(--pa-card-bg);
          border: 1px solid var(--pa-card-border);
          border-radius: 14px;
          position: relative;
          overflow: hidden;
          transition: border-color 0.3s ease, transform 0.3s ease, box-shadow 0.3s ease;
        }
        .interactive-card::before {
          content: "";
          position: absolute;
          inset: 0;
          pointer-events: none;
          opacity: 0;
          transition: opacity 0.35s ease;
          background: radial-gradient(320px circle at var(--card-mx, 50%) var(--card-my, 50%), rgba(167, 139, 250, 0.14), transparent 70%);
        }
        .interactive-card:hover {
          border-color: var(--pa-card-hover);
          box-shadow: 0 16px 40px rgba(7, 3, 17, 0.8), 0 0 30px rgba(124, 58, 237, 0.2);
          transform: translateY(-4px);
        }
        .interactive-card:hover::before { opacity: 1; }

        /* Buttons */
        .btn-purple-primary {
          background: linear-gradient(135deg, #8B5CF6 0%, #7C3AED 100%);
          color: #FFFFFF;
          font-weight: 600;
          border-radius: 10px;
          padding: 12px 24px;
          display: inline-flex;
          align-items: center;
          gap: 9px;
          border: 1px solid rgba(196, 181, 253, 0.35);
          box-shadow: 0 4px 20px rgba(124, 58, 237, 0.4), inset 0 1px 1px rgba(255, 255, 255, 0.3);
          transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
          cursor: pointer;
          position: relative;
          overflow: hidden;
        }
        .btn-purple-primary:hover {
          box-shadow: 0 8px 30px rgba(124, 58, 237, 0.65), inset 0 1px 2px rgba(255, 255, 255, 0.4);
          transform: translateY(-2px);
          border-color: rgba(221, 214, 254, 0.7);
        }
        .btn-dark-secondary {
          background: rgba(255, 255, 255, 0.04);
          color: #EDE9F6;
          font-weight: 500;
          border-radius: 10px;
          padding: 12px 22px;
          display: inline-flex;
          align-items: center;
          gap: 9px;
          border: 1px solid rgba(255, 255, 255, 0.1);
          transition: all 0.2s ease;
          cursor: pointer;
        }
        .btn-dark-secondary:hover {
          background: rgba(255, 255, 255, 0.08);
          border-color: rgba(167, 139, 250, 0.35);
          color: #FFFFFF;
          transform: translateY(-2px);
        }

        /* Checkmark Bullets */
        .check-pill {
          width: 18px;
          height: 18px;
          border-radius: 50%;
          background: rgba(139, 92, 246, 0.18);
          border: 1px solid rgba(139, 92, 246, 0.4);
          display: inline-flex;
          align-items: center;
          justify-content: center;
          color: #C4B5FD;
          flex-shrink: 0;
          font-size: 11px;
        }

        @media (max-width: 1024px) {
          .hero-grid { grid-template-columns: 1fr !important; }
          .two-col-grid { grid-template-columns: 1fr !important; gap: 40px !important; }
          .three-col-grid { grid-template-columns: 1fr !important; }
          .four-col-grid { grid-template-columns: repeat(2, 1fr) !important; }
        }
        @media (max-width: 640px) {
          .four-col-grid { grid-template-columns: 1fr !important; }
          .nav-links-desktop { display: none !important; }
          .hero-title-text { font-size: 44px !important; }
        }
      `}</style>

      {/* ── Scroll Progress Bar ─────────────────────────────────────────── */}
      <div className="scroll-progress"></div>

      {/* ── Background Grids & Parallax Lights ──────────────────────────── */}
      <div className="bg-grid-pattern"></div>
      <div className="ambient-orb ambient-orb-1"></div>
      <div className="ambient-orb ambient-orb-2"></div>

      {/* ── 1. NAVBAR (WITH AUTHENTIC BRAND LOGO) ────────────────────────── */}
      <header
        className="nav-container"
        style={{
          position: 'sticky',
          top: 0,
          zIndex: 1000,
          backgroundColor: 'rgba(7, 3, 17, 0.8)',
          backdropFilter: 'blur(18px)',
          WebkitBackdropFilter: 'blur(18px)',
          borderBottom: '1px solid rgba(255, 255, 255, 0.06)'
        }}
      >
        <div
          className="section-wrap"
          style={{
            height: '76px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between'
          }}
        >
          {/* Authentic Brand Logo */}
          <a href="#top" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <img
              src="/logos/app-icon.png"
              alt="Purple Agent Logo"
              style={{
                width: '38px',
                height: '38px',
                borderRadius: '10px',
                boxShadow: '0 0 20px rgba(139, 92, 246, 0.55)',
                objectFit: 'contain'
              }}
            />
            <span
              className="font-display"
              style={{ fontSize: '21px', fontWeight: '800', color: '#EDE9F6', letterSpacing: '-0.02em' }}
            >
              PurpleAgent
            </span>
          </a>

          {/* Navigation Menu Items */}
          <nav className="nav-links-desktop" style={{ display: 'flex', alignItems: 'center', gap: '28px' }}>
            <a href="#features" style={{ fontSize: '14.5px', color: '#9E94B8', transition: 'color 0.2s' }} onMouseEnter={e => e.target.style.color = '#EDE9F6'} onMouseLeave={e => e.target.style.color = '#9E94B8'}>Features</a>
            <a href="#how-it-works" style={{ fontSize: '14.5px', color: '#9E94B8', transition: 'color 0.2s' }} onMouseEnter={e => e.target.style.color = '#EDE9F6'} onMouseLeave={e => e.target.style.color = '#9E94B8'}>How it works</a>
            <a href="#use-cases" style={{ fontSize: '14.5px', color: '#9E94B8', transition: 'color 0.2s' }} onMouseEnter={e => e.target.style.color = '#EDE9F6'} onMouseLeave={e => e.target.style.color = '#9E94B8'}>Use cases</a>
            <a href="#pricing" style={{ fontSize: '14.5px', color: '#9E94B8', transition: 'color 0.2s' }} onMouseEnter={e => e.target.style.color = '#EDE9F6'} onMouseLeave={e => e.target.style.color = '#9E94B8'}>Pricing</a>
            <a href="#docs" style={{ fontSize: '14.5px', color: '#9E94B8', transition: 'color 0.2s' }} onMouseEnter={e => e.target.style.color = '#EDE9F6'} onMouseLeave={e => e.target.style.color = '#9E94B8'}>Docs</a>
            <a href="#community" style={{ fontSize: '14.5px', color: '#9E94B8', transition: 'color 0.2s' }} onMouseEnter={e => e.target.style.color = '#EDE9F6'} onMouseLeave={e => e.target.style.color = '#9E94B8'}>Community</a>
          </nav>

          {/* Right Action Buttons */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '18px' }}>
            {onOpenAuth ? (
              <button
                onClick={onOpenAuth}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: '#C4BBD8',
                  fontSize: '14.5px',
                  fontWeight: '500',
                  cursor: 'pointer',
                  padding: '6px 10px'
                }}
              >
                Sign in
              </button>
            ) : (
              <a href="#pricing" style={{ fontSize: '14.5px', color: '#C4BBD8' }}>Sign in</a>
            )}

            <button
              onClick={onLaunchDemo}
              className="btn-purple-primary magnetic-btn"
              style={{ fontSize: '14px', padding: '9px 18px', borderRadius: '8px' }}
            >
              <span>Get PurpleAgent</span>
            </button>
          </div>
        </div>
      </header>

      {/* ── 2. HERO SECTION ──────────────────────────────────────────────── */}
      <section className="hero-section" id="top" style={{ padding: '80px 0 100px', position: 'relative' }}>
        <div className="section-wrap">
          <div
            className="hero-grid"
            style={{
              display: 'grid',
              gridTemplateColumns: '1.05fr 1.15fr',
              gap: '48px',
              alignItems: 'center'
            }}
          >
            {/* Left Content Column */}
            <div>
              {/* Eyebrow */}
              <div
                className="hero-eyebrow font-mono"
                style={{
                  fontSize: '11.5px',
                  letterSpacing: '0.12em',
                  textTransform: 'uppercase',
                  color: '#A78BFA',
                  marginBottom: '18px',
                  fontWeight: '600',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px'
                }}
              >
                <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#A78BFA', boxShadow: '0 0 10px #A78BFA' }}></span>
                SERVER MONITORING &amp; INCIDENT DIAGNOSIS
              </div>

              {/* Main Headline with Mask Entrance */}
              <h1
                className="hero-title font-display hero-title-text"
                style={{
                  fontSize: '62px',
                  fontWeight: '800',
                  lineHeight: '1.04',
                  margin: '0 0 24px',
                  color: '#FFFFFF'
                }}
              >
                <span className="wm"><span className="w">Monitor</span></span>{' '}
                <span className="wm"><span className="w">your</span></span><br />
                <span className="wm"><span className="w">servers.</span></span><br />
                <span className="wm"><span className="w">Understand</span></span><br />
                <span className="wm"><span className="w text-accent-gradient">what's wrong.</span></span>
              </h1>

              {/* Description */}
              <p
                className="hero-sub"
                style={{
                  fontSize: '17px',
                  color: '#9E94B8',
                  lineHeight: '1.65',
                  marginBottom: '36px',
                  maxWidth: '520px'
                }}
              >
                PurpleAgent continuously checks your servers, detects issues, explains the root cause and helps you fix them — from one place, with clear insights, and actionable steps.
              </p>

              {/* Action Buttons */}
              <div
                className="hero-actions"
                style={{
                  display: 'flex',
                  gap: '14px',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  marginBottom: '34px'
                }}
              >
                <button
                  onClick={onLaunchDemo}
                  className="btn-purple-primary magnetic-btn"
                  style={{ fontSize: '15.5px', padding: '14px 28px' }}
                >
                  <span>Get started free</span>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
                    <line x1="5" y1="12" x2="19" y2="12"></line>
                    <polyline points="12 5 19 12 12 19"></polyline>
                  </svg>
                </button>

                <button
                  onClick={onLaunchDemo}
                  className="btn-dark-secondary magnetic-btn"
                  style={{ fontSize: '15px', padding: '14px 24px' }}
                >
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="#C4B5FD">
                    <polygon points="5 3 19 12 5 21 5 3"></polygon>
                  </svg>
                  <span>Watch Demo</span>
                </button>
              </div>

              {/* Trust Checkmarks */}
              <div style={{ display: 'flex', gap: '24px', alignItems: 'center', flexWrap: 'wrap' }}>
                <div className="hero-trust-item" style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13.5px', color: '#9E94B8' }}>
                  <span className="check-pill">✓</span>
                  No credit card required
                </div>
                <div className="hero-trust-item" style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13.5px', color: '#9E94B8' }}>
                  <span className="check-pill">✓</span>
                  Setup in minutes
                </div>
                <div className="hero-trust-item" style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13.5px', color: '#9E94B8' }}>
                  <span className="check-pill">✓</span>
                  Works on Linux servers
                </div>
              </div>
            </div>

            {/* Right Mockup Graphic Column */}
            <div style={{ perspective: '1200px', position: 'relative' }}>
              {/* Floating Alert Pill in Top-Right */}
              <div
                className="floating-alert-badge"
                style={{
                  position: 'absolute',
                  top: '-24px',
                  right: '-16px',
                  zIndex: 20,
                  background: 'rgba(239, 68, 68, 0.15)',
                  border: '1px solid rgba(239, 68, 68, 0.45)',
                  backdropFilter: 'blur(14px)',
                  borderRadius: '12px',
                  padding: '12px 16px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                  boxShadow: '0 12px 30px rgba(0,0,0,0.5), 0 0 20px rgba(239, 68, 68, 0.25)'
                }}
              >
                <div
                  style={{
                    width: '32px',
                    height: '32px',
                    borderRadius: '8px',
                    background: 'rgba(239, 68, 68, 0.25)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: '#F87171'
                  }}
                >
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                    <line x1="12" y1="9" x2="12" y2="13"></line>
                    <line x1="12" y1="17" x2="12.01" y2="17"></line>
                  </svg>
                </div>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: '700', color: '#FCA5A5' }}>High CPU usage</div>
                  <div style={{ fontSize: '11px', color: '#D1D5DB' }}>Detected on web-01 · 2 mins ago</div>
                </div>
              </div>

              {/* 3D Isometric Purple Cube with PurpleAgent Shield */}
              <div
                ref={cube1Ref}
                style={{
                  position: 'absolute',
                  bottom: '-35px',
                  right: '-28px',
                  zIndex: 25,
                  width: '92px',
                  height: '92px',
                  filter: 'drop-shadow(0 15px 30px rgba(124, 58, 237, 0.7))'
                }}
              >
                <div style={{ position: 'relative', width: '100%', height: '100%' }}>
                  <svg viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg" style={{ width: '100%', height: '100%' }}>
                    <path d="M50 6 L90 29 L50 52 L10 29 Z" fill="#9333EA" stroke="#C084FC" strokeWidth="1.5" />
                    <path d="M10 29 L50 52 L50 96 L10 73 Z" fill="#6B21A8" stroke="#A855F7" strokeWidth="1.5" />
                    <path d="M50 52 L90 29 L90 73 L50 96 Z" fill="#4C1D95" stroke="#9333EA" strokeWidth="1.5" />
                  </svg>
                  <img
                    src="/logos/logo-shield.png"
                    alt="Purple Agent Shield"
                    style={{
                      position: 'absolute',
                      top: '52%',
                      left: '50%',
                      transform: 'translate(-50%, -50%)',
                      width: '38px',
                      height: '38px',
                      objectFit: 'contain',
                      filter: 'drop-shadow(0 0 12px rgba(255, 255, 255, 0.6))'
                    }}
                  />
                </div>
              </div>

              {/* Main Dashboard Preview Card */}
              <div
                ref={heroCardRef}
                className="interactive-card"
                style={{
                  borderRadius: '16px',
                  border: '1px solid rgba(139, 92, 246, 0.28)',
                  background: 'linear-gradient(145deg, #0E0921 0%, #070311 100%)',
                  boxShadow: '0 30px 80px rgba(0, 0, 0, 0.75), 0 0 60px rgba(124, 58, 237, 0.25)',
                  transformStyle: 'preserve-3d',
                  display: 'flex',
                  minHeight: '420px',
                  overflow: 'hidden'
                }}
              >
                {/* Mini Left Sidebar */}
                <div
                  style={{
                    width: '144px',
                    borderRight: '1px solid rgba(255, 255, 255, 0.06)',
                    background: 'rgba(0, 0, 0, 0.25)',
                    padding: '16px 12px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '14px'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', paddingBottom: '12px', borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                    <img
                      src="/logos/app-icon.png"
                      alt="Purple Agent"
                      style={{ width: '22px', height: '22px', borderRadius: '6px', objectFit: 'contain' }}
                    />
                    <span style={{ fontSize: '12.5px', fontWeight: '700', color: '#EDE9F6' }}>PurpleAgent</span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <div style={{ padding: '6px 8px', borderRadius: '6px', fontSize: '11px', color: '#9E94B8' }}>Services</div>
                    <div style={{ padding: '6px 8px', borderRadius: '6px', fontSize: '11px', color: '#C4B5FD', background: 'rgba(139, 92, 246, 0.16)', fontWeight: '600' }}>Servers</div>
                    <div style={{ padding: '6px 8px', borderRadius: '6px', fontSize: '11px', color: '#F87171', display: 'flex', justifyContent: 'space-between' }}>
                      <span>Incidents</span>
                      <span style={{ background: 'rgba(239, 68, 68, 0.3)', padding: '1px 5px', borderRadius: '4px', fontSize: '10px' }}>1</span>
                    </div>
                    <div style={{ padding: '6px 8px', borderRadius: '6px', fontSize: '11px', color: '#9E94B8' }}>Logs</div>
                    <div style={{ padding: '6px 8px', borderRadius: '6px', fontSize: '11px', color: '#9E94B8' }}>Alerts</div>
                    <div style={{ padding: '6px 8px', borderRadius: '6px', fontSize: '11px', color: '#9E94B8' }}>Reports</div>
                    <div style={{ padding: '6px 8px', borderRadius: '6px', fontSize: '11px', color: '#9E94B8' }}>Settings</div>
                  </div>
                </div>

                {/* Dashboard Main Workspace */}
                <div style={{ flex: 1, padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  {/* Top Bar */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ fontSize: '14px', fontWeight: '600', color: '#EDE9F6' }}>Overview</div>
                    <div style={{ background: 'rgba(255, 255, 255, 0.05)', borderRadius: '6px', padding: '4px 10px', fontSize: '11px', color: '#776E91' }}>
                      Search servers...
                    </div>
                  </div>

                  {/* 4 Metric Cards */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px' }}>
                    <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', padding: '10px' }}>
                      <div style={{ fontSize: '18px', fontWeight: '700', color: '#EDE9F6' }}>12</div>
                      <div style={{ fontSize: '10px', color: '#9E94B8' }}>Servers</div>
                      <div style={{ fontSize: '9px', color: '#34D399', marginTop: '2px' }}>+2 this week</div>
                    </div>
                    <div style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: '8px', padding: '10px' }}>
                      <div style={{ fontSize: '18px', fontWeight: '700', color: '#F87171' }}>1</div>
                      <div style={{ fontSize: '10px', color: '#FCA5A5' }}>Critical</div>
                      <div style={{ fontSize: '9px', color: '#F87171', marginTop: '2px' }}>+1 new</div>
                    </div>
                    <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', padding: '10px' }}>
                      <div style={{ fontSize: '18px', fontWeight: '700', color: '#EDE9F6' }}>99.9%</div>
                      <div style={{ fontSize: '10px', color: '#9E94B8' }}>Uptime</div>
                      <div style={{ fontSize: '9px', color: '#34D399', marginTop: '2px' }}>+0.1%</div>
                    </div>
                    <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', padding: '10px' }}>
                      <div style={{ fontSize: '18px', fontWeight: '700', color: '#EDE9F6' }}>245<span style={{ fontSize: '11px', fontWeight: '400' }}>ms</span></div>
                      <div style={{ fontSize: '10px', color: '#9E94B8' }}>Avg Response</div>
                      <div style={{ fontSize: '9px', color: '#34D399', marginTop: '2px' }}>-12ms</div>
                    </div>
                  </div>

                  {/* Server Health Chart Wave */}
                  <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '10px', padding: '12px 14px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <span style={{ fontSize: '12px', fontWeight: '600', color: '#EDE9F6' }}>Server Health</span>
                      <span className="font-mono" style={{ fontSize: '9.5px', color: '#34D399', background: 'rgba(52, 211, 153, 0.1)', padding: '2px 6px', borderRadius: '4px' }}>
                        ● LIVE DASHBOARD 16s ago
                      </span>
                    </div>
                    {/* SVG Chart */}
                    <svg viewBox="0 0 460 75" style={{ width: '100%', height: '75px', display: 'block' }}>
                      <defs>
                        <linearGradient id="heroChartFill" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#8B5CF6" stopOpacity="0.45" />
                          <stop offset="100%" stopColor="#8B5CF6" stopOpacity="0.0" />
                        </linearGradient>
                      </defs>
                      <path d="M0 55 Q 50 48, 100 35 T 200 42 T 300 22 T 380 48 T 460 20 L 460 75 L 0 75 Z" fill="url(#heroChartFill)" />
                      <path className="chart-stroke" strokeDasharray="1" pathLength="1" d="M0 55 Q 50 48, 100 35 T 200 42 T 300 22 T 380 48 T 460 20" fill="none" stroke="#A78BFA" strokeWidth="2.2" strokeLinecap="round" />
                    </svg>
                  </div>

                  {/* Recent Incidents Table */}
                  <div style={{ fontSize: '11.5px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', color: '#776E91', paddingBottom: '6px', fontSize: '11px' }}>
                      <span>Recent Incidents</span>
                      <span style={{ color: '#A78BFA', cursor: 'pointer' }}>View all →</span>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 8px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#EDE9F6' }}>
                          <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#EF4444' }}></span>
                          High CPU usage
                        </span>
                        <span style={{ color: '#776E91' }}>web-01</span>
                        <span style={{ color: '#776E91' }}>2 mins ago</span>
                        <span style={{ background: 'rgba(239, 68, 68, 0.2)', color: '#F87171', padding: '2px 6px', borderRadius: '4px', fontSize: '9px' }}>Investigating</span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 8px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#EDE9F6' }}>
                          <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#F59E0B' }}></span>
                          Low space (91%)
                        </span>
                        <span style={{ color: '#776E91' }}>db-01</span>
                        <span style={{ color: '#776E91' }}>14 mins ago</span>
                        <span style={{ background: 'rgba(245, 158, 11, 0.2)', color: '#FBBF24', padding: '2px 6px', borderRadius: '4px', fontSize: '9px' }}>Acknowledged</span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 8px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#EDE9F6' }}>
                          <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#10B981' }}></span>
                          Service down
                        </span>
                        <span style={{ color: '#776E91' }}>api-01</span>
                        <span style={{ color: '#776E91' }}>1 hour ago</span>
                        <span style={{ background: 'rgba(16, 185, 129, 0.2)', color: '#34D399', padding: '2px 6px', borderRadius: '4px', fontSize: '9px' }}>Resolved</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── 3. SECTION: BEYOND SIMPLE PING MONITORING ─────────────────────── */}
      <section className="sec" id="features" style={{ padding: '110px 0' }}>
        <div className="section-wrap">
          <div
            className="two-col-grid"
            style={{
              display: 'grid',
              gridTemplateColumns: '1.05fr 1.35fr',
              gap: '64px',
              alignItems: 'center'
            }}
          >
            {/* Left Headline */}
            <div>
              <div className="sec-eyebrow font-mono" style={{ fontSize: '11.5px', color: '#A78BFA', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: '14px', fontWeight: '600' }}>
                BEYOND SIMPLE PING MONITORING
              </div>
              <h2 className="sec-h font-display" style={{ fontSize: '46px', fontWeight: '800', lineHeight: '1.1', margin: '0 0 20px', color: '#EDE9F6' }}>
                <span className="wm"><span className="w">Most</span></span>{' '}
                <span className="wm"><span className="w">tools</span></span>{' '}
                <span className="wm"><span className="w">show</span></span>{' '}
                <span className="wm"><span className="w">you</span></span>{' '}
                <span className="wm"><span className="w">a</span></span>{' '}
                <span className="wm"><span className="w">spike.</span></span><br />
                <span className="wm"><span className="w">We</span></span>{' '}
                <span className="wm"><span className="w">tell</span></span>{' '}
                <span className="wm"><span className="w">you</span></span>{' '}
                <span className="wm"><span className="w text-accent-gradient">why.</span></span>
              </h2>
              <p style={{ fontSize: '16.5px', color: '#9E94B8', lineHeight: '1.65', margin: 0, maxWidth: '480px' }}>
                PurpleAgent doesn't just alert you. It analyzes logs, metrics and system data deeper to find the root cause — and explains it in simple terms.
              </p>
            </div>

            {/* Right: 3 Value Cards with Animation */}
            <div className="card-grid-anim" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
              {/* Card 1 */}
              <div className="interactive-card card-anim" style={{ padding: '28px 20px', textAlign: 'center' }}>
                <div
                  style={{
                    width: '46px',
                    height: '46px',
                    borderRadius: '50%',
                    background: 'rgba(139, 92, 246, 0.15)',
                    border: '1px solid rgba(139, 92, 246, 0.35)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    margin: '0 auto 18px',
                    color: '#C4B5FD'
                  }}
                >
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="22" y1="12" x2="18" y2="12"></line>
                    <line x1="6" y1="12" x2="2" y2="12"></line>
                    <line x1="12" y1="6" x2="12" y2="2"></line>
                    <line x1="12" y1="22" x2="12" y2="18"></line>
                  </svg>
                </div>
                <h3 className="font-display" style={{ fontSize: '18px', fontWeight: '700', margin: '0 0 10px', color: '#EDE9F6' }}>
                  Detect issues
                </h3>
                <p style={{ fontSize: '13.5px', color: '#9E94B8', margin: 0, lineHeight: '1.5' }}>
                  Monitor real-time logs, metrics, services and more.
                </p>
              </div>

              {/* Card 2 */}
              <div className="interactive-card card-anim" style={{ padding: '28px 20px', textAlign: 'center' }}>
                <div
                  style={{
                    width: '46px',
                    height: '46px',
                    borderRadius: '50%',
                    background: 'rgba(139, 92, 246, 0.15)',
                    border: '1px solid rgba(139, 92, 246, 0.35)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    margin: '0 auto 18px',
                    color: '#C4B5FD'
                  }}
                >
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                    <polyline points="14 2 14 8 20 8"></polyline>
                    <line x1="16" y1="13" x2="8" y2="13"></line>
                    <line x1="16" y1="17" x2="8" y2="17"></line>
                  </svg>
                </div>
                <h3 className="font-display" style={{ fontSize: '18px', fontWeight: '700', margin: '0 0 10px', color: '#EDE9F6' }}>
                  Analyse &amp; Explain
                </h3>
                <p style={{ fontSize: '13.5px', color: '#9E94B8', margin: 0, lineHeight: '1.5' }}>
                  Pinpoint root cause using logs and system data.
                </p>
              </div>

              {/* Card 3 */}
              <div className="interactive-card card-anim" style={{ padding: '28px 20px', textAlign: 'center' }}>
                <div
                  style={{
                    width: '46px',
                    height: '46px',
                    borderRadius: '50%',
                    background: 'rgba(139, 92, 246, 0.15)',
                    border: '1px solid rgba(139, 92, 246, 0.35)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    margin: '0 auto 18px',
                    color: '#C4B5FD'
                  }}
                >
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                    <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"></path>
                  </svg>
                </div>
                <h3 className="font-display" style={{ fontSize: '18px', fontWeight: '700', margin: '0 0 10px', color: '#EDE9F6' }}>
                  Guide You To Fix
                </h3>
                <p style={{ fontSize: '13.5px', color: '#9E94B8', margin: 0, lineHeight: '1.5' }}>
                  Get clear, step-by-step remediation steps.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── 4. SECTION: REAL TIME INSIGHTS (SERVERS LIST TABLE) ───────────── */}
      <section className="sec" style={{ padding: '90px 0', background: 'rgba(13, 8, 29, 0.35)' }}>
        <div className="section-wrap">
          <div
            className="two-col-grid"
            style={{
              display: 'grid',
              gridTemplateColumns: '1.25fr 1fr',
              gap: '64px',
              alignItems: 'center'
            }}
          >
            {/* Left: Interactive Servers Table Mockup with Row Animation */}
            <div
              className="interactive-card servers-table-card"
              style={{
                borderRadius: '16px',
                border: '1px solid rgba(139, 92, 246, 0.25)',
                background: '#0B061A',
                overflow: 'hidden',
                boxShadow: '0 24px 60px rgba(0,0,0,0.6)'
              }}
            >
              {/* Header */}
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '16px 20px',
                  borderBottom: '1px solid rgba(255, 255, 255, 0.06)'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <img
                    src="/logos/app-icon.png"
                    alt="PurpleAgent"
                    style={{ width: '18px', height: '18px', borderRadius: '4px', objectFit: 'contain' }}
                  />
                  <span style={{ fontSize: '14px', fontWeight: '700', color: '#EDE9F6' }}>Servers</span>
                </div>
                <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                  <div style={{ background: 'rgba(255,255,255,0.05)', borderRadius: '6px', padding: '4px 10px', fontSize: '11px', color: '#776E91' }}>
                    🔍 Search servers...
                  </div>
                  <button
                    onClick={onLaunchDemo}
                    style={{
                      background: 'rgba(139, 92, 246, 0.25)',
                      border: '1px solid rgba(139, 92, 246, 0.5)',
                      color: '#C4B5FD',
                      borderRadius: '6px',
                      padding: '4px 10px',
                      fontSize: '11.5px',
                      fontWeight: '600',
                      cursor: 'pointer'
                    }}
                  >
                    + Add Server
                  </button>
                </div>
              </div>

              {/* Rows List */}
              <div style={{ padding: '8px 16px' }}>
                {/* Row 1: web-01 */}
                <div className="server-row-anim" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', fontSize: '13px' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#EDE9F6', fontWeight: '600' }}>
                      <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#10B981', boxShadow: '0 0 8px #10B981' }}></span>
                      web-01
                    </div>
                    <div className="font-mono" style={{ fontSize: '10.5px', color: '#776E91' }}>192.168.10.20</div>
                  </div>
                  <span style={{ color: '#34D399', fontSize: '11px', background: 'rgba(16, 185, 129, 0.1)', padding: '2px 8px', borderRadius: '4px' }}>Online</span>
                  <svg className="sparkline-svg" viewBox="0 0 80 20" style={{ width: '85px', height: '24px' }}>
                    <path className="chart-stroke" strokeDasharray="1" pathLength="1" d="M0 14 L15 12 L30 15 L45 8 L60 11 L80 6" fill="none" stroke="#A78BFA" strokeWidth="1.8" />
                  </svg>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ color: '#EDE9F6', fontSize: '12px' }}>CPU: <b style={{ color: '#A78BFA' }}>34%</b></div>
                    <div style={{ color: '#776E91', fontSize: '11px' }}>Mem: 58%</div>
                  </div>
                </div>

                {/* Row 2: api-01 */}
                <div className="server-row-anim" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', fontSize: '13px' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#EDE9F6', fontWeight: '600' }}>
                      <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#10B981' }}></span>
                      api-01
                    </div>
                    <div className="font-mono" style={{ fontSize: '10.5px', color: '#776E91' }}>192.168.10.21</div>
                  </div>
                  <span style={{ color: '#34D399', fontSize: '11px', background: 'rgba(16, 185, 129, 0.1)', padding: '2px 8px', borderRadius: '4px' }}>Online</span>
                  <svg className="sparkline-svg" viewBox="0 0 80 20" style={{ width: '85px', height: '24px' }}>
                    <path className="chart-stroke" strokeDasharray="1" pathLength="1" d="M0 10 L15 14 L30 8 L45 12 L60 6 L80 10" fill="none" stroke="#A78BFA" strokeWidth="1.8" />
                  </svg>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ color: '#EDE9F6', fontSize: '12px' }}>CPU: <b style={{ color: '#A78BFA' }}>62%</b></div>
                    <div style={{ color: '#776E91', fontSize: '11px' }}>Mem: 74%</div>
                  </div>
                </div>

                {/* Row 3: db-01 (Failing Spike) */}
                <div className="server-row-anim" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', fontSize: '13px' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#EDE9F6', fontWeight: '600' }}>
                      <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#EF4444', boxShadow: '0 0 8px #EF4444' }}></span>
                      db-01
                    </div>
                    <div className="font-mono" style={{ fontSize: '10.5px', color: '#776E91' }}>192.168.10.22</div>
                  </div>
                  <span style={{ color: '#F87171', fontSize: '11px', background: 'rgba(239, 68, 68, 0.15)', padding: '2px 8px', borderRadius: '4px' }}>Failing</span>
                  <svg className="sparkline-svg" viewBox="0 0 80 20" style={{ width: '85px', height: '24px' }}>
                    <path className="chart-stroke" strokeDasharray="1" pathLength="1" d="M0 14 L20 12 L35 15 L50 3 L65 2 L80 2" fill="none" stroke="#EF4444" strokeWidth="2.2" />
                  </svg>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ color: '#F87171', fontSize: '12px' }}>CPU: <b>91%</b></div>
                    <div style={{ color: '#FCA5A5', fontSize: '11px' }}>Mem: 89%</div>
                  </div>
                </div>

                {/* Row 4: cache-01 */}
                <div className="server-row-anim" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 0', fontSize: '13px' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#EDE9F6', fontWeight: '600' }}>
                      <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#10B981' }}></span>
                      cache-01
                    </div>
                    <div className="font-mono" style={{ fontSize: '10.5px', color: '#776E91' }}>192.168.10.23</div>
                  </div>
                  <span style={{ color: '#34D399', fontSize: '11px', background: 'rgba(16, 185, 129, 0.1)', padding: '2px 8px', borderRadius: '4px' }}>Online</span>
                  <svg className="sparkline-svg" viewBox="0 0 80 20" style={{ width: '85px', height: '24px' }}>
                    <path className="chart-stroke" strokeDasharray="1" pathLength="1" d="M0 16 L20 15 L40 16 L60 14 L80 15" fill="none" stroke="#A78BFA" strokeWidth="1.8" />
                  </svg>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ color: '#EDE9F6', fontSize: '12px' }}>CPU: <b style={{ color: '#A78BFA' }}>18%</b></div>
                    <div style={{ color: '#776E91', fontSize: '11px' }}>Mem: 42%</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Right: Copy & Checklist */}
            <div>
              <div className="sec-eyebrow font-mono" style={{ fontSize: '11.5px', color: '#A78BFA', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: '14px', fontWeight: '600' }}>
                REAL TIME INSIGHTS
              </div>
              <h2 className="sec-h font-display" style={{ fontSize: '44px', fontWeight: '800', lineHeight: '1.12', margin: '0 0 20px', color: '#EDE9F6' }}>
                <span className="wm"><span className="w">Dashboard,</span></span>{' '}
                <span className="wm"><span className="w">alerts</span></span><br />
                <span className="wm"><span className="w">and</span></span>{' '}
                <span className="wm"><span className="w text-accent-gradient">visitor logs.</span></span>
              </h2>
              <p style={{ fontSize: '16.5px', color: '#9E94B8', lineHeight: '1.65', margin: '0 0 28px' }}>
                Get a clear view of your infrastructure health, active incidents and detailed logs — all in one place.
              </p>

              {/* Checklist items */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '15.5px', color: '#EDE9F6' }}>
                  <span className="check-pill">✓</span>
                  Real-time server health
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '15.5px', color: '#EDE9F6' }}>
                  <span className="check-pill">✓</span>
                  Smart alerts with context
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '15.5px', color: '#EDE9F6' }}>
                  <span className="check-pill">✓</span>
                  Detailed visitor and access logs
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '15.5px', color: '#EDE9F6' }}>
                  <span className="check-pill">✓</span>
                  Custom thresholds and notifications
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── 5. SECTION: INCIDENT INVESTIGATION ───────────────────────────── */}
      <section className="sec" id="how-it-works" style={{ padding: '110px 0' }}>
        <div className="section-wrap">
          <div
            className="two-col-grid"
            style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1.35fr',
              gap: '64px',
              alignItems: 'center'
            }}
          >
            {/* Left Content */}
            <div>
              <div className="sec-eyebrow font-mono" style={{ fontSize: '11.5px', color: '#A78BFA', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: '14px', fontWeight: '600' }}>
                INCIDENT INVESTIGATION
              </div>
              <h2 className="sec-h font-display" style={{ fontSize: '44px', fontWeight: '800', lineHeight: '1.12', margin: '0 0 20px', color: '#EDE9F6' }}>
                <span className="wm"><span className="w">Pick</span></span>{' '}
                <span className="wm"><span className="w">an</span></span>{' '}
                <span className="wm"><span className="w">incident.</span></span><br />
                <span className="wm"><span className="w">Watch</span></span>{' '}
                <span className="wm"><span className="w">it</span></span>{' '}
                <span className="wm"><span className="w text-accent-gradient">get explained.</span></span>
              </h2>
              <p style={{ fontSize: '16.5px', color: '#9E94B8', lineHeight: '1.65', margin: '0 0 28px' }}>
                PurpleAgent analyses logs, metrics and system data to show the actual cause, not just the symptom.
              </p>

              {/* Checklist */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '15px', color: '#EDE9F6' }}>
                  <span className="check-pill">✓</span> Root cause analysis
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '15px', color: '#EDE9F6' }}>
                  <span className="check-pill">✓</span> Related logs and events
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '15px', color: '#EDE9F6' }}>
                  <span className="check-pill">✓</span> Clear explanation
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '15px', color: '#EDE9F6' }}>
                  <span className="check-pill">✓</span> Actionable fix steps
                </div>
              </div>
            </div>

            {/* Right: Incident Explanation Card */}
            <div
              className="interactive-card incident-card-anim"
              style={{
                borderRadius: '16px',
                border: '1px solid rgba(139, 92, 246, 0.3)',
                background: '#0B061A',
                padding: '24px',
                boxShadow: '0 24px 60px rgba(0,0,0,0.65)'
              }}
            >
              {/* Header */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ background: '#EF4444', color: '#FFFFFF', padding: '3px 8px', borderRadius: '4px', fontSize: '10px', fontWeight: '800' }}>
                    CRITICAL
                  </span>
                  <span style={{ fontSize: '16px', fontWeight: '700', color: '#EDE9F6' }}>High CPU usage on web-01</span>
                </div>
                <span style={{ fontSize: '12px', color: '#776E91' }}>2 mins ago</span>
              </div>

              {/* Tabs */}
              <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '12px', marginBottom: '20px' }}>
                {['explanation', 'logs', 'metrics', 'fix steps'].map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveIncidentTab(tab)}
                    style={{
                      background: activeIncidentTab === tab ? 'rgba(139, 92, 246, 0.2)' : 'transparent',
                      border: activeIncidentTab === tab ? '1px solid rgba(139, 92, 246, 0.45)' : '1px solid transparent',
                      color: activeIncidentTab === tab ? '#C4B5FD' : '#776E91',
                      borderRadius: '6px',
                      padding: '5px 12px',
                      fontSize: '12.5px',
                      fontWeight: activeIncidentTab === tab ? '600' : '400',
                      cursor: 'pointer',
                      textTransform: 'capitalize',
                      transition: 'all 0.2s'
                    }}
                  >
                    {tab === 'fix steps' ? 'Fix Steps' : tab}
                  </button>
                ))}
              </div>

              {/* Tab Content */}
              <div>
                <div style={{ fontSize: '13px', fontWeight: '700', color: '#EDE9F6', marginBottom: '8px' }}>What happened?</div>
                <p style={{ fontSize: '14.5px', color: '#B3AAC7', lineHeight: '1.6', margin: '0 0 20px' }}>
                  The CPU usage spiked due to a runaway PHP process started by a scheduled cron script. The process consumed high CPU for over 15 minutes.
                </p>

                <div style={{ fontSize: '13px', fontWeight: '700', color: '#EDE9F6', marginBottom: '10px' }}>Evidence</div>

                {/* Evidence Terminal Box with Animating Lines */}
                <div
                  className="font-mono"
                  style={{
                    background: '#06020E',
                    border: '1px solid rgba(255, 255, 255, 0.08)',
                    borderRadius: '10px',
                    padding: '16px',
                    fontSize: '12px',
                    lineHeight: '1.8',
                    color: '#D1D5DB'
                  }}
                >
                  <div className="log-line-anim" style={{ color: '#9E94B8' }}>
                    <span style={{ color: '#776E91' }}>May 04 15:35:05</span> web-01 <span style={{ color: '#38BDF8' }}>[syslog]</span> Processing large dataset...
                  </div>
                  <div className="log-line-anim" style={{ color: '#9E94B8' }}>
                    <span style={{ color: '#776E91' }}>May 04 15:35:05</span> web-01 <span style={{ color: '#34D399' }}>[system]</span> Memory usage: 7.1 GB
                  </div>
                  <div className="log-line-anim" style={{ color: '#F87171', background: 'rgba(239, 68, 68, 0.1)', padding: '2px 4px', borderRadius: '4px' }}>
                    <span style={{ color: '#776E91' }}>May 04 15:36:07</span> web-01 <span style={{ color: '#EF4444' }}>[cron]</span> CPU usage above 90% (process 154)
                  </div>
                  <div className="log-line-anim" style={{ color: '#F87171' }}>
                    <span style={{ color: '#776E91' }}>May 04 15:37:32</span> web-01 <span style={{ color: '#EF4444' }}>[system]</span> php-worker service high CPU
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── 6. SECTION: EVERYTHING A JUNIOR SYSADMIN WOULD WATCH ─────────── */}
      <section className="sec" id="use-cases" style={{ padding: '100px 0', background: 'rgba(13, 8, 29, 0.3)' }}>
        <div className="section-wrap">
          <div style={{ textAlign: 'center', maxWidth: '820px', margin: '0 auto 60px' }}>
            <div className="sec-eyebrow font-mono" style={{ fontSize: '11.5px', color: '#A78BFA', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: '14px', fontWeight: '600' }}>
              EVERYTHING A SYSADMIN WOULD WATCH
            </div>
            <h2 className="sec-h font-display" style={{ fontSize: '46px', fontWeight: '800', lineHeight: '1.15', margin: '0 auto', color: '#EDE9F6' }}>
              <span className="wm"><span className="w">Everything</span></span>{' '}
              <span className="wm"><span className="w">a</span></span>{' '}
              <span className="wm"><span className="w">junior</span></span>{' '}
              <span className="wm"><span className="w">sysadmin</span></span>{' '}
              <span className="wm"><span className="w">would</span></span><br />
              <span className="wm"><span className="w">watch,</span></span>{' '}
              <span className="wm"><span className="w">without</span></span>{' '}
              <span className="wm"><span className="w">the</span></span>{' '}
              <span className="wm"><span className="w text-accent-gradient">sleep.</span></span>
            </h2>
          </div>

          {/* 6 Cards 3x2 Grid with Staggered ScrollTrigger */}
          <div
            className="card-grid-anim"
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(3, 1fr)',
              gap: '22px'
            }}
          >
            {/* Card 1: CPU & Memory */}
            <div className="interactive-card card-anim" style={{ padding: '32px 26px' }}>
              <div style={{ width: '42px', height: '42px', borderRadius: '10px', background: 'rgba(139, 92, 246, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#A78BFA', marginBottom: '20px' }}>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <rect x="4" y="4" width="16" height="16" rx="2" ry="2"></rect>
                  <rect x="9" y="9" width="6" height="6"></rect>
                  <line x1="9" y1="1" x2="9" y2="4"></line>
                  <line x1="15" y1="1" x2="15" y2="4"></line>
                  <line x1="9" y1="20" x2="9" y2="23"></line>
                  <line x1="15" y1="20" x2="15" y2="23"></line>
                  <line x1="20" y1="9" x2="23" y2="9"></line>
                  <line x1="20" y1="15" x2="23" y2="15"></line>
                  <line x1="1" y1="9" x2="4" y2="9"></line>
                  <line x1="1" y1="15" x2="4" y2="15"></line>
                </svg>
              </div>
              <h3 className="font-display" style={{ fontSize: '20px', fontWeight: '700', color: '#EDE9F6', margin: '0 0 10px' }}>
                CPU &amp; Memory
              </h3>
              <p style={{ fontSize: '15px', color: '#9E94B8', lineHeight: '1.6', margin: 0 }}>
                Monitor resource usage, detect unusual spikes and get alerted before it becomes a problem.
              </p>
            </div>

            {/* Card 2: Disk & File System */}
            <div className="interactive-card card-anim" style={{ padding: '32px 26px' }}>
              <div style={{ width: '42px', height: '42px', borderRadius: '10px', background: 'rgba(139, 92, 246, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#A78BFA', marginBottom: '20px' }}>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <ellipse cx="12" cy="5" rx="9" ry="3"></ellipse>
                  <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path>
                  <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path>
                </svg>
              </div>
              <h3 className="font-display" style={{ fontSize: '20px', fontWeight: '700', color: '#EDE9F6', margin: '0 0 10px' }}>
                Disk &amp; File System
              </h3>
              <p style={{ fontSize: '15px', color: '#9E94B8', lineHeight: '1.6', margin: 0 }}>
                Track disk usage, inode exhaustion and file system errors.
              </p>
            </div>

            {/* Card 3: Services & Processes */}
            <div className="interactive-card card-anim" style={{ padding: '32px 26px' }}>
              <div style={{ width: '42px', height: '42px', borderRadius: '10px', background: 'rgba(139, 92, 246, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#A78BFA', marginBottom: '20px' }}>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <circle cx="12" cy="12" r="3"></circle>
                  <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
                </svg>
              </div>
              <h3 className="font-display" style={{ fontSize: '20px', fontWeight: '700', color: '#EDE9F6', margin: '0 0 10px' }}>
                Services &amp; Processes
              </h3>
              <p style={{ fontSize: '15px', color: '#9E94B8', lineHeight: '1.6', margin: 0 }}>
                Monitor critical services, spot failures and auto-restart when needed.
              </p>
            </div>

            {/* Card 4: Logs & Access */}
            <div className="interactive-card card-anim" style={{ padding: '32px 26px' }}>
              <div style={{ width: '42px', height: '42px', borderRadius: '10px', background: 'rgba(139, 92, 246, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#A78BFA', marginBottom: '20px' }}>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                </svg>
              </div>
              <h3 className="font-display" style={{ fontSize: '20px', fontWeight: '700', color: '#EDE9F6', margin: '0 0 10px' }}>
                Logs &amp; Access
              </h3>
              <p style={{ fontSize: '15px', color: '#9E94B8', lineHeight: '1.6', margin: 0 }}>
                Analyze system and visitor logs to detect suspicious activity.
              </p>
            </div>

            {/* Card 5: Network & Ports */}
            <div className="interactive-card card-anim" style={{ padding: '32px 26px' }}>
              <div style={{ width: '42px', height: '42px', borderRadius: '10px', background: 'rgba(139, 92, 246, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#A78BFA', marginBottom: '20px' }}>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <circle cx="12" cy="12" r="10"></circle>
                  <line x1="2" y1="12" x2="22" y2="12"></line>
                  <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                </svg>
              </div>
              <h3 className="font-display" style={{ fontSize: '20px', fontWeight: '700', color: '#EDE9F6', margin: '0 0 10px' }}>
                Network &amp; Ports
              </h3>
              <p style={{ fontSize: '15px', color: '#9E94B8', lineHeight: '1.6', margin: 0 }}>
                Monitor port availability, response times and connection errors.
              </p>
            </div>

            {/* Card 6: Uptime & SSL */}
            <div className="interactive-card card-anim" style={{ padding: '32px 26px' }}>
              <div style={{ width: '42px', height: '42px', borderRadius: '10px', background: 'rgba(139, 92, 246, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#A78BFA', marginBottom: '20px' }}>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                  <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                </svg>
              </div>
              <h3 className="font-display" style={{ fontSize: '20px', fontWeight: '700', color: '#EDE9F6', margin: '0 0 10px' }}>
                Uptime &amp; SSL
              </h3>
              <p style={{ fontSize: '15px', color: '#9E94B8', lineHeight: '1.6', margin: 0 }}>
                Keep track of uptime, SSL certificate expiry and domain availability.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ── 7. SECTION: TIME SAVED CALCULATOR (ROI) ───────────────────────── */}
      <section className="sec" id="roi" style={{ padding: '110px 0' }}>
        <div className="section-wrap">
          <div
            className="three-col-grid"
            style={{
              display: 'grid',
              gridTemplateColumns: '1.1fr 1.3fr 1fr',
              gap: '40px',
              alignItems: 'center'
            }}
          >
            {/* Left Column: Heading & Copy */}
            <div>
              <div className="sec-eyebrow font-mono" style={{ fontSize: '11.5px', color: '#A78BFA', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: '14px', fontWeight: '600' }}>
                SAVING A SYSADMIN WOULD
              </div>
              <h2 className="sec-h font-display" style={{ fontSize: '42px', fontWeight: '800', lineHeight: '1.15', margin: '0 0 18px', color: '#EDE9F6' }}>
                <span className="wm"><span className="w">Estimate</span></span>{' '}
                <span className="wm"><span className="w">the</span></span>{' '}
                <span className="wm"><span className="w">time</span></span><br />
                <span className="wm"><span className="w">you</span></span>{' '}
                <span className="wm"><span className="w">could</span></span>{' '}
                <span className="wm"><span className="w text-accent-gradient">win back.</span></span>
              </h2>
              <p style={{ fontSize: '16px', color: '#9E94B8', lineHeight: '1.6', margin: '0 0 28px' }}>
                Automate routine monitoring and incident diagnosis so you can focus on what matters.
              </p>
              <button
                onClick={onLaunchDemo}
                className="btn-purple-primary magnetic-btn"
                style={{ fontSize: '14px', padding: '12px 24px' }}
              >
                <span>Calculate ROI</span>
                <span>→</span>
              </button>
            </div>

            {/* Middle Column: Interactive Time Saved Calculator */}
            <div
              className="interactive-card"
              style={{
                padding: '30px',
                background: '#0B061A',
                border: '1px solid rgba(139, 92, 246, 0.25)'
              }}
            >
              <h3 className="font-display" style={{ fontSize: '18px', fontWeight: '700', color: '#EDE9F6', margin: '0 0 24px' }}>
                Time Saved Calculator
              </h3>

              {/* Slider 1: Number of servers */}
              <div style={{ marginBottom: '22px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span style={{ fontSize: '14px', color: '#C4BBD8' }}>Number of servers</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <button
                      onClick={() => setServers(Math.max(1, servers - 1))}
                      style={{ background: 'rgba(255,255,255,0.06)', border: 'none', color: '#EDE9F6', width: '24px', height: '24px', borderRadius: '4px', cursor: 'pointer' }}
                    >-</button>
                    <span className="font-mono" style={{ fontSize: '15px', fontWeight: '700', color: '#C4B5FD', minWidth: '24px', textAlign: 'center' }}>
                      {servers}
                    </span>
                    <button
                      onClick={() => setServers(servers + 1)}
                      style={{ background: 'rgba(255,255,255,0.06)', border: 'none', color: '#EDE9F6', width: '24px', height: '24px', borderRadius: '4px', cursor: 'pointer' }}
                    >+</button>
                  </div>
                </div>
                <input
                  type="range"
                  min="1"
                  max="100"
                  value={servers}
                  onChange={(e) => setServers(parseInt(e.target.value))}
                  style={{ width: '100%', accentColor: '#8B5CF6', cursor: 'pointer' }}
                />
              </div>

              {/* Slider 2: Avg hours spent per incident */}
              <div style={{ marginBottom: '22px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span style={{ fontSize: '14px', color: '#C4BBD8' }}>Avg. hours spent per incident</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <button
                      onClick={() => setHoursPerInc(Math.max(1, hoursPerInc - 1))}
                      style={{ background: 'rgba(255,255,255,0.06)', border: 'none', color: '#EDE9F6', width: '24px', height: '24px', borderRadius: '4px', cursor: 'pointer' }}
                    >-</button>
                    <span className="font-mono" style={{ fontSize: '15px', fontWeight: '700', color: '#C4B5FD', minWidth: '24px', textAlign: 'center' }}>
                      {hoursPerInc}
                    </span>
                    <button
                      onClick={() => setHoursPerInc(hoursPerInc + 1)}
                      style={{ background: 'rgba(255,255,255,0.06)', border: 'none', color: '#EDE9F6', width: '24px', height: '24px', borderRadius: '4px', cursor: 'pointer' }}
                    >+</button>
                  </div>
                </div>
                <input
                  type="range"
                  min="1"
                  max="10"
                  value={hoursPerInc}
                  onChange={(e) => setHoursPerInc(parseInt(e.target.value))}
                  style={{ width: '100%', accentColor: '#8B5CF6', cursor: 'pointer' }}
                />
              </div>

              {/* Slider 3: Incidents per month */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span style={{ fontSize: '14px', color: '#C4BBD8' }}>Incidents per month</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <button
                      onClick={() => setIncidentsPerMonth(Math.max(1, incidentsPerMonth - 1))}
                      style={{ background: 'rgba(255,255,255,0.06)', border: 'none', color: '#EDE9F6', width: '24px', height: '24px', borderRadius: '4px', cursor: 'pointer' }}
                    >-</button>
                    <span className="font-mono" style={{ fontSize: '15px', fontWeight: '700', color: '#C4B5FD', minWidth: '24px', textAlign: 'center' }}>
                      {incidentsPerMonth}
                    </span>
                    <button
                      onClick={() => setIncidentsPerMonth(incidentsPerMonth + 1)}
                      style={{ background: 'rgba(255,255,255,0.06)', border: 'none', color: '#EDE9F6', width: '24px', height: '24px', borderRadius: '4px', cursor: 'pointer' }}
                    >+</button>
                  </div>
                </div>
                <input
                  type="range"
                  min="1"
                  max="20"
                  value={incidentsPerMonth}
                  onChange={(e) => setIncidentsPerMonth(parseInt(e.target.value))}
                  style={{ width: '100%', accentColor: '#8B5CF6', cursor: 'pointer' }}
                />
              </div>
            </div>

            {/* Right Column: 2 Result Stat Cards */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Stat 1: Hours Saved */}
              <div
                className="interactive-card"
                style={{
                  padding: '24px',
                  background: 'rgba(139, 92, 246, 0.08)',
                  border: '1px solid rgba(139, 92, 246, 0.35)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '18px'
                }}
              >
                <div
                  style={{
                    width: '50px',
                    height: '50px',
                    borderRadius: '50%',
                    background: 'rgba(139, 92, 246, 0.25)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: '#C4B5FD',
                    flexShrink: 0
                  }}
                >
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                    <circle cx="12" cy="12" r="10"></circle>
                    <polyline points="12 6 12 12 16 14"></polyline>
                  </svg>
                </div>
                <div>
                  <div className="font-mono" style={{ fontSize: '10.5px', color: '#A78BFA', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
                    YOU COULD SAVE
                  </div>
                  <div ref={hoursNumRef} className="font-display" style={{ fontSize: '32px', fontWeight: '800', color: '#EDE9F6', lineHeight: 1.1 }}>
                    {hoursSaved} hrs
                  </div>
                  <div style={{ fontSize: '12px', color: '#776E91' }}>per month</div>
                </div>
              </div>

              {/* Stat 2: Dollars Saved */}
              <div
                className="interactive-card"
                style={{
                  padding: '24px',
                  background: 'rgba(45, 212, 191, 0.06)',
                  border: '1px solid rgba(45, 212, 191, 0.3)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '18px'
                }}
              >
                <div
                  style={{
                    width: '50px',
                    height: '50px',
                    borderRadius: '50%',
                    background: 'rgba(45, 212, 191, 0.2)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: '#2DD4BF',
                    flexShrink: 0
                  }}
                >
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                    <line x1="12" y1="1" x2="12" y2="23"></line>
                    <path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"></path>
                  </svg>
                </div>
                <div>
                  <div className="font-mono" style={{ fontSize: '10.5px', color: '#2DD4BF', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
                    THAT'S ABOUT
                  </div>
                  <div ref={dollarNumRef} className="font-display" style={{ fontSize: '32px', fontWeight: '800', color: '#EDE9F6', lineHeight: 1.1 }}>
                    ${dollarSaved}
                  </div>
                  <div style={{ fontSize: '12px', color: '#776E91' }}>in recovered time</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── 8. SECTION: ONE AGENT PER SERVER (WORKFLOW STEPS) ─────────────── */}
      <section className="sec" style={{ padding: '90px 0', background: 'rgba(13, 8, 29, 0.25)' }}>
        <div className="section-wrap">
          <div style={{ textAlign: 'center', maxWidth: '720px', margin: '0 auto 54px' }}>
            <div className="sec-eyebrow font-mono" style={{ fontSize: '11.5px', color: '#A78BFA', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: '14px', fontWeight: '600' }}>
              ONE AGENT PER SERVER
            </div>
            <h2 className="sec-h font-display" style={{ fontSize: '44px', fontWeight: '800', lineHeight: '1.15', margin: '0 0 16px', color: '#EDE9F6' }}>
              <span className="wm"><span className="w">One</span></span>{' '}
              <span className="wm"><span className="w">place</span></span>{' '}
              <span className="wm"><span className="w">to</span></span>{' '}
              <span className="wm"><span className="w text-accent-gradient">look.</span></span>
            </h2>
            <p style={{ fontSize: '16.5px', color: '#9E94B8', margin: 0 }}>
              Install a lightweight agent on each server and monitor everything from a single dashboard.
            </p>
          </div>

          {/* 4 Connected Process Cards with Staggered Cascading Animation */}
          <div
            className="four-col-grid workflow-grid-anim"
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: '20px'
            }}
          >
            {/* Step 1: Install */}
            <div className="interactive-card workflow-step-anim" style={{ padding: '28px 22px', textAlign: 'center' }}>
              <div style={{ width: '44px', height: '44px', borderRadius: '50%', background: 'rgba(139, 92, 246, 0.16)', color: '#C4B5FD', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px', fontWeight: '700' }}>
                1
              </div>
              <h3 className="font-display" style={{ fontSize: '19px', fontWeight: '700', color: '#EDE9F6', margin: '0 0 8px' }}>
                Install
              </h3>
              <p style={{ fontSize: '13.5px', color: '#9E94B8', margin: 0 }}>Run a simple command</p>
            </div>

            {/* Step 2: Monitor */}
            <div className="interactive-card workflow-step-anim" style={{ padding: '28px 22px', textAlign: 'center' }}>
              <div style={{ width: '44px', height: '44px', borderRadius: '50%', background: 'rgba(139, 92, 246, 0.16)', color: '#C4B5FD', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px', fontWeight: '700' }}>
                2
              </div>
              <h3 className="font-display" style={{ fontSize: '19px', fontWeight: '700', color: '#EDE9F6', margin: '0 0 8px' }}>
                Monitor
              </h3>
              <p style={{ fontSize: '13.5px', color: '#9E94B8', margin: 0 }}>Continuous telemetry data</p>
            </div>

            {/* Step 3: Analyse */}
            <div className="interactive-card workflow-step-anim" style={{ padding: '28px 22px', textAlign: 'center' }}>
              <div style={{ width: '44px', height: '44px', borderRadius: '50%', background: 'rgba(139, 92, 246, 0.16)', color: '#C4B5FD', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px', fontWeight: '700' }}>
                3
              </div>
              <h3 className="font-display" style={{ fontSize: '19px', fontWeight: '700', color: '#EDE9F6', margin: '0 0 8px' }}>
                Analyse
              </h3>
              <p style={{ fontSize: '13.5px', color: '#9E94B8', margin: 0 }}>Detects and explains issues</p>
            </div>

            {/* Step 4: Fix */}
            <div className="interactive-card workflow-step-anim" style={{ padding: '28px 22px', textAlign: 'center' }}>
              <div style={{ width: '44px', height: '44px', borderRadius: '50%', background: 'rgba(139, 92, 246, 0.16)', color: '#C4B5FD', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px', fontWeight: '700' }}>
                4
              </div>
              <h3 className="font-display" style={{ fontSize: '19px', fontWeight: '700', color: '#EDE9F6', margin: '0 0 8px' }}>
                Fix
              </h3>
              <p style={{ fontSize: '13.5px', color: '#9E94B8', margin: 0 }}>Get clear remediation steps</p>
            </div>
          </div>
        </div>
      </section>

      {/* ── 9. SECTION: FOUR SIGNALS, EVERY 60TH INTERVAL ─────────────────── */}
      <section className="sec" style={{ padding: '90px 0' }}>
        <div className="section-wrap">
          <div style={{ maxWidth: '780px', marginBottom: '46px' }}>
            <div className="sec-eyebrow font-mono" style={{ fontSize: '11.5px', color: '#A78BFA', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: '14px', fontWeight: '600' }}>
              FOUR SIGNALS, EVERY 60th INTERVAL
            </div>
            <h2 className="sec-h font-display" style={{ fontSize: '44px', fontWeight: '800', lineHeight: '1.15', margin: '0 0 16px', color: '#EDE9F6' }}>
              <span className="wm"><span className="w">Four</span></span>{' '}
              <span className="wm"><span className="w">signals.</span></span>{' '}
              <span className="wm"><span className="w">A</span></span>{' '}
              <span className="wm"><span className="w text-accent-gradient">clear picture.</span></span>
            </h2>
            <p style={{ fontSize: '16.5px', color: '#9E94B8', margin: 0 }}>
              PurpleAgent combines multiple signals to detect and explain issues accurately:
            </p>
          </div>

          {/* 4 Cards Grid with Stagger */}
          <div
            className="four-col-grid card-grid-anim"
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: '20px'
            }}
          >
            {/* Signal 1 */}
            <div className="interactive-card card-anim" style={{ padding: '28px 24px' }}>
              <div style={{ color: '#A78BFA', marginBottom: '18px' }}>
                <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <path d="M18 20V10"></path>
                  <path d="M12 20V4"></path>
                  <path d="M6 20v-6"></path>
                </svg>
              </div>
              <h3 className="font-display" style={{ fontSize: '19px', fontWeight: '700', color: '#EDE9F6', margin: '0 0 10px' }}>
                System Metrics
              </h3>
              <p style={{ fontSize: '14px', color: '#9E94B8', margin: 0, lineHeight: '1.55' }}>
                CPU, memory, disk, load averages
              </p>
            </div>

            {/* Signal 2 */}
            <div className="interactive-card card-anim" style={{ padding: '28px 24px' }}>
              <div style={{ color: '#A78BFA', marginBottom: '18px' }}>
                <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                  <polyline points="14 2 14 8 20 8"></polyline>
                </svg>
              </div>
              <h3 className="font-display" style={{ fontSize: '19px', fontWeight: '700', color: '#EDE9F6', margin: '0 0 10px' }}>
                Logs
              </h3>
              <p style={{ fontSize: '14px', color: '#9E94B8', margin: 0, lineHeight: '1.55' }}>
                System, application and access logs
              </p>
            </div>

            {/* Signal 3 */}
            <div className="interactive-card card-anim" style={{ padding: '28px 24px' }}>
              <div style={{ color: '#A78BFA', marginBottom: '18px' }}>
                <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
                  <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
                  <line x1="6" y1="6" x2="6.01" y2="6"></line>
                  <line x1="6" y1="18" x2="6.01" y2="18"></line>
                </svg>
              </div>
              <h3 className="font-display" style={{ fontSize: '19px', fontWeight: '700', color: '#EDE9F6', margin: '0 0 10px' }}>
                Services
              </h3>
              <p style={{ fontSize: '14px', color: '#9E94B8', margin: 0, lineHeight: '1.55' }}>
                Process and service health checks
              </p>
            </div>

            {/* Signal 4 */}
            <div className="interactive-card card-anim" style={{ padding: '28px 24px' }}>
              <div style={{ color: '#A78BFA', marginBottom: '18px' }}>
                <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <circle cx="12" cy="12" r="10"></circle>
                  <line x1="2" y1="12" x2="22" y2="12"></line>
                </svg>
              </div>
              <h3 className="font-display" style={{ fontSize: '19px', fontWeight: '700', color: '#EDE9F6', margin: '0 0 10px' }}>
                Network
              </h3>
              <p style={{ fontSize: '14px', color: '#9E94B8', margin: 0, lineHeight: '1.55' }}>
                Ports, latency and response times
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ── 10. SECTION: RUNNING IN THREE COMMANDS (TERMINAL) ────────────── */}
      <section className="sec" id="quickstart" style={{ padding: '100px 0', background: 'rgba(13, 8, 29, 0.35)' }}>
        <div className="section-wrap">
          <div
            className="two-col-grid"
            style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1.35fr',
              gap: '64px',
              alignItems: 'center'
            }}
          >
            {/* Left Column */}
            <div>
              <div className="sec-eyebrow font-mono" style={{ fontSize: '11.5px', color: '#A78BFA', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: '14px', fontWeight: '600' }}>
                RUN COMMANDS SECURELY
              </div>
              <h2 className="sec-h font-display" style={{ fontSize: '44px', fontWeight: '800', lineHeight: '1.15', margin: '0 0 18px', color: '#EDE9F6' }}>
                <span className="wm"><span className="w">Running</span></span>{' '}
                <span className="wm"><span className="w">in</span></span>{' '}
                <span className="wm"><span className="w">three</span></span>{' '}
                <span className="wm"><span className="w text-accent-gradient">commands.</span></span>
              </h2>
              <p style={{ fontSize: '16.5px', color: '#9E94B8', lineHeight: '1.65', margin: 0 }}>
                Install the agent, connect it and start monitoring in minutes.
              </p>
            </div>

            {/* Right: Interactive Terminal Window */}
            <div
              className="interactive-card terminal-window-anim"
              style={{
                borderRadius: '16px',
                border: '1px solid rgba(139, 92, 246, 0.28)',
                background: '#0B061A',
                overflow: 'hidden',
                boxShadow: '0 24px 60px rgba(0,0,0,0.65)'
              }}
            >
              {/* Header with OS Tabs & Copy Button */}
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '12px 18px',
                  borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
                  background: 'rgba(0, 0, 0, 0.3)'
                }}
              >
                {/* OS Buttons */}
                <div style={{ display: 'flex', gap: '6px' }}>
                  {['linux', 'macos', 'windows'].map((os) => (
                    <button
                      key={os}
                      onClick={() => setSelectedOS(os)}
                      style={{
                        background: selectedOS === os ? 'rgba(139, 92, 246, 0.25)' : 'transparent',
                        border: selectedOS === os ? '1px solid rgba(139, 92, 246, 0.5)' : '1px solid transparent',
                        color: selectedOS === os ? '#C4B5FD' : '#776E91',
                        borderRadius: '6px',
                        padding: '4px 12px',
                        fontSize: '12px',
                        cursor: 'pointer',
                        textTransform: os === 'macos' ? 'none' : 'capitalize',
                        fontWeight: selectedOS === os ? '600' : '400'
                      }}
                    >
                      {os === 'macos' ? 'macOS' : os}
                    </button>
                  ))}
                </div>

                {/* Copy Button */}
                <button
                  onClick={copyToClipboard}
                  style={{
                    background: 'rgba(255, 255, 255, 0.05)',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    borderRadius: '6px',
                    color: copiedCode ? '#34D399' : '#EDE9F6',
                    padding: '4px 10px',
                    fontSize: '11.5px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}
                >
                  {copiedCode ? '✓ Copied' : '📋 Copy'}
                </button>
              </div>

              {/* Code Area */}
              <div
                className="font-mono"
                style={{
                  padding: '22px',
                  fontSize: '13.5px',
                  lineHeight: '1.85',
                  color: '#EDE9F6',
                  whiteSpace: 'pre',
                  overflowX: 'auto'
                }}
              >
                {codeSnippets[selectedOS]}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── 11. SECTION: STILL IN DOUBT? (FAQ ACCORDIONS) ─────────────────── */}
      <section className="sec" id="docs" style={{ padding: '100px 0' }}>
        <div className="section-wrap">
          <div
            className="two-col-grid"
            style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1.4fr',
              gap: '64px',
              alignItems: 'flex-start'
            }}
          >
            {/* Left */}
            <div>
              <div className="sec-eyebrow font-mono" style={{ fontSize: '11.5px', color: '#A78BFA', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: '14px', fontWeight: '600' }}>
                STILL IN DOUBT?
              </div>
              <h2 className="sec-h font-display" style={{ fontSize: '44px', fontWeight: '800', lineHeight: '1.15', margin: '0 0 16px', color: '#EDE9F6' }}>
                <span className="wm"><span className="w">Start</span></span>{' '}
                <span className="wm"><span className="w text-accent-gradient">here.</span></span>
              </h2>
              <p style={{ fontSize: '16.5px', color: '#9E94B8', margin: 0 }}>
                Quick answers to common questions.
              </p>
            </div>

            {/* Right: Accordions with Card Anim */}
            <div className="card-grid-anim" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {/* Question 1 */}
              <div
                className="interactive-card card-anim"
                style={{
                  padding: '20px 24px',
                  cursor: 'pointer',
                  borderColor: openFaq === 0 ? 'var(--pa-accent-light)' : 'var(--pa-card-border)'
                }}
                onClick={() => setOpenFaq(openFaq === 0 ? null : 0)}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="font-display" style={{ fontSize: '18px', fontWeight: '700', color: '#EDE9F6' }}>
                    What is PurpleAgent?
                  </span>
                  <span style={{ color: '#A78BFA', fontSize: '18px', transform: openFaq === 0 ? 'rotate(90deg)' : 'none', transition: 'transform 0.25s' }}>
                    ›
                  </span>
                </div>
                {openFaq === 0 && (
                  <p style={{ margin: '14px 0 0', color: '#9E94B8', fontSize: '15px', lineHeight: '1.65' }}>
                    PurpleAgent is an autonomous server monitoring and AI SRE agent. It connects lightweight telemetry from your machines to an intelligent diagnosis engine that correlates logs, metrics and events to find root causes in plain English.
                  </p>
                )}
              </div>

              {/* Question 2 */}
              <div
                className="interactive-card card-anim"
                style={{
                  padding: '20px 24px',
                  cursor: 'pointer',
                  borderColor: openFaq === 1 ? 'var(--pa-accent-light)' : 'var(--pa-card-border)'
                }}
                onClick={() => setOpenFaq(openFaq === 1 ? null : 1)}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="font-display" style={{ fontSize: '18px', fontWeight: '700', color: '#EDE9F6' }}>
                    How does the agent work?
                  </span>
                  <span style={{ color: '#A78BFA', fontSize: '18px', transform: openFaq === 1 ? 'rotate(90deg)' : 'none', transition: 'transform 0.25s' }}>
                    ›
                  </span>
                </div>
                {openFaq === 1 && (
                  <p style={{ margin: '14px 0 0', color: '#9E94B8', fontSize: '15px', lineHeight: '1.65' }}>
                    The agent is a single binary that consumes less than 15MB of RAM and 0.1% CPU. It reads local procfs, systemd states, and syslog streams, buffering data securely over TLS WebSockets directly to your dashboard.
                  </p>
                )}
              </div>

              {/* Question 3 */}
              <div
                className="interactive-card card-anim"
                style={{
                  padding: '20px 24px',
                  cursor: 'pointer',
                  borderColor: openFaq === 2 ? 'var(--pa-accent-light)' : 'var(--pa-card-border)'
                }}
                onClick={() => setOpenFaq(openFaq === 2 ? null : 2)}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="font-display" style={{ fontSize: '18px', fontWeight: '700', color: '#EDE9F6' }}>
                    Is my data secure?
                  </span>
                  <span style={{ color: '#A78BFA', fontSize: '18px', transform: openFaq === 2 ? 'rotate(90deg)' : 'none', transition: 'transform 0.25s' }}>
                    ›
                  </span>
                </div>
                {openFaq === 2 && (
                  <p style={{ margin: '14px 0 0', color: '#9E94B8', fontSize: '15px', lineHeight: '1.65' }}>
                    Yes. PurpleAgent is 100% open-source and MIT licensed. When you self-host, all telemetry stays exclusively inside your own cloud infrastructure, VPC, or private network. No data leaves your control.
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── 12. SECTION: PRICING (FREE TO SELF-HOST TODAY) ────────────────── */}
      <section className="sec" id="pricing" style={{ padding: '100px 0', background: 'rgba(13, 8, 29, 0.35)' }}>
        <div className="section-wrap">
          <div
            className="two-col-grid"
            style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1.35fr',
              gap: '64px',
              alignItems: 'center'
            }}
          >
            {/* Left */}
            <div>
              <div className="sec-eyebrow font-mono" style={{ fontSize: '11.5px', color: '#A78BFA', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: '14px', fontWeight: '600' }}>
                PRICING
              </div>
              <h2 className="sec-h font-display" style={{ fontSize: '44px', fontWeight: '800', lineHeight: '1.15', margin: '0 0 16px', color: '#EDE9F6' }}>
                <span className="wm"><span className="w">Free</span></span>{' '}
                <span className="wm"><span className="w">to</span></span>{' '}
                <span className="wm"><span className="w">self-host</span></span>{' '}
                <span className="wm"><span className="w text-accent-gradient">today.</span></span>
              </h2>
              <p style={{ fontSize: '16.5px', color: '#9E94B8', margin: 0 }}>
                Get started with the open-source version or talk to us for managed options.
              </p>
            </div>

            {/* Right: 2 Pricing Cards */}
            <div className="card-grid-anim" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
              {/* Card 1: Self-hosted (Free) */}
              <div
                className="interactive-card card-anim"
                style={{
                  padding: '32px 24px',
                  background: 'rgba(139, 92, 246, 0.08)',
                  borderColor: 'rgba(139, 92, 246, 0.45)',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between'
                }}
              >
                <div>
                  <div style={{ fontSize: '14px', color: '#9E94B8', fontWeight: '500' }}>Self-hosted</div>
                  <div className="font-display" style={{ fontSize: '36px', fontWeight: '800', color: '#EDE9F6', margin: '6px 0 16px' }}>
                    Free
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13.5px', color: '#C4BBD8', marginBottom: '24px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="check-pill">✓</span> Have 1 server
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="check-pill">✓</span> All core features
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="check-pill">✓</span> No usage limits
                    </div>
                  </div>
                </div>

                <a
                  href="https://github.com/salman2610/purple-agent"
                  target="_blank"
                  rel="noreferrer"
                  className="btn-purple-primary magnetic-btn"
                  style={{ width: '100%', justifyContent: 'center', fontSize: '14px', padding: '10px' }}
                >
                  Fork on GitHub →
                </a>
              </div>

              {/* Card 2: Managed (soon) */}
              <div
                className="interactive-card card-anim"
                style={{
                  padding: '32px 24px',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between'
                }}
              >
                <div>
                  <div style={{ fontSize: '14px', color: '#9E94B8', fontWeight: '500' }}>Managed (soon)</div>
                  <div className="font-display" style={{ fontSize: '24px', fontWeight: '700', color: '#EDE9F6', margin: '14px 0 20px' }}>
                    Get notified
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13.5px', color: '#9E94B8', marginBottom: '24px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="check-pill">✓</span> Hosted for you
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="check-pill">✓</span> Easy setup
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="check-pill">✓</span> Priority support
                    </div>
                  </div>
                </div>

                <button
                  onClick={onLaunchDemo}
                  className="btn-dark-secondary magnetic-btn"
                  style={{ width: '100%', justifyContent: 'center', fontSize: '14px', padding: '10px' }}
                >
                  Join waitlist →
                </button>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── 13. CALL TO ACTION BANNER BOX (WITH PURPLEAGENT SHIELD LOGO) ──── */}
      <section style={{ padding: '40px 0 100px' }}>
        <div className="section-wrap">
          <div
            className="interactive-card cta-banner-anim"
            style={{
              padding: '40px 48px',
              borderRadius: '20px',
              border: '1px solid rgba(139, 92, 246, 0.45)',
              background: 'linear-gradient(135deg, rgba(139, 92, 246, 0.16) 0%, rgba(26, 12, 48, 0.85) 100%)',
              boxShadow: '0 30px 80px rgba(0,0,0,0.7), 0 0 50px rgba(124, 58, 237, 0.25)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '32px',
              flexWrap: 'wrap'
            }}
          >
            {/* Left Graphic with Authentic Shield */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '26px' }}>
              <div
                ref={cube2Ref}
                style={{
                  width: '68px',
                  height: '68px',
                  borderRadius: '18px',
                  background: 'rgba(124, 58, 237, 0.25)',
                  border: '1px solid rgba(167, 139, 250, 0.5)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 0 30px rgba(139, 92, 246, 0.8)',
                  flexShrink: 0
                }}
              >
                <img
                  src="/logos/logo-shield.png"
                  alt="Purple Agent Shield"
                  style={{ width: '48px', height: '48px', objectFit: 'contain' }}
                />
              </div>

              <div>
                <h3 className="font-display" style={{ fontSize: '26px', fontWeight: '800', color: '#EDE9F6', margin: '0 0 6px' }}>
                  Stop staring at graphs. <span className="text-accent-gradient">Start understanding your servers.</span>
                </h3>
                <p style={{ fontSize: '14.5px', color: '#C4BBD8', margin: 0 }}>
                  Get early access, contribute on GitHub or join the waitlist for managed hosting.
                </p>
              </div>
            </div>

            {/* Right Buttons */}
            <div style={{ display: 'flex', gap: '14px', alignItems: 'center' }}>
              <button
                onClick={onLaunchDemo}
                className="btn-purple-primary magnetic-btn"
                style={{ fontSize: '14.5px', padding: '12px 24px' }}
              >
                <span>Get started free →</span>
              </button>

              <a
                href="https://github.com/salman2610/purple-agent"
                target="_blank"
                rel="noreferrer"
                className="btn-dark-secondary magnetic-btn"
                style={{ fontSize: '14px', padding: '12px 20px' }}
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
                </svg>
                <span>View on GitHub</span>
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* ── 14. FOOTER WITH BRAND LOGO & USER ATTRIBUTION ─────────────────── */}
      <footer style={{ borderTop: '1px solid rgba(255, 255, 255, 0.08)', background: '#05020C', padding: '64px 0 36px' }}>
        <div className="section-wrap">
          {/* Top Row: Brand & Columns */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: '2fr 1fr 1fr 1fr 1fr',
              gap: '40px',
              paddingBottom: '48px',
              borderBottom: '1px solid rgba(255, 255, 255, 0.06)'
            }}
          >
            {/* Left Brand Column */}
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '14px' }}>
                <img
                  src="/logos/app-icon.png"
                  alt="PurpleAgent"
                  style={{
                    width: '32px',
                    height: '32px',
                    borderRadius: '8px',
                    objectFit: 'contain',
                    boxShadow: '0 0 16px rgba(139, 92, 246, 0.5)'
                  }}
                />
                <span className="font-display" style={{ fontSize: '19px', fontWeight: '700', color: '#EDE9F6' }}>PurpleAgent</span>
              </div>
              <p style={{ fontSize: '14px', color: '#9E94B8', lineHeight: '1.6', margin: 0, maxWidth: '300px' }}>
                Open source server monitoring and incident diagnosis. Built for developers, sysadmins and infrastructure teams.
              </p>
            </div>

            {/* Column 1: Product */}
            <div>
              <div style={{ fontSize: '13px', fontWeight: '700', color: '#EDE9F6', marginBottom: '14px' }}>Product</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13.5px', color: '#776E91' }}>
                <a href="#features" style={{ transition: 'color 0.2s' }} onMouseEnter={e => e.target.style.color = '#EDE9F6'} onMouseLeave={e => e.target.style.color = '#776E91'}>Features</a>
                <a href="#how-it-works" style={{ transition: 'color 0.2s' }} onMouseEnter={e => e.target.style.color = '#EDE9F6'} onMouseLeave={e => e.target.style.color = '#776E91'}>How it works</a>
                <a href="#use-cases" style={{ transition: 'color 0.2s' }} onMouseEnter={e => e.target.style.color = '#EDE9F6'} onMouseLeave={e => e.target.style.color = '#776E91'}>Use cases</a>
                <a href="#pricing" style={{ transition: 'color 0.2s' }} onMouseEnter={e => e.target.style.color = '#EDE9F6'} onMouseLeave={e => e.target.style.color = '#776E91'}>Pricing</a>
              </div>
            </div>

            {/* Column 2: Resources */}
            <div>
              <div style={{ fontSize: '13px', fontWeight: '700', color: '#EDE9F6', marginBottom: '14px' }}>Resources</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13.5px', color: '#776E91' }}>
                <a href="#docs" style={{ transition: 'color 0.2s' }} onMouseEnter={e => e.target.style.color = '#EDE9F6'} onMouseLeave={e => e.target.style.color = '#776E91'}>Docs</a>
                <a href="#quickstart" style={{ transition: 'color 0.2s' }} onMouseEnter={e => e.target.style.color = '#EDE9F6'} onMouseLeave={e => e.target.style.color = '#776E91'}>Quick start</a>
                <a href="#community" style={{ transition: 'color 0.2s' }} onMouseEnter={e => e.target.style.color = '#EDE9F6'} onMouseLeave={e => e.target.style.color = '#776E91'}>Community</a>
                <a href="https://github.com/salman2610/purple-agent" target="_blank" rel="noreferrer" style={{ transition: 'color 0.2s' }} onMouseEnter={e => e.target.style.color = '#EDE9F6'} onMouseLeave={e => e.target.style.color = '#776E91'}>GitHub</a>
              </div>
            </div>

            {/* Column 3: Company */}
            <div>
              <div style={{ fontSize: '13px', fontWeight: '700', color: '#EDE9F6', marginBottom: '14px' }}>Company</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13.5px', color: '#776E91' }}>
                <a href="#features" style={{ transition: 'color 0.2s' }} onMouseEnter={e => e.target.style.color = '#EDE9F6'} onMouseLeave={e => e.target.style.color = '#776E91'}>About</a>
                <a href="#features" style={{ transition: 'color 0.2s' }} onMouseEnter={e => e.target.style.color = '#EDE9F6'} onMouseLeave={e => e.target.style.color = '#776E91'}>Contact</a>
              </div>
            </div>

            {/* Column 4: Socials */}
            <div>
              <div style={{ fontSize: '13px', fontWeight: '700', color: '#EDE9F6', marginBottom: '14px' }}>Social</div>
              <div style={{ display: 'flex', gap: '14px', alignItems: 'center' }}>
                {/* GitHub */}
                <a href="https://github.com/salman2610/purple-agent" target="_blank" rel="noreferrer" style={{ color: '#9E94B8', transition: 'color 0.2s' }} onMouseEnter={e => e.currentTarget.style.color = '#FFFFFF'} onMouseLeave={e => e.currentTarget.style.color = '#9E94B8'}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
                  </svg>
                </a>
                {/* X / Twitter */}
                <a href="https://x.com" target="_blank" rel="noreferrer" style={{ color: '#9E94B8', transition: 'color 0.2s' }} onMouseEnter={e => e.currentTarget.style.color = '#FFFFFF'} onMouseLeave={e => e.currentTarget.style.color = '#9E94B8'}>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z" />
                  </svg>
                </a>
                {/* LinkedIn */}
                <a href="https://linkedin.com" target="_blank" rel="noreferrer" style={{ color: '#9E94B8', transition: 'color 0.2s' }} onMouseEnter={e => e.currentTarget.style.color = '#FFFFFF'} onMouseLeave={e => e.currentTarget.style.color = '#9E94B8'}>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.783 1.764-1.75 1.764zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z" />
                  </svg>
                </a>
              </div>
            </div>
          </div>

          {/* Bottom Row: Exact user requirement */}
          <div
            style={{
              paddingTop: '28px',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '16px',
              fontSize: '13.5px',
              color: '#776E91'
            }}
          >
            {/* Copyright */}
            <div>
              © 2026 PurpleAgent. All rights reserved.
            </div>

            {/* Exact requirement: designed and developed by salmanul faris, name clicked goes to salman2610.github.io */}
            <div style={{ color: '#9E94B8' }}>
              designed and developed by{' '}
              <a
                href="https://salman2610.github.io"
                target="_blank"
                rel="noreferrer"
                style={{
                  color: '#C4B5FD',
                  fontWeight: '600',
                  textDecoration: 'underline',
                  textUnderlineOffset: '3px',
                  transition: 'color 0.2s ease, text-shadow 0.2s ease'
                }}
                onMouseEnter={e => {
                  e.target.style.color = '#FFFFFF';
                  e.target.style.textShadow = '0 0 12px rgba(167, 139, 250, 0.8)';
                }}
                onMouseLeave={e => {
                  e.target.style.color = '#C4B5FD';
                  e.target.style.textShadow = 'none';
                }}
              >
                salmanul faris
              </a>
            </div>

            {/* Legal Links */}
            <div style={{ display: 'flex', gap: '20px' }}>
              <a href="#privacy" style={{ color: '#776E91', transition: 'color 0.2s' }} onMouseEnter={e => e.target.style.color = '#EDE9F6'} onMouseLeave={e => e.target.style.color = '#776E91'}>Privacy Policy</a>
              <a href="#terms" style={{ color: '#776E91', transition: 'color 0.2s' }} onMouseEnter={e => e.target.style.color = '#EDE9F6'} onMouseLeave={e => e.target.style.color = '#776E91'}>Terms of Service</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
