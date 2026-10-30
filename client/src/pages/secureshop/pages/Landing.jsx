import React, { useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { motion, useReducedMotion } from 'framer-motion';
import { Sparkles, ArrowRight, Bot, LineChart, ShieldCheck } from 'lucide-react';

import { useAuth } from '../context/AuthContext';
import Footer from '../components/Footer.jsx';
import ProductCard from '../components/ProductCard.jsx';
import Button from '../components/Button.jsx';
import { safeLoginDestination } from '../utils/loginDestination.mjs';
import '../theme.css';

/**
 * Landing.jsx — public marketing page at /secureshop.
 *
 * Full-viewport hero, three product shelves, editorial section, testimonials,
 * footer. Renders its own top nav (with sign-in / register CTAs) so it can
 * be shown outside the authed Shell.
 */
const CATEGORIES = [
  { label: 'Electronics', query: 'Electronics' },
  { label: 'Beauty', query: 'Beauty' },
  { label: 'Books', query: 'Books' },
];

const TESTIMONIALS = [
  { quote: 'I asked "find me a laptop under $1500 with good battery life" and the customer agent narrowed 400 SKUs down to three that made sense.', name: 'Priya S.', role: 'Data engineer' },
  { quote: 'Every review has a moderator note. When one got flagged as suspicious, I knew before spending a dime. Transparency, but agentic.', name: 'Marcus R.', role: 'Systems architect' },
  { quote: 'The agent lane shows every hop. First time an e-commerce site felt debuggable.', name: 'Sara K.', role: 'Security researcher' },
];

const SECTION_IDS = Object.freeze({ '#about': 'about', '#how': 'how',
  '#agent-lane': 'agent-lane', '#lab-notes': 'lab-notes' });

export default function Landing() {
  const { isAuthed, user } = useAuth();
  const reduce = useReducedMotion();
  const location = useLocation();

  const [feeds, setFeeds] = useState({});
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    if (location.pathname !== '/secureshop') return;
    const section = SECTION_IDS[location.hash];
    if (section) document.getElementById(section)?.scrollIntoView?.({
      behavior: reduce ? 'auto' : 'smooth', block: 'start',
    });
  }, [location.pathname, location.hash, location.key, reduce]);

  useEffect(() => {
    let cancelled = false;
    async function loadCategoryFeeds() {
      setFeeds({});
      const results = await Promise.all(CATEGORIES.map(async (c) => {
        try {
          const r = await fetch(`/api/secureshop/products?category=${encodeURIComponent(c.query)}&limit=8`);
          if (!r.ok) return [c.label, { status: 'error' }];
          const j = await r.json();
          if (!Array.isArray(j?.products)) return [c.label, { status: 'error' }];
          return [c.label, { status: 'ok', products: j.products }];
        } catch {
          return [c.label, { status: 'error' }];
        }
      }));
      if (!cancelled) setFeeds(Object.fromEntries(results));
    }
    loadCategoryFeeds();
    return () => { cancelled = true; };
  }, [reloadKey]);

  return (
    <div className="ss-root">
      <LandingTopNav authed={isAuthed} user={user} />

      {/* HERO */}
      <section className="ss-landing-hero">
        <motion.div
          initial={reduce ? { opacity: 0 } : { opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
        >
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: 8,
            fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.08em',
            color: 'var(--copper)', marginBottom: 24, padding: '4px 12px',
            border: '1px solid var(--copper)', borderRadius: 999,
          }}>
            <Sparkles size={12} /> agentic commerce
          </div>
          <h1 className="ss-hero__head" style={{ fontSize: 'clamp(48px, 6.5vw, 84px)' }}>
            Everything<br />
            you need. Now with agents<br />
            that <span style={{ color: 'var(--copper)' }}>actually shop</span> for you.
          </h1>
          <p className="ss-hero__sub">
            OWASP AI SecureShop is a real store, backed by a hierarchy of specialist AI agents.
            Every product page is written by an LLM, every price is set by an agent,
            every review is moderated by one. Watch every decision, in a lane, in real time.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 8 }}>
            {isAuthed ? (
              <Button as={Link} to={safeLoginDestination('', user)} size="lg" iconRight={<ArrowRight size={16} />}>
                Continue shopping
              </Button>
            ) : (
              <>
                <Button as={Link} to="/secureshop/login" size="lg" iconRight={<ArrowRight size={16} />}>
                  Sign in
                </Button>
                <Button as={Link} to="/secureshop/register" variant="ghost" size="lg">
                  Create an account
                </Button>
              </>
            )}
            <Button as={Link} to="/secureshop/catalog" variant="ghost" size="lg">
              Browse as guest
            </Button>
          </div>
        </motion.div>

        <div aria-hidden="true">
          <WarehouseSVG />
        </div>
      </section>

      {/* SHELVES */}
      {CATEGORIES.map((c, idx) => (
        <ScrollRevealSection key={c.label}>
          <div className="ss-container" style={{ padding: '30px 32px' }}>
            <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 20 }}>
              <h2 className="ss-shelf__title" style={{ margin: 0 }}>{c.label}</h2>
              <Link to={`/secureshop/catalog?category=${encodeURIComponent(c.query)}`}
                    style={{ color: 'var(--signal)', textDecoration: 'none', fontSize: 13, fontWeight: 500 }}>
                See all {c.label.toLowerCase()} →
              </Link>
            </div>
            <div className="ss-shelf__row">
              {!feeds[c.label] && Array.from({ length: 4 }).map((_, i) => (
                <div key={i} className="ss-product-card">
                  <div className="ss-skel" style={{ aspectRatio: '4/5' }} />
                  <div style={{ padding: 14 }}>
                    <div className="ss-skel" style={{ width: '60%', height: 12, marginBottom: 8 }} />
                    <div className="ss-skel" style={{ width: '90%', height: 18, marginBottom: 12 }} />
                    <div className="ss-skel" style={{ width: '30%', height: 14 }} />
                  </div>
                </div>
              ))}
              {feeds[c.label]?.status === 'ok' && feeds[c.label].products.slice(0, 8).map((p, i) => (
                <ProductCard key={p.id} product={p} index={i} />
              ))}
              {feeds[c.label]?.status === 'ok' && !feeds[c.label].products.length && (
                <div style={{ gridColumn: '1 / -1', padding: 40, opacity: 0.6, textAlign: 'center' }}>
                  No products in {c.label} yet.
                </div>
              )}
              {feeds[c.label]?.status === 'error' && (
                <div style={{ gridColumn: '1 / -1', padding: 40, textAlign: 'center' }}>
                  Products are unavailable right now.{' '}
                  <button type="button" className="ss-btn ss-btn--ghost" onClick={() => setReloadKey((key) => key + 1)}>Retry</button>
                </div>
              )}
            </div>
          </div>
        </ScrollRevealSection>
      ))}

      {/* EDITORIAL */}
      <ScrollRevealSection>
        {/* M12 D4 — anchor IDs matching TopNav ("#how") and Footer ("#about",
            "#agents"/"#agent-lane", "#lab-notes"). Duplicated so both anchor
            targets ("how it works" from the nav and "about" from the footer)
            land here. */}
        <div id="about" className="ss-container" style={{ padding: '80px 32px' }}>
          <span id="how" style={{ position: 'absolute' }} aria-hidden="true"></span>
          <div className="ss-landing-editorial">
            <div>
              <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--copper)', marginBottom: 12 }}>
                How it works
              </div>
              <h2 style={{ fontFamily: 'var(--display)', fontSize: 44, lineHeight: 1.05, letterSpacing: '-0.01em', margin: 0 }}>
                How OWASP AI SecureShop thinks.
              </h2>
            </div>
            <div style={{ fontSize: 16, lineHeight: 1.65, opacity: 0.85 }}>
              <p style={{ marginTop: 0 }}>
                Under the hood, OWASP AI SecureShop runs seventeen specialist agents talking over MCP.
                Product summaries are written by the <strong>summarizer</strong> agent — the
                same one that reads your uploaded manuals and answers "does this fit?".
              </p>
              <p>
                Prices come from <strong>price-advisor</strong>, and it can be argued with —
                politely or otherwise. Reviews are moderated by <strong>review-moderator</strong>,
                which decides "approved" or "hold" and writes a note explaining why.
                When you file a support ticket, <strong>support</strong> triages, drafts a
                response, and — with your permission — files a refund.
              </p>
              <p>
                Every decision streams into the agent lane on the right. That transparency
                isn't a debug panel: it's the honest surface of an agentic system.
              </p>

              <div style={{ display: 'flex', gap: 20, marginTop: 32, flexWrap: 'wrap' }}>
                <PillarCard icon={<Bot size={18} />} title="17 agents" text="Specialist supervisors + tools" />
                <PillarCard icon={<LineChart size={18} />} title="LLM-set prices" text="Live from price-advisor" />
                <PillarCard icon={<ShieldCheck size={18} />} title="Every hop visible" text="Trace lane, every message" />
              </div>
            </div>
          </div>
        </div>
      </ScrollRevealSection>

      {/* TESTIMONIALS */}
      <ScrollRevealSection>
        <div id="agents" className="ss-container" style={{ padding: '40px 32px' }}>
          {/* Footer also links to "#agent-lane" — same landing spot. */}
          <span id="agent-lane" style={{ position: 'absolute' }} aria-hidden="true"></span>
          <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--copper)', marginBottom: 8 }}>
            What people say
          </div>
          <h2 style={{ fontFamily: 'var(--display)', fontSize: 36, letterSpacing: '-0.01em', margin: '0 0 30px 0' }}>
            Field reports.
          </h2>
          <div className="ss-testimonial-grid">
            {TESTIMONIALS.map((t, i) => (
              <motion.div key={i} className="ss-testimonial"
                initial={reduce ? { opacity: 0 } : { opacity: 0, y: 12 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.3 }}
                transition={{ duration: 0.28, delay: i * 0.06 }}
              >
                <div className="ss-testimonial__quote">"{t.quote}"</div>
                <div className="ss-testimonial__author">
                  <div style={{ fontWeight: 600 }}>{t.name}</div>
                  <div style={{ opacity: 0.6, fontSize: 12 }}>{t.role}</div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </ScrollRevealSection>

      {/* CTA */}
      <ScrollRevealSection>
        <div id="lab-notes" style={{
          padding: '80px 32px', textAlign: 'center',
          background: 'var(--carbon)', color: 'var(--paper)',
        }}>
          <h2 style={{ fontFamily: 'var(--display)', fontSize: 40, margin: '0 0 20px 0' }}>
            Meet the agents.
          </h2>
          <p style={{ maxWidth: 560, margin: '0 auto 30px auto', fontSize: 16, opacity: 0.85 }}>
            Start with a demo account, then wire the AI you already use.
          </p>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
            <Button as={Link} to="/secureshop/register" size="lg">Create an account</Button>
            <Button as={Link} to="/secureshop/login" variant="ghost" size="lg" style={{ color: 'var(--paper)', borderColor: 'var(--paper)' }}>
              Sign in
            </Button>
          </div>
        </div>
      </ScrollRevealSection>

      <Footer />
    </div>
  );
}

function LandingTopNav({ authed, user }) {
  return (
    <nav className="ss-landing-nav" role="navigation" aria-label="Marketing nav">
      <Link to="/secureshop" className="ss-nav__brand">OWASP AI SecureShop</Link>
      <div style={{ display: 'flex', gap: 20, alignItems: 'center' }}>
        <Link to="/secureshop/catalog" className="ss-nav__link">Shop</Link>
        <Link to="/secureshop#how" className="ss-nav__link">How it works</Link>
        {authed ? (
          <Link to={safeLoginDestination('', user)} className="ss-btn ss-btn--sm">Continue</Link>
        ) : (
          <>
            <Link to="/secureshop/login" className="ss-nav__link">Sign in</Link>
            <Link to="/secureshop/register" className="ss-btn ss-btn--sm">Register</Link>
          </>
        )}
      </div>
    </nav>
  );
}

function ScrollRevealSection({ children }) {
  const reduce = useReducedMotion();
  return (
    <motion.section
      initial={reduce ? { opacity: 0 } : { opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.15 }}
      transition={{ duration: 0.45, ease: [0.16, 1, 0.3, 1] }}
    >
      {children}
    </motion.section>
  );
}

function PillarCard({ icon, title, text }) {
  return (
    <div style={{
      flex: '1 1 200px', minWidth: 180,
      padding: '18px 20px',
      border: '1px solid var(--rule)',
      background: 'color-mix(in srgb, var(--paper) 92%, var(--carbon))',
    }}>
      <div style={{ marginBottom: 10, color: 'var(--signal)' }}>{icon}</div>
      <div style={{ fontFamily: 'var(--display)', fontSize: 20, fontWeight: 600, marginBottom: 6 }}>{title}</div>
      <div style={{ fontSize: 13, opacity: 0.75 }}>{text}</div>
    </div>
  );
}

function WarehouseSVG() {
  const reduce = useReducedMotion();
  return (
    <svg viewBox="0 0 500 460" width="100%" style={{ maxWidth: 520 }} aria-hidden="true">
      <defs>
        <linearGradient id="floor" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor="var(--carbon)" stopOpacity="0.08" />
          <stop offset="100%" stopColor="var(--carbon)" stopOpacity="0.02" />
        </linearGradient>
      </defs>
      {/* isometric shelves */}
      {[0, 1, 2, 3, 4].map((row) => (
        <g key={row} transform={`translate(${row * 6}, ${row * 30})`}>
          <line x1="30" y1={80 + row * 20} x2="470" y2={80 + row * 20} stroke="var(--rule)" strokeWidth="1" />
          {[0, 1, 2, 3, 4, 5, 6].map((col) => (
            <motion.rect
              key={col}
              x={50 + col * 55}
              y={55 + row * 20}
              width={40}
              height={22}
              fill={(col + row) % 6 === 2 ? 'var(--signal)' : 'var(--carbon)'}
              opacity={0.85 - row * 0.13}
              initial={reduce ? { opacity: 1 } : { opacity: 0 }}
              animate={{ opacity: 0.85 - row * 0.13 }}
              transition={{ duration: 0.4, delay: row * 0.06 + col * 0.02 }}
            />
          ))}
        </g>
      ))}
      {/* floor */}
      <rect x="0" y="380" width="500" height="80" fill="url(#floor)" />
      {/* moving picker */}
      <motion.g
        initial={reduce ? { x: 0 } : { x: -60 }}
        animate={{ x: 60 }}
        transition={{ duration: 6, ease: 'linear', repeat: Infinity, repeatType: 'reverse' }}
      >
        <circle cx="230" cy="400" r="6" fill="var(--copper)" />
        <rect x="215" y="404" width="30" height="14" fill="var(--copper)" opacity="0.6" />
      </motion.g>
      <text x="250" y="450" textAnchor="middle" fontFamily="var(--mono)" fontSize="10" fill="var(--ink)" opacity="0.6">
        customer supervisor · walking the shelves
      </text>
    </svg>
  );
}
