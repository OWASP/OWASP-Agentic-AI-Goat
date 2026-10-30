import React, { useEffect, useRef, useState } from 'react';
import axios from 'axios';
import WorkshopNavbar from '../components/WorkshopNavbar';

const buttonStyle = { padding: '0.65rem 1rem', borderRadius: '6px', border: '1px solid white', cursor: 'pointer' };

export default function SessionDisclosureDemo() {
  const [session, setSession] = useState(null);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const active = useRef(null);
  useEffect(() => () => { active.current?.abort(); active.current = null; }, []);

  const run = async (reset = false) => {
    if (active.current) return;
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setSession(null);
    setMessage('');
    try {
      let resetGeneration;
      if (reset) {
        const rotated = await axios.post('/api/vulnerabilities/session/reset', {}, { signal: controller.signal });
        if (rotated.data?.success !== true || rotated.data.generation == null) throw new Error('Reset not confirmed');
        resetGeneration = rotated.data.generation;
      }
      const { data } = await axios.get('/api/vulnerabilities/session/info', { signal: controller.signal });
      if (controller.signal.aborted) return;
      // Explicitly select the challenge projection; never render arbitrary API
      // fields, browser cookies, local storage, or platform authentication data.
      if (data?.scope !== 'isolated synthetic lab session' || !data.session
          || typeof data.cookies?.owasp_ai_goat_lab_session !== 'string'
          || typeof data.session.sessionId !== 'string' || typeof data.session.role !== 'string'
          || !/^\d+$/.test(String(data.session.generation))
          || (reset && String(data.session.generation) !== String(resetGeneration))) {
        throw new Error('Invalid lab projection');
      }
      setSession({ sessionId: data.session.sessionId, role: data.session.role,
        generation: data.session.generation, credential: data.cookies.owasp_ai_goat_lab_session });
      setMessage(reset ? 'Lab credential rotated. Previously issued lab cookies are now invalid.' : 'Current isolated lab credential loaded.');
    } catch (error) {
      if (!controller.signal.aborted) {
        setMessage(error.response?.status === 401
          ? 'The lab cookie is stale or authentication is required. Sign in if needed, then inspect again.'
          : 'The lab session could not be loaded. Retry when the service is available.');
      }
    } finally {
      if (active.current === controller) {
        active.current = null;
        setBusy(false);
      }
    }
  };

  return <>
    <WorkshopNavbar />
    <div style={{ minHeight: '100vh', background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'white', textAlign: 'center', padding: '2rem' }}>
      <div>
        <h1>🔐 Session Security Scenario Briefing</h1>
        <p>Inspect and rotate a synthetic credential in an isolated lab session.</p>
        <p>This demonstration is ungraded. It does not expose your platform login session.</p>
        <div style={{ marginTop: '2rem', padding: '1rem', background: 'rgba(255,255,255,0.1)', borderRadius: '10px' }}>
          <h3>Objectives:</h3>
          <ul style={{ textAlign: 'left', maxWidth: '400px', margin: '0 auto' }}>
            <li>Observe disclosure of a deliberately readable lab credential</li>
            <li>Rotate the credential and observe the new generation</li>
            <li>Explain why stale credentials must be rejected</li>
          </ul>
          <p>Lab credentials belong to the signed-in learner. Sharing one does not grant access to another learner’s session.</p>
          <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'center' }}>
            <button style={buttonStyle} disabled={busy} onClick={() => run()}>Inspect lab session</button>
            <button style={buttonStyle} disabled={busy} onClick={() => run(true)}>Reset lab session</button>
          </div>
          <p role="status">{busy ? 'Loading lab session…' : message}</p>
          {session && <dl style={{ textAlign: 'left', maxWidth: '550px', overflowWrap: 'anywhere' }}>
            <dt>Lab session ID</dt><dd>{session.sessionId}</dd>
            <dt>Lab role</dt><dd>{session.role}</dd>
            <dt>Generation</dt><dd>{session.generation}</dd>
            <dt>Synthetic lab credential</dt><dd><code>{session.credential}</code></dd>
          </dl>}
        </div>
      </div>
    </div>
  </>;
}
