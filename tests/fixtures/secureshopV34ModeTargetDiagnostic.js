'use strict';

// Runs in the existing page realm. Never retain text, URLs, HTML or credentials.
function v34ModeTargetSnapshot(label) {
  const groups = [...document.querySelectorAll('[role="group"][aria-label="Shop feature mode"]')];
  const buttons = groups.length === 1 ? [...groups[0].querySelectorAll('button')]
    .filter(node => node.textContent.trim() === label) : [];
  const node = buttons.length === 1 ? buttons[0] : null;
  const finite = value => Number.isFinite(value) ? Math.max(-1000000, Math.min(1000000, Math.round(value))) : null;
  const rect = node?.getBoundingClientRect();
  const hit = rect ? document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2) : null;
  const tag = hit?.tagName;
  const toggle = document.querySelector('button[aria-controls="secureshop-settings"]');
  return { version: 1, groupCount: Math.min(groups.length, 2), targetCount: Math.min(buttons.length, 2),
    connected: node ? node.isConnected === true : null, disabled: node ? node.disabled === true : null,
    pressed: node ? node.getAttribute('aria-pressed') === 'true' : null,
    rect: rect ? { left: finite(rect.left), top: finite(rect.top), width: finite(rect.width), height: finite(rect.height) } : null,
    viewport: { width: finite(window.innerWidth), height: finite(window.innerHeight), scrollX: finite(window.scrollX), scrollY: finite(window.scrollY) },
    hitTag: typeof tag === 'string' && /^[A-Z]{1,16}$/.test(tag) ? tag : null,
    targetOwnsHit: !!(node && hit && (node === hit || node.contains(hit))),
    settingsPresent: !!document.querySelector('aside[aria-label="Shop settings"]'),
    settingsExpanded: toggle ? toggle.getAttribute('aria-expanded') === 'true' : null };
}

async function withV34ModeTargetDiagnostic(frame, label, operation, capture) {
  // Diagnostics must not stall the original action/failure if a page realm or
  // recorder stops responding. Late diagnostic completion has no authority.
  const bounded = async action => {
    let timer;
    try { return await Promise.race([Promise.resolve().then(action).catch(() => null),
      new Promise(resolve => { timer = setTimeout(() => resolve(null), 250); })]); }
    finally { clearTimeout(timer); }
  };
  let before = null;
  before = await bounded(() => frame.evaluate(v34ModeTargetSnapshot, label));
  try { return await operation(); }
  catch (originalError) {
    let after = null;
    after = await bounded(() => frame.evaluate(v34ModeTargetSnapshot, label));
    await bounded(() => capture({ kind: 'mode-target-hit-failure', requestedMode: label === 'Fixed' ? 'fixed' : 'vuln', before, after }));
    throw originalError;
  }
}
module.exports = { v34ModeTargetSnapshot, withV34ModeTargetDiagnostic };
