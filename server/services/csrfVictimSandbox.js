/**
 * CSRF Victim Sandbox — "VaultLink" online bank (educational, intentionally vulnerable)
 * =====================================================================================
 * Four-tab lab: GET / POST / XSS / Indirect. Each tab has its OWN logged-in
 * victim, its own defense toggle, its own attack log, and its own agent-chat
 * gate. A forged HTTP request to /api/workshop/csrf/agent-action?tab=<id>
 * mutates that tab's victim in place, so learners watch the consequence land
 * in the matching Victim panel.
 *
 * VECTORS → OBJECTIVES (12 total, 3 per tab):
 *   get       direct_get                    csrf_g1 csrf_g2 csrf_g3
 *   post      direct_post + fetch           csrf_p1 csrf_p2 csrf_p3
 *   xss       same-origin token bypass      csrf_x1 csrf_x2 csrf_x3
 *   indirect  agentic + poisoned document   csrf_i1 csrf_i2 csrf_i3
 *
 * DEFENSES (per-tab toggle): when ON we require a per-request CSRF token AND
 * SameSite=Strict. Cross-site vectors (direct_get / direct_post / fetch) are
 * BLOCKED; same-origin XSS and the confused-deputy agent still succeed — the
 * key teaching payoff about why tokens alone are not enough.
 */

const ACTIONS = {
  change_email:    { label: 'Change account email',      danger: 'account takeover (password-reset hijack)' },
  add_payee:       { label: 'Add a money-transfer payee', danger: 'sets up an attacker-controlled beneficiary' },
  transfer:        { label: 'Transfer funds to a payee',  danger: 'moves money out of the account' },
  change_password: { label: 'Change account password',    danger: 'full account takeover' },
  promote_role:    { label: 'Change account role',        danger: 'privilege escalation to admin' },
  disable_mfa:     { label: 'Disable multi-factor auth',  danger: 'removes the last line of defense' },
};

const VECTORS = {
  direct_get:  { label: 'Direct GET (tracking-pixel <img>)',   crossSite: true  },
  direct_post: { label: 'Direct POST (auto-submit <form>)',    crossSite: true  },
  fetch:       { label: 'fetch()/XHR with credentials',        crossSite: true  },
  xss:         { label: 'Same-origin XSS-delivered request',   crossSite: false },
  agentic:     { label: 'Confused-deputy AI agent',            crossSite: false },
  indirect:    { label: 'Poisoned document → AI agent',        crossSite: false },
};

// One logged-in victim persona per tab.
const TABS = {
  get: {
    label: 'GET CSRF',
    victim: { name: 'Alex Rivera', email: 'alex.rivera@personalmail.com', phone: '+1-555-0142',
      password: 'Sunshine#2024', balance: 10000, role: 'customer',
      payees: [{ id: 'savings', label: 'My Savings (self)', trusted: true },
               { id: 'landlord', label: 'Oakwood Property Mgmt', trusted: true }] },
    vectors: ['direct_get'],
    objectives: ['csrf_g1', 'csrf_g2', 'csrf_g3'],
  },
  post: {
    label: 'POST CSRF',
    victim: { name: 'Maya Chen', email: 'maya.chen@vaultlink-biz.com', phone: '+1-555-0199',
      password: 'DragonFruit!9', balance: 42500, role: 'business',
      payees: [{ id: 'payroll', label: 'ADP Payroll', trusted: true },
               { id: 'aws', label: 'AWS Billing', trusted: true }] },
    vectors: ['direct_post', 'fetch'],
    objectives: ['csrf_p1', 'csrf_p2', 'csrf_p3'],
  },
  xss: {
    label: 'CSRF via XSS',
    victim: { name: 'Jordan Patel', email: 'jordan.p@corp-mail.net', phone: '+1-555-0177',
      password: 'Velvet#Moon77', balance: 3200, role: 'customer',
      payees: [{ id: 'rent', label: 'Riverside Apartments', trusted: true }] },
    vectors: ['xss'],
    objectives: ['csrf_x1', 'csrf_x2', 'csrf_x3'],
  },
  indirect: {
    label: 'Indirect / AI-Agent CSRF',
    victim: { name: 'Sam Okafor', email: 'sam.okafor@mailhub.io', phone: '+1-555-0155',
      password: 'Cobalt$Rain21', balance: 18750, role: 'customer',
      payees: [{ id: 'tuition', label: 'State University Bursar', trusted: true }] },
    vectors: ['agentic', 'indirect'],
    objectives: ['csrf_i1', 'csrf_i2', 'csrf_i3'],
  },
};

const TAB_IDS = Object.keys(TABS);
const ALL_OBJECTIVES = TAB_IDS.flatMap((t) => TABS[t].objectives);

function freshTabState(tabId) {
  const seed = TABS[tabId].victim;
  return {
    victim: {
      victimName: seed.name,
      profile: { email: seed.email, phone: seed.phone },
      security: { password: seed.password, mfaEnabled: true },
      account: { balance: seed.balance, role: seed.role, payees: seed.payees.map((p) => ({ ...p })) },
    },
    baseline: { email: seed.email, password: seed.password, mfaEnabled: true, balance: seed.balance,
      role: seed.role, payeeCount: seed.payees.length },
    defenses: { csrfToken: false, sameSite: 'None' },
    csrfToken: 'tok_' + Math.random().toString(36).slice(2, 10),
    attackLog: [],
    // XSS (email) + Indirect (RAG) tabs drive the attack THROUGH the chat
    // (list/read email, ask a question), so chat is on by default there.
    // GET/POST use the Payload Builder, so chat starts off (recon/defense only).
    agentChatEnabled: (tabId === 'xss' || tabId === 'indirect'),
    reconCount: 0,
    // XSS tab (email delivery): the attacker's temp inbox + whether an attack
    // email was sent + whether the agent has read it.
    xssInbox: null,
    xssEmailSent: false,
    xssEmailRead: false,
    // Indirect tab (RAG poisoning): the vector-store session id + which distinct
    // questions have already triggered the poisoned chunk (for i2 vs i3).
    ragSessionId: null,
    ragPoisoned: false,
    ragFiredQuestions: [],
  };
}

const sandboxes = new Map();

// Production state is PostgreSQL-only. Tests that exercise the pure mutation
// model can inject null explicitly or use the existing EXPORT_INTERNALS seam.
function defaultPersistence() {
  if (process.env.EXPORT_INTERNALS === '1') return null;
  return require('../database/postgres/csrfWorkshopDb');
}

class CsrfVictimSandbox {
  constructor(sessionId, { persistence = defaultPersistence() } = {}) {
    this.sessionId = sessionId;
    this._persistence = persistence;
    this.tabs = {};
    TAB_IDS.forEach((t) => { this.tabs[t] = freshTabState(t); });
    this.hitObjectives = new Set();
    this._loaded = false;      // _load() has been kicked off
    this._pgReady = null;
    this._pendingState = undefined;
    this._pendingDelete = false;
    this._invalid = false;
    this._flushTail = Promise.resolve();
  }

  _assertUsable() {
    if (this._invalid) throw Object.assign(new Error('Victim state requires authoritative reload'), {
      code: 'CSRF_VICTIM_STATE_UNAVAILABLE', statusCode: 503,
    });
  }

  _invalidate() {
    this._invalid = true;
    this._pendingState = undefined;
    this._pendingDelete = false;
    // Never evict a replacement created by a later owner lifecycle operation.
    if (sandboxes.get(this.sessionId) === this) sandboxes.delete(this.sessionId);
  }

  // Hydrate this.tabs from the persisted DB row (if any). Called synchronously
  // by getOrCreateSandbox the first time a session is materialised.
  _load() {
    if (this._loaded) return;
    this._loaded = true;
    if (!this._persistence) return;
    this._pgReady = this._persistence.getVictimState(this.sessionId).then(saved => {
      this._assertUsable();
      if (saved) TAB_IDS.forEach(tab => { if (saved[tab]) this.tabs[tab] = { ...freshTabState(tab), ...saved[tab] }; });
    }).catch(error => { this._invalidate(); throw error; });
    // Requests await ready(); attaching a rejection observer avoids an unhandled promise during creation.
    this._pgReady.catch(() => {});
  }

  // Hydration completes before admitted routes mutate or publish this state.
  async ready() { this._assertUsable(); await this._pgReady; this._assertUsable(); }

  flush() {
    const next = this._flushTail.then(() => this._flush());
    this._flushTail = next.catch(() => {});
    return next;
  }

  async _flush() {
    await this.ready();
    if (!this._persistence) return;
    try {
      if (!this._pendingDelete) this.persist();
      if (this._pendingDelete) { await this._persistence.deleteVictimState(this.sessionId); this._pendingDelete = false; }
      if (this._pendingState !== undefined) {
        const state = this._pendingState;
        await this._persistence.saveVictimState(this.sessionId, state);
        if (this._pendingState === state) this._pendingState = undefined;
      }
      this._assertUsable();
    } catch (error) {
      // A rejected acknowledgement does not prove rollback. Discard only RAM;
      // the next request must read whichever state actually committed.
      this._invalidate();
      throw error;
    }
  }

  persist() {
    this._assertUsable();
    if (!this._persistence) return;
    this._pendingDelete = false;
    this._pendingState = JSON.parse(JSON.stringify(this.tabs));
  }

  _clearPersisted() {
    this._assertUsable();
    if (!this._persistence) return;
    this._pendingState = undefined;
    this._pendingDelete = true;
  }

  tab(id) { this._assertUsable(); return this.tabs[id] || this.tabs.get; }

  describeSurface(tabId = 'get') {
    const t = this.tab(tabId);
    return {
      bank: 'VaultLink',
      tab: tabId,
      tabLabel: TABS[tabId]?.label,
      victim: t.victim.victimName,
      actions: Object.entries(ACTIONS).map(([id, a]) => ({ id, ...a })),
      vectors: (TABS[tabId]?.vectors || []).map((v) => ({ id: v, label: VECTORS[v].label })),
      defenses: { ...t.defenses },
    };
  }

  getTabState(tabId) {
    const t = this.tab(tabId);
    // Every mutating route handler ends by returning getTabState(...) in its
    // response, so persisting here captures all in-request mutations (including
    // the route's direct field writes: xssInbox, ragPoisoned, etc.) right before
    // the response is sent. The route publication fence flushes this snapshot.
    this.persist();
    return {
      tab: tabId,
      tabLabel: TABS[tabId]?.label,
      victim: t.victim.victimName,
      profile: { ...t.victim.profile },
      security: { password: t.victim.security.password, mfaEnabled: t.victim.security.mfaEnabled },
      account: { balance: t.victim.account.balance, role: t.victim.account.role,
        payees: t.victim.account.payees.map((p) => ({ ...p })) },
      baseline: { ...t.baseline },
      defenses: { ...t.defenses },
      csrfToken: t.csrfToken,
      agentChatEnabled: t.agentChatEnabled,
      reconCount: t.reconCount,
      attackLog: t.attackLog.slice(-30),
      xssInbox: t.xssInbox,
      xssEmailSent: t.xssEmailSent,
      xssEmailRead: t.xssEmailRead,
      ragPoisoned: t.ragPoisoned,
      ragFiredCount: (t.ragFiredQuestions || []).length,
    };
  }

  getState() {
    const tabs = {};
    TAB_IDS.forEach((id) => { tabs[id] = this.getTabState(id); });
    const g = tabs.get;
    // Back-compat flat shape (primary = GET tab) so existing consumers keep working.
    return {
      bank: 'VaultLink',
      victim: g.victim,
      loggedIn: true,
      profile: g.profile,
      security: g.security,
      account: g.account,
      defenses: g.defenses,
      csrfToken: g.csrfToken,
      agentChatEnabled: g.agentChatEnabled,
      reconCount: g.reconCount,
      attackLog: g.attackLog,
      tabs,
    };
  }

  setDefenses(tabId, on) {
    const t = this.tab(tabId);
    t.defenses = on ? { csrfToken: true, sameSite: 'Strict' } : { csrfToken: false, sameSite: 'None' };
    return { on: !!on, defenses: { ...t.defenses } };
  }

  setAgentChat(tabId, on) {
    const t = this.tab(tabId);
    t.agentChatEnabled = !!on;
    return t.agentChatEnabled;
  }

  /**
   * @returns { blocked, vector, vectorLabel, action, actionLabel, outcome, changed, defenses, note }
   */
  forge(tabId, vector, action, params = {}) {
    const t = this.tab(tabId);
    const vMeta = VECTORS[vector];
    if (!vMeta) return { blocked: true, error: `Unknown vector "${vector}".`, vector, action };
    if (!ACTIONS[action]) {
      return { blocked: true, error: `Unknown action "${action}". Try: ${Object.keys(ACTIONS).join(', ')}.`, vector, action };
    }

    const def = t.defenses;
    const protectedNow = def.csrfToken === true || def.sameSite === 'Strict';

    let blocked = false;
    let blockReason = null;
    if (protectedNow && vMeta.crossSite) {
      blocked = true;
      blockReason = def.csrfToken
        ? 'Rejected (HTTP 403): missing/invalid anti-CSRF token — a cross-site request cannot read the victim\'s token.'
        : 'Blocked: SameSite=Strict cookie was NOT attached to the cross-site request, so the server saw an unauthenticated call.';
    }

    const entry = {
      ts: new Date().toISOString(), tab: tabId, vector, vectorLabel: vMeta.label,
      action, actionLabel: ACTIONS[action].label, params: { ...params },
      crossSite: vMeta.crossSite, blocked,
    };

    if (blocked) {
      entry.outcome = blockReason;
      t.attackLog.push(entry);
      return { blocked: true, vector, vectorLabel: vMeta.label, action, actionLabel: ACTIONS[action].label,
        outcome: blockReason, changed: null, defenses: { ...def } };
    }

    const before = JSON.stringify(t.victim);
    const applied = this._applyAction(t.victim, action, params, vector);
    const stateChanged = before !== JSON.stringify(t.victim);
    const changed = stateChanged ? applied.changed : null;
    const detail = stateChanged ? applied.detail : `Action executed without a victim state change. ${applied.detail}`;
    entry.outcome = detail;
    entry.changed = changed;
    entry.executed = true;
    entry.stateChanged = stateChanged;
    t.attackLog.push(entry);

    return {
      blocked: false, vector, vectorLabel: vMeta.label, action, actionLabel: ACTIONS[action].label,
      outcome: detail, executed: true, stateChanged, changed, defenses: { ...def },
      note: (vector === 'xss' && protectedNow)
        ? 'Defenses were ON, yet this SAME-ORIGIN payload read the CSRF token from the page and bypassed them — anti-CSRF tokens do not stop XSS.'
        : ((vector === 'agentic' || vector === 'indirect') && protectedNow)
          ? 'Defenses were ON, but the AI agent holds a valid session + token, so as a confused deputy it forged the request anyway.'
          : undefined,
    };
  }

  _applyAction(victim, action, params, vector) {
    const v = victim;
    switch (action) {
      case 'change_email': {
        const to = params.email || params.value || 'attacker@evil.example';
        const from = v.profile.email;
        v.profile.email = to;
        return { changed: { field: 'profile.email', from, to }, detail: `Account email changed from ${from} to ${to}. Password-reset links now go to the attacker.` };
      }
      case 'add_payee': {
        const id = (params.id || params.name || 'attacker').toString().toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 20) || 'attacker';
        const label = params.label || params.name || 'Attacker Beneficiary (external)';
        if (!v.account.payees.some((p) => p.id === id)) {
          v.account.payees.push({ id, label, trusted: false, addedBy: vector });
        }
        return { changed: { field: 'account.payees', added: { id, label } }, detail: `New payee "${label}" (${id}) added to the victim's account.` };
      }
      case 'transfer': {
        const amount = Math.max(1, Math.min(parseInt(params.amount, 10) || 2500, v.account.balance));
        const to = params.to || params.payeeId || 'attacker';
        v.account.balance -= amount;
        return { changed: { field: 'account.balance', delta: -amount, to, balance: v.account.balance }, detail: `Transferred $${amount.toLocaleString()} to "${to}". New balance: $${v.account.balance.toLocaleString()}.` };
      }
      case 'change_password': {
        const to = params.password || params.value || 'Pwned!123';
        const from = v.security.password;
        v.security.password = to;
        return { changed: { field: 'security.password', from, to }, detail: `Account password changed from "${from}" to "${to}". The attacker now controls the login.` };
      }
      case 'promote_role': {
        const to = params.role || 'admin';
        const from = v.account.role;
        v.account.role = to;
        return { changed: { field: 'account.role', from, to }, detail: `Account role escalated from "${from}" to "${to}".` };
      }
      case 'disable_mfa': {
        const from = v.security.mfaEnabled;
        v.security.mfaEnabled = false;
        return { changed: { field: 'security.mfaEnabled', from, to: false }, detail: from ? 'Multi-factor authentication DISABLED on the victim account.' : 'MFA was already disabled.' };
      }
      default:
        return { changed: null, detail: 'No-op.' };
    }
  }

  resetTab(tabId) {
    this._assertUsable();
    if (!TABS[tabId]) return;
    this.tabs[tabId] = freshTabState(tabId);
    TABS[tabId].objectives.forEach((o) => this.hitObjectives.delete(o));
    this.persist();
  }

  reset() {
    this._assertUsable();
    TAB_IDS.forEach((t) => { this.tabs[t] = freshTabState(t); });
    this.hitObjectives = new Set();
    this._clearPersisted();
  }
}

function getOrCreateSandbox(sessionId) {
  if (!sandboxes.has(sessionId)) {
    const sb = new CsrfVictimSandbox(sessionId);
    sb._load();
    sandboxes.set(sessionId, sb);
  }
  return sandboxes.get(sessionId);
}

function resetSandbox(sessionId) {
  const sb = sandboxes.get(sessionId);
  if (sb) sb._clearPersisted();
  sandboxes.delete(sessionId);
}

module.exports = {
  getOrCreateSandbox,
  resetSandbox,
  ACTIONS,
  VECTORS,
  TABS,
  TAB_IDS,
  ALL_OBJECTIVES,
  CsrfVictimSandbox,
};
