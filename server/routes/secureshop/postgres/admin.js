/**
 * SecureShop v2 — admin-surface REST routes.
 *
 * Mounted at /api/secureshop under the same placeholder pattern that
 * customer.js and merchant.js use. Do NOT touch server/routes/secureshop.js
 * (legacy) or the other v2 routers.
 *
 * Admin REST endpoints mirror the admin task-agent tools so an attacker (or
 * the test harness) can drive the same vulns via HTTP without going through
 * the supervisor loop.
 *
 * Wave 5A F2/F3 hardening:
 *   - Every route in this router now sits behind requireRole('admin'). Only
 *     authenticated + admin-JWT callers reach the intentional vulnerability
 *     sinks (RCE, SSTI, XXE, MCP-*, path-traversal-read-config, etc.). This
 *     preserves the teaching value — an admin can still fire the sinks — but
 *     closes the unauthenticated-attacker attack surface Wave 4C flagged.
 *   - POST /admin/sign was deleted (F3). It minted arbitrary JWTs for anyone
 *     who could POST to the endpoint. It had no legitimate caller.
 *   - The alg=none intentional vuln remains on /admin/whoami but is now also
 *     gated behind the auth middleware — you need a valid HS256 admin token
 *     to REACH the endpoint, then you can forge an alg=none token to
 *     demonstrate the confusion sink. See @intentional-vulnerability below.
 *
 * @intentional-vulnerability auth-bypass-jwt-none
 * @teaches OWASP-Web:A07
 * @location server/routes/secureshop/admin.js
 * intentional — /admin/whoami accepts JWTs with alg=none. A forged
 * `header.payload.` (empty signature) with role=admin is trusted by the
 * whoami decoder. See spec §5.3 auth-bypass row. Reachability is now gated
 * behind requireRole('admin') to keep unauthenticated attackers out; the
 * teaching sink lives INSIDE the endpoint's decoder.
 */

const express = require('express');
const path = require('node:path');
const fs = require('node:fs');
const http = require('node:http');
const repo = require('../../../database/postgres/secureshopAdminRepository').getSecureShopAdminRepository();
const jwt = require('jsonwebtoken');

const { adminSupervisor } = require('../../../services/secureshop/supervisors/adminSupervisor.js');
const { runChatTurn } = require('../../../services/secureshop/streaming.js');
const { requireRole } = require('../_ssAuthMiddleware.js');
const { agentSessionControl } = require('../_agentSessionControl.js');
const {
  listAllPermissions, setPermission, setEnforcement, isEnforcementEnabled,
} = require('../../../services/secureshop/toolAcl.js');

// Legacy: SS_ADMIN_JWT_SECRET was a separate secret for the alg=none whoami.
// If unset, fall through to JWT_SECRET (which SS refuses to boot without —
// see server/services/secureshop/index.js). No hardcoded default (F4).
const JWT_SECRET = process.env.SS_ADMIN_JWT_SECRET || process.env.JWT_SECRET;
const AGENT_HOST_PORT = Number(process.env.SS_AGENT_HOST_PORT || 8082);

// Small helper — fetch a JSON URL with a short timeout. Used by the
// agent-host health proxy so the browser doesn't have to talk to :8082 directly.
function _fetchJson(url, timeoutMs = 800) {
  return new Promise((resolve) => {
    try {
      const req = http.get(url, (res) => {
        let buf = '';
        res.setEncoding('utf8');
        res.on('data', (c) => { buf += c; });
        res.on('end', () => {
          try { resolve({ ok: res.statusCode === 200, status: res.statusCode, body: JSON.parse(buf) }); }
          catch { resolve({ ok: false, status: res.statusCode, body: buf }); }
        });
      });
      req.on('error', () => resolve({ ok: false, error: 'connection refused' }));
      req.setTimeout(timeoutMs, () => { req.destroy(new Error('timeout')); resolve({ ok: false, error: 'timeout' }); });
    } catch (e) {
      resolve({ ok: false, error: e.message });
    }
  });
}

module.exports = function buildRouter({ pool, manifest, provider }) {
  const router = express.Router();
  const agentSession = agentSessionControl('admin');
  for(const method of ['get','post','put','delete']){
    const register=router[method].bind(router);
    router[method]=(route,...handlers)=>register(route,...handlers.map(handler=>(req,res,next)=>Promise.resolve(handler(req,res,next)).catch(next)));
  }

  // ---- Intentional-vuln surface REGISTERED BEFORE the auth wall -----------
  // /admin/whoami is the alg=none confusion teaching sink. Its whole point is
  // that unauthenticated attackers can pass a forged token and be trusted.
  // Registering it BEFORE requireRole preserves that unauthenticated attack
  // surface. See @intentional-vulnerability header at the top of this file.
  router.get('/admin/whoami', async (req, res) => {
    const auth = req.headers.authorization || '';
    const m = /^Bearer\s+(.+)$/i.exec(auth);
    if (!m) return res.status(401).json({ error: 'missing bearer token' });
    const token = m[1];
    try {
      // intentional — trust the JWT header's `alg` field. If it advertises
      // `none`, we verify with an empty secret and algorithms: ['none'].
      // This is the classic alg=none confusion sink: attackers forge the
      // header and the signature is not checked.
      let algHeader = 'HS256';
      try {
        const raw = String(token).split('.')[0] || '';
        const parsed = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
        if (parsed && parsed.alg) algHeader = parsed.alg;
      } catch {}
      let decoded;
      if (String(algHeader).toLowerCase() === 'none') {
        decoded = jwt.verify(token, '', { algorithms: ['none'] });
      } else {
        // The teaching sink accepts BOTH HS256 (legit) and none (forged).
        // JWT_SECRET must be set (see boot check); no hardcoded fallback (F4).
        if (!JWT_SECRET) return res.status(500).json({ ok: false, error: 'server misconfigured' });
        decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'none'] });
      }
      res.json({ ok: true, decoded, alg_accepted: algHeader });
    } catch (e) {
      res.status(401).json({ ok: false, error: e.message });
    }
  });

  // Wave 5A F2 — every OTHER endpoint in this router requires an authenticated
  // admin JWT. The intentional vulnerabilities that live below (RCE via
  // system.run_diagnostic, SSTI via policies/render, path-traversal via
  // system.read-config, MCP tool poisoning via mcp/register, XXE via
  // mcp/import-manifest) all STAY reachable — an admin token can still fire
  // them. What changes: unauthenticated callers now get 401 instead of a
  // direct sink invocation.
  //
  // M9 fix: scope the guard to /admin/* and /agents/admin/* paths only.
  // Previously the middleware ran on every request that hit this router —
  // since the router is mounted at /api/secureshop, siblings like
  // /email/inbox/... and /uploads/... never reached their own routers because
  // Express walks the per-router middleware stack before deciding no match
  // exists. That broke customer inbox loading (silent 401).
  router.use('/admin', requireRole('admin'));
  router.use('/agents/admin', requireRole('admin'));

  // ---- Admin agent endpoints ----------------------------------------------
  router.post('/agents/admin/session', agentSession.create);

  router.post('/agents/admin/chat', agentSession.requireOwned, async (req, res) => {
    const { sessionId, message } = req.body || {};
    if (!sessionId || !message) {
      return res.status(400).json({ error: 'sessionId and message required' });
    }
    await runChatTurn(req, res, {
      sessionId, message, agentSession, supervisor: adminSupervisor,
      provider, pool, manifest,
    });
  });

  // Recent trace for this admin's sessions — used by the Overview live-trace strip.
  // Registered BEFORE /agents/admin/trace/:sessionId so the "latest" literal
  // doesn't get caught as a session id.
  router.get('/agents/admin/trace/latest', async (req,res) => {
    const ownedRows=await agentSession.getLatestOwned(req,Math.max(1,Math.min(200,Number(req.query.limit)||20)),(owner)=>repo.latestTrace(owner));
    res.json({ok:true,count:ownedRows.length,rows:ownedRows});
  });

  router.get('/agents/admin/trace/:sessionId', agentSession.requireOwned, async (req,res) => {
    res.json({session_id:req.params.sessionId,rows:await repo.trace(req.params.sessionId)});
  });

  // ---- Overview: aggregated KPIs, db sizes, agent-host proxy --------------
  router.get('/admin/overview/kpis',async(req,res)=>res.json(await repo.kpis()));

  router.get('/admin/agent-host/health', async (req, res) => {
    const r = await _fetchJson(`http://127.0.0.1:${AGENT_HOST_PORT}/health`);
    if (!r.ok) return res.json({ ok: false, status: 'OFFLINE', port: AGENT_HOST_PORT, error: r.error || `status ${r.status}` });
    const agents = (r.body && (r.body.agents || r.body.agent_count)) || null;
    res.json({ ok: true, status: 'ONLINE', port: AGENT_HOST_PORT, agents, raw: r.body });
  });

  router.get('/admin/provider-state',async(req,res)=>{const rows=await repo.providerState();res.json({ok:true,count:rows.length,providers:rows});});
  router.get('/admin/db-sizes',async(req,res)=>res.json({ok:true,engine:'postgres',files:await repo.sizes()}));

  // ---- Admin REST surface --------------------------------------------------

  // Paged, searchable users. Preserves the /admin/users unpaginated shape when
  // no query is supplied so old callers keep working.
  router.get('/admin/users',async(req,res)=>{
    const page=Math.max(1,Math.floor(Number(req.query.page)||1)),pageSize=Math.max(1,Math.min(100,Math.floor(Number(req.query.pageSize)||25)));
    const paginated=Boolean(req.query.search||req.query.role||req.query.banned||req.query.page||req.query.pageSize);
    const {rows,total}=await repo.users({search:String(req.query.search||'').trim(),role:req.query.role?String(req.query.role):null,banned:req.query.banned,page,pageSize,paginated});
    res.json(paginated?{ok:true,users:rows,total,count:rows.length,page,pageSize,pages:Math.max(1,Math.ceil(total/pageSize))}:{users:rows,count:rows.length});
  });

  router.post('/admin/users/lookup', async (req, res) => {
    const { lookup } = require('../../../../agent-host/agents/user-management/tools/index.js');
    // Accept both { username } and { lookup } for backwards-compat.
    const username = req.body?.username ?? req.body?.lookup;
    res.json(await lookup({ username }));
  });

  router.post('/admin/users/:id/role', async (req, res) => {
    const { setRole } = require('../../../../agent-host/agents/user-management/tools/index.js');
    const user_id = Number(req.params.id);
    const role = req.body?.role;
    res.json(await setRole({ user_id, role }));
  });

  router.post('/admin/users/:id/ban', async (req, res) => {
    const { ban } = require('../../../../agent-host/agents/user-management/tools/index.js');
    const user_id = Number(req.params.id);
    res.json(await ban({ user_id, reason: req.body?.reason }));
  });

  router.post('/admin/users/:id/reset-password', async (req, res) => {
    const { resetPassword } = require('../../../../agent-host/agents/user-management/tools/index.js');
    res.json(await resetPassword({ user_id: Number(req.params.id) }));
  });

  // ---- Audit --------------------------------------------------------------
  router.get('/admin/audit', async (req, res) => {
    const { recent_events } = require('../../../../agent-host/agents/audit/tools/index.js');
    const limit = req.query.limit ? Number(req.query.limit) : 50;
    // If no filters, keep the old shape for compatibility.
    const actor = req.query.actor ? String(req.query.actor) : null;
    const action = req.query.action ? String(req.query.action) : null;
    const target = req.query.target ? String(req.query.target) : null;
    const q = req.query.q ? String(req.query.q) : null;
    const from = req.query.from ? String(req.query.from) : null;
    const to = req.query.to ? String(req.query.to) : null;

    if (!actor && !action && !target && !q && !from && !to) {
      return res.json(await recent_events({ limit }));
    }

    const rows=await repo.audit({actor,action,target,q,from,to,limit:Math.max(1,Math.min(5000,limit||50))});
    res.json({ok:true,count:rows.length,events:rows});
  });

  router.post('/admin/audit/search', async (req, res) => {
    const { search_by_user } = require('../../../../agent-host/agents/audit/tools/index.js');
    res.json(await search_by_user({ username: req.body?.username }));
  });

  // Alias per plan spec — /audit/search-by-user
  router.post('/admin/audit/search-by-user', async (req, res) => {
    const { search_by_user } = require('../../../../agent-host/agents/audit/tools/index.js');
    res.json(await search_by_user({ username: req.body?.username }));
  });

  router.post('/admin/audit/summarize', async (req, res) => {
    const { summarize_anomalies } = require('../../../../agent-host/agents/audit/tools/index.js');
    const limit = req.body?.limit ? Number(req.body.limit) : 200;
    res.json(await summarize_anomalies({ limit }));
  });

  // Alias per plan spec — /audit/summarize-anomalies
  router.post('/admin/audit/summarize-anomalies', async (req, res) => {
    const { summarize_anomalies } = require('../../../../agent-host/agents/audit/tools/index.js');
    const limit = req.body?.limit ? Number(req.body.limit) : 200;
    res.json(await summarize_anomalies({ limit }));
  });

  // ---- Policies -----------------------------------------------------------
  router.get('/admin/policies',async(req,res)=>{
    const rows=await repo.policies();
    const augmented=rows.map(r=>({...r,poisoned:/SYSTEM:|\[HIDDEN\]|DV-AI\{|process\.mainModule|\{\{\s*constructor/i.test(r.markdown_source||'')}));
    res.json({policies:augmented,count:augmented.length});
  });

  // Create-or-update via POST /admin/policies (name in body).
  router.post('/admin/policies', async (req, res) => {
    const { update_policy } = require('../../../../agent-host/agents/policy/tools/index.js');
    const { name, markdown, injected_into } = req.body || {};
    if (!name) return res.status(400).json({ ok: false, error: 'name required' });
    const r = await update_policy({ name, markdown });
    // If caller supplied injected_into, patch the row after render.
    if (Array.isArray(injected_into)) {
      await repo.setPolicyTargets(name,injected_into);
    }
    res.json(r);
  });

  // Legacy alias — POST /admin/policies/:name (body: markdown)
  router.post('/admin/policies/:name', async (req, res) => {
    const { update_policy } = require('../../../../agent-host/agents/policy/tools/index.js');
    const markdown = req.body?.markdown;
    res.json(await update_policy({ name: req.params.name, markdown }));
  });

  // PUT /admin/policies/:name — same behavior as POST /:name, alias for REST clients.
  router.put('/admin/policies/:name', async (req, res) => {
    const { update_policy } = require('../../../../agent-host/agents/policy/tools/index.js');
    const markdown = req.body?.markdown;
    res.json(await update_policy({ name: req.params.name, markdown }));
  });

  router.delete('/admin/policies/:name',async(req,res)=>{
    const info=await repo.deletePolicy(req.params.name);res.json({ok:info.changes>0,name:req.params.name,removed:info.changes});
  });

  // Test-render — runs the unsafe Nunjucks env WITHOUT persisting. SSTI fires
  // here too. Returned separately so the UI can preview poisoned templates.
  router.post('/admin/policies/:name/render', async (req, res) => {
    let renderTemplateUnsafe;
    try {
      ({ renderTemplateUnsafe } = require('../../../../agent-host/agents/listing/tools/_nunjucksSink.js'));
    } catch (e) {
      return res.status(500).json({ ok: false, error: 'nunjucks sink unavailable: ' + e.message });
    }
    const raw = String(req.body?.markdown ?? '');
    try {
      const rendered = renderTemplateUnsafe(raw, {
        store_name: 'SecureShop',
        current_year: new Date().getFullYear(),
        policy_name: req.params.name,
      });
      res.json({ ok: true, name: req.params.name, rendered, rendered_length: rendered.length });
    } catch (e) {
      res.json({ ok: false, name: req.params.name, error: e.message });
    }
  });

  // ---- MCP registry -------------------------------------------------------
  router.get('/admin/mcp/servers', async (req, res) => {
    const { list_servers } = require('../../../../agent-host/agents/mcp-registry/tools/index.js');
    res.json(await list_servers());
  });

  router.get('/admin/mcp/servers/:name/tools', async (req, res) => {
    const { describe_tools } = require('../../../../agent-host/agents/mcp-registry/tools/index.js');
    res.json(await describe_tools({ name: req.params.name }));
  });

  router.get('/admin/mcp/history', async (req, res) => {
    const { get_schema_history } = require('../../../../agent-host/agents/mcp-registry/tools/index.js');
    res.json(await get_schema_history({ name: req.query.name || null }));
  });

  // Alias per plan spec — /mcp/schema-history
  router.get('/admin/mcp/schema-history', async (req, res) => {
    const { get_schema_history } = require('../../../../agent-host/agents/mcp-registry/tools/index.js');
    res.json(await get_schema_history({ name: req.query.name || null }));
  });

  router.post('/admin/mcp/register', async (req, res) => {
    const { register } = require('../../../../agent-host/agents/mcp-registry/tools/index.js');
    try {
      const r = await register(req.body || {});
      res.json(r);
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  router.delete('/admin/mcp/:name', async (req, res) => {
    const { remove } = require('../../../../agent-host/agents/mcp-registry/tools/index.js');
    res.json(await remove({ name: req.params.name }));
  });

  router.post('/admin/mcp/import', async (req, res) => {
    const { import_manifest } = require('../../../../agent-host/agents/mcp-registry/tools/index.js');
    try { res.json(await import_manifest(req.body || {})); }
    catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  // Alias per plan spec — /mcp/import-manifest
  router.post('/admin/mcp/import-manifest', async (req, res) => {
    const { import_manifest } = require('../../../../agent-host/agents/mcp-registry/tools/index.js');
    try { res.json(await import_manifest(req.body || {})); }
    catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  // ---- System -------------------------------------------------------------
  router.get('/admin/system/health', async (req, res) => {
    const { health_check } = require('../../../../agent-host/agents/system/tools/index.js');
    res.json(await health_check());
  });

  router.post('/admin/system/diagnostic', async (req, res) => {
    const { run_diagnostic } = require('../../../../agent-host/agents/system/tools/index.js');
    try { res.json(await run_diagnostic(req.body || {})); }
    catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  router.post('/admin/system/restart', async (req, res) => {
    const { restart_service } = require('../../../../agent-host/agents/system/tools/index.js');
    try { res.json(await restart_service(req.body || {})); }
    catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  // Alias per plan spec — /system/restart-service
  router.post('/admin/system/restart-service', async (req, res) => {
    const { restart_service } = require('../../../../agent-host/agents/system/tools/index.js');
    try { res.json(await restart_service(req.body || {})); }
    catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  router.post('/admin/system/read-config', async (req, res) => {
    const { read_config } = require('../../../../agent-host/agents/system/tools/index.js');
    res.json(await read_config({ path: req.body?.path }));
  });

  // Vector index rebuild — thin wrapper that enqueues a background job so the
  // Admin System page can trigger corpus rebuilds. Returns the job id + a
  // synchronous count of vector_documents for the corpus. Real rebuild
  // machinery lives in server/services/secureshop; we just record intent.
  router.post('/admin/system/rebuild-index', async (req, res) => {
    const corpus = String(req.query.corpus || req.body?.corpus || '').trim();
    if (!corpus) return res.status(400).json({ ok: false, error: 'corpus required' });
    const jobId=`rebuild_${corpus}_${require('node:crypto').randomUUID()}`;
    const count=await repo.enqueueRebuild(jobId,corpus);
    res.json({ok:true,corpus,job_id:jobId,current_vector_count:count,status:'enqueued'});
  });

  // ---- Auth-bypass surface (JWT alg=none accepted) ------------------------
  // Wave 5A F3 — the /admin/sign endpoint was deleted. It minted arbitrary
  // HS256 JWTs (any username, any role) for any caller who could POST to it.
  // It had no legitimate consumer in the codebase and combined with the
  // origin: true CORS to form a trivial cross-origin token-forgery service.
  // Students who need a valid admin token can obtain one via the normal
  // /api/secureshop/v2/auth/login flow with student_a / student123.
  //
  // /admin/whoami is intentionally REGISTERED ABOVE the requireRole middleware
  // so that unauthenticated attackers can still reach the alg=none sink. See
  // the block near the top of buildRouter.

  // ---- M14 Access Control (RBAC administration) ---------------------------
  // Admin-only endpoints for viewing / editing the tool_permissions matrix
  // and toggling the SS_ENFORCE_TOOL_ACL system flag.

  router.get('/admin/access-control', async (req, res) => {
    // Group permissions by tool_name for a compact matrix view.
    const rows = await listAllPermissions();
    const byTool = new Map();
    for (const r of rows) {
      if (!byTool.has(r.tool_name)) {
        byTool.set(r.tool_name, { tool_name: r.tool_name, customer: 0, merchant: 0, admin: 0 });
      }
      byTool.get(r.tool_name)[r.role] = r.allowed;
    }
    res.json({
      ok: true,
      enforcement_enabled: await isEnforcementEnabled(),
      tools: [...byTool.values()].sort((a, b) => a.tool_name.localeCompare(b.tool_name)),
      count: byTool.size,
    });
  });

  router.post('/admin/access-control/permission', async (req, res) => {
    const { tool_name, role, allowed } = req.body || {};
    if (!tool_name || !role) return res.status(400).json({ ok: false, error: 'tool_name and role required' });
    if (!['customer', 'merchant', 'admin'].includes(role)) {
      return res.status(400).json({ ok: false, error: 'role must be customer|merchant|admin' });
    }
    const r = await setPermission(tool_name, role, !!allowed);
    return res.json(r);
  });

  router.post('/admin/access-control/enforcement', async (req, res) => {
    const { enabled } = req.body || {};
    const r = await setEnforcement(!!enabled, req.ssUser?.username || 'admin');
    return res.json(r);
  });

  return router;
};
