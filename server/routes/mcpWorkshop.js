const {ownerWorkflowRoute,checkOwnerRun,getOwnerExecution,withOwnerExecution} = require('../agent-runtime/ownerWorkflowRoutes');
const ownerRuns = require('../agent-runtime/runCoordinator').createRunCoordinator({family:'MCP',
  defaultTimeoutMs:require('../services/mcp/timing').createMcpTiming().runTimeoutMs});
/**
 * MCP Vulnerable Server Workshop — routes
 * =========================================
 * Exposes a real MCP server (Streamable HTTP) with an intentional command-injection
 * vulnerability in the run_safe_command tool. Students learn to exploit weak
 * first-token validation via chaining operators.
 */

const express = require('express');
const router = express.Router();
const requirePlatformAuthority = process.env.PLATFORM_DATABASE_ENGINE === 'postgres'
  ? require('../middleware/workshopPlatformAuthority').createWorkshopPlatformAuthority({
    authenticateToken: require('../middleware/adminAuth').authenticateToken,
  }) : null;
const { syncObjectiveComplete, checkAndMarkWorkshopComplete, resetWorkshopProgress, syncWorkshopStarted, getUserWorkshopProgress } = require('../utils/progressSync');
const mcpWorkshopDb = require('../database/mcpWorkshopDb');
const mcpSandbox = require('../services/mcp/sandboxShell');
const mcpAgent = require('../services/mcp/workshopAgent');
const aiService = require('../services/multiProviderAIService');
const sandboxRunner = require('../services/mcp/sandboxRunnerClient');
const mailClient = require('../services/mcp/mailClient');
const mcpConfig = require('../services/mcp/config');
const probes = require('../services/mcp/_probes');
const ecsMetadata = require('../services/mcp/ecsMetadata');
const { createWorkshopConfigService } = require('../services/workshopConfigService');
const { createMcpObjectiveGrader } = require('../services/mcpObjectiveGrader');
const mcpProtocol = require('../services/mcp/sdk/sessionManager');
const mcpRegistry = require('../services/mcp/toolRegistry');
const { createDisabledMcpOwnedResourceApplication } = require('../services/mcp/ownedResourceApplication');
const { createMcpResourceRepository } = require('../database/postgres/mcpResourceRepository');
const { QUALIFICATION_VERSION, QUALIFIED_OBJECTIVES, isProductionQualification } = require('../services/mcp/ownedQualification');
const { createWorkshopModeHandlers } = require('../services/workshopModeHandlers');
const { createWorkshopModeRunAuthority } = require('../services/workshopModeRunAuthority');

const WORKSHOP_KEY = 'mcp_workshop';
const TOTAL_OBJECTIVES = 11;
const workshopConfig = createWorkshopConfigService();
let objectiveGrader = createMcpObjectiveGrader({ syncObjectiveComplete });
let progressProjector = (...args) => markNativeProgress(...args);
let ownedResources = createDisabledMcpOwnedResourceApplication();
let conversationPersistence = null;
let protectedRecovery = null;
let modeService = require('../services/workshopModeService');
let modeScopeReader = async (userId, workshopKey) => mcpWorkshopDb.engine === 'postgres'
  ? require('../services/postgresPlatformStores').getPostgresPlatformStores().progress.getEvaluationScope(userId, workshopKey)
  : { generation: 0, mode: null, modeStamp: 'default' };
const modeAuthority = createWorkshopModeRunAuthority({ workshopKey: WORKSHOP_KEY,
  readScope: (userId, workshopKey) => modeScopeReader(userId, workshopKey) });

// 11 distinct MCP attack techniques (1:1 with the objective cards in the UI).
const OBJECTIVES = [
  'mcp_recon',              // capability discovery via natural language
  'mcp_cmd_injection',      // escape the "safe command" allowlist
  'mcp_ssrf',               // fetch_url reaches an internal-only service
  'mcp_tool_poisoning',     // hidden instruction in a tool description
  'mcp_indirect_injection', // poisoned support ticket hijacks the agent
  'mcp_confused_deputy',    // talk the bot into couriering secrets out
  'mcp_broken_authz',       // invoke an admin-only tool without admin rights
  'mcp_secret_exposure',    // tool hands back live tokens/keys in plaintext
  'mcp_supply_chain',       // install a tampered plugin/dependency
  'mcp_audit_gap',          // disable/clear the audit trail unnoticed
  'mcp_shadow_server',      // register an unapproved/rogue MCP server
];

async function getVisibleMcpObjectiveIds() {
  const exercise = (await workshopConfig.getSnapshot()).exercises[WORKSHOP_KEY];
  if (exercise?.isVisible !== true) return new Set();
  return new Set(OBJECTIVES.filter(id => exercise.objectives?.[id]?.isVisible === true));
}

function getUserId(req) {
  return req.user?.id || (requirePlatformAuthority ? null : req.session?.userId) || null;
}

function requireWorkshopUser(req, res, next) {
  if (requirePlatformAuthority) return requirePlatformAuthority(req, res, next);
  const uid = getUserId(req);
  if (!uid) return res.status(401).json({ error: 'login_required' });
  next();
}

function requireSupportedOwnedRuntime(req, res, next) {
  if (mcpWorkshopDb.engine === 'postgres' && ownedResources.enabled !== true) {
    return res.status(503).json({ error: 'MCP_OWNED_RESOURCES_UNAVAILABLE',
      message: 'The MCP exercise runtime is unavailable.' });
  }
  next();
}

function rejectPostgresListener(req, res, next) {
  if (mcpWorkshopDb.engine === 'postgres') {
    return res.status(503).json({ error: 'MCP_OWNED_RESOURCES_UNAVAILABLE',
      message: 'The MCP exercise runtime is unavailable.' });
  }
  next();
}

// Called only inside this family's durable owner reset/drain fence. Disabled
// execution is not proof of absence: inspect all owner resource ledgers first.
async function retirePostgresOwnerResources(owner, { check, request } = {}) {
  const platformOwnerId = Number(owner);
  if (!Number.isSafeInteger(platformOwnerId) || platformOwnerId < 1 || platformOwnerId > 2147483647
      || String(platformOwnerId) !== String(owner) || typeof check !== 'function') {
    throw new TypeError('Exact MCP retirement owner and authority required');
  }
  await check();
  const repository = createMcpResourceRepository(await mcpWorkshopDb.runtimePool());
  const proveRetired = async () => {
    await check();
    const proof = await repository.assertOwnerResourcesRetired({ platformOwnerId });
    await check();
    if (proof?.status !== 'retired' || proof.platformOwnerId !== platformOwnerId
        || !Number.isSafeInteger(proof.targetCount) || proof.targetCount < 0
        || !Number.isSafeInteger(proof.mailIntentCount) || proof.mailIntentCount < 0) {
      throw new Error('MCP resource retirement proof is invalid');
    }
    return proof;
  };
  let priorProof;
  try { priorProof = await proveRetired(); }
  catch (error) { if (error.code !== 'MCP_OWNER_RESOURCES_PENDING') throw error; }
  // Enabled applications must still validate the genuine reset authority and
  // retire process-local protocol/debt state, even after durable cleanup.
  if (ownedResources.enabled !== true && priorProof) return priorProof;
  const retirementMethod = request ? 'reset' : 'retireOwner';
  if (ownedResources.enabled !== true || typeof ownedResources[retirementMethod] !== 'function') {
    throw Object.assign(new Error('The MCP exercise resources cannot be retired while its runtime is unavailable.'),
      { code: 'MCP_OWNED_RESOURCES_UNAVAILABLE', statusCode: 503 });
  }
  await check();
  const retired = request ? await ownedResources.reset(request, { check })
    : await ownedResources.retireOwner({ platformOwnerId, check });
  await check();
  if (retired?.ok !== true || !Array.isArray(retired.receipts)) {
    throw new Error('MCP owned resource retirement is incomplete');
  }
  return proveRetired();
}

function reconcileProgress(rows, canonicalRows, visibleObjectiveIds, localAvailable = true) {
  const local = new Set((rows || []).filter(row => row.completed).map(row => row.objective_id));
  const completed = (canonicalRows || [])
    .filter(row => row.workshop_key === WORKSHOP_KEY && row.completed && visibleObjectiveIds.has(row.objective_id))
    .map(row => row.objective_id);
  return { completed, projectionPending: localAvailable ? completed.filter(id => !local.has(id)) : [], projectionUnavailable: !localAvailable };
}

// ── LLM status ────────────────────────────────────────────────────────
router.get('/llm-status', async (_req, res) => {
  try {
    const available = await aiService.checkOllamaAvailable();
    res.json({ available, provider: 'multiProvider' });
  } catch {
    res.json({ available: false, provider: 'multiProvider' });
  }
});

// ── Lab infrastructure (sidecar topology + live status) ───────────────
// Dynamic: endpoints come from the same env-driven config the tools use, so
// this reflects the ACTUAL deployment (localhost sidecars locally, the shared
// task-netns addresses on AWS Fargate). Students see what's wired, whether each
// backend is up. Owned-runtime capability and live readiness are reported
// separately from catalog visibility; unavailable effects cannot earn credit.

router.get('/infra', requireWorkshopUser, async (req, res) => {
  if (mcpWorkshopDb.engine === 'postgres' && ownedResources.enabled !== true) {
    return res.json({ mode: 'unavailable', note: 'The MCP exercise runtime is unavailable.',
      environment: await ecsMetadata.getEnvironment().catch(() => ({ platform: 'local', label: 'Local' })),
      supervisor: null, sidecars: [], runtimeQualification: { mode: 'qualified_subset',
        version: 'mcp-owned-runtime-unavailable', qualifiedObjectives: [] } });
  }
  if (ownedResources.enabled) {
    try {
      const readiness = await ownedResources.readiness();
      const qualifiedObjectives = [...ownedResources.qualification.qualifiedObjectives];
      const runnerObjectives = [
        ['mcp_cmd_injection', 'Command Injection'], ['mcp_broken_authz', 'Broken Authorization'],
        ['mcp_secret_exposure', 'Secret Exposure'], ['mcp_audit_gap', 'Audit Gap'],
        ['mcp_tool_poisoning', 'Tool Poisoning'], ['mcp_indirect_injection', 'Indirect Injection'],
        ['mcp_supply_chain', 'Supply Chain'],
      ].filter(([id]) => qualifiedObjectives.includes(id)).map(([, label]) => label);
      const mailObjectives = [
        ['mcp_confused_deputy', 'Confused Deputy'], ['mcp_indirect_injection', 'Indirect Injection'],
      ].filter(([id]) => qualifiedObjectives.includes(id)).map(([, label]) => label);
      const sidecars = [
        { key: 'owned-sandbox-runner', name: 'Owner-isolated Sandbox Runner', url: readiness.runnerEndpoint,
          up: readiness.runnerReady === true, isolation: readiness.runnerIsolation || null,
          role: 'Provides isolated tool effects for the listed runtime-qualified exercises inside their exact owner/session/generation target.',
          objectives: runnerObjectives },
        { key: 'owned-mailpit', name: 'Owner-bound Mail Sink (Mailpit)', url: mcpConfig.MAILPIT_API_URL,
          up: readiness.mailReady === true, smtp: `${mcpConfig.MAILPIT_SMTP_HOST}:${mcpConfig.MAILPIT_SMTP_PORT}`,
          role: 'Captures and verifies full messages through durable owner-bound mail intents for the listed delivery exercises.',
          objectives: mailObjectives },
      ];
      const remaining = Math.max(0, OBJECTIVES.length - qualifiedObjectives.length);
      return res.json({ mode: readiness.ready === true ? 'real' : 'unavailable',
        note: readiness.ready === true
          ? `Qualified subset ready: ${qualifiedObjectives.length} exercises use owner-isolated effects and durable evidence. The other ${remaining} catalog objectives remain visible but unavailable in this runtime until their own targets are qualified.`
          : 'The configured owner-isolated MCP runtime is currently unavailable. Its qualified capabilities cannot execute or score until database, runner, conversation and mail readiness checks pass.',
        environment: await ecsMetadata.getEnvironment().catch(() => ({ platform: 'local', label: 'Local' })),
        supervisor: null, sidecars,
        runtimeQualification: { mode: 'qualified_subset', version: ownedResources.qualification.version,
          qualifiedObjectives } });
    } catch {
      return res.json({ mode: 'unavailable',
        note: 'The owner-isolated MCP runtime is unavailable. No qualified effect can run or score until its runner, database, and mail readiness checks pass.',
        environment: await ecsMetadata.getEnvironment().catch(() => ({ platform: 'local', label: 'Local' })),
        supervisor: null, sidecars: [],
        runtimeQualification: { mode: 'qualified_subset', version: ownedResources.qualification.version,
          qualifiedObjectives: [...ownedResources.qualification.qualifiedObjectives] } });
    }
  }
  const mailApi = mcpConfig.MAILPIT_API_URL;
  const [runner, ssrf, rogue, mail] = await Promise.all([
    sandboxRunner.health().then(h => !!(h && h.ok)).catch(() => false),
    probes.http(`${mcpConfig.SSRF_TARGET_URL}/health`),
    probes.http(`${mcpConfig.ROGUE_MCP_URL}/health`),
    probes.http(`${mailApi}/api/v1/messages?limit=1`),
  ]);
  const runnerHealth = await sandboxRunner.health().catch(() => ({}));
  const environment = await ecsMetadata.getEnvironment().catch(() => ({ platform: 'local', label: 'Local' }));
  const onAws = environment.platform === 'aws-fargate';
  // Env-aware explainer for the loopback address: on AWS the sidecars share the
  // Fargate task's network namespace, so the app reaches them over the task
  // loopback (127.0.0.1) — there is no separate per-sidecar IP. Locally the
  // ports are published on the host. Either way the address shown is the REAL
  // path the app uses.
  const netNote = onAws
    ? 'Runs inside this Fargate task; the app reaches it over the shared task loopback (127.0.0.1) — you never connect to it directly.'
    : 'Published on your host by docker-compose.';
  const downNote = 'When DOWN, the related exploit returns an honest "backend unreachable" error and does NOT score.';
  const sidecars = [
    {
      key: 'sandbox-runner', name: 'Isolated Sandbox Runner', url: mcpConfig.SANDBOX_RUNNER_URL, netNote,
      up: runner, isolation: runnerHealth && runnerHealth.isolation ? runnerHealth.isolation : null,
      role: `Executes the run_command / read_file / key-rotation / plugin-postinstall calls for real, as a non-root user inside an isolated container. ${downNote}`,
      objectives: ['Command Injection', 'Tool Poisoning', 'Broken Authorization', 'Supply Chain'],
    },
    {
      key: 'ssrf-target', name: 'Internal SSRF Target', url: mcpConfig.SSRF_TARGET_URL, netNote,
      up: ssrf,
      role: `Stands in for the cloud metadata service (169.254.169.254) and internal-only admin APIs that fetch_url reaches. Also the collector the supply-chain postinstall couriers stolen env to. ${downNote}`,
      objectives: ['SSRF via fetch_url', 'Supply Chain'],
    },
    {
      key: 'rogue-mcp', name: 'Rogue MCP Server', url: mcpConfig.ROGUE_MCP_URL, netNote,
      up: rogue,
      role: `A real second MCP server the app connects to when you register an unapproved endpoint — the client completes a genuine tools/list handshake and imports its (attacker-controlled) tools. ${downNote}`,
      objectives: ['Shadow MCP Server'],
    },
    {
      key: 'mailpit', name: 'Mail Sink (Mailpit)', url: mailApi, netNote,
      up: !!mail, smtp: `${mcpConfig.MAILPIT_SMTP_HOST}:${mcpConfig.MAILPIT_SMTP_PORT}`,
      role: `Catches the real emails the assistant is tricked into sending (confused-deputy and indirect-injection exfil), so the delivered message is inspectable. ${downNote}`,
      objectives: ['Confused Deputy', 'Indirect Injection'],
    },
  ];
  const upCount = sidecars.filter(s => s.up).length;
  const mode = upCount === sidecars.length ? 'real'
    : upCount > 0 ? 'degraded'
    : 'unavailable';
  const envPhrase = onAws
    ? `Running on ${environment.label}${environment.region ? ` (${environment.region})` : ''} — the 4 sidecars are containers in the same task, reached over the task loopback (127.0.0.1:PORT).`
    : `Running ${environment.label} — the 4 sidecars are on 127.0.0.1:PORT.`;
  const notes = {
    real: `Real-execution mode: every exploit hits genuine isolated backends (real files, real sockets, real SMTP). ${envPhrase}`,
    degraded: 'Partial: some backends are up. Exploits whose backend is down return an honest error and do not score until it is reachable.',
    unavailable: 'Backends are down — exploit tools return an honest "backend unreachable" error and DO NOT score. The sidecars auto-start with the app via docker compose; start Docker (on AWS they run as task containers).',
  };
  const supervisor = req.app.locals.mcpSidecars ? req.app.locals.mcpSidecars.describe() : null;
  res.json({ mode, note: notes[mode], environment, supervisor, sidecars });
});

// ── Tool catalog (reference panel; does NOT mark recon) ───────────────
router.get('/tools', requireWorkshopUser, requireSupportedOwnedRuntime, async (req, res) => {
  try {
    const owned = ownedResources.enabled ? await ownedResources.readOnly(req) : null;
    const sandbox = owned ? owned.sandbox : mcpSandbox.getOrCreateSandbox(`mcp_${getUserId(req)}`);
    res.json({ tools: mcpRegistry.catalogFor(sandbox)
      .map(({ name, description, inputSchema }) => ({ name, description, inputSchema })) });
  } catch (error) {
    res.status(error.statusCode || 503).json({ error: error.code || 'MCP_OWNED_RESOURCES_UNAVAILABLE' });
  }
});

// ── MCP Streamable HTTP endpoint ──────────────────────────────────────
// Mutation-capable POST/DELETE traffic is admitted through the owner run. GET
// only attaches an authenticated event stream to the latest initialized
// generation; it cannot invoke a tool and therefore does not hold a mutation
// lease. Retirement closes that generation's transport and its streams.
router.all('/mcp', requireWorkshopUser, requireSupportedOwnedRuntime, async (req, res) => {
  if (req.method === 'GET') {
    try {
      const owned = await ownedResources.readOnly(req);
      const manager = owned?.protocol || mcpProtocol;
      return await manager.handleReadOnlyHttp(`mcp_${getUserId(req)}`, req, res, { ownerId: owned?.ownerId || getUserId(req) });
    } catch (error) { return res.status(error.statusCode || (error.code === 'MCP_PROTOCOL_SESSION_REQUIRED' ? 409 : 500)).json({ error: error.message }); }
  }
  const userId = getUserId(req);
  const sessionId = `mcp_${userId}`;
  const controller = new AbortController();
  const abort = () => controller.abort(Object.assign(new Error('MCP client disconnected'), { name: 'AbortError' }));

  try {
    req.once('aborted', abort);
    await ownerRuns.run(String(userId), { signal: controller.signal }, execution =>
      withOwnerExecution(execution, async () => {
        const owned = await ownedResources.admitChat(req, execution);
        return (owned?.protocol || mcpProtocol).handleHttp(sessionId, req, res, { execution:owned?.execution||execution,
          actor: { platformRole: req.user?.role || (requirePlatformAuthority ? undefined : req.session?.role), labRole: 'operator' } });
      }));
  } catch (err) {
    if (err.code === 'GRAPH_RUN_CAPACITY_EXCEEDED') {
      if (!res.headersSent) res.status(503).json({error:'Agent capacity is unavailable.',code:'GRAPH_RUN_CAPACITY_EXCEEDED'});
      return;
    }
    console.error('[MCP Workshop] Transport error:', err.message);
    if (!res.headersSent) {
      res.status(500).json({ error: 'MCP transport error', message: err.message });
    }
  } finally {
    req.removeListener('aborted', abort);
  }
});

// ── JSON-RPC convenience endpoint (for Inspector tab) ─────────────────
router.post('/jsonrpc', requireWorkshopUser, requireSupportedOwnedRuntime, ownerWorkflowRoute(ownerRuns, req => String(getUserId(req)), async (req, res) => {
  const userId = getUserId(req);
  const sessionId = `mcp_${userId}`;
  const { method, params, id: rpcId } = req.body;

  if (!method) {
    return res.status(400).json({ jsonrpc: '2.0', error: { code: -32600, message: 'Missing method' }, id: rpcId || null });
  }

  try {
    const execution = getOwnerExecution();
    const owned = await ownedResources.admitChat(req, execution);
    const sandbox = owned?.sandbox || mcpSandbox.getOrCreateSandbox(sessionId);
    const manager = owned?.protocol || mcpProtocol;
    const admittedExecution = owned?.execution || execution;
    let result;

    if (method === 'tools/list') {
      result = { tools: await manager.listTools(sessionId, { execution:admittedExecution, surface: 'inspector',
        actor: { platformRole: req.user?.role || (requirePlatformAuthority ? undefined : req.session?.role), labRole: 'operator' } }) };
      // NOTE: The Inspector is exploration-only. It deliberately does NOT score
      // objectives — recon (and every other technique) is completed exclusively
      // by prompting the MCP Assistant in the chat tab.

    } else if (method === 'tools/call') {
      const toolName = params?.name;
      const toolArgs = params?.arguments || {};

      const exec = await manager.callTool(sessionId, String(toolName || ''), toolArgs, {
        execution:admittedExecution, surface: 'inspector', effectKey: `mcp_inspector_${String(rpcId ?? 'call')}`,
        actor: { platformRole: req.user?.role || (requirePlatformAuthority ? undefined : req.session?.role), labRole: 'operator' },
      });
      const output = exec.error || exec.output || '(no output)';
      result = { content: [{ type: 'text', text: String(output) }], isError: Boolean(exec.blocked || exec.error) };

    } else if (method === 'resources/list') {
      result = {
        resources: [
          { name: 'server-readme', uri: 'mcp://acme-ops/readme', mimeType: 'text/plain', description: 'Server documentation' },
          { name: 'allowlist-policy', uri: 'mcp://acme-ops/policy/allowlist', mimeType: 'text/plain', description: 'Command allowlist security policy' },
        ],
      };

    } else if (method === 'resources/read') {
      const uri = params?.uri || '';
      if (uri.includes('readme')) {
        // Derived from the REAL tool catalog so it can never drift from reality.
        const tools = mcpRegistry.catalogFor(sandbox);
        const toolLines = tools.map(t => `- ${t.name}: ${t.description.split('\n')[0]}`).join('\n');
        const text = `ACME Ops MCP Server v1.3.0\n\nAvailable tools (${tools.length}):\n${toolLines}\n\nSecurity: run_command validation checks only the first token against the allowlist.\n`;
        result = { contents: [{ uri, text, mimeType: 'text/plain' }] };
      } else if (uri.includes('allowlist')) {
        const permitted = [...mcpSandbox.ADVERTISED_ALLOWLIST].join(', ');
        const text = `Command Allowlist Policy\n\nPermitted first tokens: ${permitted}\nValidation: first-token extraction only\nKnown limitation: chained commands (; && |) are not re-validated.\n`;
        result = { contents: [{ uri, text, mimeType: 'text/plain' }] };
      } else {
        result = { contents: [] };
      }

    } else {
      return res.json({ jsonrpc: '2.0', error: { code: -32601, message: `Method not found: ${method}` }, id: rpcId || null });
    }

    res.json({ jsonrpc: '2.0', result, id: rpcId || null });
  } catch (err) {
    console.error('[MCP Workshop] jsonrpc error:', err);
    res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: err.message }, id: rpcId || null });
  }
}, {reset:false}));

// ── AI Chat endpoint (MCP Assistant tab) ──────────────────────────────
// The bounded LangGraph loop retains each tool observation. The Judge grades
// the observation that produced each candidate, using durable completion gates.
async function performMcpConversationTurn({userId,message,history:conversationHistory,execution:ownerExecution=getOwnerExecution(),actor,sandbox=null,stateReader=null,protocolManager=null,objectiveObserver=null}) {
  if (!ownerExecution) throw new Error('Protected owner execution is required');
  const capturedMode = await modeAuthority.capture(userId, ownerExecution);
  const { mode } = capturedMode;
  const sessionId = `mcp_${userId}`;
    await syncWorkshopStarted(userId, WORKSHOP_KEY);

    // The durable completion service binds an attempt to this exact wrapper.
    // Capture its generation before any MCP tool can produce evidence.
    const gradingExecution = { ...ownerExecution, ownerId: String(userId), emit: ownerExecution.trace };
    const attempt = await objectiveGrader.begin(userId, gradingExecution);
    await capturedMode.check();

    const result = await mcpAgent.chat(userId, sessionId, message, [], {
      conversationHistory: mode === 'fixed' ? undefined : conversationHistory, actor, sandbox,
      mode, checkMode: capturedMode.check,
      ...(protocolManager ? {protocolManager} : {})});
    await capturedMode.check();
    const toolResult = result.toolResult;
    const outcome = (toolResult && toolResult.achieved && toolResult.objective) ? toolResult.objective : null;

    // Audit-gap consequence (genuine): once audit logging has been disabled via
    // set_audit_logging, tool calls are NO LONGER written to the activity log —
    // so an attacker's later actions leave no trace. The exception is the
    // disable/enable action itself, which we still surface so the UI can show
    // what happened. This makes the "no audit trail" objective observable.
    const auditObservations = result.toolObservations?.length ? result.toolObservations
      : [{toolUsed:result.toolUsed,toolResult,auditEnabled:(stateReader ? stateReader() : mcpSandbox.getSandboxState(sessionId)).auditEnabled!==false}];
    for (const observed of auditObservations) {
      for (const activity of activityRecordsForObservation(observed)) {
        if (activity.toolUsed && (observed.auditEnabled || activity.toolUsed === 'set_audit_logging')) {
          const value=activity.toolResult;
          await logToolCall(userId, activity.toolUsed, JSON.stringify(activity.args || {}),
            value?.error || value?.output || '', value?.achieved ? value.objective : null, Boolean(value && !value.error && !value.blocked));
        }
      }
    }

    // Judge only server-detected objectives currently enabled by the instructor.
    const visibleObjectiveIds = await getVisibleMcpObjectiveIds();
    const objectiveCandidates = qualifiedObjectiveCandidates(result.objectivesHit, visibleObjectiveIds);
    const judgments = [];
    const completedObjectives = [];
    const projectionPending = [];
    const sandboxState = stateReader ? stateReader() : mcpSandbox.getSandboxState(sessionId);
    const serverObservation = {
      auditEnabled: sandboxState.auditEnabled !== false,
      adminAuthorizationEnforced: false,
      deliveredExternalReports: (sandboxState.sentReports || []).filter(item => item.external && item.delivered).length,
      installedPlugins: [...(sandboxState.installedPlugins || [])],
      registeredServers: (sandboxState.registeredServers || []).map(item => item.url),
      shadowTools: (sandboxState.shadowTools || []).map(item => item.name),
      capturedListenerEntries: mcpSandbox.getListenerData(sessionId).length,
    };
    for (const objectiveId of objectiveCandidates) {
      await gradingExecution.check();
      await capturedMode.check();
      const observation = result.toolObservations?.find(item => item.objectivesHit?.includes(objectiveId));
      const gradingResult = observation ? { ...result, ...observation, response: result.response } : result;
      const objectiveEvidence = typeof objectiveObserver === 'function'
        ? await objectiveObserver({ objectiveId, result: gradingResult.toolResult }) : {};
      const grade = await objectiveGrader.evaluate({ userId, objectiveId, message, result: gradingResult, mode,
        execution: gradingExecution, attempt, serverObservation: { ...serverObservation, ...objectiveEvidence } });
      judgments.push(grade.judgment);
      if (grade.completed) {
        completedObjectives.push(objectiveId);
        try { await progressProjector(userId, objectiveId); }
        catch (error) {
          if (error?.name === 'AbortError') throw error;
          projectionPending.push(objectiveId);
          console.error('[MCP Workshop] accepted completion projection pending:', objectiveId, error.message);
        }
      }
      await gradingExecution.check();
    }
    if (completedObjectives.length > 0) {
      await checkAndMarkWorkshopComplete(userId, WORKSHOP_KEY, TOTAL_OBJECTIVES);
    }

    return {
      success: true,
      response: result.response,
      intent: result.intent,
      toolUsed: result.toolUsed,
      toolResult,
      outcome,
      // Existing clients consume objectivesHit as completions, so it now
      // contains only accepted durable grades. Candidates are diagnostic.
      objectivesHit: completedObjectives,
      objectiveCandidates,
      completedObjectives,
      projectionPending,
      judgments,
      // The configured provider name alone is not proof that a particular
      // model produced every decision/reply in this turn. Judge packets retain
      // actual provider provenance; this public field stays null until the
      // complete turn has one equally strong provenance receipt.
      model: null,
      assistantPersona: 'acme-ops-assistant',
    };
}

router.get('/mode', requireWorkshopUser, (req, res) =>
  createWorkshopModeHandlers({ workshopKey: WORKSHOP_KEY, modeService }).get(req, res));
router.post('/mode', requireWorkshopUser,
  ownerWorkflowRoute(ownerRuns, req => String(getUserId(req)), (req, res) =>
    createWorkshopModeHandlers({ workshopKey: WORKSHOP_KEY, modeService }).set(req, res), { reset: true }));

router.post('/protected-operations/reconcile', requireWorkshopUser, requireSupportedOwnedRuntime,
  require('../middleware/rateLimiter').generalRateLimiter,
  require('../services/mcp/protectedRecoveryRoute').createProtectedRecoveryHandler({getService:()=>protectedRecovery}));

router.post('/chat', requireWorkshopUser, requireSupportedOwnedRuntime, ownerWorkflowRoute(ownerRuns, req => String(getUserId(req)), async (req, res) => {
  if (conversationPersistence) {
    if (typeof req.body?.message !== 'string' || !req.body.message.trim()
        || Buffer.byteLength(req.body.message) > 16384
        || typeof req.body?.requestId !== 'string'
        || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(req.body.requestId)) {
      return res.status(400).json({ error: 'A bounded message and requestId are required for the owned conversation runtime' });
    }
  } else if (!req.body.message) return res.status(400).json({error:'message is required'});
  try {
    const execution = getOwnerExecution();
    const admission = await ownedResources.admitChat(req, execution);
    const admittedExecution = admission?.execution || execution;
    const perform = history => performMcpConversationTurn({userId:getUserId(req),message:req.body.message,
      history, execution:admittedExecution, sandbox:admission?.sandbox, protocolManager:admission?.protocol,
      stateReader: typeof admission?.state==='function' ? admission.state : null,
      objectiveObserver: typeof admission?.observeObjective==='function' ? admission.observeObjective : null,
      actor:{platformRole:req.user?.role || (requirePlatformAuthority ? undefined : req.session?.role),labRole:'operator'}});
    if (conversationPersistence) {
      const requestId = String(req.body.requestId || '').toLowerCase();
      return res.json(await conversationPersistence.service.execute({ userId: Number(getUserId(req)), requestId,
        message: req.body.message, execution: admittedExecution }, ({ history }) => perform(history)));
    }
    res.json(await perform([]));
  } catch (err) {
    console.error('[MCP Workshop] chat error:', err);
    res.status(err.statusCode || 500).json({ error: err.code || 'Chat processing failed', message: err.message });
  }
}, {reset:false}));

// The caller supplies qualified repositories after schema installation. This
// factory is not mounted automatically while the migration remains a draft.
router.createConversationRouter = ({requests,conversations,perform=performMcpConversationTurn,service:suppliedService,diagnose}) => {
  const service=suppliedService||require('../services/mcp/conversationService').createMcpConversationService({requests,conversations,coordinator:ownerRuns});
  return require('./mcpConversationRoutes').createMcpConversationRouter({coordinator:ownerRuns,service,conversations,
    admit:async(req,execution)=>{
      const resources=await ownedResources.admitChat(req,execution);
      if(!resources)throw Object.assign(new Error('Owned MCP resources are not installed'),
        {code:'MCP_OWNED_RESOURCES_UNAVAILABLE',statusCode:503});
      return resources;
    },perform,diagnose});
};

// Editing this learner-owned artifact is not objective completion. Both calls
// use the same authenticated owner coordinator as model turns and reset.
router.use('/shadow-source', require('./mcpShadowSourceRoutes').createMcpShadowSourceRouter({
  coordinator: ownerRuns, requireUser: requireWorkshopUser, requireRuntime: requireSupportedOwnedRuntime,
  ownerId: req => String(getUserId(req)), getResources: (req, execution) => ownedResources.admitChat(req, execution),
  visible: async () => (await getVisibleMcpObjectiveIds()).has('mcp_shadow_server'),
}));

// Activation seam for the qualified owned-resource composition. server/index
// calls its default-off installer; it cannot publish this seam until every
// schema, privilege, Mailpit and strict-runner readiness check succeeds.
router.installOwnedResources = application => {
  if (!application || application.enabled !== true || typeof application.admitChat !== 'function'
      || typeof application.readOnly !== 'function' || typeof application.readiness !== 'function'
      || typeof application.reset !== 'function' || typeof application.retireOwner !== 'function'
      || typeof application.state !== 'function'
      || !isProductionQualification(application.qualification)) {
    throw new TypeError('Qualified MCP owned-resource application is required');
  }
  if (ownedResources.enabled) throw new Error('MCP owned resources are already installed');
  ownedResources = application;
};

function installOwnedRuntimeForQualification({ application, requests, conversations, protectedRecovery: recovery = null } = {},
  expectedVersion, expectedObjectives) {
  if (!application || application.enabled !== true || typeof application.admitChat !== 'function'
      || typeof application.readOnly !== 'function' || typeof application.readiness !== 'function'
      || typeof application.reset !== 'function' || typeof application.retireOwner !== 'function'
      || typeof application.state !== 'function'
      || application.qualification?.version !== expectedVersion
      || JSON.stringify(application.qualification.qualifiedObjectives) !== JSON.stringify(expectedObjectives)
      || !requests || typeof requests.admit !== 'function' || typeof requests.complete !== 'function'
      || !conversations || typeof conversations.list !== 'function'
      || typeof conversations.clearBeforeCurrentGeneration !== 'function') {
    throw new TypeError('Complete qualified MCP owned runtime is required');
  }
  if (ownedResources.enabled || conversationPersistence) throw new Error('MCP owned runtime is already installed');
  const service = require('../services/mcp/conversationService').createMcpConversationService({
    requests, conversations, coordinator: ownerRuns,
  });
  if(recovery!==null&&typeof recovery.reconcile!=='function')throw TypeError('Qualified protected recovery required');
  protectedRecovery = recovery;
  conversationPersistence = Object.freeze({ requests, conversations, service });
  ownedResources = application;
}

router.installOwnedRuntime = value => {
  if (!isProductionQualification(value?.application?.qualification)) {
    throw new TypeError('Complete qualified MCP owned runtime is required');
  }
  installOwnedRuntimeForQualification(value, value.application.qualification.version,
    value.application.qualification.qualifiedObjectives);
};

router.installConversationPersistence = ({ requests, conversations } = {}) => {
  if (!requests || typeof requests.admit !== 'function' || typeof requests.complete !== 'function'
      || !conversations || typeof conversations.list !== 'function'
      || typeof conversations.clearBeforeCurrentGeneration !== 'function') {
    throw new TypeError('Qualified MCP conversation repositories are required');
  }
  if (conversationPersistence) throw new Error('MCP conversation persistence is already installed');
  conversationPersistence = Object.freeze({ requests, conversations,
    service: require('../services/mcp/conversationService').createMcpConversationService({
      requests, conversations, coordinator: ownerRuns,
    }) });
};

// ── Progress ──────────────────────────────────────────────────────────
router.get('/progress', requireWorkshopUser, async (req, res) => {
  const userId = getUserId(req);
  const visibleObjectiveIds = await getVisibleMcpObjectiveIds();
  if (mcpWorkshopDb.engine === 'postgres') {
    try {
      const objectives = OBJECTIVES.filter(id => visibleObjectiveIds.has(id));
      let rows = [], localAvailable = true;
      try { rows = await mcpWorkshopDb.getProgress(String(userId)); }
      catch (error) {
        localAvailable = false;
        console.error('[MCP Workshop] progress projection unavailable:', error.message);
      }
      const reconciled = reconcileProgress(rows, await getUserWorkshopProgress(userId), visibleObjectiveIds, localAvailable);
      return res.json({ objectives, ...reconciled, total: objectives.length,
        runtimeQualification: qualificationFor(objectives) });
    } catch { return res.status(500).json({ error: 'Unable to load MCP progress' }); }
  }

  mcpWorkshopDb.all(
    'SELECT objective_id, completed, completed_at FROM mcp_workshop_progress WHERE user_key = ?',
    [String(userId)],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      const objectives = OBJECTIVES.filter(id => visibleObjectiveIds.has(id));
      const completed = (rows || []).filter(r => r.completed && visibleObjectiveIds.has(r.objective_id)).map(r => r.objective_id);
      res.json({ objectives, completed, total: objectives.length,
        runtimeQualification: qualificationFor(objectives) });
    }
  );
});

router.post('/progress/complete', requireWorkshopUser, ownerWorkflowRoute(ownerRuns, req => String(getUserId(req)), async (req, res) => {
  const { objectiveId } = req.body;
  if (!objectiveId || !OBJECTIVES.includes(objectiveId)) {
    return res.status(400).json({ error: 'Invalid objective' });
  }
  if (!(await getVisibleMcpObjectiveIds()).has(objectiveId)) {
    return res.status(404).json({ error: 'objective disabled by instructor' });
  }
  return res.status(409).json({ code: 'JUDGED_ATTEMPT_REQUIRED',
    error: 'Objectives are completed only from server-observed MCP assistant outcomes' });
}, {reset:false}));

router.post('/progress/reset', requireWorkshopUser, ownerWorkflowRoute(ownerRuns, req => String(getUserId(req)), async (req, res) => {
  const userId = getUserId(req);
  const sessionId = `mcp_${userId}`;

  if (mcpWorkshopDb.engine === 'postgres') {
    let stage = 'resources';
    try {
      const check = getOwnerExecution()?.check;
      await retirePostgresOwnerResources(userId, { request: req, check });
      await check();
      stage = 'progress'; await mcpWorkshopDb.resetUser(String(userId));
      await check();
      stage = 'canonical'; await resetWorkshopProgress(userId, WORKSHOP_KEY);
      await check();
      return res.json({ success: true });
    } catch (error) {
      return res.status(503).json({ success: false, code: error.code === 'MCP_OWNED_RESOURCES_UNAVAILABLE'
        ? error.code : 'RESET_INCOMPLETE', failedSteps: [stage], error: 'Reset cleanup is incomplete. Retry the reset.' });
    }
  }

  let ownedReset = null;
  try {
    if (ownedResources.enabled) ownedReset = await ownedResources.reset(req);
  } catch (error) {
    return res.status(error.statusCode || 503).json({ success:false, code:error.code || 'RESET_INCOMPLETE', error:error.message });
  }
  const result = await require('../services/mcp/resetWorkflow').resetMcpWorkshop({
    progress: async () => {
      if(mcpWorkshopDb.engine==='postgres')await mcpWorkshopDb.resetUser(String(userId));
      else for(const table of ['mcp_workshop_progress','mcp_workshop_tool_log'])await new Promise((resolve,reject)=>mcpWorkshopDb.run(`DELETE FROM ${table} WHERE user_key = ?`,[String(userId)],err=>err?reject(err):resolve()));
    },
    sandbox: () => ownedReset ? ({ok:true}) : mcpSandbox.resetSandbox(sessionId),
    protocol: () => mcpProtocol.retireSession(sessionId),
    canonical: () => resetWorkshopProgress(userId, WORKSHOP_KEY),
  });
  res.status(result.success ? 200 : 503).json(result);
}, {reset:true}));

// ── Activity log ──────────────────────────────────────────────────────
router.get('/activity', requireWorkshopUser, async (req, res) => {
  const userId = getUserId(req);
  if (mcpWorkshopDb.engine === 'postgres') {
    try { return res.json({ activity: await mcpWorkshopDb.listActivity(String(userId)) }); }
    catch { return res.status(500).json({ error: 'Unable to load MCP activity' }); }
  }
  mcpWorkshopDb.all(
    'SELECT id, tool_name, args, result_summary, outcome, success, created_at FROM mcp_workshop_tool_log WHERE user_key = ? ORDER BY id DESC LIMIT 50',
    [String(userId)],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ activity: rows || [] });
    }
  );
});

router.delete('/activity', requireWorkshopUser, async (req, res) => {
  const userId = getUserId(req);
  if (mcpWorkshopDb.engine === 'postgres') {
    try { await mcpWorkshopDb.clearActivity(String(userId)); return res.json({ success: true }); }
    catch { return res.status(500).json({ error: 'Unable to clear MCP activity' }); }
  }
  mcpWorkshopDb.run('DELETE FROM mcp_workshop_tool_log WHERE user_key = ?', [String(userId)]);
  res.json({ success: true });
});

// ── Server side-effect state (Captured Data panel) ───────────────────
// Surfaces the REAL, observable consequences of each exploit so the learner
// can see them land instead of trusting the assistant's word: emails the
// deputy couriered out (with the stolen secret), tampered plugins that were
// installed, rogue MCP servers that were registered, whether the audit trail
// was silenced, and any data exfiltrated out-of-band to the listener.
router.get('/exfil', requireWorkshopUser, requireSupportedOwnedRuntime, async (req, res) => {
  const userId = getUserId(req);
  const sessionId = `mcp_${userId}`;
  try {
    const owned = ownedResources.enabled ? await ownedResources.readOnly(req) : null;
    const state = owned ? owned.state() : mcpSandbox.getSandboxState(sessionId);
    const ownedSmtpMessageIds = owned ? [] : mailClient.deliveredSmtpMessageIds(state.sentReports);
    // Enrich with REAL backend evidence: the isolated runner's mode and the
    // actual emails delivered to the mail sink. Both are best-effort so the
    // panel still renders when a backend is offline (exploits fail honestly).
    const [health, mail] = owned ? [{ ok: true }, await owned.mailProjection()]
      : await Promise.all([
        sandboxRunner.health().catch(() => ({ ok: false })),
        mailClient.listMessagesBySmtpIds(ownedSmtpMessageIds).catch(() => ({ ok: false, messages: [] })),
      ]);
    const realExecution = owned ? owned.realExecution : {
      available: !!health.ok,
      isolation: health.ok ? health.isolation : 'unavailable',
      bwrap: !!health.bwrap,
    };
    // SMTP Message-ID receipts belong to this session. Recipient matching is
    // insufficient because workshop users may deliberately share recipients.
    const deliveredMail = mail.ok ? mail.messages : [];
    res.json({
      success: true,
      sessionId,
      state,
      realExecution,
      deliveredMail,
      mailSinkAvailable: !!mail.ok,
    });
  } catch (err) {
    res.status(err.statusCode || 500).json({ success: false,
      error: err.code || 'MCP_CAPTURED_EFFECTS_UNAVAILABLE' });
  }
});

// ── OOB Listener ──────────────────────────────────────────────────────
// GET: requires auth + session ownership (prevents cross-user data leakage)
router.get('/listener/:sessionId', requireWorkshopUser, rejectPostgresListener, (req, res) => {
  const { sessionId } = req.params;
  const userId = getUserId(req);
  const expectedSession = `mcp_${userId}`;
  if (sessionId !== expectedSession) {
    return res.status(403).json({ error: 'Cannot access another user\'s listener data' });
  }
  const data = mcpSandbox.getListenerData(sessionId);
  res.json({ success: true, sessionId, entries: data, count: data.length });
});

// POST: intentionally unauthenticated — sandbox curl targets this endpoint
router.post('/listener/:sessionId', rejectPostgresListener, (req, res) => {
  const { sessionId } = req.params;
  mcpSandbox.appendListenerData(sessionId, {
    method: 'POST',
    url: req.originalUrl,
    params: req.query,
    body: req.body,
    sourceCommand: 'external',
  });
  res.json({ status: 'received', message: 'Data logged to listener' });
});

// ── Helpers ───────────────────────────────────────────────────────────

async function markNativeProgress(userId, objectiveId) {
  await checkOwnerRun();
  if (mcpWorkshopDb.engine === 'postgres') await mcpWorkshopDb.markProgress(String(userId),objectiveId);
  else await new Promise((resolve,reject)=>mcpWorkshopDb.run(`INSERT INTO mcp_workshop_progress (user_key, objective_id, completed, completed_at) VALUES (?, ?, 1, CURRENT_TIMESTAMP) ON CONFLICT(user_key, objective_id) DO UPDATE SET completed = 1, completed_at = CURRENT_TIMESTAMP`,[String(userId),objectiveId],err=>err?reject(err):resolve()));
}

function qualificationFor(objectives) {
  const metadata = ownedResources.qualification;
  if (mcpWorkshopDb.engine === 'postgres' && ownedResources.enabled !== true) {
    return { mode: 'qualified_subset', version: 'mcp-owned-runtime-unavailable',
      objectives: objectives.map(objectiveId => ({ objectiveId, qualified: false })) };
  }
  return { mode: metadata.mode, version: metadata.version,
    objectives: objectives.map(objectiveId => ({ objectiveId,
      qualified: metadata.mode === 'legacy' ? null : metadata.canGrade(objectiveId) })) };
}

function qualifiedObjectiveCandidates(objectivesHit, visibleObjectiveIds, qualification = ownedResources.qualification) {
  if (mcpWorkshopDb.engine === 'postgres' && ownedResources.enabled !== true) return [];
  return (objectivesHit || []).filter(id => visibleObjectiveIds.has(id) && qualification.canGrade(id));
}

async function logToolCall(userId, toolName, args, output, outcome, success = true) {
  await checkOwnerRun();
  const summary=output.length>200?output.substring(0,200)+'...':output;
  if(mcpWorkshopDb.engine==='postgres')return mcpWorkshopDb.logToolCall({userKey:String(userId),toolName,args,resultSummary:summary,outcome:outcome||null,success});
  await new Promise((resolve,reject)=>mcpWorkshopDb.run(`INSERT INTO mcp_workshop_tool_log (user_key, tool_name, args, result_summary, outcome, success) VALUES (?, ?, ?, ?, ?, ?)`,[String(userId),toolName,args,summary,outcome||null,success?1:0],err=>err?reject(err):resolve()));
}

function activityRecordsForObservation(observed) {
  const value = observed?.toolResult;
  if (((observed?.toolUsed === 'check_system_status' && value?.modelAction?.tool === 'read_file')
      || (observed?.toolUsed === 'read_ticket' && value?.modelAction?.tool === 'send_report'))
      && typeof value.observationOutput === 'string' && typeof value.consequenceOutput === 'string') {
    return [
      { toolUsed: observed.toolUsed, args: value.args || {}, toolResult: {
        output: value.observationOutput, error: value.observationError, blocked: value.observationBlocked,
        real: value.observationReal, achieved: false } },
      { toolUsed: value.modelAction.tool, args: value.modelAction.params || {}, toolResult: {
        output: value.consequenceOutput, error: value.error, blocked: value.blocked, real: value.real,
        achieved: value.achieved, objective: value.objective } },
    ];
  }
  return [{ toolUsed: observed?.toolUsed, args: value?.args || {}, toolResult: value }];
}

// Export internals for unit tests
if (process.env.EXPORT_INTERNALS === '1') {
  router._internals = { markNativeProgress, logToolCall, activityRecordsForObservation, reconcileProgress, OBJECTIVES, WORKSHOP_KEY,
    setObjectiveGraderForTests: grader => { objectiveGrader = grader; },
    setProgressProjectorForTests: projector => { progressProjector = projector || ((...args) => markNativeProgress(...args)); },
    setOwnedResourcesForTests: application => { ownedResources = application || createDisabledMcpOwnedResourceApplication(); },
    setConversationPersistenceForTests: value => { conversationPersistence = value; }, qualificationFor,
    setModeAuthorityForTests: ({ service, readScope } = {}) => {
      if (service) modeService = service;
      if (readScope) modeScopeReader = readScope;
    },
    qualifiedObjectiveCandidates,
    installOwnedRuntimeForQualificationForTests: (value, qualification) => {
      if (!qualification || typeof qualification.version !== 'string'
          || !Array.isArray(qualification.qualifiedObjectives) || typeof qualification.canGrade !== 'function') {
        throw new TypeError('Exact candidate MCP qualification is required');
      }
      return installOwnedRuntimeForQualification(value, qualification.version, qualification.qualifiedObjectives);
    } };
}

router.resetOwner = (owner, work, { check: authorityCheck } = {}) => {
  if (typeof work !== 'function' || (authorityCheck !== undefined && typeof authorityCheck !== 'function')) {
    throw new TypeError('MCP reset work and authority required');
  }
  return ownerRuns.reset(owner, async execution => {
    if (typeof execution?.check !== 'function') throw new TypeError('MCP reset lease check required');
    const check = async () => {
      await execution.check();
      if (authorityCheck) await authorityCheck();
      await execution.check();
    };
    await check();
    if (mcpWorkshopDb.engine === 'postgres') {
      await retirePostgresOwnerResources(owner, { check });
    } else {
      const retired = await mcpProtocol.retireSession(`mcp_${owner}`);
      if (retired?.ok !== true) throw new Error('MCP protocol session retirement incomplete');
    }
    await check();
    await work(Object.freeze({ ...execution, check }));
    await check();
  });
};
module.exports = router;
