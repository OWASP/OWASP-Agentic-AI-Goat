'use strict';

const crypto = require('node:crypto');
const { BACKEND_TIMEOUT_MS } = require('./config');
const protocol = require('./protocolContext');
const { validateCommandOutputReceipt } = require('./commandOutputReceipt');

// Only trusted transport code can enroll an uncertain protected operation.
const uncertainProtectedOperations = new WeakSet();
function protectedOperationUncertain() {
  const error = Object.assign(new Error('Protected operation outcome is uncertain; do not retry automatically.'),
    { code: 'MCP_PROTECTED_OPERATION_UNCERTAIN', statusCode: 503 });
  uncertainProtectedOperations.add(error); return error;
}
function isProtectedOperationUncertain(error) { return uncertainProtectedOperations.has(error); }
// Revocation/retirement also occur in withTarget's post-work return fence.
// Their codes alone cannot prove the effect did not commit.
const PRE_EFFECT_REJECTIONS = new Set(['TARGET_LOCKED', 'TARGET_SCOPE_INVALID', 'PROTECTED_OPERATION_INVALID']);
const TOKEN = /^[A-Za-z0-9_-]{43,128}$/;
const CAPABILITY = /^mcp-target-[a-f0-9]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const VERSION = 'mcp-owned-target-http.v1';
const MAX_OUTPUT_BYTES = 1024 * 1024;
const PROTECTED_VERSION = 'mcp-owned-protected-state.v1';
const PROTECTED_READBACK_CAPABILITY='mcp-owned-protected-readback.v1';
const PROTECTED_JOURNAL_CAPABILITY='mcp-owned-protected-operation-journal.v1';
const PROTECTED_STATE_CAPABILITY = 'mcp-owned-protected-state-transition.v2';
const OBSERVED_ACTION_CAPABILITY = 'mcp-owned-observed-action.v1';
const PACKAGE_INSTALL_CAPABILITY = 'mcp-owned-package-install.v1';
const PACKAGE_RECEIPT_VERSION = 'mcp-owned-package-install.v1';
const TICKET_READ_CAPABILITY = 'mcp-owned-ticket-read.v2';
const TICKET_RECEIPT_VERSION = 'mcp-owned-ticket-read.v1';
const CONTROLLED_TICKET_ID = '4295';
const CONTROLLED_TICKET_IDS = Object.freeze(['4290', CONTROLLED_TICKET_ID, '4301']);
const CONTROLLED_TICKET_ID_SET = new Set(CONTROLLED_TICKET_IDS);
const CONTROLLED_PACKAGES = Object.freeze({
  '@acme/analytics': Object.freeze({ archiveSha256: 'd43b1b73d2f859eb5b70e77d7a2b0d42bc2e3db7754443a25a9b951fd8b74b6c',
    packageName: '@acme/analytics', packageVersion: '1.0.0', provenance: 'trusted_internal', signatureVerified: true, hiddenToolName: null }),
  'https://cdn.acme-billing-partner.io/pkg/analytics-boost.tgz': Object.freeze({
    archiveSha256: '28ad1b38813766bd06c9297a5297440b0a6dcac37dffee83f35167569b0869e1',
    packageName: 'analytics-boost', packageVersion: '1.0.0', provenance: 'untrusted_external', signatureVerified: false,
    hiddenToolName: 'exfiltrate_env' }),
});
const trustedPackageReceipts = new WeakSet();
const trustedTicketReceipts = new WeakSet();
const trustedProtectedReceipts = new WeakSet();
const fail = (code, message) => { const error = new Error(message); error.code = code; error.statusCode = 503; throw error; };
const exactKeys = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
function exactScope(value, expected) {
  return exactKeys(value, ['targetId', 'platformOwnerId', 'platformSessionId', 'generation'])
    && value.targetId === expected?.targetId && value.platformOwnerId === expected?.platformOwnerId
    && value.platformSessionId === expected?.platformSessionId && value.generation === expected?.generation;
}
const canonical = value => JSON.stringify(value, Object.keys(value).sort());
function protectedReceipt(value, expected, operation, runId) {
  const fields = {
    read_configuration: ['audited','byteCount','configSha256','generation','operation','output','platformOwnerId','platformSessionId','receiptSha256','runId','targetId','version'],
    rotate_keys: ['audited','changed','generation','keyVersionAfter','keyVersionBefore','labRole','operation','platformOwnerId','platformSessionId','policy','receiptSha256','runId','targetId','version'],
    set_audit_logging: ['action','auditEnabled','auditEnabledBefore','audited','entriesAfter','entriesBefore','generation','operation','platformOwnerId','platformSessionId','receiptSha256','runId','targetId','version'],
    inspect_audit: ['auditEnabled','auditSha256','entryCount','generation','operation','platformOwnerId','platformSessionId','receiptSha256','runId','targetId','version'],
  }[operation];
  if (!fields || !exactKeys(value, fields) || value.version !== PROTECTED_VERSION
      || value.operation !== operation || value.runId !== runId
      || value.targetId !== expected?.targetId || value.platformOwnerId !== expected?.platformOwnerId
      || value.platformSessionId !== expected?.platformSessionId || value.generation !== expected?.generation
      || typeof value.receiptSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.receiptSha256)) {
    fail('MCP_OWNED_PROTECTED_RESULT_INVALID', 'Owned protected-state receipt is invalid');
  }
  const body = Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'receiptSha256'));
  const bytes = operation === 'read_configuration' && typeof value.output === 'string' ? Buffer.from(value.output) : null;
  const semantic = operation === 'read_configuration'
    ? bytes && bytes.length >= 1 && bytes.length <= 64 * 1024 && value.byteCount === bytes.length
      && value.configSha256 === crypto.createHash('sha256').update(bytes).digest('hex') && typeof value.audited === 'boolean'
    : operation === 'rotate_keys'
      ? ['unprivileged', 'privileged'].includes(value.labRole) && ['vulnerable', 'enforced'].includes(value.policy)
        && typeof value.changed === 'boolean' && typeof value.audited === 'boolean'
        && Number.isSafeInteger(value.keyVersionBefore) && value.keyVersionBefore >= 1
        && Number.isSafeInteger(value.keyVersionAfter)
        && value.keyVersionAfter === value.keyVersionBefore + (value.changed ? 1 : 0)
        && !(value.policy === 'enforced' && value.labRole === 'unprivileged' && value.changed)
      : operation === 'set_audit_logging'
        ? ['enable', 'disable', 'clear'].includes(value.action) && typeof value.auditEnabled === 'boolean'
          && typeof value.auditEnabledBefore === 'boolean'
          && typeof value.audited === 'boolean' && Number.isSafeInteger(value.entriesBefore) && value.entriesBefore >= 0
          && Number.isSafeInteger(value.entriesAfter) && value.entriesAfter >= 0
          && (value.action !== 'enable' || value.auditEnabled === true)
          && (value.action !== 'disable' || value.auditEnabled === false)
        : typeof value.auditEnabled === 'boolean' && /^[a-f0-9]{64}$/.test(value.auditSha256 || '')
          && Number.isSafeInteger(value.entryCount) && value.entryCount >= 0;
  if (crypto.createHash('sha256').update(Buffer.from(canonical(body))).digest('hex') !== value.receiptSha256 || !semantic) {
    fail('MCP_OWNED_PROTECTED_RESULT_INVALID', 'Owned protected-state receipt digest or output is invalid');
  }
  const verified = Object.freeze(value);
  trustedProtectedReceipts.add(verified);
  return verified;
}
function isTrustedPackageReceipt(value) { return Boolean(value && trustedPackageReceipts.has(value)); }
function isTrustedTicketReceipt(value) { return Boolean(value && trustedTicketReceipts.has(value)); }
function isTrustedProtectedReceipt(value) { return Boolean(value && trustedProtectedReceipts.has(value)); }
function uuidFrom(value) {
  const bytes = Buffer.from(crypto.createHash('sha256').update(value).digest().subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x50; bytes[8] = (bytes[8] & 0x3f) | 0x80;
  return `${bytes.toString('hex', 0, 4)}-${bytes.toString('hex', 4, 6)}-${bytes.toString('hex', 6, 8)}-${bytes.toString('hex', 8, 10)}-${bytes.toString('hex', 10, 16)}`;
}
function packageMetadata(value, controlled) {
  if (typeof value !== 'string' || Buffer.byteLength(value) < 2 || Buffer.byteLength(value) > 4096) return null;
  let parsed;
  try { parsed = JSON.parse(value); } catch { return null; }
  const fields = controlled.hiddenToolName ? ['hiddenTool', 'plugin', 'status'] : ['plugin', 'status'];
  if (!parsed || Object.getPrototypeOf(parsed) !== Object.prototype
      || Object.keys(parsed).sort().join(',') !== fields.sort().join(',')
      || parsed.plugin !== controlled.packageName || parsed.status !== 'ready'
      || (controlled.hiddenToolName ? parsed.hiddenTool !== controlled.hiddenToolName : 'hiddenTool' in parsed)) return null;
  return Object.freeze(parsed);
}
function packageReceipt(value, expected, source, runId, operationId) {
  const fields = ['archiveSha256','artifactByteCount','artifactSha256','changed','completedAt','generation',
    'hiddenToolName','installedPath','manifestSha256','metadataByteCount','metadataSha256','operation','operationId','packageName','packageVersion',
    'platformOwnerId','platformSessionId','postinstallByteCount','postinstallOutput','postinstallSha256',
    'postinstallMetadata','provenance','receiptSha256','runId','signatureVerified','source','targetId','version'];
  const controlled = CONTROLLED_PACKAGES[source];
  const metadata = controlled ? packageMetadata(value?.postinstallMetadata, controlled) : null;
  if (!controlled || !exactKeys(value, fields) || value.version !== PACKAGE_RECEIPT_VERSION
      || value.operation !== 'install_package' || value.runId !== runId || value.operationId !== operationId
      || value.source !== source || value.targetId !== expected?.targetId
      || value.platformOwnerId !== expected?.platformOwnerId
      || value.platformSessionId !== expected?.platformSessionId || value.generation !== expected?.generation
      || value.changed !== true || value.archiveSha256 !== controlled.archiveSha256
      || value.provenance !== controlled.provenance || value.signatureVerified !== controlled.signatureVerified
      || value.packageName !== controlled.packageName || value.packageVersion !== controlled.packageVersion
      || value.hiddenToolName !== controlled.hiddenToolName
      || (metadata?.hiddenTool ?? null) !== value.hiddenToolName
      || value.installedPath !== `/var/tmp/package-installs/${operationId}`
      || ![value.archiveSha256, value.manifestSha256, value.postinstallSha256,
        value.artifactSha256, value.receiptSha256].every(item => /^[a-f0-9]{64}$/.test(item || ''))
      || typeof value.postinstallOutput !== 'string'
      || value.postinstallByteCount !== Buffer.byteLength(value.postinstallOutput)
      || !metadata || value.metadataByteCount !== Buffer.byteLength(value.postinstallMetadata)
      || !/^[a-f0-9]{64}$/.test(value.metadataSha256 || '')
      || crypto.createHash('sha256').update(Buffer.from(value.postinstallMetadata)).digest('hex') !== value.metadataSha256
      || !Number.isSafeInteger(value.artifactByteCount) || value.artifactByteCount < 1
      || typeof value.completedAt !== 'string' || !Number.isFinite(Date.parse(value.completedAt))
      || new Date(value.completedAt).toISOString() !== value.completedAt) {
    fail('MCP_OWNED_PACKAGE_RESULT_INVALID', 'Owned package install receipt is invalid');
  }
  const body = Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'receiptSha256'));
  if (crypto.createHash('sha256').update(Buffer.from(canonical(body))).digest('hex') !== value.receiptSha256) {
    fail('MCP_OWNED_PACKAGE_RESULT_INVALID', 'Owned package install receipt digest is invalid');
  }
  const verified = Object.freeze(value);
  trustedPackageReceipts.add(verified);
  return verified;
}
function ticketReceipt(value, expected, ticketId, runId, operationId) {
  const fields = ['artifactByteCount','artifactSha256','bodySha256','completedAt','generation','operation',
    'operationId','platformOwnerId','platformSessionId','receiptSha256','runId','targetId','ticket','ticketId','version'];
  const ticketFields = ['body', 'from', 'id', 'subject'];
  if (!CONTROLLED_TICKET_ID_SET.has(ticketId) || !exactKeys(value, fields) || value.version !== TICKET_RECEIPT_VERSION
      || value.operation !== 'read_ticket' || value.ticketId !== ticketId
      || value.runId !== runId || value.operationId !== operationId
      || value.targetId !== expected?.targetId || value.platformOwnerId !== expected?.platformOwnerId
      || value.platformSessionId !== expected?.platformSessionId || value.generation !== expected?.generation
      || !exactKeys(value.ticket, ticketFields) || value.ticket.id !== ticketId
      || typeof value.ticket.from !== 'string' || typeof value.ticket.subject !== 'string'
      || typeof value.ticket.body !== 'string' || !value.ticket.from || !value.ticket.subject || !value.ticket.body
      || Buffer.byteLength(value.ticket.from) > 320 || Buffer.byteLength(value.ticket.subject) > 512
      || Buffer.byteLength(value.ticket.body) > 16 * 1024
      || !Number.isSafeInteger(value.artifactByteCount) || value.artifactByteCount < 1
      || value.artifactByteCount > 16 * 1024
      || ![value.artifactSha256, value.bodySha256, value.receiptSha256]
        .every(item => /^[a-f0-9]{64}$/.test(item || ''))
      || crypto.createHash('sha256').update(Buffer.from(value.ticket.body)).digest('hex') !== value.bodySha256
      || typeof value.completedAt !== 'string' || !Number.isFinite(Date.parse(value.completedAt))
      || new Date(value.completedAt).toISOString() !== value.completedAt) {
    fail('MCP_OWNED_TICKET_RESULT_INVALID', 'Owned ticket read receipt is invalid');
  }
  const orderedTicket = Object.fromEntries(Object.keys(value.ticket).sort().map(key => [key, value.ticket[key]]));
  const artifact = Buffer.from(`${JSON.stringify(orderedTicket)}\n`);
  const body = Object.fromEntries(Object.entries(value)
    .filter(([key]) => key !== 'receiptSha256').sort(([left], [right]) => left.localeCompare(right)));
  if (artifact.length !== value.artifactByteCount
      || crypto.createHash('sha256').update(artifact).digest('hex') !== value.artifactSha256
      || crypto.createHash('sha256').update(Buffer.from(JSON.stringify(body))).digest('hex') !== value.receiptSha256) {
    fail('MCP_OWNED_TICKET_RESULT_INVALID', 'Owned ticket receipt digest is invalid');
  }
  const verified = Object.freeze({ ...value, ticket: Object.freeze({ ...orderedTicket }) });
  trustedTicketReceipts.add(verified);
  return verified;
}

function createMcpOwnedTargetClient({ baseURL, token, timeoutMs = BACKEND_TIMEOUT_MS, fetchImpl = fetch } = {}) {
  let origin;
  let packageInstallReady = false;
  let ticketReadReady = false;
  let protectedJournalReady=false,protectedReadbackReady=false;
  try { origin = new URL(baseURL); } catch { throw new TypeError('Owned target URL is required'); }
  if (!['http:', 'https:'].includes(origin.protocol) || origin.username || origin.password || origin.search || origin.hash
      || origin.pathname !== '/' || !TOKEN.test(token || '') || typeof fetchImpl !== 'function'
      || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000) {
    throw new TypeError('Exact private owned target client configuration is required');
  }
  async function request(path, body, protectedOperation = false, externalSignal = null) {
    let knownRejection = null;
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl(new URL(path, origin), { method: body === undefined ? 'GET' : 'POST',
        headers: { authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: externalSignal ? AbortSignal.any([controller.signal,externalSignal]) : controller.signal, redirect: 'error' });
      const result = await response.json().catch(() => null);
      if (!response.ok || !result) {
        if (protectedOperation) {
          if ([409,503].includes(response.status) && result && exactKeys(result, ['error','message'])
              && PRE_EFFECT_REJECTIONS.has(result.error) && typeof result.message === 'string') {
            knownRejection = Object.assign(new Error('Protected operation rejected before execution.'),
              { code: result.error, statusCode: 503 });
            throw knownRejection;
          }
          throw protectedOperationUncertain();
        }
        fail(result?.error || 'MCP_OWNED_TARGET_UNAVAILABLE', result?.message || 'Owned target sidecar is unavailable');
      }
      return result;
    } catch (error) {
      if (protectedOperation) {
        if (error === knownRejection || isProtectedOperationUncertain(error)) throw error;
        throw protectedOperationUncertain();
      }
      // Only preserve errors created by this adapter. Native fetch failures can
      // also carry a platform code (for example ECONNREFUSED); those are private
      // transport failures, not an application error contract.
      if (error?.statusCode === 503) throw error;
      fail('MCP_OWNED_TARGET_UNAVAILABLE', 'Owned target sidecar is unavailable');
    } finally { clearTimeout(timer); }
  }
  return Object.freeze({
    async readiness() {
      protectedReadbackReady=false;protectedJournalReady=false;
      const raw = await request('/owned-targets/health');
      const {protectedJournalCapability,protectedReadbackCapability,...withoutJournal}=raw||{};
      if(protectedReadbackCapability!==undefined&&protectedReadbackCapability!==PROTECTED_READBACK_CAPABILITY)fail('MCP_OWNED_TARGET_UNAVAILABLE','Unsupported protected readback capability');
      if(protectedJournalCapability!==undefined && protectedJournalCapability!==PROTECTED_JOURNAL_CAPABILITY)fail('MCP_OWNED_TARGET_UNAVAILABLE','Unsupported protected journal capability');
      const value=withoutJournal;
      const legacyShape = exactKeys(value, ['isolation','ready','supervisorProfile','version']);
      const protectedShape = exactKeys(value, ['isolation','protectedStateCapability','ready','supervisorProfile','version'])
        && value.protectedStateCapability === PROTECTED_STATE_CAPABILITY;
      const observedActionShape = exactKeys(value, ['isolation','observedActionCapability','protectedStateCapability','ready','supervisorProfile','version'])
        && value.protectedStateCapability === PROTECTED_STATE_CAPABILITY
        && value.observedActionCapability === OBSERVED_ACTION_CAPABILITY;
      const packageShape = exactKeys(value, ['isolation','observedActionCapability','packageInstallCapability','protectedStateCapability','ready','supervisorProfile','version'])
        && value.protectedStateCapability === PROTECTED_STATE_CAPABILITY
        && value.observedActionCapability === OBSERVED_ACTION_CAPABILITY
        && value.packageInstallCapability === PACKAGE_INSTALL_CAPABILITY;
      const ticketShape = exactKeys(value, ['isolation','observedActionCapability','packageInstallCapability','protectedStateCapability','ready','supervisorProfile','ticketReadCapability','version'])
        && value.protectedStateCapability === PROTECTED_STATE_CAPABILITY
        && value.observedActionCapability === OBSERVED_ACTION_CAPABILITY
        && value.packageInstallCapability === PACKAGE_INSTALL_CAPABILITY
        && value.ticketReadCapability === TICKET_READ_CAPABILITY;
      const valid = (legacyShape || protectedShape || observedActionShape || packageShape || ticketShape) && value.ready === true
        && value.version === VERSION && value.isolation === 'bwrap-seccomp-v1'
        && /^owasp-ai-goat-mcp-sandbox(?:-[a-f0-9]{12})? \(enforce\)$/.test(value.supervisorProfile || '');
      if (!valid) fail('MCP_OWNED_TARGET_UNAVAILABLE', 'Owned target readiness receipt is invalid');
      protectedJournalReady=protectedJournalCapability===PROTECTED_JOURNAL_CAPABILITY && ticketShape;
      protectedReadbackReady=protectedJournalReady&&protectedReadbackCapability===PROTECTED_READBACK_CAPABILITY;
      packageInstallReady = packageShape || ticketShape;
      ticketReadReady = ticketShape;
      return Object.freeze({ ready: true, runnerReady: true, version: value.version,
        isolation: value.isolation, supervisorProfile: value.supervisorProfile,
        // `origin` was validated once at construction (no credentials, query,
        // fragment, or mutable path). Project that same authority into public
        // readiness instead of asking routes to read the environment again.
        endpoint: origin.href,
        ...((protectedShape || observedActionShape || packageShape || ticketShape) ? { protectedStateCapability: value.protectedStateCapability } : {}),
        ...((observedActionShape || packageShape || ticketShape) ? { observedActionCapability: value.observedActionCapability } : {}),
        ...((packageShape || ticketShape) ? { packageInstallCapability: value.packageInstallCapability } : {}),
        ...(ticketShape ? { ticketReadCapability: value.ticketReadCapability } : {}),
        ...(protectedJournalReady?{protectedJournalCapability}: {}),
        ...(protectedReadbackReady?{protectedReadbackCapability}: {}) });
    },
    // Explicit trusted read-only path after caller recreation. This endpoint
    // recovers an existing target; it cannot provision or execute an operation.
    async readProtectedOperationReceipt({request:original,check}={}) {
      if(!protectedReadbackReady||typeof check!=='function')fail('MCP_PROTECTED_READBACK_UNAVAILABLE','Current protected readback capability is required');
      const selected=JSON.parse(protocol._internals.canonical(original));
      if(!exactKeys(selected,['operationId','runId','operation','arguments','binding'])||!UUID.test(selected.operationId||'')||!UUID.test(selected.runId||''))fail('MCP_OWNED_TARGET_SCOPE_INVALID','Exact original protected intent is required');
      const scope=selected.binding;
      await check();const signal=AbortSignal.timeout(timeoutMs);
      const recovered=await request('/owned-targets/recover',{scope},false,signal);
      if(!exactKeys(recovered,['capability','scope','version'])||recovered.version!==VERSION||!exactScope(recovered.scope,scope)||!CAPABILITY.test(recovered.capability||''))fail('MCP_OWNED_TARGET_SCOPE_INVALID','Recovered target binding is invalid');
      await check();const {binding,...operation}=selected;
      const result=await request('/owned-targets/protected-receipt',{capability:recovered.capability,...operation},false,signal);
      const requestDigest=protocol.canonicalDigest(selected);
      if(!['absent','uncertain','completed'].includes(result?.state)||result.requestDigest!==requestDigest||!exactKeys(result,result.state==='completed'?['state','requestDigest','result']:['state','requestDigest']))fail('MCP_PROTECTED_READBACK_INVALID','Original protected receipt does not match');
      const verified=result.state==='completed'?protectedReceipt(result.result,scope,selected.operation,selected.runId):null;
      await check();return Object.freeze({state:result.state,requestDigest,...(verified?{result:verified}:{})});
    },
    async admit({ scope, execution, withProtectedOperation } = {}) {
      if (!execution || typeof execution.check !== 'function') fail('MCP_OWNED_TARGET_AUTHORITY_REQUIRED', 'Current owner execution is required');
      await execution.check();
      const value = await request('/owned-targets/admit', { scope });
      if (!exactKeys(value, ['capability','scope','version']) || value.version !== VERSION
          || !exactScope(value.scope, scope) || !CAPABILITY.test(value.capability || '')) {
        fail('MCP_OWNED_TARGET_SCOPE_INVALID', 'Owned target admission receipt is invalid');
      }
      await execution.check();
      const capability = value.capability;
      let packageInstalls = Object.freeze([]);
      if (packageInstallReady) {
        const inventory = await request('/owned-targets/package-installs', { capability });
        if (!exactKeys(inventory, ['packages', 'version']) || inventory.version !== VERSION
            || !Array.isArray(inventory.packages) || inventory.packages.length > 64) {
          fail('MCP_OWNED_PACKAGE_RESULT_INVALID', 'Owned package install inventory is invalid');
        }
        packageInstalls = Object.freeze(inventory.packages.map(item => packageReceipt(item, scope,
          item?.source, item?.runId, item?.operationId)));
      }
      await execution.check();
      async function protectedCall(sessionId,operation,args,readOnly){
          if (sessionId !== `mcp_${scope.platformOwnerId}` || !args
              || Object.getPrototypeOf(args) !== Object.prototype) {
            fail('MCP_OWNED_TARGET_SCOPE_INVALID', 'Protected-state operation does not match its owner');
          }
          const invocation = protocol.requireProtocolContext(sessionId);
          const current = invocation.execution;
          if (current.ownerKey !== JSON.stringify(['MCP', String(scope.platformOwnerId)])
              || String(current.durableGeneration) !== String(scope.generation)
              || !UUID.test(current.runId || '')) {
            fail('MCP_OWNED_TARGET_SCOPE_INVALID', 'Protected-state execution does not match its admitted target');
          }
          const operationArgs = operation === 'rotate_keys'
            ? { ...args, labRole: invocation.actor.labRole === 'privileged' ? 'privileged' : 'unprivileged' }
            : { ...args };
          await current.check();
          if(protectedJournalReady && (typeof invocation.effectKey!=='string' || !invocation.effectKey || Buffer.byteLength(invocation.effectKey)>512))fail('MCP_OWNED_TARGET_SCOPE_INVALID','Stable protected operation effect key is required');
          if(readOnly && !protectedJournalReady)fail('MCP_PROTECTED_READBACK_UNAVAILABLE','Protected receipt readback is unavailable');
          const operationId=protectedJournalReady?uuidFrom(protocol.canonicalDigest(['protected-operation.v1',current.runId,invocation.effectKey])):null;
          const selected={operation,arguments:operationArgs,runId:current.runId,...(operationId?{operationId}:{})};
          const perform=()=>request(readOnly?'/owned-targets/protected-receipt':'/owned-targets/protected-operation',{capability,...selected},true);
          if(withProtectedOperation&&!protectedJournalReady)fail('MCP_PROTECTED_ADMISSION_UNAVAILABLE','Protected journal capability is required');
          const result=withProtectedOperation&&!readOnly
            ?await withProtectedOperation({...selected,binding:{...scope}},current,perform)
            :await perform();
          let verified;
          try {
            if(protectedJournalReady){
              const requestDigest=protocol.canonicalDigest({...selected,binding:{...scope}});
              if(!['absent','uncertain','completed'].includes(result?.state)||result.requestDigest!==requestDigest
                  ||!exactKeys(result,result.state==='completed'?['state','requestDigest','result']:['state','requestDigest']))throw Error('Invalid journal response');
              if(result.state==='completed')verified=protectedReceipt(result.result,scope,operation,current.runId);
              await current.check();
              if(readOnly)return Object.freeze({state:result.state,requestDigest,operationId,...(verified?{result:verified}:{})});
              if(!verified)throw protectedOperationUncertain();
            }else verified=protectedReceipt(result,scope,operation,current.runId);
          }catch(error){if(error?.name==='AbortError')throw error;throw protectedOperationUncertain();}
          await current.check();return verified;
      }
      return Object.freeze({ scope: value.scope, packageInstalls, runner: Object.freeze({
        async observeCommand(sessionId, command) {
          if (sessionId !== `mcp_${scope.platformOwnerId}` || typeof command !== 'string'
              || !command || Buffer.byteLength(command) > 65536) {
            fail('MCP_OWNED_TARGET_SCOPE_INVALID', 'Command observation does not match its admitted target');
          }
          const invocation = protocol.requireProtocolContext(sessionId);
          const current = invocation.execution;
          if (current.ownerKey !== JSON.stringify(['MCP', String(scope.platformOwnerId)])
              || String(current.durableGeneration) !== String(scope.generation)
              || !UUID.test(current.runId || '') || typeof invocation.effectKey !== 'string') {
            fail('MCP_OWNED_TARGET_SCOPE_INVALID', 'Command observation execution is invalid');
          }
          const operationId = uuidFrom(`${current.runId}:${invocation.effectKey}:command-observation`);
          await current.check();
          const result = await request('/owned-targets/command-observation', {
            capability, command, runId: current.runId, operationId,
          });
          const verified = validateCommandOutputReceipt(result, { scope, command,
            runId: current.runId, operationId });
          await current.check();
          return verified;
        },
        async exec(sessionId, command) {
          if (sessionId !== `mcp_${scope.platformOwnerId}`) fail('MCP_OWNED_TARGET_SCOPE_INVALID', 'Sandbox session does not match its owner');
          // Sandboxes persist across conversation runs. Resolve authority from
          // the current private SDK invocation instead of retaining the
          // execution that happened to admit this capability first.
          const invocation = protocol.requireProtocolContext(sessionId);
          const current = invocation.execution;
          if (current.ownerKey !== JSON.stringify(['MCP', String(scope.platformOwnerId)])
              || String(current.durableGeneration) !== String(scope.generation)
              || !UUID.test(current.runId || '')) {
            fail('MCP_OWNED_TARGET_SCOPE_INVALID', 'Sandbox execution does not match its admitted target');
          }
          await current.check();
          // MCP SDK dispatch already owns the durable effect receipt. Nesting a
          // second ledger effect here would deadlock/replay the wrong command.
          const result = await request('/owned-targets/exec', { capability, command });
          if (!exactKeys(result, ['exitCode','isolation','ok','stderr','stdout','timedOut','truncated','version'])
              || result.version !== VERSION || result.ok !== true || result.isolation !== 'bwrap-seccomp-v1'
              || result.timedOut !== false || result.truncated !== false
              || !Number.isSafeInteger(result.exitCode) || result.exitCode < 0 || result.exitCode > 255
              || typeof result.stdout !== 'string' || typeof result.stderr !== 'string'
              || Buffer.byteLength(result.stdout) + Buffer.byteLength(result.stderr) > MAX_OUTPUT_BYTES) {
            fail('MCP_OWNED_TARGET_RESULT_INVALID', 'Owned target execution receipt is invalid');
          }
          await current.check();
          return result;
        },
        protectedOperation:(sessionId,operation,args={})=>protectedCall(sessionId,operation,args,false),
        readProtectedOperation:(sessionId,operation,args={})=>protectedCall(sessionId,operation,args,true),
        async readTicket(sessionId, ticketId) {
          if (!ticketReadReady) fail('MCP_OWNED_TICKET_UNAVAILABLE', 'Owned ticket read capability is unavailable');
          if (sessionId !== `mcp_${scope.platformOwnerId}` || typeof ticketId !== 'string'
              || !CONTROLLED_TICKET_ID_SET.has(ticketId)) {
            fail('MCP_OWNED_TARGET_SCOPE_INVALID', 'Ticket read does not match its owner or controlled artifact');
          }
          const invocation = protocol.requireProtocolContext(sessionId);
          const current = invocation.execution;
          if (current.ownerKey !== JSON.stringify(['MCP', String(scope.platformOwnerId)])
              || String(current.durableGeneration) !== String(scope.generation)
              || !UUID.test(current.runId || '') || typeof invocation.effectKey !== 'string') {
            fail('MCP_OWNED_TARGET_SCOPE_INVALID', 'Ticket read execution does not match its admitted target');
          }
          const operationId = uuidFrom(`${current.runId}:${invocation.effectKey}:${ticketId}:ticket-read`);
          await current.check();
          const result = await request('/owned-targets/ticket-read', {
            capability, operationId, runId: current.runId, ticketId,
          });
          const verified = ticketReceipt(result, scope, ticketId, current.runId, operationId);
          await current.check();
          return verified;
        },
        async installPackage(sessionId, source) {
          if (sessionId !== `mcp_${scope.platformOwnerId}` || typeof source !== 'string') {
            fail('MCP_OWNED_TARGET_SCOPE_INVALID', 'Package install does not match its owner');
          }
          const invocation = protocol.requireProtocolContext(sessionId);
          const current = invocation.execution;
          if (current.ownerKey !== JSON.stringify(['MCP', String(scope.platformOwnerId)])
              || String(current.durableGeneration) !== String(scope.generation)
              || !UUID.test(current.runId || '') || typeof invocation.effectKey !== 'string') {
            fail('MCP_OWNED_TARGET_SCOPE_INVALID', 'Package install execution does not match its admitted target');
          }
          const operationId = uuidFrom(`${current.runId}:${invocation.effectKey}:${source}:package-install`);
          await current.check();
          const result = await request('/owned-targets/package-install', {
            capability, operationId, runId: current.runId, source,
          });
          const verified = packageReceipt(result, scope, source, current.runId, operationId);
          await current.check();
          return verified;
        },
      }) });
    },
    async retire({ scope, operationId } = {}) { return request('/owned-targets/retire', { scope, operationId }); },
    async readRetirement({ scope, operationId } = {}) { return request('/owned-targets/retirement', { scope, operationId }); },
  });
}

module.exports = { createMcpOwnedTargetClient, isProtectedOperationUncertain,
  isTrustedPackageReceipt, isTrustedTicketReceipt, isTrustedProtectedReceipt,
  _internals: { protectedReceipt, packageReceipt, packageMetadata, uuidFrom, PACKAGE_INSTALL_CAPABILITY, PACKAGE_RECEIPT_VERSION,
    CONTROLLED_PACKAGES, ticketReceipt, TICKET_READ_CAPABILITY, TICKET_RECEIPT_VERSION,
    CONTROLLED_TICKET_ID, CONTROLLED_TICKET_IDS } };
