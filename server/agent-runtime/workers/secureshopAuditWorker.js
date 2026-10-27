'use strict';
const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { performance } = require('node:perf_hooks');
const { createSecureShopAuditSummaryGraph } = require('../secureshopAuditSummaryGraph');
const { createSecureShopModelQualifier } = require('../../services/secureshopModelQualification');
const { OllamaProvider } = require('../../services/secureshop/providers/ollamaProvider');
const { createLaunchScope } = require('../../services/secureshopConversationBinding');
const MAX_SOURCE_BYTES = 64 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 128 * 1024 * 1024;
const digest = value => createHash('sha256').update(value).digest('hex');
const diagnostics = new WeakMap();
function workerDiagnostic(error) {
  return diagnostics.get(error) || { version: 1, code: 'AUDIT_WORKER_FAILED', stage: 'worker', phase: null };
}
async function withGraphDiagnostics({ provider, signal, transportBudget }, run) {
  let phase = null, providerFailed = false;
  const observed = Object.create(provider);
  for (const [method, label] of [['chat', 'decision'], ['finalResponse', 'final']]) {
    observed[method] = async (...args) => {
      phase = label; providerFailed = false;
      try {
        if(transportBudget){
          const transportTimeoutMs=transportBudget();
          args[0]={...args[0],transportTimeoutMs};
        }
        return await provider[method](...args);
      }
      catch (error) { providerFailed = true; throw error; }
    };
  }
  try { return await run(observed); }
  catch (error) {
    const timeout = signal.aborted && signal.reason?.name === 'TimeoutError';
    const record = { version: 1,
      code: timeout ? 'AUDIT_WORKER_GRAPH_TIMEOUT' : providerFailed ? 'AUDIT_WORKER_PROVIDER_FAILED' : 'AUDIT_WORKER_GRAPH_FAILED',
      stage: timeout || !providerFailed ? 'graph' : 'provider', phase };
    // Only worker-owned state can classify the failure; exception text/codes
    // and provider payloads are never emitted across this diagnostic boundary.
    const failure = new Error('Audit worker did not complete');
    diagnostics.set(failure, record);
    throw failure;
  }
}
async function verifiedFile(filename, expectedHash) {
  const handle = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > MAX_SOURCE_BYTES) throw new Error('AUDIT_WORKER_SOURCE_LIMIT');
    const data = await handle.readFile();
    if (data.length > MAX_SOURCE_BYTES || digest(data) !== expectedHash) throw new Error('AUDIT_WORKER_SOURCE_CHANGED');
    return data;
  } finally { await handle.close(); }
}
async function writeArtifacts(directory, values, maximum = MAX_ARTIFACT_BYTES) {
  let total = 0; const artifacts = {};
  for (const name of ['messages', 'traces', 'effects']) {
    const handle = await fs.open(path.join(directory, `${name}.json`), 'wx', 0o600);
    const hash = createHash('sha256'); let bytes = 0;
    async function write(text) {
      const size = Buffer.byteLength(text);
      if (total + size > maximum) throw new Error('AUDIT_WORKER_ARTIFACT_LIMIT');
      await handle.writeFile(text, 'utf8'); hash.update(text); total += size; bytes += size;
    }
    try {
      await write('[');
      let first = true;
      for (const record of values[name]) {
        await write((first ? '' : ',') + JSON.stringify(record)); first = false;
      }
      await write(']'); await handle.sync();
    } finally { await handle.close(); }
    artifacts[name] = { sha256: hash.digest('hex'), bytes };
  }
  return artifacts;
}
async function execute(input, { admitTool } = {}) {
  const { directory, manifest, baseUrl, model, persona, taskRequestVersion = 1, graphTimeoutMs } = input;
  require('../../services/secureshopAuditSummaryTaskPrompt')
    .createAuditSummaryTaskPrompt({ version: taskRequestVersion, requestedCount: 1 });
  const promptPolicySnapshot=input.promptPolicySnapshot===undefined?undefined:require('../../services/secureshopPromptPolicySnapshot').validatePolicySnapshot(input.promptPolicySnapshot);
  if(promptPolicySnapshot&&promptPolicySnapshot.role!=='admin')throw new Error('AUDIT_PROMPT_POLICY_INVALID');
  createLaunchScope(manifest?.scope);
  if (typeof directory !== 'string' || !path.isAbsolute(directory) || manifest.version !== 1
      || !Number.isSafeInteger(manifest.requestedCount) || manifest.requestedCount < 1
      || !Number.isSafeInteger(manifest.rowCount) || manifest.rowCount < 0 || manifest.rowCount > manifest.requestedCount
      || ![manifest.logSha256, manifest.sourcesSha256].every(value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value))
      || typeof manifest.runId !== 'string' || !manifest.runId || typeof model !== 'string' || !model
      || typeof baseUrl !== 'string'
      || taskRequestVersion===2&&(!Number.isSafeInteger(graphTimeoutMs)||graphTimeoutMs<5000||graphTimeoutMs>180000)
      || taskRequestVersion===1&&graphTimeoutMs!==undefined) throw new Error('AUDIT_WORKER_INVALID_INPUT');
  const directoryStat = await fs.lstat(directory);
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) throw new Error('AUDIT_WORKER_INVALID_INPUT');
  const sourceBytes = await verifiedFile(path.join(directory, 'sources.json'), manifest.sourcesSha256);
  const logBytes = await verifiedFile(path.join(directory, 'log.txt'), manifest.logSha256);
  if (sourceBytes.length + logBytes.length !== manifest.sourceBytes) throw new Error('AUDIT_WORKER_SOURCE_CHANGED');
  const log = logBytes.toString('utf8');
  let observation;
  const messages = [], traces = [], effects = [];
  const provider = new OllamaProvider({ baseUrl, model });
  const graphSignal = AbortSignal.timeout(taskRequestVersion===2?graphTimeoutMs:90000);
  const graphDeadline=taskRequestVersion===2?performance.now()+graphTimeoutMs:undefined;
  const transportBudget=graphDeadline===undefined?undefined:()=>{
    const remaining=Math.min(175000,Math.floor(graphDeadline-performance.now()-5000));
    if(remaining<1000)throw Object.assign(new Error('Audit provider deadline exhausted'),{name:'TimeoutError'});
    return remaining;
  };
  const result = await withGraphDiagnostics({ provider, signal: graphSignal, transportBudget }, async observedProvider => {
  const run = createSecureShopAuditSummaryGraph({ provider: observedProvider, qualifyModel: createSecureShopModelQualifier(provider),
    taskRequestVersion,
    Trace: class { record(row) { traces.push(row); } async flush() {} },
    store: {
      async appendUserMessage(_id, content) { messages.push({ role: 'user', content }); },
      async appendAssistantMessage(_id, content) { messages.push({ role: 'assistant', content }); },
      async appendAssistantToolCalls(_id, calls) { messages.push({ role: 'assistant', content: '', tool_calls: calls.map(call => ({
        id: call.id, type: 'function', function: { name: call.name, arguments: JSON.stringify(call.args) },
      })) }); },
      async appendToolResult(_id, tool_call_id, content) { messages.push({ role: 'tool', tool_call_id, content }); },
      async getMessages() { return [...messages]; }, async remainingBudget() { return 100000000; }, async addUsedTokens() {},
    },
    async readObservation({focusAction}) {
      const factories=require('../../services/secureshopAuditSummaryObservation');
      observation=(focusAction===undefined?factories.createAuditSummaryObservationV2:factories.createAuditSummaryObservationV3)({
        logText:log,requestedCount:manifest.requestedCount,rowCount:manifest.rowCount,
        logSha256:manifest.logSha256,sourcesSha256:manifest.sourcesSha256,
        ...(focusAction===undefined?{}:{focusAction})});
      return observation;
    },
    ...(admitTool ? { admitTool } : {}),
    ...(promptPolicySnapshot?{promptPolicySnapshot}:{}),
  });
  return run({ sessionId: manifest.runId, requestedCount: manifest.requestedCount, persona,
    signal: graphSignal, check: async () => {},
    // These are worker-local observation receipts. The parent must commit the
    // whole job + file digests under its own protected effect before grading.
    async effectWithReceipt(key, callback) {
      const value = await callback(); const receipt = { status: 'completed', effectKey: key, workerLocal: true };
      effects.push(receipt); return { value, receipt };
    },
  });
  });
  if (Buffer.byteLength(result.summary) > 65536) throw new Error('AUDIT_WORKER_OUTPUT_LIMIT');
  effects.push(require('../../services/secureshopAuditModelChain').buildAuditModelChain({
    manifest,messages,traces,effects,observation,result,qualifyModel:createSecureShopModelQualifier(provider),
  }));
  const artifacts = await writeArtifacts(directory, { messages, traces, effects });
  return { version: 1, runId: manifest.runId, ...result, artifacts,
    logSha256: manifest.logSha256, sourcesSha256: manifest.sourcesSha256,
    rowCount: manifest.rowCount, objectiveCredit: false };
}
async function main() {
  const chunks = []; let bytes = 0;
  for await (const chunk of process.stdin) {
    bytes += chunk.length; if (bytes > 2*1024*1024) throw new Error('AUDIT_WORKER_INVALID_INPUT'); chunks.push(chunk);
  }
  const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if(input.promptPolicySnapshot===undefined&&bytes>16384)throw new Error('AUDIT_WORKER_INVALID_INPUT');
  const policy = input.policyAdmission === true
    ? require('../../services/secureshopAuditPolicyChannel').createAuditPolicyChild(process) : null;
  try {
    const result = await execute(input, policy ? { admitTool: context => policy.request(context) } : {});
    process.stdout.write(JSON.stringify(result));
  } finally {
    policy?.close();
    if (process.connected) process.disconnect();
  }
}
if (require.main === module) main().catch(error => { process.stderr.write(JSON.stringify(workerDiagnostic(error)) + '\n'); process.exitCode = 1; });
module.exports = { execute, writeArtifacts, withGraphDiagnostics, workerDiagnostic };
