'use strict';
const path = require('node:path');
const { performance } = require('node:perf_hooks');
const { spawn } = require('node:child_process');
const { verifyAuditWorkerArtifacts } = require('./secureshopAuditArtifactVerification');
const WORKER = path.join(__dirname, '../agent-runtime/workers/secureshopAuditWorker.js');
const failure = code => Object.assign(new Error('Audit worker did not complete'), { code });
function parseWorkerDiagnostic(bytes) {
  try {
    if (bytes.length > 512) return null;
    const value = JSON.parse(bytes.toString('utf8'));
    if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).sort().join(',') !== 'code,phase,stage,version' || value.version !== 1
      || ![null, 'decision', 'final'].includes(value.phase)) return null;
    const stages = { AUDIT_WORKER_FAILED: 'worker', AUDIT_WORKER_GRAPH_TIMEOUT: 'graph',
      AUDIT_WORKER_GRAPH_FAILED: 'graph', AUDIT_WORKER_PROVIDER_FAILED: 'provider' };
    if (!Object.hasOwn(stages, value.code) || stages[value.code] !== value.stage
      || (value.code === 'AUDIT_WORKER_FAILED' && value.phase !== null)
      || (value.code === 'AUDIT_WORKER_PROVIDER_FAILED' && value.phase === null)) return null;
    return value;
  } catch { return null; }
}

// A V8 heap budget and bounded transport protect this application job; they
// are not OS memory/CPU quotas and do not constrain the external Ollama host.
async function runSecureShopAuditWorker({ spool, baseUrl, model, persona, checkCurrent, signal,
  timeoutMs = 100000, admitTool, promptPolicySnapshot, taskRequestVersion = 1,
  now = () => performance.now() } = {}) {
  if (!spool?.manifest || typeof spool.directory !== 'string' || typeof checkCurrent !== 'function'
      || typeof baseUrl !== 'string' || typeof model !== 'string'
      || ![1, 2].includes(taskRequestVersion)
      || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1
      || timeoutMs > (taskRequestVersion===2?190000:120000)
      || taskRequestVersion===2&&timeoutMs<20000 || typeof now!=='function') throw new TypeError('Owned audit worker request required');
  const hostStartedAt=taskRequestVersion===2?now():undefined;
  if(admitTool!==undefined&&typeof admitTool!=='function')throw new TypeError('Invalid audit policy admission');
  const admittedPrompt=promptPolicySnapshot===undefined?undefined:require('./secureshopPromptPolicySnapshot').validatePolicySnapshot(promptPolicySnapshot);
  if(admittedPrompt&&admittedPrompt.role!=='admin')throw failure('AUDIT_PROMPT_POLICY_INVALID');
  const workerEnv = { PATH: path.dirname(process.execPath), LANG: 'C.UTF-8' };
  const configuredContext = process.env.OLLAMA_CONTEXT_WINDOW;
  if (configuredContext !== undefined && configuredContext !== '') {
    // Carry only the provider's validated context setting across the worker
    // boundary; credentials and other parent process settings stay private.
    workerEnv.OLLAMA_CONTEXT_WINDOW = String(require('../agent-runtime/providers/langchainProvider')
      .ollamaContextWindow({}, { OLLAMA_CONTEXT_WINDOW: configuredContext }));
  }
  let policy;
  const check = async () => { signal?.throwIfAborted(); await checkCurrent(); signal?.throwIfAborted(); };
  await check();
  // Admission checks may wait on the live owner. Do not grant the child time
  // already spent here; the parent only transferred a remaining duration.
  const hostTimeoutMs=taskRequestVersion===2?Math.floor(timeoutMs-(now()-hostStartedAt)):timeoutMs;
  if(taskRequestVersion===2&&(!Number.isSafeInteger(hostTimeoutMs)||hostTimeoutMs<20000||hostTimeoutMs>190000))
    throw failure('AUDIT_WORKER_TIMEOUT');
  // Transfer a duration, never the parent process's performance.now() origin.
  const graphTimeoutMs=taskRequestVersion===2?Math.min(180000,hostTimeoutMs-10000):undefined;
  const input = JSON.stringify({ directory: spool.directory, manifest: spool.manifest, baseUrl, model, persona,
    taskRequestVersion, ...(graphTimeoutMs===undefined?{}:{graphTimeoutMs}),
    ...(admittedPrompt?{promptPolicySnapshot:admittedPrompt}:{}), ...(admitTool ? {policyAdmission:true} : {}) });
  if (Buffer.byteLength(input) > (admittedPrompt?2*1024*1024:16384)) throw failure('AUDIT_WORKER_INPUT_LIMIT');
  const output = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--max-old-space-size=256', WORKER], {
      env: workerEnv, stdio: admitTool ? ['pipe', 'pipe', 'pipe', 'ipc'] : ['pipe', 'pipe', 'pipe'],
    });
    let problem, ended = false, killTimer, checking = false, stdoutBytes = 0, stderrBytes = 0;
    const chunks = [], diagnosticChunks = [];
    const stop = error => {
      if (ended || problem) return;
      problem = error; child.kill('SIGTERM');
      killTimer = setTimeout(() => { if (!ended) child.kill('SIGKILL'); }, 2000);
    };
    if(admitTool){
      policy=require('./secureshopAuditPolicyChannel').createAuditPolicyParent({
        runId:spool.manifest.runId,requestedCount:spool.manifest.requestedCount,taskRequestVersion,admit:admitTool,check,
        send:message=>{if(!ended&&!problem)child.send(message,error=>{if(error)stop(failure('AUDIT_WORKER_TRANSPORT_FAILED'));});},stop});
      child.on('message',message=>{void policy.receive(message);});
    }
    const abort = () => stop(signal.reason || failure('AUDIT_WORKER_CANCELLED'));
    const deadline = setTimeout(() => stop(failure('AUDIT_WORKER_TIMEOUT')), hostTimeoutMs);
    const fence = setInterval(async () => {
      if (checking || ended || problem) return;
      checking = true;
      try { await check(); } catch (error) { stop(error); } finally { checking = false; }
    }, 250);
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
    child.stdout.on('data', chunk => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > 128 * 1024) stop(failure('AUDIT_WORKER_OUTPUT_LIMIT'));
      else if (!problem) chunks.push(chunk);
    });
    child.stderr.on('data', chunk => {
      stderrBytes += chunk.length;
      if (stderrBytes > 16384) stop(failure('AUDIT_WORKER_DIAGNOSTIC_LIMIT'));
      else if (stderrBytes <= 512) diagnosticChunks.push(chunk);
    });
    child.on('error', () => stop(failure('AUDIT_WORKER_START_FAILED')));
    child.stdin.on('error', () => stop(failure('AUDIT_WORKER_TRANSPORT_FAILED')));
    child.on('close', (code, exitSignal) => {
      ended = true; policy?.close(); clearTimeout(deadline); clearTimeout(killTimer); clearInterval(fence);
      signal?.removeEventListener('abort', abort);
      if (problem) { reject(problem); return; }
      if (code !== 0 || exitSignal) {
        const diagnostic = code === 1 && !exitSignal && stderrBytes <= 512
          ? parseWorkerDiagnostic(Buffer.concat(diagnosticChunks)) : null;
        reject(diagnostic ? Object.assign(failure(diagnostic.code), { stage: diagnostic.stage, phase: diagnostic.phase })
          : failure('AUDIT_WORKER_FAILED')); return;
      }
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(failure('AUDIT_WORKER_INVALID_RESULT')); }
    });
    child.stdin.end(input);
  });
  await check();
  if (output?.version !== 1 || output.runId !== spool.manifest.runId
      || output.logSha256 !== spool.manifest.logSha256 || output.sourcesSha256 !== spool.manifest.sourcesSha256
      || output.rowCount !== spool.manifest.rowCount || output.provider !== 'ollama' || output.model !== model
      || typeof output.summary !== 'string' || !output.summary.trim() || output.objectiveCredit !== false) {
    throw failure('AUDIT_WORKER_INVALID_RESULT');
  }
  const artifacts = await verifyAuditWorkerArtifacts({ directory: spool.directory,
    artifacts: output.artifacts, manifest: spool.manifest, checkCurrent: check, signal });
  if(policy||admittedPrompt){
    // Verify the persisted child trace against parent-issued decisions, not a
    // child-only success flag. Artifact verification above binds these bytes.
    const fs=require('node:fs/promises'),{constants}=require('node:fs');
    const handle=await fs.open(path.join(spool.directory,'traces.json'),constants.O_RDONLY|constants.O_NOFOLLOW);
    let rows;
    try{
      const stat=await handle.stat();
      if(!stat.isFile()||stat.size!==artifacts.traces.bytes||stat.size>128*1024*1024)throw failure('AUDIT_POLICY_TRACE_INVALID');
      const bytes=await handle.readFile();
      if(require('node:crypto').createHash('sha256').update(bytes).digest('hex')!==artifacts.traces.sha256)throw failure('AUDIT_POLICY_TRACE_INVALID');
      rows=JSON.parse(bytes.toString('utf8'));
    }finally{await handle.close();}
    if(!Array.isArray(rows))throw failure('AUDIT_POLICY_TRACE_INVALID');
    const snapshots=rows.filter(row=>row.kind==='prompt_policy_snapshot');
    if(admittedPrompt){
      const row=snapshots[0];let actual;
      try{actual=JSON.parse(row?.result_json);}catch{throw failure('AUDIT_PROMPT_POLICY_TRACE_INVALID');}
      const expected={policyVersion:admittedPrompt.policyVersion,sha256:admittedPrompt.sha256,role:'admin',policyCount:admittedPrompt.policies.length};
      if(snapshots.length!==1||row.step!==0||row.actor!=='supervisor'
        ||!actual||Object.keys(actual).length!==4||Object.keys(expected).some(key=>actual[key]!==expected[key]))throw failure('AUDIT_PROMPT_POLICY_TRACE_INVALID');
    }else if(snapshots.length)throw failure('AUDIT_PROMPT_POLICY_TRACE_INVALID');
    if(policy){
    const decisions=rows.filter(row=>row.kind==='policy_decision');
    if(decisions.length!==policy.receipts.size)throw failure('AUDIT_POLICY_TRACE_INVALID');
    const seen=new Set();
    for(const row of decisions){
      const entry=JSON.parse(row.params_json),id=`${row.step}:${entry.callId}`,issued=policy.receipts.get(id);
      if(seen.has(id)||!issued||row.actor!=='supervisor'||row.agent_ns!=='audit'||row.tool_name!=='summarize_anomalies'
        ||JSON.stringify(entry.admission)!==JSON.stringify(issued))throw failure('AUDIT_POLICY_TRACE_INVALID');
      seen.add(id);
      const calls=rows.filter(value=>value.kind==='local_tool_call'&&value.step===row.step&&value.agent_ns==='audit'&&value.tool_name==='summarize_anomalies');
      if(calls.length!==(issued.action==='dispatch'?1:0)||calls.some(value=>value.params_json!==JSON.stringify(policy.argumentsByInvocation.get(id))))throw failure('AUDIT_POLICY_TRACE_INVALID');
    }
    if(rows.filter(row=>row.kind==='local_tool_call').length!==[...policy.receipts.values()].filter(row=>row.action==='dispatch').length)throw failure('AUDIT_POLICY_TRACE_INVALID');
    }
    await check();
  }
  return Object.freeze({ ...output, artifacts });
}
module.exports = { runSecureShopAuditWorker, parseWorkerDiagnostic };
