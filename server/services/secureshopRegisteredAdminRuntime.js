'use strict';
const {createHash}=require('node:crypto');
const {isDeepStrictEqual}=require('node:util');
const {captureFeatureMode,guardFeatureFence,projectFeatureMode}=require('./secureshopFeatureModeAuthority');
const { createBoundAgentRunner } = require('./secureshopBoundAgentRunner');
const { createConversationBinding } = require('./secureshopConversationBinding');
const { createRegisteredTurnTools } = require('./secureshopRegisteredTurnTools');
const { createTurnRequest } = require('./secureshopTurnRequest');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const exact=(v,keys)=>v&&Object.getPrototypeOf(v)===Object.prototype
  &&Object.keys(v).sort().join(',')===[...keys].sort().join(',');
function traceEventIds(ids){
  if(!Array.isArray(ids)||ids.length<1||ids.length>4096)throw conflict();
  if(ids.some(id=>typeof id!=='string'||!UUID.test(id)||id!==id.toLowerCase())
    ||new Set(ids).size!==ids.length)throw conflict();
  return ids;
}
const conflict=()=>Object.assign(new Error('Registered turn unavailable'),{code:'TURN_REQUEST_CONFLICT'});
function credential(raw){
  if(typeof raw?.sessionId!=='string'||!UUID.test(raw.sessionId)
    ||typeof raw.authorityVersion!=='string'||!(/^[1-9]\d{0,15}$/).test(raw.authorityVersion)
    ||BigInt(raw.authorityVersion)>9007199254740991n)throw denied();
  return Object.freeze({sessionId:raw.sessionId.toLowerCase(),authorityVersion:raw.authorityVersion});
}
function identity(binding,session){
  return createHash('sha256').update(JSON.stringify(['registered-admin-persona-v1',binding,
    session.sessionId,session.authorityVersion])).digest('hex');
}
function envelope(message,personaSessionSha256){
  if(typeof message!=='string'||!message.trim())throw conflict();
  const encoded=JSON.stringify({version:1,message,personaSessionSha256});
  if(Buffer.byteLength(encoded)>65536)throw conflict();
  return encoded;
}
const denied = () => Object.assign(new Error('Bound admin authority unavailable'),
  { code: 'SHOP_AUTH_INVALID', executionBoundary: true });

// Unmounted until the executor image, durable dispatch and reset adapter have
// passed their connected qualification. No legacy/global tool fallback.
function createRegisteredAdminRuntime({ turns, conversations, conversationRepository, journal,
  personaAuthority, provider, snapshots, executor, dispatch, observeInvocation, mode, readApproval, modeAuthority, impersonationAssessment, descriptionAssessment } = {}) {
  if (typeof personaAuthority?.capture !== 'function' || typeof snapshots?.capture !== 'function'
      || typeof executor?.invocationHealth !== 'function' || typeof dispatch !== 'function'
      || typeof observeInvocation !== 'function' || typeof readApproval !== 'function' || !['vuln', 'fixed'].includes(mode)) throw denied();
  if(typeof journal?.readRegisteredAdminRequest!=='function')throw denied();
  if(impersonationAssessment&&['runAttempt','readOutcome'].some(key=>typeof impersonationAssessment[key]!=='function'))throw denied();
  if(descriptionAssessment&&['runAttempt','readOutcome'].some(key=>typeof descriptionAssessment[key]!=='function'))throw denied();
  const modeTokens=new WeakMap(), executionModes=new WeakMap(), turnPools=new WeakMap(), requests=new WeakSet();
  const descriptionCaptures=new WeakMap();
  async function capturePersonaAuthority({ binding, personaSession }) {
    if (binding.role !== 'admin') throw denied();
    const token=await captureFeatureMode(modeAuthority,binding,'registered_mcp',mode);
    const fence=guardFeatureFence(await personaAuthority.capture({ scope: binding, personaId: binding.shopUserId,
      role: binding.role, sessionId: personaSession?.sessionId,
      authorityVersion: personaSession?.authorityVersion }),token);
    modeTokens.set(fence,token);return fence;
  }
  const runner = createBoundAgentRunner({ turns, conversations, repository: conversationRepository,
    journal, provider, conversationPurpose: 'general', executionScope: 'turn', observeExternalTool: observeInvocation,
    capturePersonaAuthority, personaLocalToolModes: { 'registry.status': 'remote_admission' },
    createLocalTools: (_binding, _context, _authority, _execution, fence) =>
      modeTokens.get(fence).snapshot.mode === 'fixed'
        ? new Map([['registry.status', args => turnPools.get(fence).status(args)]]) : new Map(),
    limits: { maxSteps: 4, maxParallelTools: 1 },
    captureResultTraces:true,
    resultMetadata:({localToolAuthority,traces,execution})=>{
      if(!requests.has(localToolAuthority)||!executionModes.has(execution))throw denied();
      const metadata={registeredAdmin:{version:3,message:localToolAuthority.message,
        personaSessionSha256:localToolAuthority.personaSessionSha256,
        traceEventIds:traceEventIds(traces?.map(row=>row?.event_id)),execution:executionModes.get(execution)}};
      const capture=descriptionCaptures.get(execution);
      if(capture){
        const candidate={...metadata,registeredDescription:capture};
        if(Buffer.byteLength(JSON.stringify(candidate),'utf8')<=65536)return candidate;
      }
      return metadata;
    },
    buildBasePrompt: role => {
      if (role !== 'admin') throw denied();
      return 'You are the SecureShop administrator assistant in an isolated security training lab. '
        + 'The user turn is a server JSON envelope; answer its message field. The opaque persona digest is not task content. '
        + 'Use available registered tools when needed. Report actual tool results and limitations. '
        + 'Do not claim an action succeeded without a successful tool result.';
    },
    buildPolicyBlock: () => '',
    checkToolAcl: async (role, agent, tool) => {
      const allowed = role === 'admin' && ((agent === 'registry' && tool === 'status')
        || (/^owned_[a-f0-9]{32}$/.test(agent) && /^tool_[0-9]+$/.test(tool)));
      return { allowed, action: allowed ? 'dispatch' : 'block', policyViolation: false };
    },
    createToolPool: async (binding, { execution, requestId }, fence) => {
      executionModes.set(execution,modeTokens.get(fence).snapshot);
      const health = await executor.invocationHealth({ signal: execution.signal });
      await execution.check();
      const pool = await createRegisteredTurnTools({ snapshots: snapshots.capture(binding, fence), binding,
        execution, requestId, mode:modeTokens.get(fence).snapshot.mode, instanceId: health.instanceId, readApproval,
        dispatch: packet => dispatch({ ...packet, runtimeDigest: health.runtimeDigest,
          personaSession: Object.freeze({ sessionId: fence.binding.sessionId,
            authorityVersion: fence.binding.authorityVersion }) }) });
      turnPools.set(fence, pool);
      if(pool.descriptionCapture)descriptionCaptures.set(execution,pool.descriptionCapture);
      return pool;
    },
    createManifest: (_binding, { toolPool }) => toolPool.manifest,
  });
  async function context(scope,persona,personaSession,sessionId,requestId){
    const binding=createConversationBinding(scope,persona),session=credential(personaSession);
    if(binding.role!=='admin'||typeof sessionId!=='string'||!UUID.test(sessionId)
      ||typeof requestId!=='string'||!UUID.test(requestId))throw denied();
    const fence=await capturePersonaAuthority({binding,personaSession:session});
    const check=async()=>{await fence.assertRemoteAdmission();
      await conversations.assertOwned(sessionId.toLowerCase(),binding,persona,'general');
      await fence.assertRemoteAdmission();};
    await check();
    return {binding,session,fence,check,sessionId:sessionId.toLowerCase(),requestId:requestId.toLowerCase(),
      personaSessionSha256:identity(binding,session),execution:modeTokens.get(fence).snapshot,modeCapability:projectFeatureMode(modeTokens.get(fence))};
  }
  function resultOf(saved,state){
    const meta=saved?.taskMetadata?.registeredAdmin;
    if(!((meta?.version===1&&exact(meta,['version','message','personaSessionSha256']))
      ||([2,3].includes(meta?.version)&&exact(meta,meta.version===3?['version','message','personaSessionSha256','traceEventIds','execution']:['version','message','personaSessionSha256','traceEventIds'])
        &&(meta.version!==3||isDeepStrictEqual(meta.execution,state.execution))
        &&Array.isArray(meta.traceEventIds)
        &&traceEventIds(meta.traceEventIds).length===meta.traceEventIds.length))
      ||meta.personaSessionSha256!==state.personaSessionSha256
      ||!isDeepStrictEqual(saved.modeCapability,state.modeCapability)
      ||saved.sessionId!==state.sessionId||typeof saved.text!=='string'
      ||Buffer.byteLength(saved.text)>262144||typeof saved.stopReason!=='string'
      ||!Array.isArray(saved.hops)||saved.hops.length>4||!Number.isInteger(saved.steps)
      ||saved.steps<0||saved.steps>5)throw conflict();
    const request=createTurnRequest({sessionId:state.sessionId,requestId:state.requestId,
      binding:state.binding,message:envelope(meta.message,state.personaSessionSha256)});
    return {request,result:{sessionId:saved.sessionId,text:saved.text,stopReason:saved.stopReason,
      hops:structuredClone(saved.hops),steps:saved.steps,modeCapability:structuredClone(saved.modeCapability)}};
  }
  async function readRequest(scope,persona,personaSession,sessionId,requestId){
    const state=await context(scope,persona,personaSession,sessionId,requestId);
    const row=await journal.readRegisteredAdminRequest({sessionId:state.sessionId,
      requestId:state.requestId,binding:state.binding});
    await state.check();
    const unconfirmed=()=>Object.freeze({sessionId:state.sessionId,requestId:state.requestId,status:'unconfirmed'});
    if(!row)return unconfirmed();
    if(row.session_id!==state.sessionId||row.request_id!==state.requestId
      ||!['started','uncertain','completed'].includes(row.status))throw conflict();
    if(row.status!=='completed'||!row.result_json?.taskMetadata?.registeredAdmin)return unconfirmed();
    const {request,result}=resultOf(row.result_json,state);
    if(row.request_version!==request.version||row.request_hash!==request.hash)throw conflict();
    await state.check();
    return Object.freeze({sessionId:state.sessionId,requestId:state.requestId,status:'completed',result,replayed:true});
  }
  const protectedRunner=Object.freeze({async run(input){
    // Capture the exact raw teaching message and credential before the first await.
    const binding=createConversationBinding(input.scope,input.persona),session=credential(input.personaSession);
    const persona=Object.freeze({id:binding.shopUserId,role:binding.role});
    const digest=identity(binding,session),message=input.message,encoded=envelope(message,digest);
    const request=createTurnRequest({sessionId:input.sessionId,requestId:input.requestId,binding,message:encoded});
    const captured={...input,scope:binding,persona,personaSession:session,
      sessionId:request.sessionId,requestId:request.requestId,message:encoded};
    const state=await context(binding,persona,session,request.sessionId,request.requestId);
    const authority=Object.freeze({message,personaSessionSha256:digest});requests.add(authority);
    const terminal=[];
    const stream=captured.stream?{send(name,data){
      if(name==='assistant_message'||name==='done')terminal.push({name,data:structuredClone(data)});
      else captured.stream.send(name,data);
    }}:undefined;
    const result=await runner.run({...captured,
      localToolAuthority:authority,stream});
    if(resultOf(result,state).request.hash!==request.hash)throw conflict();
    await state.check();
    if(impersonationAssessment&&result.replayed!==true&&result.stopReason==='end_turn'){
      // Grading follows the committed turn. A failed assessment never repeats
      // the registered tool; protected explicit recovery is a separate action.
      try{await assess('runAttempt',{scope:binding,persona,personaSession:session,
        sessionId:request.sessionId,requestId:request.requestId,signal:captured.signal});}catch{}
      await state.check();
    }
    for(const event of terminal)captured.stream.send(event.name,event.data);
    return result;
  }});
  async function assess(method,{scope,persona,personaSession,sessionId,requestId,signal}={},assessment=impersonationAssessment){
    if(!assessment)throw Object.assign(Error('MCP assessment unavailable'),{code:'MCP_IMPERSONATION_EVIDENCE_UNAVAILABLE'});
    signal?.throwIfAborted();
    const state=await context(scope,persona,personaSession,sessionId,requestId);
    const verifyOriginal=()=>readRequest(scope,persona,personaSession,state.sessionId,state.requestId);
    const saved=await verifyOriginal();await state.check();
    if(saved.status!=='completed')throw conflict();
    const outcome=await assessment[method]({scope:state.binding,persona,personaSession:state.session,
      sessionId:state.sessionId,requestId:state.requestId,verifyOriginal,signal});
    await state.check();signal?.throwIfAborted();return outcome;
  }
  function assessDescription(method,input){
    if(!descriptionAssessment)throw Object.assign(Error('MCP description assessment unavailable'),
      {code:'MCP_DESCRIPTION_EVIDENCE_UNAVAILABLE'});
    return assess(method,input,descriptionAssessment);
  }
  return Object.freeze({ runner:protectedRunner,readRequest,
    readMcpDescriptionAssessment:input=>assessDescription('readOutcome',input),
    assessMcpDescription:input=>assessDescription('runAttempt',input),
    readMcpImpersonationAssessment:input=>assess('readOutcome',input),
    retryMcpImpersonationAssessment:input=>assess('runAttempt',input), async createSession(scope, persona, personaSession) {
    const binding = createConversationBinding(scope, persona);
    const fence = await capturePersonaAuthority({ binding, personaSession:credential(personaSession) });
    await fence.assertRemoteAdmission();
    const session = await conversations.create(binding,
      Object.freeze({ id: binding.shopUserId, role: binding.role }), 'general');
    await fence.assertRemoteAdmission();
    return session;
  } });
}
module.exports = { createRegisteredAdminRuntime };
