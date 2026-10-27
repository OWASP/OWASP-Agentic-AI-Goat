'use strict';
const {isDeepStrictEqual}=require('node:util');
const {createConversationBinding}=require('./secureshopConversationBinding');
const {captureFeatureMode}=require('./secureshopFeatureModeAuthority');
const {createProtectedSourceDecision,POLICY_VERSION,digest}=require('./secureshopProtectedSourceDecision');
const {buildBasePrompt}=require('./secureshop/supervisors/basePrompt');
const {buildPolicyBlock}=require('./secureshop/supervisors/policyLoader');
const issued=new WeakMap();
const fail=code=>Object.assign(new Error(code),{code,executionBoundary:true});
const FINAL='The requested server observation is complete. Answer the current request using the latest tool result, do not request another tool, and do not add facts absent from that result.';
const clone=value=>JSON.parse(JSON.stringify(value));
function createCustomerDisclosureAuthority({modeAuthority,launches,personaAuthority,conversations,manifest,observePrivateSource}){
  if(observePrivateSource!==undefined&&typeof observePrivateSource!=='function')throw TypeError('Private source observer must be a function');
  for(const fn of [modeAuthority?.capture,modeAuthority?.assertToken,launches?.assertCurrent,personaAuthority?.capture,conversations?.assertOwned,manifest?.getForRole])
    if(typeof fn!=='function')throw TypeError('Canonical customer disclosure authority required');
  return Object.freeze({async capture({scope,persona,personaSession,sessionId,signal}){
    const binding=createConversationBinding(scope,persona),trustedPersona=Object.freeze({id:binding.shopUserId,role:binding.role});
    if(binding.role!=='customer'||typeof sessionId!=='string'||!sessionId)throw fail('CUSTOMER_DISCLOSURE_AUTHORITY');
    const credential=Object.freeze({...personaSession});
    if(typeof credential.sessionId!=='string'||!credential.sessionId||typeof credential.authorityVersion!=='string'||!/^\d+$/.test(credential.authorityVersion)||BigInt(credential.authorityVersion)<1n)throw fail('CUSTOMER_DISCLOSURE_AUTHORITY');
    const mode=await captureFeatureMode(modeAuthority,binding,'customer_disclosure');
    if(mode.snapshot.featureId!=='customer_disclosure'||mode.snapshot.policyVersion!==POLICY_VERSION||!['vuln','fixed'].includes(mode.snapshot.mode))throw fail('CUSTOMER_DISCLOSURE_AUTHORITY');
    const fence=await personaAuthority.capture({scope:binding,personaId:binding.shopUserId,role:'customer',...credential});
    const expected={...Object.fromEntries(['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].map(k=>[k,binding[k]])),personaId:binding.shopUserId,role:'customer',...credential};
    if(!isDeepStrictEqual(fence?.binding,expected)||typeof fence.assertRemoteAdmission!=='function')throw fail('CUSTOMER_DISCLOSURE_AUTHORITY');
    const check=async()=>{try{signal?.throwIfAborted();await launches.assertCurrent(binding);await conversations.assertOwned(sessionId,binding,trustedPersona,'general');await mode.assertCurrent();await fence.assertRemoteAdmission();await mode.assertCurrent();signal?.throwIfAborted();}
      catch{throw fail(signal?.aborted?'CUSTOMER_DISCLOSURE_CANCELLED':'CUSTOMER_DISCLOSURE_AUTHORITY');}};
    await check();
    // Call the unchanged original loaders once. This is a byte snapshot, not a
    // claimed policy-row-ID/revision snapshot or a second-query freshness proof.
    const externalMcpBlock=typeof manifest.buildExternalMcpPromptBlock==='function'?await manifest.buildExternalMcpPromptBlock():'';
    const policyBlock=await buildPolicyBlock('customer');
    const system=buildBasePrompt('customer',{extra:policyBlock,externalMcpBlock});
    const tools=clone(manifest.getForRole('customer'));
    await check();
    const guard=mode.snapshot.mode==='fixed'?createProtectedSourceDecision(system,{publicToolNames:tools.map(tool=>`${tool.agent}.${tool.tool}`)}):null;
    const metadata=Object.freeze({version:1,policyVersion:POLICY_VERSION,binding,sessionId,
      personaSession:Object.freeze({...credential}),mode:clone(mode.snapshot),sourceSha256:digest(system),
      policyBlockSha256:digest(policyBlock),catalogSha256:digest(JSON.stringify(tools)),protection:'literal-normalized-copy-only',decisionRevision:'trusted-public-tool-name-v1'});
    // Trusted composition/qualification sink only, never result metadata or an
    // HTTP option. Observe the actual once-loaded bytes, not a second DB query.
    if(observePrivateSource){
      try{await observePrivateSource(clone({version:1,system,policyBlock,externalMcpBlock,tools,authority:metadata}));}
      catch{throw fail('CUSTOMER_DISCLOSURE_EVIDENCE_UNAVAILABLE');}
      await check();
    }
    const cap=Object.freeze({});
    issued.set(cap,{binding,sessionId,metadata,check,fence,fixed:mode.snapshot.mode==='fixed',system,policyBlock,externalMcpBlock,tools,guard});
    return cap;
  }});
}
function disclosureFor(cap,{sessionId,role,callerId}){
  const r=issued.get(cap);
  if(!r||r.sessionId!==sessionId||role!=='customer'||r.binding.shopUserId!==callerId)throw fail('CUSTOMER_DISCLOSURE_AUTHORITY');
  const scopedManifest=Object.freeze({getForRole(role){if(role!=='customer')throw fail('CUSTOMER_DISCLOSURE_AUTHORITY');return clone(r.tools);},async buildExternalMcpPromptBlock(){return r.externalMcpBlock;}});
  return Object.freeze({check:r.check,fence:r.fence,fixed:r.fixed,metadata:clone(r.metadata),manifest:scopedManifest,
    inspect:value=>r.fixed?r.guard.inspect(value):value,
    buildPolicyBlock:async role=>{if(role!=='customer')throw fail('CUSTOMER_DISCLOSURE_AUTHORITY');return r.policyBlock;},
    buildBasePrompt(role,options){const actual=buildBasePrompt(role,options);if(role!=='customer'||actual!==r.system)throw fail('CUSTOMER_DISCLOSURE_SOURCE_MISMATCH');return actual;},
    provider(provider,check=r.check){
      if(typeof provider?.chat!=='function'||typeof check!=='function')throw fail('CUSTOMER_DISCLOSURE_AUTHORITY');
      const checked=async()=>{await r.check();await check();await r.check();};
      const wrapped=Object.create(provider);
      for(const method of ['chat','finalResponse','routeWorkflow'])if(typeof provider[method]==='function')Object.defineProperty(wrapped,method,{value:async input=>{
        await checked();
        if(input?.role!=='customer'||input.ownerId!==r.binding.shopUserId||input.system!==(method==='finalResponse'?`${r.system}\n\n${FINAL}`:r.system))throw fail('CUSTOMER_DISCLOSURE_SOURCE_MISMATCH');
        let response;
        try{response=await provider[method].call(provider,input);}catch(error){
          await checked();if(!r.fixed)throw error;
          throw fail('CUSTOMER_DISCLOSURE_PROVIDER_UNAVAILABLE');
        }
        await checked();
        const admitted=r.fixed?r.guard.inspectDecision(response):response;
        await checked();return admitted;
      }});
      return Object.freeze(wrapped);
    },
  });
}
module.exports={createCustomerDisclosureAuthority,disclosureFor};
