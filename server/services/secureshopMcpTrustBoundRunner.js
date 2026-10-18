'use strict';
const {createBoundToolPolicyAdmission}=require('./secureshopBoundToolPolicyAdmission');
const {createBoundAgentRunner}=require('./secureshopBoundAgentRunner');
const {createSecureShopMcpTrustExecutionConfig}=require('./secureshopMcpTrustExecutionConfig');
function unavailable(){return Object.assign(new Error('Bound MCP runner unavailable'),{code:'BOUND_MCP_UNAVAILABLE'});}
function createSecureShopMcpTrustBoundRunner({feature,schema,turns,conversations,conversationRepository,journal,
  provider,checkCurrent,conversationPurpose,capturePersonaAuthority,toolPolicyRepository,promptPolicyAdmission,
  personaSession,modeEpoch,limits={maxSteps:8,maxParallelTools:2}}={}){
  if(toolPolicyRepository!==undefined&&(typeof toolPolicyRepository?.admitTool!=='function'||typeof capturePersonaAuthority!=='function'))throw unavailable();
  if(capturePersonaAuthority!==undefined&&typeof capturePersonaAuthority!=='function')throw unavailable();
  if(personaSession!==undefined&&(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(personaSession?.sessionId||'')
    ||typeof personaSession?.authorityVersion!=='string'
    ||!/^[1-9]\d*$/.test(personaSession.authorityVersion)))throw unavailable();
  if(modeEpoch!==undefined&&(!modeEpoch||typeof modeEpoch!=='object'
    ||!((modeEpoch.generation===null&&modeEpoch.modeStamp===null)
      ||(Number.isSafeInteger(modeEpoch.generation)&&modeEpoch.generation>=0
        &&typeof modeEpoch.modeStamp==='string'&&modeEpoch.modeStamp.length>0))))throw unavailable();
  if(feature?.ready!==true||typeof feature?.createExternalAdapter!=='function'
    ||typeof feature?.assessment?.assessmentFactory!=='function'||typeof checkCurrent!=='function')throw unavailable();
  // Pin the admitted schema for this invocation before it can become model context.
  const admittedSchema=structuredClone(schema);
  const admittedMcp={serverIdentity:admittedSchema?.serverIdentity,schema:admittedSchema,trustScenario:admittedSchema?.trustScenario||feature.application?.trustScenario};
  const config=createSecureShopMcpTrustExecutionConfig(admittedMcp);
  const toolPolicyAdmission=toolPolicyRepository===undefined?undefined:createBoundToolPolicyAdmission({repository:toolPolicyRepository,workflow:admittedMcp.trustScenario==='rogue_registration'?'mcp-rogue':'mcp-rug-pull',declaredTools:config.manifest.getForRole('admin'),admittedMcp});
  const external=feature.createExternalAdapter({checkCurrent,schemaSha256:admittedSchema.schemaSha256});
  const runner=createBoundAgentRunner({turns,conversations,...(promptPolicyAdmission===undefined?{}:{promptPolicyAdmission}),...(toolPolicyAdmission?{toolPolicyAdmission}:{}),repository:conversationRepository,journal,provider,
    manifest:config.manifest,buildBasePrompt:config.buildBasePrompt,buildPolicyBlock:config.buildPolicyBlock,
    checkToolAcl:config.checkToolAcl,assessmentFactory:feature.assessment.assessmentFactory,
    createToolPool:external.createToolPool,observeExternalTool:external.observeExternalTool,
    ...(capturePersonaAuthority===undefined?{}:{capturePersonaAuthority,personaLocalToolModes:Object.freeze({})}),
    createLocalTools:async()=>Object.freeze({}),conversationPurpose,limits,
    resultMetadata:({execution,requestId})=>Object.freeze({kind:'mcp_trust_schema',version:1,
      trustScenario:admittedMcp.trustScenario,serverIdentity:admittedSchema.serverIdentity,
      schemaVersion:admittedSchema.version,schemaSha256:admittedSchema.schemaSha256,
      runId:execution.runId,requestId,
      modeGeneration:modeEpoch?.generation??null,modeStamp:modeEpoch?.modeStamp??null,
      ...(personaSession?{personaSessionId:personaSession.sessionId.toLowerCase(),authorityVersion:personaSession.authorityVersion}:{})})});
  return Object.freeze({runner,manifest:config.manifest,external});
}
module.exports={createSecureShopMcpTrustBoundRunner};
