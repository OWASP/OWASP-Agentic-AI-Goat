'use strict';
const {createBoundToolPolicyAdmission}=require('./secureshopBoundToolPolicyAdmission');
const {resolveObjectiveGradingDependencies}=require('./objectiveGradingCore');
const {createSecureShopBoundSsrfRepository}=require('../database/postgres/secureshopBoundSsrfRepository');
const {createObjectiveJudgmentRepository}=require('../database/postgres/objectiveJudgmentRepository');
const {createWorkshopProgressRepository}=require('../database/postgres/workshopProgressRepository');
const {createBoundAgentRunner}=require('./secureshopBoundAgentRunner');
const {createSecureShopModelQualifier}=require('./secureshopModelQualification');
const {createSecureShopSsrfApplication}=require('./secureshopSsrfApplication');
const {createSecureShopSsrfAssessment}=require('./secureshopSsrfAssessment');
const {createSecureShopSsrfExternalAdapter}=require('./secureshopSsrfExternalAdapter');
const {createSecureShopSsrfExecutionConfig}=require('./secureshopSsrfExecutionConfig');
const {createSecureShopSsrfAvailability}=require('./secureshopSsrfAvailability');
const {createSecureShopSsrfResetAdapter}=require('./secureshopSsrfResetAdapter');
const {OBJECTIVE:HTML_OBJECTIVE}=require('./secureshopPolicyFinalHtmlContract');
const {createPolicyFinalHtmlOriginalReader}=require('./secureshopPolicyFinalHtmlOriginal');
const {createPolicyFinalHtmlAssessment}=require('./secureshopPolicyFinalHtmlAssessment');
const {captureFeatureMode,guardFeatureFence}=require('./secureshopFeatureModeAuthority');
function unavailable(){return Object.assign(new Error('Controlled SSRF composition unavailable'),{code:'BOUND_SSRF_UNAVAILABLE'});}
function createSecureShopSsrfComposition({enabled=false,identityPool,agentsPool,provider,judge,resetComposition,targetPool,upstreamPool,personaAuthority,modeAuthority,personaBindings,gradingCore,toolPolicyRepository,promptPolicyRepository,policyOutputBrowserQualification}={}){
  const grading=gradingCore===undefined?undefined:resolveObjectiveGradingDependencies(gradingCore,{identityPool,...(Object.hasOwn(arguments[0]||{},'personaBindings')?{personaBindings}:{})});
  if(grading)personaBindings=grading.personaBindings;
  if(personaBindings!==undefined&&(typeof personaBindings?.capture!=='function'||typeof personaAuthority?.capture!=='function'))throw unavailable();
  if(typeof enabled!=='boolean')throw unavailable();if(!enabled)return Object.freeze({ready:false});
  const promptPolicyOptions = require('./secureshopPromptPolicyRunnerOptions').promptPolicyRunnerOptions(promptPolicyRepository, personaAuthority);
  if(toolPolicyRepository!==undefined&&(typeof toolPolicyRepository?.admitTool!=='function'||typeof personaAuthority?.capture!=='function'))throw unavailable();
  const launches=resetComposition?.launches,conversations=resetComposition?.conversationService,turns=resetComposition?.turns;
  const bundle=resetComposition?.ssrf;
  targetPool ||= bundle?.targetPool;
  if(bundle && targetPool!==bundle.targetPool)throw unavailable();
  if(typeof identityPool?.query!=='function'||typeof agentsPool?.query!=='function'||typeof agentsPool?.connect!=='function'
    ||typeof launches?.assertCurrent!=='function'||typeof launches?.reserveSsrfTarget!=='function'||typeof launches?.readExistingSsrfTarget!=='function'
    ||typeof resetComposition?.cleanupAuthority?.checkTarget!=='function'||typeof conversations?.create!=='function'
    ||typeof turns?.run!=='function'||typeof resetComposition?.journal?.claim!=='function'
    ||typeof resetComposition?.conversations?.appendTraces!=='function'||typeof provider?.chat!=='function'
    ||typeof targetPool?.issue!=='function'||typeof upstreamPool?.callTool!=='function')throw unavailable();
  const availability=bundle?.availability || createSecureShopSsrfAvailability(identityPool);
  const current=async value=>{await launches.assertCurrent(value);};
  const repository=bundle?.repository || createSecureShopBoundSsrfRepository(agentsPool,{checkCurrent:current,
    checkCleanup:value=>resetComposition.cleanupAuthority.checkTarget({...value,targetKind:'controlled_ssrf',fromGeneration:value.generation})});
  const receipts=grading?.receipts || createObjectiveJudgmentRepository(identityPool,...(personaBindings===undefined?[]:[{personaBindings}])),progress=grading?.progress || createWorkshopProgressRepository(identityPool);
  let application,runner,htmlRunner;
  const assessment=createSecureShopSsrfAssessment({receipts,progress,...(personaBindings===undefined?{}:{personaBindings}),...(judge?{judge}:{}),qualifyModel:createSecureShopModelQualifier(provider),
    resolveTarget:(binding,fence)=>{
      return application.resolveExistingTarget(binding);
    },readInvocation:(binding,id)=>repository.readInvocation(binding,id)});
  const external=createSecureShopSsrfExternalAdapter({resolveRequest:(binding,context)=>application.resolveRequest(binding,context),
    targetPool,upstreamPool,recordInvocation:(binding,input,persona,fence)=>fence ? fence.withPersonaEffect(client=>repository.recordInvocationWithClient(client,binding,input,persona,{effectTimeoutMs:3000})) : repository.recordInvocation(binding,input,persona),checkCurrent:async request=>{await current(request);await availability.assertObjective(request.resourceKind==='html-policy'?HTML_OBJECTIVE:'ss_controlled_ssrf');}});
  const config=createSecureShopSsrfExecutionConfig();
  const toolPolicyAdmission=toolPolicyRepository===undefined?undefined:createBoundToolPolicyAdmission({repository:toolPolicyRepository,workflow:'ssrf',declaredTools:config.manifest.getForRole('customer')});
  const runnerOptions={turns,conversations,...promptPolicyOptions,...(toolPolicyAdmission?{toolPolicyAdmission}:{}),repository:resetComposition.conversations,journal:resetComposition.journal,provider,
    ...(personaAuthority?{capturePersonaAuthority:async({binding,personaSession})=>{
      const mode=await captureFeatureMode(modeAuthority,binding,'controlled_ssrf','vuln');
      const fence=await personaAuthority.capture({scope:binding,personaId:binding.shopUserId,role:binding.role,sessionId:personaSession?.sessionId,authorityVersion:personaSession?.authorityVersion});
      return guardFeatureFence(fence,mode);
    },personaLocalToolModes:{}}:{}),
    manifest:config.manifest,buildBasePrompt:config.buildBasePrompt,buildPolicyBlock:config.buildPolicyBlock,checkToolAcl:config.checkToolAcl,
    assessmentFactory:assessment.assessmentFactory,createToolPool:external.createToolPool,observeExternalTool:external.observeExternalTool,
    enterFinalResponseAfterExternalTool:async packet => {
      if (!packet?.externalRecord?.invocation || packet.externalRecord.effectReceipt?.status !== 'completed') return false;
      return true;
    },
    createLocalTools:async()=>Object.freeze({}),limits:{maxSteps:8,maxParallelTools:1}};
  runner=createBoundAgentRunner(runnerOptions);
  htmlRunner=createBoundAgentRunner({...runnerOptions,assessmentFactory:undefined,captureResultTraces:true,
    resultMetadata:async({execution,binding,traces})=>{
      const mode=await captureFeatureMode(modeAuthority,binding,'controlled_ssrf');await mode.assertCurrent();
      return {policyFinalHtml:{version:1,runId:execution.runId,mode:mode.snapshot,traceEventIds:traces.map(row=>row.event_id)}};
    }});
  application=createSecureShopSsrfApplication({launches,repository,targetPool,conversations,availability,personaAuthority,modeAuthority,
    runAgent:({resourceKind,...input})=>(resourceKind==='html-policy'?htmlRunner:runner).run(input)});
  const originalReader=createPolicyFinalHtmlOriginalReader({repository,conversations:resetComposition.conversations,
    agentsPool,identityPool,resolveTarget:application.resolveExistingTarget,qualifyModel:createSecureShopModelQualifier(provider)});
  let ownedBrowser,browserClosed=false;
  const browser=policyOutputBrowserQualification||{
    readComponent(){if(browserClosed)throw unavailable();ownedBrowser ||= require('./secureshopPolicyOutputBrowserQualification').createSecureShopPolicyOutputBrowserQualification();return ownedBrowser.readComponent();},
    qualifyPolicyOutput(input){if(browserClosed)throw unavailable();ownedBrowser ||= require('./secureshopPolicyOutputBrowserQualification').createSecureShopPolicyOutputBrowserQualification();return ownedBrowser.qualifyPolicyOutput(input);},
  };
  const htmlAssessment=personaAuthority&&personaBindings&&modeAuthority?createPolicyFinalHtmlAssessment({identityPool,agentsPool,launches,
    conversationRepository:resetComposition.conversations,coordinator:resetComposition.runCoordinator,journal:resetComposition.journal,
    personaAuthority,personaBindings,modeAuthority,publicationModes:require('../database/postgres/secureshopModeRepository').createSecureShopModeRepository(identityPool),
    availability,receipts,progress,judge:judge||require('../agent-runtime/objectiveJudge').createObjectiveJudge(),qualifyModel:createSecureShopModelQualifier(provider),originalReader,browserQualification:browser}):null;
  const reset=createSecureShopSsrfResetAdapter({repository,targetPool,cleanupAuthority:resetComposition.cleanupAuthority});
  return Object.freeze({ready:true,application,runner,repository,assessment,htmlAssessment,reset,availability,async close(){if(browserClosed)return;browserClosed=true;if(ownedBrowser)await ownedBrowser.close();}});
}
module.exports={createSecureShopSsrfComposition};
