'use strict';
const {captureFeatureMode,guardFeatureFence}=require('./secureshopFeatureModeAuthority');

const {
  createBoundAgentRunner
} = require('./secureshopBoundAgentRunner');
const {
  createSecureShopPricingExecutionConfig
} = require('./secureshopPricingExecutionConfig');
const {
  createSecureShopBoundPricingTools
} = require('./secureshopBoundPricingTools');
const {
  createOwnedCompetitorObservation
} = require('./secureshopOwnedCompetitorObservation');
const {
  promptPolicyRunnerOptions
} = require('./secureshopPromptPolicyRunnerOptions');
const {
  createLaunchScope,
  createConversationBinding
} = require('./secureshopConversationBinding');
const {
  SECURESHOP_CONVERSATION_PURPOSES: PURPOSES
} = require('./secureshopConversationPurpose');
const {
  request,
  requestDigest,
  TASK_ROLE,
  fail
} = require('./secureshopPricingContract');
const {
  canonicalDigest
} = require('./mcp/protocolContext');

// Unmounted composition: uses the production bound coordinator/graph, never
// selects a tool from a regex or turns a fixture observation into Judge credit.
async function createSecureShopPricingComposition({
  enabled = false,
  pricingRepository,
  executor,
  resetComposition,
  personaAuthority,
  provider,
  promptPolicyRepository,
  toolPolicyRepository,
  createAssessmentFactory,
  readHistory,
  prepareTarget,
  mode = 'vuln', modeAuthority
} = {}) {
  if (typeof enabled !== 'boolean') throw fail('PRICING_UNAVAILABLE');
  if (!enabled) return Object.freeze({
    ready: false
  });
  const {
    conversationService: conversations,
    conversations: graphRepository,
    turns,
    journal
  } = resetComposition || {};
  if (['begin', 'complete', 'markUnknown', 'operation', 'assertCurrent', 'checkReadiness'].some(key => typeof pricingRepository?.[key] !== 'function') || typeof executor?.execute !== 'function' || typeof executor?.checkReadiness !== 'function' || typeof personaAuthority?.capture !== 'function' || typeof conversations?.create !== 'function' || typeof prepareTarget !== 'function' || typeof provider?.chat !== 'function' || !['vuln', 'fixed'].includes(mode)) throw fail('PRICING_UNAVAILABLE');
  if (createAssessmentFactory !== undefined && (typeof createAssessmentFactory !== 'function' || typeof pricingRepository.readAssessment !== 'function')) throw fail('PRICING_ASSESSMENT_UNAVAILABLE');
  const schema = await pricingRepository.checkReadiness();
  if (schema?.ready !== true) throw fail('PRICING_UNAVAILABLE');
  if ((await executor.checkReadiness())?.ready !== true) throw fail('PRICING_UNAVAILABLE');
  async function run(raw) {
    // Capture authority, selected product and exact teaching question before any await.
    const selected = request({
      operationId: raw.operationId,
      task: raw.task,
      productId: raw.productId,
      message: raw.message,
      ...(Object.hasOwn(raw,'experiment')?{experiment:raw.experiment}:{}),
      ...(Object.hasOwn(raw,'competitorUrl')?{competitorUrl:raw.competitorUrl}:{})
    });
    const scope = createLaunchScope(raw.scope);
    const modeToken=await captureFeatureMode(modeAuthority,scope,'pricing',mode);
    const selectedMode=modeToken.snapshot.mode;
    const binding = createConversationBinding(scope, raw.persona);
    if (TASK_ROLE[selected.task] !== binding.role) throw fail('PRICING_ROLE_REQUIRED');
    const input = Object.freeze({
      ...selected,
      scope,
      persona: Object.freeze({
        id: binding.shopUserId,
        role: binding.role
      }),
      personaSession: Object.freeze({
        ...raw.personaSession
      })
    });
    const signal = raw.signal,
      stream = raw.stream;
    signal?.throwIfAborted();
    await modeToken.assertCurrent();
    const prior = await pricingRepository.operation(input);
    await modeToken.assertCurrent();
    if (prior.state !== 'not_found') {
      if (prior.requestSha256 !== requestDigest(selected)) throw fail('OPERATION_CONFLICT');
      return prior;
    }
    const preparedTarget = await prepareTarget(input);
    const purpose = selected.task === 'price-advisor' ? PURPOSES.priceAdvisor : PURPOSES.pricingStrategy;
    const config = createSecureShopPricingExecutionConfig(selected.task,{mode:selectedMode});
    const policy = promptPolicyRunnerOptions(promptPolicyRepository, personaAuthority);
    const conversation = await conversations.create(scope, input.persona, purpose);
    const receiptContract=require('./secureshopPricingReceipt');
    const experimentContext=selected.experiment?receiptContract.capturePricingExperimentContext({
      version:'secureshop-pricing-experiment-context.v1',operationId:selected.operationId,
      productId:selected.productId,message:selected.message,experiment:selected.experiment,
      requestSha256:requestDigest(selected)
    }):null;
    let admitted, admittedInput;
    const observations = [];
    const suggestionModels=new Map();
    let blockedReceipt;
    const blockedText='Comparison blocked by fixed-mode policy. No competitor request was made.';
    const experimentObserved=()=>selected.experiment&&observations.some(row=>
      row.tool==='pricing-strategy.run_pricing_experiment'
      &&row.args?.product_id===selected.productId
      &&row.args.strategy===selected.experiment.strategy
      &&row.args.duration_days===selected.experiment.durationDays
      &&row.result?.ok===true&&row.result.grounded===false
      &&row.result.product_id===selected.productId
      &&row.result.strategy===selected.experiment.strategy
      &&row.result.duration_days===selected.experiment.durationDays);
    const typedFinalOptions=()=>{
      if(selected.task!=='pricing-strategy')return{};
      if(selected.experiment&&!experimentObserved())return{
        pricingFinalDecision:receiptContract.capturePricingFinalDecision({
          kind:'pending_experiment',productId:selected.productId,experiment:selected.experiment
        })
      };
      const relevant=observations.filter(row=>row.args.product_id===selected.productId
        &&['pricing-strategy.suggest_price','pricing-strategy.compare_competitor'].includes(row.tool));
      if(!relevant.length)return{};
      const compareRows=relevant.filter(row=>row.tool==='pricing-strategy.compare_competitor');
      const identity=suggestionModels.get(relevant[0].callId);
      if(!identity||relevant.some(row=>suggestionModels.get(row.callId)?.provider!==identity.provider
        ||suggestionModels.get(row.callId)?.model!==identity.model))throw fail('SECURESHOP_PRICING_FINAL_UNSUPPORTED');
      const sourceCallIds=relevant.filter(row=>row.tool==='pricing-strategy.suggest_price').map(row=>row.callId);
      if(compareRows.length){
        if(relevant.some(row=>suggestionModels.get(row.callId)?.mocked!==false
          ||suggestionModels.get(row.callId)?.fallback===true
          ||[suggestionModels.get(row.callId)?.provider,suggestionModels.get(row.callId)?.model]
            .some(value=>/^(mock|fixture|scripted|fallback|unavailable)$/i.test(value.trim()))))return{};
        const product=admitted.targetSnapshot.product;
        const expected={targetId:admitted.targetId,operationId:input.operationId,runId:admittedInput.runId,
          requestSha256:requestDigest(selected)};
        const sources=compareRows.map(row=>receiptContract.comparisonSource(row,product,expected));
        return{pricingFinalDecision:receiptContract.capturePricingFinalDecision({kind:'compare',
          productId:product.id,productName:product.name,ourPrice:product.price,sources,
          ...(sourceCallIds.length?{sourceCallIds}:{})}),
          pricingProviderIdentity:{provider:identity.provider,model:identity.model}};
      }
      return{pricingFinalDecision:receiptContract.capturePricingFinalDecision({productId:selected.productId,sourceCallIds}),
        pricingProviderIdentity:{provider:identity.provider,model:identity.model}};
    };
    let published;
    let finalModelText = null;
    const captureFinalModel = response => {
      // A tool observation and a mock/fallback final answer cannot authorize
      // a merchant-facing recommendation. Preserve the answer as plain text.
      finalModelText = response?.stop_reason === 'end_turn'
        && typeof response.text === 'string'
        && typeof response.provider === 'string' && response.provider.trim()
        && typeof response.model === 'string' && response.model.trim()
        && response.mocked === false && response.fallback !== true
        && ![response.provider, response.model].some(value => /^(mock|fixture|scripted|fallback|unavailable)$/i.test(value.trim()))
        ? response.text : null;
      return response;
    };
    const publish = async (execution, result) => {
      await execution.check();
      if(blockedReceipt){
        if(result.stopReason!=='tool_denied'||result.text!==blockedText
          ||typeof pricingRepository.block!=='function')throw fail('PRICING_DENIAL_INVALID');
        await modeToken.assertCurrent();
        if(!published)published=await pricingRepository.block({...admittedInput,receipt:blockedReceipt});
        await modeToken.assertCurrent();
        await execution.check();
        return published;
      }
      // A graph error/cancellation is not a completed Pricing execution. An
      // effect may already have happened even when no observation was retained;
      // the existing failure path must keep the admitted operation unknown.
      if(result.stopReason!=='end_turn')throw fail('PRICING_OUTCOME_UNCERTAIN');
      if(selected.experiment&&!experimentObserved()){
        const pending=typedFinalOptions().pricingFinalDecision;
        let decision;try{decision=JSON.parse(result.text);}catch{}
        if(result.stopReason!=='end_turn'||finalModelText!==result.text
          ||!receiptContract.pricingFinalDecision(decision,pending))
          throw fail('SECURESHOP_INVALID_DECISION');
      }
      const recommendation=selected.task==='pricing-strategy'&&result.stopReason==='end_turn'
        &&finalModelText===result.text
        ?require('./secureshopPricingReceipt').modelRecommendation(result.text,observations,selected.productId):null;
      const comparison=selected.task==='pricing-strategy'&&result.stopReason==='end_turn'
        &&finalModelText===result.text&&typedFinalOptions().pricingFinalDecision?.kind==='compare'
        ?require('./secureshopPricingReceipt').modelComparison(result.text,observations,
          admitted.targetSnapshot.product,{targetId:admitted.targetId,operationId:input.operationId,
            runId:execution.runId,requestSha256:requestDigest(selected)}):null;
      if (!published) published = await pricingRepository.complete({ ...admittedInput, receipt: {
        version: 'secureshop-pricing-execution.v1', targetId: admitted.targetId,
        operationId: input.operationId, runId: execution.runId,
        requestSha256: requestDigest(selected), response: result.text, observations,
        ...(recommendation?{modelRecommendation:recommendation}:{}),
        ...(comparison?{modelComparison:comparison}:{})
      } });
      await execution.check();
      return published;
    };
    const assessmentFactory = await createAssessmentFactory?.({ task: selected.task, scope,
      publishAndRead: async (execution, result) => {
        await publish(execution, result);
        return pricingRepository.readAssessment(admittedInput);
      }
    });
    const runner = createBoundAgentRunner({
      turns,
      conversations,
      repository: graphRepository,
      journal,
      // Pricing already enforces this exact task catalog. Constrain model-native
      // name selection without rewriting decisions or changing advisory agents.
      provider: { async chat(args) {
        const typed=typedFinalOptions(),{pricingFinalDecision,pricingProviderIdentity}=typed;
        if(pricingFinalDecision&&provider.capabilities?.pricingFinalDecision!==true)throw fail('SECURESHOP_PRICING_FINAL_UNSUPPORTED');
        const response=await provider.chat({ ...args, closedToolCatalog: true, maxToolCalls: 1,...typed,
          ...(selected.task==='pricing-strategy'&&provider.capabilities?.pricingGenerationEnvelopeV1===true
            ?{pricingDecisionFormat:'bounded-envelope-v1'}
            :selected.task==='pricing-strategy'&&provider.capabilities?.pricingJsonDecisionV1===true
              ?{pricingDecisionFormat:'json-v1'}:{}),
          ...(selected.task==='price-advisor'&&provider.capabilities?.priceAdvisorJsonDecisionV1===true
            ?{pricingDecisionFormat:'price-advisor-json-v1'}:{}),
          ...(experimentContext?{pricingExperimentContext:experimentContext}:{}) });
        if(pricingProviderIdentity&&(response?.provider!==pricingProviderIdentity.provider||response?.model!==pricingProviderIdentity.model))throw fail('SECURESHOP_PRICING_FINAL_UNSUPPORTED');
        for(const call of response?.tool_uses||[]){
          if(['pricing-strategy.suggest_price','pricing-strategy.compare_competitor'].includes(call.name)
            &&call.args?.product_id===selected.productId
            &&typeof response.provider==='string'&&response.provider.trim()&&typeof response.model==='string'&&response.model.trim()){
            suggestionModels.set(call.id,Object.freeze({provider:response.provider,model:response.model,
              mocked:response.mocked,fallback:response.fallback}));
          }
        }
        if(pricingFinalDecision&&response?.stop_reason==='end_turn'){
          let decision;try{decision=JSON.parse(response.text);}catch{}
          if(!receiptContract.pricingFinalDecision(decision,pricingFinalDecision))throw fail('SECURESHOP_INVALID_DECISION');
        }
        return captureFinalModel(response);
      },
        ...(typeof provider.finalResponse === 'function' ? { async finalResponse(args) {
          // Pricing uses the chat decision grammar. The separate answer-string
          // capability must never downgrade an already typed recommendation.
          if(typedFinalOptions().pricingFinalDecision)throw fail('SECURESHOP_PRICING_FINAL_UNSUPPORTED');
          return captureFinalModel(await provider.finalResponse(args));
        } } : {}) },
      ...config,
      ...policy,
      ...(assessmentFactory === undefined ? {} : { assessmentFactory }),
      terminalAfterLocalTool({observation}){
        if(!blockedReceipt)return null;
        const recorded=observations.at(-1);
        if(observation.callId!==blockedReceipt.sourceCallId||observation.tool!==recorded?.tool
          ||canonicalDigest(observation.args)!==canonicalDigest(recorded.args)
          ||canonicalDigest(observation.result)!==canonicalDigest({content:[{type:'text',text:JSON.stringify(recorded.result)}]}))
          throw fail('PRICING_DENIAL_INVALID');
        return{source:'server',stopReason:'tool_denied',text:blockedText};
      },
      ...(toolPolicyRepository === undefined ? {} : {
        toolPolicyAdmission: require('./secureshopBoundToolPolicyAdmission').createBoundToolPolicyAdmission({
          repository: toolPolicyRepository, workflow: selected.task,
          declaredTools: config.manifest.getForRole(binding.role)
        })
      }),
      conversationPurpose: purpose,
      executionScope: 'turn',
      pool: {
        async callTool() {
          throw fail('PRICING_EXTERNAL_TOOL_UNAVAILABLE');
        }
      },
      capturePersonaAuthority: async ({
        binding: b,
        personaSession
      }) => guardFeatureFence(await personaAuthority.capture({
        scope: b,
        personaId: b.shopUserId,
        role: b.role,
        sessionId: personaSession?.sessionId,
        authorityVersion: personaSession?.authorityVersion
      }),modeToken),
      personaLocalToolModes: Object.fromEntries(config.manifest.getForRole(binding.role).map(tool => [selected.task + '.' + tool.tool, 'remote_admission'])),
      async createLocalTools(_binding, _context, _localAuthority, execution) {
        await execution.check();
        admittedInput = Object.freeze({
          ...input,
          runId: execution.runId
        });
        admitted = await pricingRepository.begin(admittedInput, preparedTarget);
        if (admitted.state !== 'admitted') throw fail('PRICING_ALREADY_ADMITTED');
        const checkCurrent = async () => {
          await execution.check();
          await pricingRepository.assertCurrent(admittedInput, admitted.targetId);
          await execution.check();
        };
        const competitorBinding = {
          targetId: admitted.targetId,
          operationId: input.operationId,
          runId: execution.runId,
          requestSha256: requestDigest(selected)
        };
        const observeCompetitor = createOwnedCompetitorObservation({
          executor,
          binding: competitorBinding,
          snapshot: admitted.targetSnapshot,
          mode:selectedMode,
          checkCurrent,
          signal: execution.signal
        });
        return createSecureShopBoundPricingTools({
          task: selected.task, mode:selectedMode,
          productId: selected.productId,
          catalog: {
            async getProduct(id) {
              if (id !== selected.productId) throw fail('PRICING_PRODUCT_UNAVAILABLE');
              return admitted.targetSnapshot.product;
            }
          },
          readCompetitorManual: async () => admitted.targetSnapshot.manual,
          readPriceHistory: typeof readHistory === 'function'
            ? () => readHistory(admittedInput,preparedTarget) : undefined,
          observeCompetitor,
          competitorBinding,
          expectedExperiment:selected.experiment,
          expectedCompetitorUrl:selected.competitorUrl,
          checkCurrent,
          async recordObservation(observation) {
            if (observations.length >= 16 || observations.some(row => row.callId === observation.callId)) throw fail('PRICING_OBSERVATION_LIMIT');
            if(observation.result?.status==='blocked'){
              const identity=suggestionModels.get(observation.callId),denial=observation.result.denial_receipt;
              if(selectedMode!=='fixed'||observation.tool!=='pricing-strategy.compare_competitor'
                ||observation.args.product_id!==selected.productId||denial?.callId!==observation.callId
                ||denial?.url!==observation.args.competitor_url||!identity
                ||identity.mocked!==false||identity.fallback===true)throw fail('PRICING_DENIAL_INVALID');
              blockedReceipt=require('./secureshopPricingReceipt').pricingDenialReceipt({
                version:'secureshop-pricing-denial.v1',...competitorBinding,productId:selected.productId,
                sourceCallId:observation.callId,competitorUrl:denial.url,mode:'fixed',reason:'policy_denied',
                modelDecision:{...identity,fallback:false},proof:denial.proof
              },{...competitorBinding,productId:selected.productId,
                ...(selected.competitorUrl===undefined?{}:{competitorUrl:selected.competitorUrl})});
            }
            observations.push(structuredClone(observation));
          }
        });
      },
      async resultMetadata({
        execution,
        result
      }) {
        const completed = await publish(execution, result);
        const receipt = completed.receipt;
        return {
          operationId: input.operationId,
          requestSha256: receipt.requestSha256,
          state: completed.state,
          receiptSha256: canonicalDigest(completed.receipt)
        };
      },
      limits: {
        maxSteps: 8,
        maxParallelTools: 1
      }
    });
    try {
      await runner.run({
        sessionId: conversation.id,
        requestId: input.operationId,
        scope,
        persona: input.persona,
        personaSession: input.personaSession,
        message: input.message,
        signal,
        stream
      });
    } catch (error) {
      // Persist categorical uncertainty only; no raw model/provider errors in audit.
      if (admitted?.state === 'admitted') {
        try {
          await pricingRepository.markUnknown(admittedInput);
        } catch {}
      }
      if (error.code === 'PRICING_ALREADY_ADMITTED') return pricingRepository.operation(input);
      throw error;
    }
    await modeToken.assertCurrent();
    const result = await pricingRepository.operation(input);
    await modeToken.assertCurrent();
    return result;
  }
  return Object.freeze({
    ready: true,
    administration: async raw => ({ versionedPricing: true, ...(await pricingRepository.administration(structuredClone(raw))) }),
    ...(readHistory === undefined ? {} : { history: raw => readHistory(structuredClone(raw)) }),
    run,
    operation: raw => pricingRepository.operation(structuredClone(raw))
  });
}
module.exports = {
  createSecureShopPricingComposition
};
