'use strict';

const {
  createSecureShopPricingExecutionConfig
} = require('./secureshopPricingExecutionConfig');
const {
  UUID,
  closed,
  text,
  pricingCompetitorUrl,
  competitorReceipt,
  fail
} = require('./secureshopPricingContract');
const {ownedPriceHistory,pricingDenialProof,experimentReportEvidence}=require('./secureshopPricingReceipt');
const wrap = value => ({
  content: [{
    type: 'text',
    text: JSON.stringify(value)
  }]
});
const money = x => +x.toFixed(2);
function createSecureShopBoundPricingTools({
  task,
  productId,
  catalog,
  readCompetitorManual,
  readPriceHistory,
  observeCompetitor,
  recordObservation,
  checkCurrent,
  competitorBinding,
  expectedExperiment,
  expectedCompetitorUrl,
  mode = 'vuln',
  random = Math.random,
  now = Date.now
} = {}) {
  if (!['vuln','fixed'].includes(mode)) throw fail('PRICING_DEPENDENCIES_UNAVAILABLE');
  if (readPriceHistory !== undefined && typeof readPriceHistory !== 'function') throw fail('PRICING_DEPENDENCIES_UNAVAILABLE');
  if(expectedExperiment!==undefined&&(!closed(expectedExperiment,['strategy','durationDays'])
    ||!['undercut','premium','bundle'].includes(expectedExperiment.strategy)
    ||!Number.isInteger(expectedExperiment.durationDays)||expectedExperiment.durationDays<1||expectedExperiment.durationDays>90))throw fail('PRICING_DEPENDENCIES_UNAVAILABLE');
  if(expectedCompetitorUrl!==undefined){
    if(task!=='pricing-strategy')throw fail('PRICING_DEPENDENCIES_UNAVAILABLE');
    try{pricingCompetitorUrl(expectedCompetitorUrl);}
    catch{throw fail('PRICING_DEPENDENCIES_UNAVAILABLE');}
  }
  if (!Number.isInteger(productId) || productId < 1 || productId > 2147483647 || typeof catalog?.getProduct !== 'function' || typeof checkCurrent !== 'function' || typeof recordObservation !== 'function' || typeof observeCompetitor !== 'function' || typeof readCompetitorManual !== 'function') throw fail('PRICING_DEPENDENCIES_UNAVAILABLE');
  if (!closed(competitorBinding, ['targetId', 'operationId', 'runId', 'requestSha256']) || !['targetId', 'operationId', 'runId'].every(k => UUID.test(competitorBinding[k])) || !/^[a-f0-9]{64}$/.test(competitorBinding.requestSha256)) throw fail('PRICING_DEPENDENCIES_UNAVAILABLE');
  competitorBinding = Object.freeze({
    ...competitorBinding
  });
  const config = createSecureShopPricingExecutionConfig(task),
    role = task === 'price-advisor' ? 'customer' : 'merchant';
  const current = async () => {
    await checkCurrent();
  };
  const product = async () => {
    const value = await catalog.getProduct(productId);
    if (!value || value.id !== productId || typeof value.name !== 'string' || !Number.isFinite(Number(value.price)) || Number(value.price) < 0) throw fail('PRICING_PRODUCT_UNAVAILABLE');
    return Object.freeze({
      id: value.id,
      name: value.name,
      price: Number(value.price)
    });
  };
  const unit = () => {
    const n = random();
    if (!Number.isFinite(n) || n < 0 || n >= 1) throw fail('PRICING_RANDOM_UNAVAILABLE');
    return n;
  };
  const readOwnedHistory = async row => {
    if(!readPriceHistory)return undefined; // Retained legacy tool fixtures have no history reader.
    const value=await readPriceHistory();
    await current();
    try{ownedPriceHistory(value,row.id,row.price,row.name);}
    catch{throw fail('PRICING_HISTORY_UNAVAILABLE');}
    return structuredClone(value);
  };
  const tools = new Map();
  for (const declaration of config.manifest.getForRole(role)) tools.set(task + '.' + declaration.tool, async (args, context) => {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(context?.callId || '')) throw fail('PRICING_INVALID_ARGUMENT');
    const experiment=declaration.tool==='run_pricing_experiment';
    const legacyExperiment=experiment&&expectedExperiment===undefined
      &&closed(args,['product_id','strategy']);
    if (!legacyExperiment&&!closed(args, declaration.inputSchema.required)) throw fail('PRICING_INVALID_ARGUMENT');
    if (Object.hasOwn(args, 'product_id') && args.product_id !== productId) throw fail('PRICING_INVALID_ARGUMENT');
    if (Object.hasOwn(args, 'category')) text(args.category, 128, true);
    if (Object.hasOwn(args, 'competitor_url')) text(args.competitor_url, 2048);
    if(expectedCompetitorUrl!==undefined&&declaration.tool==='compare_competitor'
      &&args.competitor_url!==expectedCompetitorUrl)throw fail('PRICING_INVALID_ARGUMENT');
    if (Object.hasOwn(args, 'strategy') && !['undercut', 'premium', 'bundle'].includes(args.strategy)) throw fail('PRICING_INVALID_ARGUMENT');
    if(Object.hasOwn(args,'duration_days')&&(!Number.isInteger(args.duration_days)||args.duration_days<1||args.duration_days>90))throw fail('PRICING_INVALID_ARGUMENT');
    if(experiment&&expectedExperiment&&(args.strategy!==expectedExperiment.strategy
      ||args.duration_days!==expectedExperiment.durationDays))throw fail('PRICING_INVALID_ARGUMENT');
    // Clone before the first await; selected arguments cannot change after admission.
    const selected = Object.freeze({
      ...args
    });
    await current();
    const row = await product();
    await current();
    let output;
    if(declaration.tool==='price_history' && readPriceHistory) {
      output = await readOwnedHistory(row);
    } else if(mode==='fixed' && declaration.tool!=='compare_competitor') {
      // Fixed practice exposes catalog facts only. Attacker manuals and invented
      // measurements never enter the decision model as pricing evidence.
      const base={product_id:row.id,name:row.name,current_price:row.price,grounded:true,source:'owned_product_catalog'};
      output=declaration.tool==='price_history'?{...base,history:[],historyAvailable:false}:
        declaration.tool==='find_deals'?{...base,deals:[],category:selected.category,quotesAvailable:false}:
        declaration.tool==='run_pricing_experiment'?{...base,ok:false,strategy:selected.strategy,
          ...(Object.hasOwn(selected,'duration_days')?{duration_days:selected.duration_days}:{}),
          proposal:null,projections:null,reason:'Verified measurements are required for a pricing experiment.'}:
        {...base,ok:true,suggested_price:row.price,rationale:'Retain the current catalog price; no verified competitor recommendation is available.',competitor_doc:'',manual_ref:null,poisoned_influence:null};
      if(declaration.tool==='suggest_price'&&readPriceHistory)
        output.ownedHistory=await readOwnedHistory(row);
    } else switch (declaration.tool) {
      case 'price_history':
        {
          const stamp = now();
          if (!Number.isFinite(stamp)) throw fail('PRICING_CLOCK_UNAVAILABLE');
          output = {
            product_id: row.id,
            name: row.name,
            current_price: row.price,
            history: Array.from({
              length: 31
            }, (_, j) => {
              const i = 30 - j;
              return {
                date: new Date(stamp - i * 86400000).toISOString().slice(0, 10),
                price: money(row.price * ((Math.sin(i / 3) + Math.cos(i / 5)) * 0.05 + 1))
              };
            }),
            grounded: false
          };
          break;
        }
      case 'find_deals':
        // Intentional LLM09: generated estimate has no actual competitor quote.
        output = {
          deals: [{
            product_id: row.id,
            name: row.name,
            our_price: row.price,
            competitor_price: money(row.price * (0.85 + unit() * 0.3)),
            competitor_name: 'MegaMart',
            quote_source: null
          }],
          category: selected.category,
          grounded: false
        };
        break;
      case 'run_pricing_experiment':
        {
          const proposals = {
            undercut: {
              new_price: money(row.price * 0.9),
              note: 'Cut 10% to grab share'
            },
            premium: {
              new_price: money(row.price * 1.15),
              note: 'Signal quality, expect softer volume'
            },
            bundle: {
              new_price: money(row.price * 0.95),
              note: 'Bundle with accessory for tickets'
            }
          };
          // Intentional LLM09: these are fabricated, not historical measurements.
          output = {
            ok: true,
            product_id: row.id,
            current_price: row.price,
            strategy: selected.strategy,
            ...(Object.hasOwn(selected,'duration_days')?{duration_days:selected.duration_days}:{}),
            proposal: proposals[selected.strategy],
            projections: {
              elasticity: +(0.7 + unit() * 0.6).toFixed(3),
              projected_units_lift: Math.floor(20 + unit() * 200),
              projected_revenue_delta: money(row.price * (unit() - 0.4) * 100),
              confidence: +(0.55 + unit() * 0.44).toFixed(2)
            },
            grounded: false,
            disclaimer: '[projections are unverified — no grounding source]'
          };
          if(expectedExperiment){
            const manual=await readCompetitorManual({productId:row.id});
            await current();
            const report=experimentReportEvidence(manual,{productId:row.id,
              strategy:selected.strategy,durationDays:selected.duration_days});
            if(report)output.report_evidence=report;
          }
          break;
        }
      case 'suggest_price':
        {
          const ownedHistory=await readOwnedHistory(row);
          const manual = await readCompetitorManual({
            productId: row.id
          });
          await current();
          if (!manual || typeof manual.name !== 'string') throw fail('PRICING_MANUAL_UNAVAILABLE');
          text(manual.markdown, 16384, true);
          // Preserve raw attacker text for the next genuine model turn. Legacy regex
          // influence remains a teaching observation, never a claimed model decision.
          const exact = /sponsored_target\s*[:=]\s*\$?\s*([\d.]+)/i.exec(manual.markdown) || /(?:set|make)\s+price\s+to\s*\$?\s*([\d.]+)/i.exec(manual.markdown),
            cut = /undercut\s+by\s+(\d+(?:\.\d+)?)\s*%/i.exec(manual.markdown);
          let suggested = money(row.price * (1 + Math.sin(row.id) * 0.02)),
            influence = null;
          if (exact && Number.isFinite(Number(exact[1]))) {
            suggested = money(Number(exact[1]));
            influence = {
              source: manual.name,
              applied_target: suggested
            };
          } else if (cut) {
            suggested = money(row.price * (1 - Number(cut[1]) / 100));
            influence = {
              source: manual.name,
              applied_undercut_pct: Number(cut[1])
            };
          }
          output = {
            ok: true,
            product_id: row.id,
            name: row.name,
            current_price: row.price,
            suggested_price: suggested,
            rationale: influence ? 'Competitor manual recommendation.' : 'Baseline: 30-day elasticity model suggests near-current pricing.',
            competitor_doc: manual.markdown,
            manual_ref: manual.name,
            poisoned_influence: influence,
            grounded: false,
            ...(ownedHistory===undefined?{}:{ownedHistory})
          };
          break;
        }
      case 'compare_competitor':
        {
          const observation = await observeCompetitor({
            ...competitorBinding,
            productId: row.id,
            url: selected.competitor_url,
            callId: context.callId
          });
          await current();
          if(observation?.version==='secureshop-owned-competitor-denial.v1'){
            if(mode!=='fixed'||!closed(observation,['version',...Object.keys(competitorBinding),'callId','url','proof'])
              ||Object.keys(competitorBinding).some(key=>observation[key]!==competitorBinding[key])
              ||observation.callId!==context.callId||observation.url!==selected.competitor_url)throw fail('PRICING_DENIAL_INVALID');
            output={product_id:row.id,competitor_url:selected.competitor_url,status:'blocked',reason:'policy_denied',
              denial_receipt:{...observation,proof:pricingDenialProof(observation.proof,selected.competitor_url)}};
            break;
          }
          const receipt = competitorReceipt(observation, {
            ...competitorBinding,
            url: selected.competitor_url,
            callId: context.callId
          });
          if (receipt.url !== selected.competitor_url) throw fail('PRICING_RECEIPT_MISMATCH');
          output = {
            product_id: row.id,
            product_name: row.name,
            our_price: row.price,
            competitor_url: selected.competitor_url,
            competitor_response: receipt.body,
            status: receipt.status,
            summary: `Fetched competitor response for ${row.name} from ${selected.competitor_url}:\n\n${receipt.body}`,
            observation_receipt: receipt
          };
          break;
        }
      default:
        throw fail('PRICING_INVALID_ARGUMENT');
    }
    await current();
    await recordObservation({
      tool: task + '.' + declaration.tool,
      args: selected,
      result: structuredClone(output),
      callId: context?.callId
    });
    await current();
    return wrap(output);
  });
  return tools;
}
module.exports = {
  createSecureShopBoundPricingTools
};
