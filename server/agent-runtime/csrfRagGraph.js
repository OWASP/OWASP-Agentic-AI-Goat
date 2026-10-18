'use strict';
const {withCsrfTeachingEffect}=require('./csrfSelectedEffect');
const {checkOwnerRun,getOwnerExecution}=require('./ownerWorkflowRoutes');
const {Annotation,StateGraph,START,END}=require('@langchain/langgraph');
function recordSuccessfulRagQuery(tab, text, outcome) {
  const succeeded = outcome.executed === true && outcome.blocked === false && !outcome.error;
  const key = require('node:crypto').createHash('sha256').update(text.toLowerCase().replace(/[^\p{L}\p{N}]/gu, '')).digest('hex');
  // Legacy keys were truncated query text and counted blocked calls. They are
  // not verified execution receipts; discard only this counter, never progress.
  const fired = (tab.ragFiredQuestions || []).filter(key => /^[a-f0-9]{64}$/.test(key));
  tab.ragFiredQuestions = fired;
  const isNewQ = succeeded && !fired.includes(key);
  if (isNewQ) fired.push(key);
  return { succeeded, isNewQ };
}
async function runCsrfRagGraph({userKey,userId,t,message,lower,sandbox},{ensureCleanKb,assertRagAvailable,ragVectorStore,summarizeWithHtml,XSS_GADGET_RE,extractGadget,directiveToAction,directiveParams,recordActivity,getCompleted,creditObjective,extractGadgetMessage,mode='vuln',assertMode,execution=getOwnerExecution()}) {
 if(!['vuln','fixed'].includes(mode))throw new TypeError('Canonical CSRF mode required');
 let contextBlock,poisonInContext,answer,llmOk,modelGenerated,htmlPreserved,gadget,action,params,forged,newlyCompleted,output,queryOutcome;
 const observed=(node,operation)=>async state=>{
  await checkOwnerRun();await execution?.check?.();await assertMode?.();
  const started=Date.now();
  const data=node==='forge'?{decisionSource:'lab_gadget_interpreter'}:{};
  await execution?.trace?.({node,type:'node_start',data});
  try{const result=await operation(state);await assertMode?.();await checkOwnerRun();await execution?.check?.();await execution?.trace?.({node,type:'node_end',data:{...data,durationMs:Date.now()-started}});return result;}
  catch(error){await execution?.trace?.({node,type:'error',data:{...data,errorCode:'CSRF_WORKFLOW_FAILED',durationMs:Date.now()-started}});throw error;}
 };
 const graph=new StateGraph(Annotation.Root({next:Annotation()}))
.addNode('retrieve',observed('retrieve',async()=>{ await checkOwnerRun();
      await assertRagAvailable?.(userKey, t);
      const cleanId = await ensureCleanKb(userKey, t);
      // ONE merged, relevance-ranked retrieval over clean KB + (if any) poison.
      const cleanHits = (await ragVectorStore.similaritySearch(userKey, cleanId, String(message), 4)) || [];
      const poisonHits = (t.ragPoisoned && t.ragSessionId)
        ? (await ragVectorStore.similaritySearch(userKey, t.ragSessionId, String(message), 3)) || []
        : [];
      const merged = [...cleanHits, ...poisonHits.map((h) => ({ ...h, poison: true }))]
        .sort((a, b) => (b.score ?? 0) - (a.score ?? 0))
        .slice(0, 5);
      contextBlock = merged.map((h) => h.text).join('\n---\n');
      // The poison "surfaces" only if a poison chunk actually ranked into the
      // top-K (real relevance) — so an MFA poison won't fire on a branch-hours Q.
      const RELEVANCE_MIN = 0.30;
      poisonInContext = merged.some((h) => h.poison && (h.score ?? 0) >= RELEVANCE_MIN);


return {};
}))
.addNode('summarize',observed('summarize',async()=>{ await checkOwnerRun();
      // Real model summary — instructed to reproduce any HTML from context verbatim.
      ({ answer, llmOk, modelGenerated, htmlPreserved } = await summarizeWithHtml(contextBlock, message, mode==='fixed'?'rag_fixed':'rag'));


return {};
}))
.addNode('detect',observed('detect',async()=>{ await checkOwnerRun();
      if(mode==='fixed'){
        output={success:true,tab:'indirect',response:answer,responseFormat:'plain_text',newlyCompleted:[],victimState:sandbox.getTabState('indirect'),llmOk};
        return {next:END};
      }
      // Only exact HTML returned by an attributable model response can drive the
      // vulnerable renderer. Retrieved source text is never a fallback.
      gadget = poisonInContext && llmOk && modelGenerated && htmlPreserved && XSS_GADGET_RE.test(String(answer))
        ? extractGadget(String(answer)) : null;
      if (!gadget) {
        // Clean conversation — the model's real answer, no attack.
        output = { success: true, tab: 'indirect', response: answer, newlyCompleted: [], victimState: sandbox.getTabState('indirect'), llmOk }; return {next:END};
      }

return {next:'forge'};
}))
.addNode('forge',observed('forge',async()=>{ await checkOwnerRun();
      // Poisoned + on-topic: the attributable model answer carries the exact XSS
      // bytes. The server interpreter remains a controlled stand-in for browser
      // execution and is not itself browser-authenticity proof.
      action = directiveToAction(gadget) || 'change_email';
      params = directiveParams(gadget, action);
      await withCsrfTeachingEffect(execution, sandbox, async () => {
        forged = sandbox.forge('indirect', 'indirect', action, params);
        queryOutcome = recordSuccessfulRagQuery(t, message, forged);
        await sandbox.flush?.();
      });
      await recordActivity(userKey, 'indirect', `rag → ${action}`, { action, ...params }, { kind: 'attack', ...forged });


return {};
}))
.addNode('grade',observed('grade',async()=>{ await checkOwnerRun();
      const { succeeded, isNewQ } = queryOutcome;
      const already = await getCompleted(userKey);
      newlyCompleted = [];
      if (succeeded) {
        if (!already.has('csrf_i2')) {
          if (await creditObjective(userKey, 'csrf_i2', userId, already)) newlyCompleted.push('csrf_i2');
        } else if (isNewQ) {
          // Persistence re-fire: a NEW poisoned query after i2 is done → csrf_i3.
          if (await creditObjective(userKey, 'csrf_i3', userId, already)) newlyCompleted.push('csrf_i3');
        }
      }


return {};
}))
.addNode('present',observed('present',async()=>{ await checkOwnerRun();
      // The model's own answer, minus the exact returned gadget (rendered
      // separately in the widget iframe so it executes exactly once).
      const answerText = llmOk ? answer.replace(gadget, '').replace(/\n{3,}/g, '\n\n').trim() : answer;
      const full = [answerText, '', '<!--RAG_HTML_START-->', gadget, '<!--RAG_HTML_END-->'].join('\n');
      const forgedMsg = extractGadgetMessage(gadget) || `${action.replace('_', ' ')}`;
      output = {
        success: true, tab: 'indirect', response: full, ragHtml: gadget,
        forged: { message: forgedMsg, vectorLabel: 'Poisoned RAG chunk → forged CSRF' },
        newlyCompleted, victimState: sandbox.getTabState('indirect'), llmOk,
      };

return {};
}))
.addEdge(START,'retrieve').addEdge('retrieve','summarize').addEdge('summarize','detect')
.addConditionalEdges('detect',s=>s.next,['forge',END]).addEdge('forge','grade').addEdge('grade','present').addEdge('present',END).compile();
 await graph.invoke({});return output;
}
module.exports={runCsrfRagGraph,recordSuccessfulRagQuery};
