'use strict';
const {withCsrfTeachingEffect}=require('./csrfSelectedEffect');
const {checkOwnerRun,getOwnerExecution}=require('./ownerWorkflowRoutes');
const {Annotation,StateGraph,START,END}=require('@langchain/langgraph');
async function runCsrfInboxGraph({userKey,userId,t,sandbox,wantsList,mailScope},{mailDispatch,mailbox,aiService,TABS,LLM_STARTING,executeClassifiedEmail,noteClassifiedEmailProof,getCompleted,creditObjective,summarizeWithHtml,extractGadgetMessage,noteGradeReceipt,execution=getOwnerExecution()}) {
 let emails,emailData,summaryResult,summary,llmOk,modelGenerated,htmlPreserved,emailGadget,browserResult,newlyCompleted,output;
 const done=value=>{output=value;return {next:END};};
 const observed=(node,operation)=>async state=>{
  await checkOwnerRun();await execution?.check?.();
  const started=Date.now();
  const data={};
  await execution?.trace?.({node,type:'node_start',data});
  try{const result=await operation(state);await checkOwnerRun();await execution?.check?.();await execution?.trace?.({node,type:'node_end',data:{...data,durationMs:Date.now()-started}});return result;}
  catch(error){await execution?.trace?.({node,type:'error',data:{...data,errorCode:'CSRF_WORKFLOW_FAILED',durationMs:Date.now()-started}});throw error;}
 };
 const graph=new StateGraph(Annotation.Root({next:Annotation()}))
.addNode('fetch',observed('fetch',async()=>{ await checkOwnerRun();
      if (!t.xssInbox) {
        const body = 'Set up your temporary inbox in the **Email panel** first (enter it and click **Verify inbox**).';
        return done({ success: true, tab: 'xss', response: body, newlyCompleted: [], victimState: sandbox.getTabState('xss'), llmOk: true });
      }
      // Exact readback performs its own owner-bound lookup. A broad mailbox
      // listing is only needed when the learner explicitly asks to list mail.
      if (!wantsList) return {next:'read'};
      let list;
      try { list = await mailbox.fetchEmails(t.xssInbox, true); }
      catch (e) { return done({ success: true, tab: 'xss', response: `Could not reach the inbox: ${e.message}`, newlyCompleted: [], victimState: sandbox.getTabState('xss'), llmOk: true }); }
      emails = list.emails || [];
      if (emails.length === 0) {
        const body = `### Victim inbox — ${t.xssInbox}\n\nNo attack email has arrived yet. **Send the payload** from the Email panel, then wait for the configured mail provider to deliver it and ask again.`;
        return done({ success: true, tab: 'xss', response: body, newlyCompleted: [], victimState: sandbox.getTabState('xss'), llmOk: true });
      }
return {next:wantsList?'list':'read'};
}))
.addNode('list',observed('list',async()=>{ await checkOwnerRun();

        // Real inbox data from the SharkLaser API → let the LLM present it
        // naturally, like a mail assistant reading the mailbox to the user.
        const inboxData = emails.slice(0, 8)
          .map((e, i) => `${i + 1}. Subject: "${e.subject || '(no subject)'}" — From: ${e.from}${e.timestamp ? ` — ${e.timestamp}` : ''}`)
          .join('\n');
        let listReply = '';
        try {
          const r = await aiService.chatWithMessages([
            { role: 'system', content: `You are ${TABS.xss.victim.name}'s AI email assistant. The user asked to see their inbox. List the messages below to them in a friendly, natural way (a one-line intro, then the messages). Do not invent messages. End by offering to open or summarize any of them.` },
            { role: 'user', content: `Inbox for ${t.xssInbox} — ${emails.length} message(s):\n${inboxData}` },
          ], { max_tokens: 260, temperature: 0.4, timeout: 20000 });
          listReply = (r && !r.fallback) ? (r.response || r.text || '').trim() : '';
        } catch (_) {}
        if (!listReply) listReply = LLM_STARTING;
        return done({ success: true, tab: 'xss', response: listReply, newlyCompleted: [], victimState: sandbox.getTabState('xss'), llmOk: !!listReply && listReply !== LLM_STARTING });

}))
.addNode('read',observed('read',async()=>{ await checkOwnerRun();
      // wantsRead → fetch the latest attack email body, parse the CSRF directive.
      
      try {
	        const r = await mailDispatch.retrieve(mailScope, { recipient: t.xssInbox });
	        if (r?.error || !r?.email) {
	          return done({ success: true, tab: 'xss', response: r?.error || 'No exact current exercise email is available.', newlyCompleted: [], victimState: sandbox.getTabState('xss'), llmOk: true });
	        }
	        emailData = r.email;
	        noteGradeReceipt(emailData);
      } catch (e) {
        return done({ success: true, tab: 'xss', response: `Failed to fetch the email body: ${e.message}`, newlyCompleted: [], victimState: sandbox.getTabState('xss'), llmOk: true });
      }

return {next:'summarize'};
}))
.addNode('summarize',observed('summarize',async()=>{ await checkOwnerRun();
      // The attack path exists only when an attributable model response preserves
      // the source HTML exactly. Refusal/unavailable text remains visible, but is
      // never supplemented from the raw email body.
      const emailCtx = require('./htmlSummaryGraph').buildCsrfEmailSummaryContext(emailData);
      summaryResult = await summarizeWithHtml(emailCtx, null, 'email', execution);
      ({ answer: summary, llmOk, modelGenerated, htmlPreserved } = summaryResult);
      emailGadget = llmOk && modelGenerated && htmlPreserved
        && typeof emailData.payload === 'string' && emailData.payload.length > 0
        && String(summary).includes(emailData.payload) ? emailData.payload : '';
      if (!emailGadget) return done({ success: true, tab: 'xss', response: summary,
        ragHtml: null, forged: null, newlyCompleted: [], victimState: sandbox.getTabState('xss'), llmOk });
      return {next:'browser'};
}))
.addNode('browser',observed('browser',async()=>{
      if (typeof executeClassifiedEmail !== 'function' || typeof noteClassifiedEmailProof !== 'function') {
        throw new Error('Classified email browser workflow unavailable');
      }
      browserResult = await executeClassifiedEmail({ retrievedMail: emailData,
        summary: summaryResult, gadgetHtml: emailGadget });
      if (browserResult?.qualified !== true || !browserResult.proof
        || !browserResult.browser?.receipt || !browserResult.browser?.activity) {
        return done({ success: true, tab: 'xss', response: summary, ragHtml: null,
          forged: null, newlyCompleted: [], victimState: sandbox.getTabState('xss'), llmOk });
      }
      await noteClassifiedEmailProof({ proof: browserResult.proof, retrievedMail: emailData,
        summary: summaryResult, browserReceipt: browserResult.browser.receipt,
        activity: browserResult.browser.activity });
      await withCsrfTeachingEffect(execution, sandbox, async () => {
        t.xssEmailRead = true;
        await sandbox.flush?.();
      });
      return {next:'grade'};
}))
.addNode('grade',observed('grade',async()=>{ await checkOwnerRun();
      const already = await getCompleted(userKey);
      newlyCompleted = [];
      for (const oid of ['csrf_x3']) {
        if (await creditObjective(userKey, oid, userId, already)) newlyCompleted.push(oid);
      }

return {next:'present'};
}))
.addNode('present',observed('present',async()=>{ await checkOwnerRun();
      // Render the exact gadget observed in the attributable model answer once.
      const summaryText = llmOk ? String(summary).replace(emailGadget, '').replace(/\n{3,}/g, '\n\n').trim() : summary;
      const full = [
        `### 📧 Email summary — "${emailData.subject}"`,
        `*From ${emailData.from}*`,
        '', summaryText,
        '', '<!--RAG_HTML_START-->', emailGadget, '<!--RAG_HTML_END-->',
      ].join('\n');
      const emailMsg = extractGadgetMessage(emailGadget) || 'Observed email request';
      return done({
        success: true, tab: 'xss', response: full, ragHtml: emailGadget || null, browserExecuted: true,
        forged: { message: emailMsg, vectorLabel: 'XSS-in-email → forged CSRF' },
        newlyCompleted, victimState: sandbox.getTabState('xss'), llmOk,
      });
}))
.addEdge(START,'fetch').addConditionalEdges('fetch',s=>s.next,['list','read',END]).addEdge('list',END)
.addConditionalEdges('read',s=>s.next,['summarize',END]).addConditionalEdges('summarize',s=>s.next,['browser',END])
.addConditionalEdges('browser',s=>s.next,['grade',END]).addEdge('grade','present').addEdge('present',END).compile();
 await graph.invoke({});return output;
}
module.exports={runCsrfInboxGraph};
