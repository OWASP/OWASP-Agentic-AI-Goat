'use strict';
const {Annotation,StateGraph,START,END}=require('@langchain/langgraph');
const {selectMailRead}=require('./csrfMailReadDecision');
const {renderSelectedMail}=require('../services/csrfMailRendering');
async function runSelectedInboxGraph({message,scope,attempt,recipient},{dispatch,model,assertAttempt,executeBrowser,noteBrowser,grade,snapshot}){
 if(!scope?.execution||typeof assertAttempt!=='function'||typeof snapshot!=='function')throw TypeError('Canonical selected mail graph required');
 const execution=scope.execution;let plan,selection,read,rendering,browser,result,summary;
 const summaryText=()=>summary?(summary.status==='summary'?'Assistant summary: ':summary.status==='refused'?'Summary declined: ':'Summary unavailable: ')+summary.text+'\n\n':'';
 const check=async()=>{await execution.check();await assertAttempt(attempt);await execution.check();};
 const output=async fields=>{await check();result={success:true,tab:'xss',responseFormat:'plain_text',newlyCompleted:[],victimState:await snapshot(),...fields};await check();return {next:END};};
 const node=(name,work)=>async()=>{await check();await execution.trace?.({node:name,type:'node_start',data:{}});const value=await work();await check();await execution.trace?.({node:name,type:'node_end',data:{}});return value;};
 const graph=new StateGraph(Annotation.Root({next:Annotation()}))
 .addNode('select',node('select_mail',async()=>{
   plan=await dispatch.prepareSelectedRead(scope,{recipient,attempt,assertAttempt});
   selection=await selectMailRead({message,metadata:plan.metadata,model,execution,persistDecision:plan.persistDecision});
   if(selection.status!=='selected')return output({response:selection.status==='empty'?'No current owned delivery is available.':'Email selection is unavailable; no message was opened.',llmOk:false,selectionStatus:selection.status});
   if(selection.decision.action==='no_action')return output({response:'No email was opened.',llmOk:true,selectionStatus:'no_action'});
   if(selection.decision.action==='list_messages')return output({response:plan.metadata.map(row=>`${row.subject} — ${row.sender}`).join('\n'),llmOk:true,selectionStatus:'list_messages'});
   return {next:'read'};
 }))
 .addNode('read',node('read_selected_mail',async()=>{read=await plan.retrieveSelection(selection.record);if(!read?.email||!read.selectedRead)return output({response:'The selected delivery is not available for exact readback.',llmOk:false});return {next:selection.decision.presentation==='summary'?'summary':'render'};}))
 .addNode('summary',node('summarize_selected_mail',async()=>{summary=await require('./csrfMailPlainSummary').summarizeSelectedMail({body:read.email.body,model,execution:{...execution,check},persistSummary:value=>plan.persistSummary(selection.record,value)});if(summary.status!=='summary')return output({response:summaryText()+'The selected email was read; no active content was rendered.',ragHtml:null,browserExecuted:false,llmOk:summary.status==='refused'});return {next:'render'};}))
 .addNode('render',node('render_selected_mail',async()=>{
   rendering=renderSelectedMail({body:read.email.payload,mode:attempt.mode??'vuln'});
   await plan.recordRendering(selection.record,rendering);
   if(attempt.mode==='fixed')return output({response:summaryText()+'Opened the selected email as inert text.',ragHtml:rendering.html,renderPolicy:rendering.policy,browserExecuted:false,llmOk:true});
   return {next:'browser'};
 }))
 .addNode('browser',node('selected_mail_browser',async()=>{
   if(typeof executeBrowser!=='function'||typeof noteBrowser!=='function'||typeof grade!=='function')throw Error('Selected mail browser grading unavailable');
   browser=await executeBrowser({retrievedMail:read.email,selectedRead:read.selectedRead,gadgetHtml:rendering.html});
   if(!browser?.qualified)return output({response:summaryText()+'The original email was read, but no qualified browser action was recorded.',ragHtml:null,llmOk:true});
   await noteBrowser({proof:browser.proof,retrievedMail:read.email,selectedRead:read.selectedRead,browserReceipt:browser.browser.receipt,activity:browser.browser.activity});
   return {next:'grade'};
 }))
 .addNode('grade',node('grade_selected_mail',async()=>{const newlyCompleted=await grade();return output({response:summaryText()+'Opened the selected email. Its original HTML was rendered by the managed browser.',ragHtml:rendering.html,renderPolicy:rendering.policy,browserExecuted:true,llmOk:true,newlyCompleted});}))
 .addEdge(START,'select').addConditionalEdges('select',s=>s.next,['read',END]).addConditionalEdges('read',s=>s.next,['summary','render',END]).addConditionalEdges('summary',s=>s.next,['render',END]).addConditionalEdges('render',s=>s.next,['browser',END]).addConditionalEdges('browser',s=>s.next,['grade',END]).addEdge('grade',END).compile();
 await graph.invoke({}, {recursionLimit:12});return result;
}
module.exports={runSelectedInboxGraph};
