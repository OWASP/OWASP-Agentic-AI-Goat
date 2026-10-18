'use strict';
// Serial local inference on recorded/synthetic evidence. No exercise tools run.
const {spawn}=require('node:child_process');
const path=require('node:path');
const suites=[
 ['DPI','dpiStructuredJudge.test.js','LIVE_DPI_MATRIX'],
 ['DPI-jailbreak-v3','dpiStructuredJudge.test.js','LIVE_DPI_JAILBREAK_V3_COHORT'],
 ['IPI','indirectAllObjectives.live.test.js','LIVE_IPI_MATRIX'],
 ['IPI-evidence-bound','indirectAllObjectives.live.test.js','LIVE_IPI_EVIDENCE_BOUND'],
 ['EA','excessiveAgencyStructuredJudge.test.js','LIVE_EA_MATRIX'],
 ['FinFlow','finflowAllObjectives.live.test.js','LIVE_OLLAMA_TEST'],
 ['CodeBot','codeBotStructuredJudge.test.js','LIVE_OLLAMA_TEST'],
 ['CSRF','csrfObjectiveJudge.live.test.js','RUN_LIVE_JUDGE'],
 ['XSS','xssObjectiveJudge.live.test.js','RUN_LIVE_JUDGE'],
 ['MCP','mcpObjectiveJudge.live.test.js','RUN_LIVE_JUDGE'],
 ['ARIA-NOVA','sqlNoSqlObjectiveJudge.live.test.js','RUN_LIVE_JUDGE'],
 ['CTF','ctfJudgeQualification.live.test.js','RUN_LIVE_JUDGE'],
 ['LegacySensitive','legacySensitiveQualification.live.test.js','RUN_LIVE_JUDGE'],
 ['LegacyEmail','xssEmailQualification.live.test.js','RUN_LIVE_JUDGE'],
];
const expectedCases={DPI:16,'DPI-jailbreak-v3':3,'IPI-evidence-bound':6,IPI:20,EA:18,FinFlow:36,CodeBot:12,CSRF:24,XSS:24,MCP:22,'ARIA-NOVA':40,CTF:20,LegacySensitive:10,LegacyEmail:8};
const objectiveManifest={
 DPI:['interact','system_prompt','jailbreak','multi_language','virtualization','role_playing','side_stepping','obfuscation'],
 'DPI-jailbreak-v3':['learner_attributed_attack_quotation','refusal_quoting_proposed_answer','genuine_quoted_assistant_answer'],
 'IPI-evidence-bound':['rag_injected_doc','rag_query_injection','email_trigger_injection'],
 IPI:['rag_upload','rag_clean_doc','rag_query','rag_injected_doc','rag_query_injection','email_create_inbox','email_send_attack','email_retrieve','email_trigger_injection','email_understand_defense'],
 EA:['1','2','3','4','5','6','7','8','9'],
 FinFlow:['tool_enum','llm_identify','tool_version','admin_enum','traversal_secrets','traversal_passwd','traversal_llm','ssrf_oob','ssrf_internal','ssrf_ollama','error_leak','admin_backup','admin_dl_backup','admin_read_logs','admin_llm_logs','admin_modify_logs','admin_secrets','admin_dirlist'],
 CodeBot:['tool_list','pkg_discover','clean_request','rce_cmd','rce_env','rce_ssh'],
 CSRF:['csrf_g1','csrf_g2','csrf_g3','csrf_p1','csrf_p2','csrf_p3','csrf_x1','csrf_x2','csrf_x3','csrf_i1','csrf_i2','csrf_i3'],
 XSS:['xss_r1','xss_r2','xss_r3','xss_s1','xss_s2','xss_s3','xss_g1','xss_g2','xss_g3','xss_e1','xss_e2','xss_e3'],
 MCP:['mcp_recon','mcp_cmd_injection','mcp_ssrf','mcp_tool_poisoning','mcp_indirect_injection','mcp_confused_deputy','mcp_broken_authz','mcp_secret_exposure','mcp_supply_chain','mcp_audit_gap','mcp_shadow_server'],
 'ARIA-NOVA':[...Array.from({length:10},(_,index)=>`sqli_${index+1}`),...Array.from({length:10},(_,index)=>`nosqli_${index+1}`)],
 CTF:Array.from({length:10},(_,index)=>`stage_${index+1}`),
 LegacySensitive:['path_traversal','ssi_injection','combined_traversal_ssi','ai_assisted_path_traversal','ai_assisted_ssi'],
 LegacyEmail:['level_1','level_2','level_3','level_4'],
};
const qualificationCases={
 'DPI-jailbreak-v3':[
  'learner_attributed_attack_quotation:negative',
  'refusal_quoting_proposed_answer:negative',
  'genuine_quoted_assistant_answer:positive',
 ],
};
function qualificationCoverage(family,stdout){
 const expected=new Set(qualificationCases[family]||(objectiveManifest[family]||[]).flatMap(id=>[`${id}:positive`,`${id}:negative`]));
 const observed=[];
 for(const line of String(stdout).split(/\r?\n/)){
  // Accept only Node diagnostic records, never JSON echoed inside assertion
  // diffs, stack messages, or arbitrary model output.
  const record=line.trim().match(/^(?:(?:#|ℹ)\s+)?(\{.*\})$/);if(!record)continue;
  let data;try{data=JSON.parse(record[1]);}catch{continue;}
  const judgment=data.judgment&&typeof data.judgment==='object'?data.judgment:{};
  if(typeof(data.verdict??judgment.verdict??(family==='CTF'?data.actual:undefined))!=='string')continue;
  // The suite-owned case id is authoritative. A nested judgment can use a
  // different runtime id (EA emits objective_1 while its fixture contract is 1).
  let id=data.id??data.case??data.name??data.objectiveId??data.objective??judgment.objectiveId;
  if(id===undefined||id===null)continue;
  id=String(id);
  let label=data.label;
  if(label!=='positive'&&label!=='negative'){
   if(typeof data.positive==='boolean')label=data.positive?'positive':'negative';
   else if(data.expected==='pass')label='positive';
   else if(['fail','not_pass','not-pass'].includes(data.expected))label='negative';
   else if(/:(observed|positive)$/.test(String(data.name??data.case??id)))label='positive';
   else if(/:(refusal|negative)$/.test(String(data.name??data.case??id)))label='negative';
   else if(family==='ARIA-NOVA'&&/_(positive|negative)$/.test(id))label=id.endsWith('_positive')?'positive':'negative';
  }
  if(family==='ARIA-NOVA')id=id.replace(/_(positive|negative)$/,'');
  else id=id.replace(/:(observed|refusal|positive|negative)$/,'');
  if(label==='positive'||label==='negative')observed.push(`${id}:${label}`);
 }
 const counts=new Map();for(const key of observed)counts.set(key,(counts.get(key)||0)+1);
 const missing=[...expected].filter(key=>counts.get(key)!==1);
 const unexpected=[...counts].filter(([key,count])=>!expected.has(key)||count!==1).map(([key,count])=>`${key}${count===1?'':` (x${count})`}`);
 return{coverageCorrect:missing.length===0&&unexpected.length===0,missingCases:missing,unexpectedCases:unexpected};
}
function assessQualification({family,stdout,code,overflow=false}){
 const summary=require('./summarize-judge-log').summarize(`Qualifying ${family} on local llama3.1:8b\n${stdout}`);
 const result=summary.total;
 const coverage=qualificationCoverage(family,stdout);
 return{family,passed:code===0&&!overflow&&coverage.coverageCorrect&&result.recorded===expectedCases[family]&&result.labeled===result.recorded&&result.duplicateCases===0&&result.unidentifiedCases===0&&result.semanticCorrect===result.recorded,expected:expectedCases[family],recorded:result.recorded,contractCorrect:result.contractCorrect,conclusiveCorrect:result.semanticCorrect,unresolved:result.unresolved,duplicateCases:result.duplicateCases,unidentifiedCases:result.unidentifiedCases,...coverage,overflow};
}
function captureChild(child,{write=chunk=>process.stdout.write(chunk),maxBytes=4*1024*1024}={}){
 return new Promise((resolve,reject)=>{let stdout='',bytes=0,overflow=false;
  const capture=chunk=>{write(chunk);bytes+=Buffer.byteLength(chunk);if(bytes<=maxBytes)stdout+=chunk.toString();else overflow=true;};
  child.stdout.on('data',capture);child.stderr.on('data',capture);child.on('error',reject);child.on('close',code=>resolve({code,stdout,overflow}));
 });
}
async function main(selected=process.argv.slice(2)){
 const base=new URL(process.env.OLLAMA_BASE_URL||'http://localhost:11434');
 if(!['localhost','127.0.0.1','[::1]'].includes(base.hostname)||!['http:','https:'].includes(base.protocol))throw Error('Local judge qualification requires a loopback OLLAMA_BASE_URL');
 if(selected.some(name=>!suites.some(s=>s[0]===name)))throw Error('Unknown family. Use '+suites.map(s=>s[0]).join(', '));
 const failed=[];
 for(const [family,file,flag] of suites.filter(s=>!selected.length||selected.includes(s[0]))){
  const env={...process.env,JUDGE_PROVIDER:'ollama',JUDGE_MODEL:'llama3.1:8b',AI_PROVIDER:'ollama',PLATFORM_DATABASE_ENGINE:'sqlite',OLLAMA_BASE_URL:base.toString()};
  for(const key of ['LIVE_DPI_MATRIX','LIVE_DPI_JAILBREAK_V3_COHORT','LIVE_IPI_MATRIX','LIVE_IPI_EVIDENCE_BOUND','LIVE_EA_MATRIX','LIVE_OLLAMA_TEST','RUN_LIVE_JUDGE','LIVE_OBJECTIVES','FINFLOW_OBJECTIVES','OPENAI_API_KEY','ANTHROPIC_API_KEY','LANGSMITH_API_KEY','LANGSMITH_TRACING','LANGCHAIN_TRACING_V2'])delete env[key];
  env[flag]='1';env.LANGSMITH_TRACING='false';env.LANGCHAIN_TRACING_V2='false';
  console.log(`\nQualifying ${family} on local llama3.1:8b`);
  const child=spawn(process.execPath,['--test',path.join('tests',file)],{cwd:path.resolve(__dirname,'..'),env,stdio:['inherit','pipe','pipe']});
  const captured=await captureChild(child);
  const qualification=assessQualification({family,...captured});
  console.log('Conclusive baseline: '+JSON.stringify(qualification));
  if(!qualification.passed)failed.push(family);
 }
 if(failed.length)throw Error('Judge qualification failed: '+failed.join(', '));
 console.log('All selected conclusive judge baselines passed: every positive passed and every negative explicitly failed, with complete diagnostics. These are evidence-level tests; run isolated integration tests separately.');
}
if(require.main===module)main().catch(error=>{console.error(error.message);process.exitCode=1;});
module.exports={assessQualification,captureChild,expectedCases,objectiveManifest,qualificationCoverage,main};
