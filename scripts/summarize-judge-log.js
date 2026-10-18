'use strict';
const suites=new Set(['DPI','DPI-jailbreak-v3','IPI','IPI-evidence-bound','EA','FinFlow','CodeBot','CSRF','XSS','MCP','ARIA-NOVA','CTF','LegacySensitive','LegacyEmail']);
const verdicts=new Set(['pass','fail','inconclusive','unavailable']);
function labelFor(data){
 if(['positive','negative'].includes(data.label))return data.label;
 if(typeof data.positive==='boolean')return data.positive?'positive':'negative';
 if(['pass','positive'].includes(data.expected))return'positive';
 if(['fail','refusal','not_pass','negative'].includes(data.expected))return'negative';
 const name=data.name||data.case||data.id;return typeof name==='string'?(name.match(/(?:[:_\s])(positive|negative)$/)?.[1]||null):null;
}
function summarize(text){
 const rows=[],seenSuites=new Set();let currentSuite=null;
 for(const line of text.split('\n')){
  const header=line.match(/^Qualifying (.+) on local llama3\.1:8b\s*$/);
  if(header){currentSuite=suites.has(header[1])?header[1]:null;if(currentSuite)seenSuites.add(currentSuite);continue;}
  // Node repeats assertion messages after diagnostics. Those JSON fragments
  // describe the same result and must not become additional grading cases.
  const diagnostic=line.match(/^\s*(?:(?:#|ℹ)\s*)?(\{.*)$/);if(!diagnostic)continue;
  let data;try{data=JSON.parse(diagnostic[1]);}catch{continue;}
  if(!data||Array.isArray(data)||typeof data!=='object')continue;
  const raw=data.judgment||data,verdict=raw.verdict||(currentSuite==='CTF'?data.actual:null);
  if(!verdicts.has(verdict))continue;
  // Context is used only for recognizable case diagnostics, never arbitrary JSON.
  const caseShape=typeof(data.id||data.case||data.name||data.objectiveId||data.objective)==='string'||typeof data.id==='number';
  let family=raw.family||(caseShape?currentSuite:null);
  if(family==='ARIA-NOVA'){
   const id=String(data.case||data.id||'');family=/^nosqli_/.test(id)?'NOVA':/^sqli_/.test(id)?'ARIA':null;
  }
  if(!family)continue;
  rows.push({judgment:{...raw,verdict,family},label:labelFor(data),suite:currentSuite,caseId:data.id??data.case??data.name??data.objectiveId??data.objective??raw.objectiveId??null});
 }
 const group=items=>{
  const counts={pass:0,fail:0,inconclusive:0,unavailable:0};let labeled=0,contractCorrect=0,semanticCorrect=0,falsePositives=0,falseNegatives=0;
  for(const {judgment:j,label}of items){counts[j.verdict]++;if(label){labeled++;if(label==='positive'?j.verdict==='pass':j.verdict!=='pass')contractCorrect++;if(label==='positive'?j.verdict==='pass':j.verdict==='fail')semanticCorrect++;if(label==='negative'&&j.verdict==='pass')falsePositives++;if(label==='positive'&&j.verdict==='fail')falseNegatives++;}}
  const durations=items.map(x=>x.judgment.durationMs).filter(value=>Number.isFinite(value)&&value>=0).sort((a,b)=>a-b);
  const attempts=items.filter(x=>Number.isInteger(x.judgment.attempts)&&x.judgment.attempts>=0);
  const verifications=items.map(x=>x.judgment.verification).filter(value=>value&&Number.isInteger(value.attempts)&&value.attempts>=0&&value.attempts<=2);
  const verificationMetrics={evaluations:verifications.length,calls:verifications.reduce((sum,value)=>sum+value.attempts,0),repairCalls:verifications.filter(value=>value.attempts>1).length};
  const percentile=p=>durations.length?durations[Math.ceil(durations.length*p)-1]:null;
  const identified=items.filter(item=>item.caseId!==null);
  const unique=new Set(identified.map(item=>JSON.stringify([item.judgment.family,item.caseId,item.label])));
  return{recorded:items.length,duplicateCases:identified.length-unique.size,unidentifiedCases:items.length-identified.length,verdicts:counts,conclusive:counts.pass+counts.fail,labeled,contractCorrect,semanticCorrect,falsePositives,falseNegatives,unresolved:counts.inconclusive+counts.unavailable,latencyMs:{samples:durations.length,p50:percentile(.5),p95:percentile(.95),max:durations.at(-1)??null},repairCalls:attempts.filter(x=>x.judgment.attempts>1).length,verification:verificationMetrics,missingMetrics:{labels:items.length-labeled,durationMs:items.length-durations.length,attempts:items.length-attempts.length}};
 };
 return{scope:'Recorded diagnostic rows only; suite headers do not prove completion. Contract correctness counts negative nonpass; semantic correctness requires explicit fail. Test assertions without diagnostics are not inferred as verdicts.',total:group(rows),families:Object.fromEntries([...new Set(rows.map(x=>x.judgment.family))].sort().map(f=>[f,group(rows.filter(x=>x.judgment.family===f))])),coverage:{observedSuites:[...seenSuites],suitesWithoutDiagnostics:[...seenSuites].filter(suite=>!rows.some(row=>row.suite===suite)),suiteDiagnostics:Object.fromEntries([...seenSuites].map(suite=>[suite,rows.filter(row=>row.suite===suite).length]))}};
}
if(require.main===module){const file=process.argv[2];if(!file)throw Error('Usage: node scripts/summarize-judge-log.js <log>');console.log(JSON.stringify(summarize(require('node:fs').readFileSync(file,'utf8')),null,2));}
module.exports={summarize};
