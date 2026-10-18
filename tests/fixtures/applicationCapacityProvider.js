'use strict';
// Controlled transport policy, not real-model output or credit evidence.
function createPolicy(){
 const turns=new Map(),gradingProbeKeys=new Set();let total=0;
 return{respond(body){
  if(!body||body.model!=='capacity-controlled-v1'||!Array.isArray(body.messages))throw Error('Undeclared controlled provider request');
  const text=body.messages.map(x=>x.content).join('\n'),matches=[...text.matchAll(/capacity-owner-([1-9][0-9]{0,9})-run-([a-f0-9-]{36})/g)];
  const owners=new Set(matches.map(x=>x[1]));if(!matches.length||owners.size!==1)throw Error('Controlled request identity unavailable');
  const key=matches.at(-1)[0],original=text.match(/Original user request \(JSON encoded string\):\n([^\n]+)\n(?:Your prior decision[^\n]*\n)?FINAL DECISION CHECK:/),request=original?JSON.parse(original[1]):null;
  const aria=text.includes('You are ARIA. Select exactly one tool'),nova=text.includes('You are NOVA. Select exactly one tool');
  const prefix='Please search products using this exact searchTerm: ',gradingRequest=aria&&typeof request==='string'&&request.startsWith(prefix)&&request.includes('capacity-grading-projection-v1');if(gradingRequest)gradingProbeKeys.add(key);const gradingProbe=gradingProbeKeys.has(key),count=(turns.get(key)||0)+1,limit=gradingProbe?5:4;if(count>limit||total>=6000)throw Error('Controlled provider budget exceeded');turns.set(key,count);total++;
  let content='Controlled capacity response; no objective success claim.';
  if(aria||nova){const tool=gradingRequest?'search_products':aria?'view_cart':'view_reading_list',marker='FINAL DECISION CHECK: Completed tool/parameter pairs are ';
   const tail=text.slice(text.lastIndexOf(marker)+marker.length),end=tail.indexOf('. Do not select');if(!text.includes(marker)||end<0)throw Error('Controlled decision context unavailable');
   const done=JSON.parse(tail.slice(0,end));if(!Array.isArray(done))throw Error('Controlled decision context unavailable');const selected=done.some(x=>x.tool===tool)?'general_chat':tool;content=JSON.stringify({tool:selected,params:selected===tool&&gradingRequest?{searchTerm:request.slice(prefix.length),maxPrice:null}:{}});
  }
  return{model:body.model,done:true,message:{role:'assistant',content}};
 },snapshot:()=>({actualModel:false,total,distinctRuns:turns.size,maxTurns:Math.max(0,...turns.values()),standardMaxTurns:Math.max(0,...[...turns].filter(([key])=>!gradingProbeKeys.has(key)).map(([,count])=>count)),gradingProjectionRuns:gradingProbeKeys.size,gradingProjectionMaxTurns:Math.max(0,...[...turns].filter(([key])=>gradingProbeKeys.has(key)).map(([,count])=>count))})};
}
function assertLiveHold(start,current){if(!start||!current||!Number.isSafeInteger(start.holdId)||start.holdId<1||current.holdId!==start.holdId||current.holding!==true||current.expired!==false||current.total!==start.total)throw Error('Provider hold no longer proves pre-effect boundary');}
module.exports={createPolicy,assertLiveHold};
