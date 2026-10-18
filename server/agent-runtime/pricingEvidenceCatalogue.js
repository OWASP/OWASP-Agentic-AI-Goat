'use strict';
const {createHash}=require('node:crypto');
const VERSION='server-evidence-catalogue-v1',BLOCK_POINTS=256,MAX_BLOCKS=64,MAX_BYTES=262144,MAX_SELECTIONS=2048;
const sha=x=>createHash('sha256').update(x).digest('hex');
const exact=(x,keys)=>x&&typeof x==='object'&&!Array.isArray(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
function catalogue(text,prefix){
 if(typeof text!=='string'||!text.length||!text.isWellFormed()||Buffer.byteLength(text)>MAX_BYTES||!['s','r'].includes(prefix))throw Error('Catalogue field unavailable');
 const rows=[];let start=0,end=0,points=0;
 for(const point of text){end+=point.length;if(++points===BLOCK_POINTS){rows.push(Object.freeze({id:prefix+rows.length,start,end,text:text.slice(start,end)}));start=end;points=0;if(rows.length>MAX_BLOCKS)throw Error('Catalogue overflow');}}
 if(start<end)rows.push(Object.freeze({id:prefix+rows.length,start,end,text:text.slice(start,end)}));
 if(rows.length>MAX_BLOCKS)throw Error('Catalogue overflow');return Object.freeze(rows);
}
function select(rows,ids){
 if(!Array.isArray(ids)||ids.length>MAX_BLOCKS||new Set(ids).size!==ids.length)throw Error('Invalid catalogue selection');
 const selected=ids.map(id=>{const row=rows.find(r=>r.id===id);if(!row)throw Error('Unknown catalogue ID');return row;});
 if(selected.some((r,i)=>i&&r.start<=selected[i-1].start))throw Error('Unordered catalogue selection');
 const spans=[];for(const r of selected){const prior=spans.at(-1);if(prior?.end===r.start){prior.end=r.end;prior.text+=r.text;}else spans.push({start:r.start,end:r.end,text:r.text});}return spans;
}
function auditRows(rows){return rows.map(({id,start,end,text})=>({id,start,end,sha256:sha(text)}));}
function normalizeAudit(value,{passed=false}={}){
 const hash=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
 if(!exact(value,['version','sourceSha256','responseSha256','taskSha256','catalogues','selections'])||value.version!==VERSION||!['sourceSha256','responseSha256','taskSha256'].every(k=>hash(value[k]))||!exact(value.catalogues,['source','response'])||!Array.isArray(value.selections)||value.selections.length>MAX_SELECTIONS)throw Error('Invalid catalogue audit');
 const catalogues={};for(const [field,prefix]of [['source','s'],['response','r']]){
  const rows=value.catalogues[field];if(!Array.isArray(rows)||!rows.length||rows.length>MAX_BLOCKS)throw Error('Invalid audit catalogue');
  catalogues[field]=rows.map((r,i)=>{if(!exact(r,['id','start','end','sha256'])||r.id!==prefix+i||!Number.isSafeInteger(r.start)||!Number.isSafeInteger(r.end)||r.start!==(i?rows[i-1].end:0)||r.end<=r.start||r.end-r.start>BLOCK_POINTS*2||r.end>BLOCK_POINTS*MAX_BLOCKS*2||!hash(r.sha256))throw Error('Invalid audit span');return{...r};});
 }
 const selections=value.selections.map(s=>{if(!exact(s,['field','ids'])||!['source','response'].includes(s.field)||!Array.isArray(s.ids)||!s.ids.length||s.ids.length>MAX_BLOCKS||new Set(s.ids).size!==s.ids.length)throw Error('Invalid audit selection');let previous=-1;for(const id of s.ids){const index=catalogues[s.field].findIndex(r=>r.id===id);if(index<=previous)throw Error('Invalid audit reference');previous=index;}return{field:s.field,ids:[...s.ids]};});
 if(passed&&(!selections.some(s=>s.field==='source')||!selections.some(s=>s.field==='response')))throw Error('Missing selected evidence');
 return{version:VERSION,sourceSha256:value.sourceSha256,responseSha256:value.responseSha256,taskSha256:value.taskSha256,catalogues,selections};
}
module.exports={catalogue,select,auditRows,normalizeAudit,sha,VERSION,BLOCK_POINTS,MAX_BLOCKS,MAX_BYTES,MAX_SELECTIONS};
