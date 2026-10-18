'use strict';
// Server-owned evidence locations for the unmounted DPI diagnostic.  Models see
// IDs and never calculate text offsets or occurrence counts.
const {createHash}=require('node:crypto');
const MAX_ENTRIES=128,MAX_BYTES=100000;
const sha=value=>createHash('sha256').update(value).digest('hex');
function fail(message){throw Object.assign(Error(message),{code:'DPI_EVIDENCE_CATALOG_INVALID'});}
function boundaries(text,{sentencesOnly=false}={}){
 const points=[...text]; if(!points.length)fail('Empty catalogue field');
 const out=[],seen=new Set(),add=(start,end)=>{if(start>=end)return;const value=points.slice(start,end).join('');if(!value.trim())return;const key=`${start}:${end}`;if(seen.has(key))return;seen.add(key);out.push({start,end,text:value});};
 // Sentence spans preserve complete, unnormalised source evidence.
 let start=0;for(let i=0;i<=points.length;i++)if(i===points.length||/[.!?。！？\n]/u.test(points[i])){add(start,i+(i<points.length?1:0));start=i+1;}
 if(sentencesOnly){if(out.length>MAX_ENTRIES)fail('Evidence catalogue overflow');return out;}
 // Default mode retains the historical alternative clause/full-field entries.
 for(const sentence of [...out]){let local=0;const chars=[...sentence.text];for(let i=0;i<=chars.length;i++)if(i===chars.length||/[,;:，；：]/u.test(chars[i])){add(sentence.start+local,sentence.start+i+(i<chars.length?1:0));local=i+1;}}
 add(0,points.length);
 if(out.length>MAX_ENTRIES)fail('Evidence catalogue overflow');
 return out;
}
function createEvidenceCatalog(fields,{sourceSentencesOnly=false}={}){
 if(!fields||Object.keys(fields).sort().join(',')!=='response,source')fail('Invalid catalogue fields');
 if(typeof sourceSentencesOnly!=='boolean')fail('Invalid catalogue mode');
 const snapshot=Object.freeze({source:fields.source,response:fields.response}),all=[];for(const field of ['source','response']){const text=snapshot[field];if(typeof text!=='string'||!text.isWellFormed()||!text.trim()||Buffer.byteLength(text)>MAX_BYTES)fail('Invalid catalogue field');for(const [n,row] of boundaries(text,{sentencesOnly:field==='source'&&sourceSentencesOnly}).entries())all.push(Object.freeze({id:`${field}_${n}`,field,startScalar:row.start,endScalar:row.end,startByte:Buffer.byteLength([...text].slice(0,row.start).join('')),endByte:Buffer.byteLength([...text].slice(0,row.end).join('')),sha256:sha(row.text),text:row.text}));}
 const digest=sha(JSON.stringify({sourceSentencesOnly,entries:all.map(({id,field,startScalar,endScalar,sha256})=>({id,field,startScalar,endScalar,sha256}))}));
 const byId=new Map(all.map(v=>[v.id,v]));
 const resolve=(id,field)=>{if(typeof id!=='string')fail('Invalid evidence ID');const row=byId.get(id);if(!row||row.field!==field)fail('Unknown or wrong-field evidence ID');return row;};
 return Object.freeze({version:'dpi-server-evidence-catalog-v2',sourceSentencesOnly,digest,entries:Object.freeze(all),resolve,resolveRange(startId,endId,field){if(field!=='source'||!sourceSentencesOnly)fail('Source sentence range unavailable');const first=resolve(startId,field),last=resolve(endId,field);if(first.startScalar>last.startScalar)fail('Reverse evidence range');const points=[...snapshot.source],text=points.slice(first.startScalar,last.endScalar).join('');return Object.freeze({field,startId,endId,startScalar:first.startScalar,endScalar:last.endScalar,startByte:first.startByte,endByte:Buffer.byteLength(points.slice(0,last.endScalar).join('')),sha256:sha(text),text});}});
}
module.exports={createEvidenceCatalog,MAX_ENTRIES};
