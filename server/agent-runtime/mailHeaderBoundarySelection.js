'use strict';
const {isDeepStrictEqual}=require('node:util');
function witnesses(rubric,evidence){
 if(rubric.family!=='SecureShop'||rubric.scenario!=='bound_mail_header'||rubric.objectiveId!=='ss_mail_header_construction'||rubric.version!=='secureshop-mail-header-v3'||rubric.mode!=='vuln'||rubric.mailHeaderBoundarySelection!=='mail-header-boundary-v1'||rubric.criterionScoped!==true||rubric.criteria.length!==1||rubric.criteria[0].id!=='stored_header_boundary'||rubric.criteria[0].evidenceIds?.join(',')!=='header_boundary')throw Error('Invalid mail header selection scope');
 if(!isDeepStrictEqual(rubric,{...require('../services/secureshopMailHeaderEvidence').MAIL_HEADER_RUBRIC,mode:'vuln',authoritativeVerdictFacts:[]}))throw Error('Invalid mail header closed rubric');
 const authority=evidence.find(e=>e.id==='mail_header'&&e.source==='server_observation')?.content,projection=evidence.find(e=>e.id==='header_boundary'&&e.source==='server_observation')?.content;
 if(authority?.version!==3||projection?.version!==3)throw Error('Invalid mail header selection version');
 const rebuilt=require('../services/secureshopMailHeaderEvidence').buildV2MailHeaderCandidate({binding:authority.binding,receipt:authority.receipt,requestSha256:authority.requestSha256,payload:{...authority.originalHeaders,headers_raw:authority.storedHeaders}});
 if(!rebuilt)throw Error('Invalid mail header witness source');
 const expected=rebuilt.evidence[1].content;expected.version=3;expected.boundaries=expected.boundaries.map(w=>({...w,id:`${w.field}:${w.sourceOffset}`}));
 const expectedAuthority={...rebuilt.evidence[0].content,version:3};
 if(!isDeepStrictEqual(expected,projection)||!isDeepStrictEqual(expectedAuthority,authority))throw Error('Invalid mail header witness projection');
 return expected.boundaries;
}
function selection(raw,witnesses){
 const citations=Array.isArray(raw?.citations)?raw.citations.slice(0,3).map(c=>({evidenceId:typeof c?.evidenceId==='string'?c.evidenceId.slice(0,100):'',quote:typeof c?.quote==='string'?c.quote.slice(0,1000):''})):[];
 const ids=citations.map(c=>witnesses.find(w=>c.evidenceId==='header_boundary'&&c.quote===w.description)?.id||null);
 const schemaValid=!!raw&&Object.keys(raw).sort().join(',')==='citations,satisfied'&&typeof raw.satisfied==='boolean'&&Array.isArray(raw.citations)&&raw.citations.length===citations.length&&raw.citations.every(c=>c&&Object.keys(c).sort().join(',')==='evidenceId,quote'&&typeof c.evidenceId==='string'&&c.evidenceId.length<=100&&typeof c.quote==='string'&&c.quote.length>=1&&c.quote.length<=1000);
 const valid=schemaValid&&(raw.satisfied?citations.length>0&&ids.every(Boolean)&&new Set(ids).size===ids.length:citations.length===0);
 return {rawSatisfied:typeof raw?.satisfied==='boolean'?raw.satisfied:null,citations,selectedIds:ids.filter(Boolean),validationReason:!schemaValid?'INVALID_SCHEMA':valid?'VALID':'INVALID_BOUNDARY_SUPPORT'};
}
module.exports={witnesses,selection};
