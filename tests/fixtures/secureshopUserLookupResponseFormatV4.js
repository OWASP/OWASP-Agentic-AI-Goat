'use strict';

// Offline V21 diagnostic only. This module is deliberately outside the
// assessment service and cannot award credit or replace the production rubric.
const fs=require('node:fs');
const path=require('node:path');
const {createHash}=require('node:crypto');
const {isDeepStrictEqual:equal}=require('node:util');
const {isUserLookupJudgeInputValid,FIELDS}=require('../../server/services/secureshopUserLookupEvidence');

const VERSION='secureshop-user-lookup-response-format-v4-diagnostic';
const CAPTURES=Object.freeze({
 'run-nza7j3mn':'ee979373915955e7c8c5b6408a40c6b831e6a275b43c17002e6a66f05b354f6b',
 'run-p2mr210n':'4ba97e3b21fe815868f61eadbb5b408c2794b0cb735f4af2ffd1c7038139d695',
});
const sha=value=>createHash('sha256').update(value).digest('hex');
const fail=message=>{throw Error(`V21 diagnostic admission: ${message}`);};

function readGenuineControl(runId){
 const expected=CAPTURES[runId];
 if(!expected)fail('unlisted retained capture');
 const file=path.join(__dirname,'../../tasks/qualification',runId,'user-lookup-disclosure-capture.json');
 const bytes=fs.readFileSync(file);
 if(sha(bytes)!==expected)fail('retained capture changed');
 const capture=JSON.parse(bytes),item=capture.cases?.[0];
 if(capture.cases?.length!==1||item?.kind!=='vuln'||item.saved?.text!==item.turn?.result_json?.text
  ||item.turn?.status!=='completed'||item.lookup?.status!=='complete'
  ||!Array.isArray(item.actorWireIndices)||item.actorWireIndices.length!==2
  ||item.actorWireIndices.some(index=>capture.wire?.[index]?.kind!=='actor'
    ||capture.wire?.[index]?.responseComplete!==true))fail('original actor evidence incomplete');
 const packet=JSON.parse(capture.canonicalJudge?.row?.packet||'null');
 if(!isUserLookupJudgeInputValid(packet)
  ||packet.evidence[2].content!==item.turn.result_json.text
  ||!equal(packet.evidence[1].content,item.lookup.user)
  ||capture.canonicalJudge.row.verdict==='pass')fail('retained packet or failed Judge provenance mismatch');
 const source=packet.evidence[1].content,response=packet.evidence[2].content;
 return Object.freeze({version:VERSION,kind:'genuine_original_actor',runId,
  captureSha256:expected,originalJudgeVerdict:capture.canonicalJudge.row.verdict,
  originalJudgeErrorCode:capture.canonicalJudge.row.result_json?.errorCode||null,
  packet,source,response,responseSha256:sha(response),
  observedDisclosure:FIELDS.every(field=>response.includes(source[field]))});
}

function responseFormat(control){
 if(control?.version!==VERSION||control.kind!=='genuine_original_actor'
  ||typeof control.response!=='string'||sha(control.response)!==control.responseSha256
  ||!equal(control.packet?.evidence?.[1]?.content,control.source)
  ||control.packet?.evidence?.[2]?.content!==control.response)fail('unbound original response');
 const verified=readGenuineControl(control.runId);
 if(verified.responseSha256!==control.responseSha256
  ||verified.captureSha256!==control.captureSha256
  ||!equal(verified.source,control.source)||!equal(verified.packet,control.packet)
  ||verified.response!==control.response)fail('unbound retained capture');
 return formatBytes(verified.source,verified.response,'genuine_original_actor');
}

function formatBytes(source,response,provenance){
 if(!source||typeof source!=='object'||Array.isArray(source)
  ||typeof response!=='string'||!response.isWellFormed()
  ||!FIELDS.every(field=>typeof source[field]==='string'&&source[field].length>0))fail('malformed response format input');
 const spans=FIELDS.map(field=>{
  const sourceValue=source[field],valueStart=response.indexOf(sourceValue);
  if(valueStart<0)return Object.freeze({field,sourceValue,present:false,excerpt:null,start:null,end:null,valueStart:null,valueEnd:null});
  const valueEnd=valueStart+sourceValue.length,start=Math.max(0,valueStart-24),end=Math.min(response.length,valueEnd+24);
  return Object.freeze({field,sourceValue,present:true,excerpt:response.slice(start,end),start,end,valueStart,valueEnd});
 });
 return Object.freeze({version:VERSION,provenance,originalResponseEvidenceId:'user_lookup_response',
  originalResponseSha256:sha(response),originalResponse:response,
  sourceValuesSha256:sha(JSON.stringify(FIELDS.map(field=>source[field]))),
  nonCitableVerbatimSpanIndex:Object.freeze(spans)});
}

// Explicitly synthetic formatting fixture for portable unit tests. Its output
// is never an admission control and cannot be passed to admitGenuinePair.
function syntheticResponseFormat(source,response){return formatBytes(source,response,'synthetic_response_counterfactual');}

function citationIsOriginal(format,field,quote){
 if(format?.version!==VERSION||typeof format.originalResponse!=='string'
  ||sha(format.originalResponse)!==format.originalResponseSha256
  ||!FIELDS.includes(field)||typeof quote!=='string'||!quote
  ||!Array.isArray(format.nonCitableVerbatimSpanIndex)
  ||format.nonCitableVerbatimSpanIndex.length!==FIELDS.length)return false;
 const spans=format.nonCitableVerbatimSpanIndex,response=format.originalResponse;
 if(spans.some((row,index)=>row?.field!==FIELDS[index]||typeof row.sourceValue!=='string'||!row.sourceValue))return false;
 if(sha(JSON.stringify(spans.map(row=>row.sourceValue)))!==format.sourceValuesSha256)return false;
 for(const span of spans){
  const valueStart=response.indexOf(span.sourceValue),present=valueStart>=0;
  if(span.present!==present)return false;
  if(!present){if(span.excerpt!==null||span.start!==null||span.end!==null
   ||span.valueStart!==null||span.valueEnd!==null)return false;continue;}
  const valueEnd=valueStart+span.sourceValue.length,start=Math.max(0,valueStart-24),end=Math.min(response.length,valueEnd+24);
  if(span.valueStart!==valueStart||span.valueEnd!==valueEnd||span.start!==start||span.end!==end
   ||span.excerpt!==response.slice(start,end))return false;
 }
 const span=spans[FIELDS.indexOf(field)];
 if(!span.present||quote.length<Math.min(24,response.length)||!quote.includes(span.sourceValue))return false;
 for(let at=response.indexOf(quote);at>=0;at=response.indexOf(quote,at+1)){
  if(at<=span.valueStart&&at+quote.length>=span.valueEnd)return true;
 }
 return false;
}

function admitGenuinePair(positive,negative){
 if(positive?.kind!=='genuine_original_actor'||positive.observedDisclosure!==true
  ||negative?.kind!=='genuine_original_actor'||negative.observedDisclosure!==false
  ||positive.runId===negative.runId
  ||CAPTURES[positive.runId]!==positive.captureSha256
  ||CAPTURES[negative.runId]!==negative.captureSha256)fail('independent genuine positive and negative required');
 const verifiedPositive=readGenuineControl(positive.runId),verifiedNegative=readGenuineControl(negative.runId);
 if(verifiedPositive.responseSha256!==positive.responseSha256
  ||verifiedPositive.observedDisclosure!==true
  ||!equal(verifiedPositive.source,positive.source)||!equal(verifiedPositive.packet,positive.packet)
  ||verifiedNegative.responseSha256!==negative.responseSha256
  ||verifiedNegative.observedDisclosure!==false
  ||!equal(verifiedNegative.source,negative.source)||!equal(verifiedNegative.packet,negative.packet))fail('independent genuine positive and negative required');
 return Object.freeze({version:VERSION,creditAuthorized:false,
  positiveRunId:positive.runId,negativeRunId:negative.runId});
}

module.exports={VERSION,CAPTURES,readGenuineControl,responseFormat,syntheticResponseFormat,citationIsOriginal,admitGenuinePair};
