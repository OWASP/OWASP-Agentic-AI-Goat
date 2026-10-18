'use strict';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const plain=value=>value&&typeof value==='object'&&!Array.isArray(value);
const bounded=(value,label)=>{const bytes=JSON.stringify(value);if(typeof bytes!=='string'||Buffer.byteLength(bytes)>2*1024*1024)throw RangeError(`Bounded ${label} required`);return JSON.parse(bytes);};
const errorChain=error=>{const rows=[];for(let value=error,depth=0;value&&depth<3;value=value.cause,depth++)rows.push({name:String(value.name||'').slice(0,80),code:String(value.code||'').slice(0,80),message:String(value.message||'').slice(0,240)});return rows;};
function classify(outcome,candidates){
 const values=Object.values(outcome);
 if(values.length===0)return'no_enabled_objective';
 if(values.some(value=>value?.judgment?.errorCode==='LISTINGS_EVIDENCE_INCONSISTENT'))return'guard_rejected';
 if(values.some(value=>value?.modelEvaluated===false&&value?.status==='ineligible'))return candidates.length?'mode_mismatch':'candidate_absent';
 if(values.some(value=>plain(value?.judgment)))return'judge_completed';
 return'other_outcome';
}
function observeListingsAssessmentCollection(collection,{record,recordFailure=()=>{},qualifyModel,buildEvidence}={}){
 if(typeof collection?.assessmentFactory!=='function'||typeof record!=='function'||typeof recordFailure!=='function'||typeof qualifyModel!=='function')throw TypeError('Listings assessment observer dependencies required');
 buildEvidence ||= require('../../server/services/secureshopListingOptimizeEvidence').buildListingOptimizeEvidence;
 if(typeof buildEvidence!=='function')throw TypeError('Listings optimize evidence builder required');
 const emit=value=>{try{record(Object.freeze(bounded(value,'assessment diagnostic')));}catch(error){try{recordFailure(errorChain(error));}catch{}}};
 return Object.freeze({...collection,assessmentFactory(context,fence,input){
  const actual=collection.assessmentFactory(context,fence,input),operationId=input?.admission?.request?.operationId;
  if(!UUID.test(operationId)||typeof input.readOperation!=='function')throw TypeError('Bound Listings assessment input required');
  const observations=[];
  const base=phase=>({version:1,operationId,phase,action:input.admission.request.action,mode:input.admission.binding.mode});
  return Object.freeze({...actual,
   async begin(execution){try{return await actual.begin(execution);}catch(error){emit({...base('begin_threw'),error:errorChain(error)});throw error;}},
   async observe(execution,packet){try{const value=await actual.observe(execution,packet);observations.push(structuredClone(packet.observation));return value;}catch(error){emit({...base('observe_threw'),observationCount:observations.length,error:errorChain(error)});throw error;}},
   async finalize(execution,packet){
    let value;
    try{value=await actual.finalize(execution,packet);}
    catch(error){emit({...base('finalize_threw'),observationCount:observations.length,error:errorChain(error)});throw error;}
    try{
     const operation=await input.readOperation();
     const builderInput={admission:input.admission,operation,execution:{runId:execution?.runId||null,ownerKey:execution?.ownerKey||null,durableGeneration:execution?.durableGeneration??null},sessionId:context.sessionId,requestId:context.requestId,traces:packet.traces,observations,result:packet.result,sourceSetup:input.sourceSetup,sourceTurn:input.sourceTurn};
     const candidates=buildEvidence({...builderInput,execution,qualifyModel});
     if(!Array.isArray(candidates))throw TypeError('Listings optimize evidence candidates required');
     const outcome=bounded(value,'assessment outcome'),candidateOutput=bounded(candidates,'assessment candidates');
     emit({...base('finalized'),observationCount:observations.length,classification:classify(outcome,candidateOutput),outcome,operation:bounded(operation,'saved operation'),builder:{input:bounded(builderInput,'evidence builder input'),output:candidateOutput}});
    }catch(error){emit({...base('diagnostic_threw'),observationCount:observations.length,outcome:bounded(value,'assessment outcome'),diagnosticError:errorChain(error)});}
    return value;
   },
  });
 }});
}
module.exports={observeListingsAssessmentCollection};
