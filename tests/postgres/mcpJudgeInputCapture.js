'use strict';
const {prepareJudgeInput}=require('../../server/agent-runtime/objectiveJudge');
const jsonBytes=value=>Buffer.byteLength(JSON.stringify(value));
function code(error){const value=typeof error?.code==='string'?error.code:error?.name||'Error';return String(value).slice(0,128);}
function createMcpJudgeInputCapture({judge,entries=[],maxEntries=16,maxBytes=512*1024}={}){
  if(typeof judge!=='function'||!Array.isArray(entries)||!Number.isSafeInteger(maxEntries)||maxEntries<1
    ||!Number.isSafeInteger(maxBytes)||maxBytes<1024)throw new TypeError('Judge input capture configuration invalid');
  let reservedBytes=jsonBytes(entries);
  if(entries.length>maxEntries||reservedBytes>maxBytes)throw new TypeError('Existing Judge input capture exceeds capacity');
  return Object.freeze({entries,async judge(packet){if(entries.length>=maxEntries)throw new Error('Judge input capture count capacity exceeded');
    const prepared=prepareJudgeInput(packet);const pending=Object.freeze({objectiveId:packet?.rubric?.objectiveId||null,
      runId:packet?.evidence?.[0]?.content?.runId||null,evidenceDigest:prepared.evidenceDigest,
      packet:JSON.parse(prepared.packet),status:'pending'});
    // Reserve the complete terminal record before calling the provider. Concurrent
    // calls cannot consume space needed to retain an earlier call's failure.
    const reservation=Math.max(jsonBytes(pending),
      jsonBytes({...pending,status:'returned',verdict:'\u0000'.repeat(32)}),
      jsonBytes({...pending,status:'prepare_error',errorCode:'\u0000'.repeat(128)}));
    const separator=entries.length?1:0;
    if(reservedBytes+separator+reservation>maxBytes)throw new Error('Judge input capture byte capacity exceeded');
    const index=entries.push(pending)-1;reservedBytes+=separator+reservation;
    const finish=next=>{entries[index]=Object.freeze(next);reservedBytes-=reservation-jsonBytes(next);};
    if(prepared.evidenceError){finish({...pending,status:'prepare_error',errorCode:code(prepared.evidenceError)});throw prepared.evidenceError;}
    try{const result=await judge(packet);if(result?.evidenceDigest!==prepared.evidenceDigest){const error=new Error('Judge result evidence digest mismatch');
        error.code='JUDGE_EVIDENCE_DIGEST_MISMATCH';throw error;}
      finish({...pending,status:'returned',verdict:typeof result.verdict==='string'?result.verdict.slice(0,32):null});return result;
    }catch(error){finish({...pending,status:'threw',errorCode:code(error)});throw error;}}
  });
}
module.exports={createMcpJudgeInputCapture};
