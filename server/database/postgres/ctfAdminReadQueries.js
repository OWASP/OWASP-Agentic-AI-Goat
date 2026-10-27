'use strict';
function validateFilters(raw={}){
 if(!raw||typeof raw!=='object'||Array.isArray(raw)||Object.keys(raw).some(k=>!['participantId','stageId','blocked','techniqueTag','wasSuccessful','offset'].includes(k)))throw TypeError('Invalid CTF attempt filters');
 const f=structuredClone(raw);
 for(const key of ['participantId','stageId'])if(f[key]!==undefined&&(!Number.isSafeInteger(f[key])||f[key]<1||f[key]>2147483647))throw TypeError('Invalid CTF filter ID');
 for(const key of ['blocked','wasSuccessful'])if(f[key]!==undefined&&typeof f[key]!=='boolean')throw TypeError('Invalid CTF boolean filter');
 if(f.techniqueTag!==undefined&&(typeof f.techniqueTag!=='string'||!f.techniqueTag.isWellFormed()||f.techniqueTag.includes('\0')||Buffer.byteLength(f.techniqueTag)>128))throw TypeError('Invalid CTF technique filter');
 if(f.offset!==undefined&&(!Number.isSafeInteger(f.offset)||f.offset<0||f.offset>100000))throw TypeError('Invalid CTF offset');return f;
}
async function attempts(c,f,limit){
 const args=[],where=[];for(const [k,col] of Object.entries({participantId:'participant_id',stageId:'stage_id',blocked:'blocked',techniqueTag:'technique_tag',wasSuccessful:'was_successful'}))if(f[k]!==undefined){args.push(['blocked','wasSuccessful'].includes(k)?Number(f[k]):f[k]);where.push(`a.${col}=$${args.length}`);}
 args.push(limit,f.offset??0);
 return(await c.query(`SELECT a.*,p.username,s.stage_name,s.stage_number,j.verdict AS judgment_verdict,j.accepted AS judgment_accepted,j.metadata AS judgment_metadata FROM ctf.ctf_attempts a JOIN ctf.ctf_participants p ON p.id=a.participant_id JOIN ctf.ctf_stages s ON s.id=a.stage_id LEFT JOIN ctf.ctf_judgments j ON j.attempt_id=a.id${where.length?' WHERE '+where.join(' AND '):''} ORDER BY a.attempt_timestamp DESC,a.id DESC LIMIT $${args.length-1} OFFSET $${args.length}`,args)).rows;
}
async function participants(c){
 const rows=[];let after=0;
 for(let page=0;page<64;page++){
  const next=(await c.query("SELECT p.*,(SELECT COUNT(*)::integer FROM ctf.ctf_progress pr WHERE pr.participant_id=p.id AND pr.status='completed') AS stages_completed,(SELECT SUM(pr.attempts_count)::integer FROM ctf.ctf_progress pr WHERE pr.participant_id=p.id) AS total_attempts,EXISTS(SELECT 1 FROM ctf.ctf_bans b WHERE b.user_id=p.user_id) AS is_banned FROM ctf.ctf_participants p WHERE p.id>$1 ORDER BY p.id LIMIT 256",[after])).rows;
  rows.push(...next);if(Buffer.byteLength(JSON.stringify(rows))>8*1024*1024)throw Error('CTF_READ_UNAVAILABLE');
  if(next.length<256)return rows.sort((a,b)=>{const at=a.started_at==null?Infinity:new Date(a.started_at).getTime(),bt=b.started_at==null?Infinity:new Date(b.started_at).getTime();return bt-at||Number(b.id)-Number(a.id);});
  after=next.at(-1).id;
 }throw Error('CTF_READ_UNAVAILABLE');
}
module.exports={validateFilters,attempts,participants};
