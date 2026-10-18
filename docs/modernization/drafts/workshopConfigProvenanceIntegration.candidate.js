'use strict';

const crypto = require('node:crypto');
const SOURCE_SHA256 = '7f882098b18856a5560082f1b50ff6ba1e5b6093690d23e978f97ba088baed8d';

function buildCandidate(source) {
  if (typeof source !== 'string'
      || crypto.createHash('sha256').update(source).digest('hex') !== SOURCE_SHA256) {
    throw new Error('workshop config repository source is not the reviewed frozen version');
  }
  const importBefore = "const secureShopCurriculum=require('../../config/secureshopCurriculum');";
  const importAfter = `${importBefore}\nconst {markCustomFields}=require('./catalogDefaultProvenance');`;
  const contentBefore = "return {changed:(await client.query(`UPDATE workshop_platform.objectives SET ${field}=${field}||$1::jsonb,updated_at=now() WHERE workshop_key=$2 AND objective_id=$3 AND ${field} IS DISTINCT FROM (${field}||$1::jsonb)`,[JSON.stringify(patch),w.workshop_key,id])).rowCount};";
  const contentAfter = `const changed=(await client.query(\`UPDATE workshop_platform.objectives SET \${field}=\${field}||$1::jsonb,updated_at=now() WHERE workshop_key=$2 AND objective_id=$3 AND \${field} IS DISTINCT FROM (\${field}||$1::jsonb)\`,[JSON.stringify(patch),w.workshop_key,id])).rowCount;
   if(changed)await markCustomFields(client,{entityKind:'objective',workshopKey:w.workshop_key,objectiveId:id},[field]);
   return {changed};`;
  const exerciseNeedle = 'changed+=(await client.query(\'UPDATE workshop_platform.objectives SET solution_enabled=$1,updated_by=$2,updated_at=now() WHERE workshop_key=$3 AND catalog_active=true AND solution_enabled IS DISTINCT FROM $1 AND (solution_content IS NOT NULL OR $1=false)\',[showSolutions,userId??null,w.workshop_key])).rowCount;';
  const exerciseReplacement = `if(changed){const fields=[];
     if(w.challenge_name!==challengeName)fields.push('challenge_name');if(w.category!==category)fields.push('category');
     if(w.difficulty!==difficulty)fields.push('difficulty');if(w.challenge_description!==description)fields.push('challenge_description');
     if(w.route!==route)fields.push('route');if(fields.length)await markCustomFields(client,{entityKind:'exercise',workshopKey:w.workshop_key},fields);}
    ${exerciseNeedle}`;
  for (const [before,after,label] of [[importBefore,importAfter,'import'],[contentBefore,contentAfter,'content'],
    [exerciseNeedle,exerciseReplacement,'exercise']]) {
    if (source.split(before).length !== 2) throw new Error(`${label} provenance seam changed`);
    source = source.replace(before,after);
  }
  return source;
}

module.exports = { SOURCE_SHA256, buildCandidate };
