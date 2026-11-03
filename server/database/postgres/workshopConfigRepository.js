'use strict';
const {withTransaction}=require('./index');
const {error,exercise,bump,consistentRead}=require('./workshopPlatformSupport');
const secureShopCurriculum=require('../../config/secureshopCurriculum');
const {markCustomFields}=require('./catalogDefaultProvenance');
const boolean=value=>{if(typeof value!=='boolean')throw error('BAD_REQUEST','enabled must be a boolean');return value;};
async function readConfig(client,{includeRaw=false}={}){
 const revision=(await client.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision;
 const rows=(await client.query(`SELECT w.*,o.objective_id,o.label,o.description,o.is_enabled,o.hint_enabled,o.solution_enabled,o.hint_content,o.solution_content
  FROM workshop_platform.exercises w LEFT JOIN workshop_platform.objectives o ON o.workshop_key=w.workshop_key AND o.catalog_active=true
  WHERE w.catalog_active=true ORDER BY w.ordinal,o.ordinal`)).rows;
 const exercises=Object.create(null);
 for(const row of rows){
  const item=exercises[row.workshop_key] ||= {workshopKey:row.workshop_key,isVisible:row.is_visible,showHints:row.show_hints,showSolutions:row.show_solutions,objectives:Object.create(null)};
  if(!row.objective_id)continue;
  const isVisible=row.is_visible&&row.is_enabled,hasHintContent=row.hint_content!==null,hasSolutionContent=row.solution_content!==null;
  const objective={workshopKey:row.workshop_key,label:row.label,description:row.description,isVisible,hintVisible:isVisible&&row.show_hints&&row.hint_enabled&&hasHintContent,solutionVisible:isVisible&&row.show_solutions&&row.solution_enabled&&hasSolutionContent,hasHintContent,hasSolutionContent};
  if(includeRaw){objective.raw={objectiveEnabled:row.is_enabled,hintEnabled:row.hint_enabled,solutionEnabled:row.solution_enabled};if(objective.hintVisible)objective.raw.hint=row.hint_content;if(objective.solutionVisible)objective.raw.solution=row.solution_content;}
  item.objectives[row.objective_id]=objective;
 }
 return {revision,exercises};
}
function createWorkshopConfigRepository(pool,{isSecureShopReady=()=>{
 if(process.env.SS_BOUND_REVIEWS_ENABLED!=='true')return false;
 try{return !!require('../../services/secureshopBoundReviewComposition').getSecureShopLaunchResetCoordinator();}catch{return false;}
}}={}){
 if(typeof isSecureShopReady!=='function')throw new TypeError('SecureShop readiness callback required');
 const getSnapshot=options=>consistentRead(pool,client=>readConfig(client,options));
 async function mutate(key,operation){
  return withTransaction(pool,async client=>{
   await client.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1 FOR UPDATE');
   const w=key==null?null:await exercise(client,key);
   const outcome=await operation(client,w);
   const changed=outcome.changed>0;
   if(changed){await client.query('UPDATE workshop_platform.config_revision SET revision=revision+1,updated_at=now() WHERE id=1');await bump(client,{scopeType:w?'workshop':'global',scopeKey:w?.workshop_key||'*',category:'workshop_config'});}
   const snapshot=await readConfig(client,{includeRaw:true});
   return {revision:snapshot.revision,changed,...(w?{exercise:snapshot.exercises[w.workshop_key]}:{exercises:snapshot.exercises,affectedCount:outcome.changed}),...(outcome.extra||{})};
  });
 }
 async function objective(client,w,id){
  const row=(await client.query('SELECT * FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=$2 AND catalog_active=true',[w.workshop_key,id])).rows[0];
  if(!row)throw error('NOT_FOUND','Unknown objective');return row;
 }
 function requireQualifiedEnable(w,id,enabled){
  if(enabled&&w.workshop_key===secureShopCurriculum.WORKSHOP_KEY
    &&!secureShopCurriculum.isQualifiedObjective(id))throw Object.assign(
      error('OBJECTIVE_UNQUALIFIED','Objective is not qualified for enablement'),{statusCode:409});
 }
 function requireExerciseReady(w,enabled,route=w.route){
  if(enabled&&w.workshop_key===secureShopCurriculum.WORKSHOP_KEY
    &&(route!=='/workshop/secureshop'||isSecureShopReady()!==true))throw Object.assign(
      error('EXERCISE_NOT_READY','The bound SecureShop application is not ready for visibility'),{statusCode:409});
 }
 function setMaster(kind,key,enabled,updatedBy){
  boolean(enabled);const master=kind==='hint'?'show_hints':'show_solutions',gate=kind==='hint'?'hint_enabled':'solution_enabled',content=kind==='hint'?'hint_content':'solution_content';
  return mutate(key,async(client,w)=>{
   let changed=(await client.query(`UPDATE workshop_platform.exercises SET ${master}=$1,updated_by=$2,updated_at=now() WHERE workshop_key=$3 AND ${master} IS DISTINCT FROM $1`,[enabled,updatedBy??null,w.workshop_key])).rowCount;
   const qualified=enabled&&w.workshop_key===secureShopCurriculum.WORKSHOP_KEY?secureShopCurriculum.QUALIFIED_OBJECTIVE_IDS:null;
   const eligible=qualified?' AND objective_id = ANY($4::text[])':'';
   const params=qualified?[enabled,updatedBy??null,w.workshop_key,qualified]:[enabled,updatedBy??null,w.workshop_key];
   changed+=(await client.query(`UPDATE workshop_platform.objectives SET ${gate}=$1,updated_by=$2,updated_at=now() WHERE workshop_key=$3 AND catalog_active=true${eligible} AND ${gate} IS DISTINCT FROM $1 AND (${content} IS NOT NULL OR $1=false)`,params)).rowCount;
   return {changed};
  });
 }
 function setObjectiveGate(kind,key,id,enabled,updatedBy){
  boolean(enabled);const master=kind==='hint'?'show_hints':'show_solutions',gate=kind==='hint'?'hint_enabled':'solution_enabled',content=kind==='hint'?'hint_content':'solution_content';
  return mutate(key,async(client,w)=>{
   requireQualifiedEnable(w,id,enabled);
   const row=await objective(client,w,id);if(enabled&&row[content]===null)throw error('NOT_FOUND','Objective content does not exist');
   let changed=(await client.query(`UPDATE workshop_platform.objectives SET ${gate}=$1,updated_by=$2,updated_at=now() WHERE workshop_key=$3 AND objective_id=$4 AND ${gate} IS DISTINCT FROM $1`,[enabled,updatedBy??null,w.workshop_key,id])).rowCount;
   const show=(await client.query(`SELECT EXISTS(SELECT 1 FROM workshop_platform.objectives WHERE workshop_key=$1 AND catalog_active=true AND ${gate}=true AND ${content} IS NOT NULL) AS enabled`,[w.workshop_key])).rows[0].enabled;
   changed+=(await client.query(`UPDATE workshop_platform.exercises SET ${master}=$1,updated_by=$2,updated_at=now() WHERE workshop_key=$3 AND ${master} IS DISTINCT FROM $1`,[show,updatedBy??null,w.workshop_key])).rowCount;
   return {changed};
  });
 }
 function validateContentPatch(kind,patch,canonicalWorkshopKey=null){
  const allowed=kind==='hint'?['title','hints']:['title','difficulty','hints','examples','approach','tips','description','code','references','estimatedTime','prerequisites'];
  // Preflight checks shape only; every write repeats admission after exercise() resolves the canonical family.
  if(kind==='solution'&&(canonicalWorkshopKey===null||['xss_workshop','csrf_workshop'].includes(canonicalWorkshopKey)))allowed.push('hint','example','explanation');
  if(kind==='solution'&&(canonicalWorkshopKey===null||canonicalWorkshopKey==='excessive_agency'))allowed.push('vulnerability');
  if(!patch||typeof patch!=='object'||Array.isArray(patch)||!Object.keys(patch).length||Object.keys(patch).some(f=>!allowed.includes(f)))throw error('BAD_REQUEST','Invalid content patch');
  let serialized;
  try{serialized=JSON.stringify(patch);}catch{throw error('BAD_REQUEST','Invalid content patch');}
  if(!serialized||Buffer.byteLength(serialized,'utf8')>65536)throw error('BAD_REQUEST','Content patch is too large');
  for(const [field,value]of Object.entries(patch)){
   if(['hints','tips'].includes(field)&&(!Array.isArray(value)||(kind==='hint'&&!value.length)||value.some(v=>typeof v!=='string'||!v.trim())))throw error('BAD_REQUEST','Invalid content list');
   if(['title','difficulty','approach'].includes(field)&&(typeof value!=='string'||!value.trim()))throw error('BAD_REQUEST','Invalid content text');
   if(field==='examples'&&(!Array.isArray(value)||!value.length||value.some(v=>typeof v!=='string'&&(typeof v!=='object'||!v||!['prompt','payload','action'].some(k=>typeof v[k]==='string'&&v[k].trim())||typeof v.explanation!=='string'))))throw error('BAD_REQUEST','Invalid solution examples');
   if(['description','code','estimatedTime','hint','example','explanation','vulnerability'].includes(field)&&typeof value!=='string')throw error('BAD_REQUEST','Invalid optional solution text');
   if(['references','prerequisites'].includes(field)&&(!Array.isArray(value)||value.some(v=>typeof v!=='string'||!v.trim())))throw error('BAD_REQUEST','Invalid optional solution list');
   if(field==='references'&&value.some(v=>!(/^(?:https?:\/\/|(?:\/|\.\.?\/)??docs\/)/i.test(v))))throw error('BAD_REQUEST','Invalid solution reference');
  }
  return patch;
 }
 function updateContent(kind,key,id,patch,updatedBy){
  validateContentPatch(kind,patch);
  const field=kind==='hint'?'hint_content':'solution_content';
  return mutate(key,async(client,w)=>{
   validateContentPatch(kind,patch,w.workshop_key);
   const row=await objective(client,w,id);
   if(row[field]===null){
    const hasBody=kind==='hint'?Array.isArray(patch.hints)&&patch.hints.length>0
     :['approach','description','hint','explanation','code'].some(name=>typeof patch[name]==='string'&&patch[name].trim())
      ||Array.isArray(patch.hints)&&patch.hints.length>0||Array.isArray(patch.examples)&&patch.examples.length>0;
    if(typeof patch.title!=='string'||!patch.title.trim()||!hasBody)throw error('BAD_REQUEST','New content needs a title and teaching text');
   }
   const changed=(await client.query(`UPDATE workshop_platform.objectives SET ${field}=COALESCE(${field},'{}'::jsonb)||$1::jsonb,updated_by=$2,updated_at=now() WHERE workshop_key=$3 AND objective_id=$4 AND ${field} IS DISTINCT FROM (COALESCE(${field},'{}'::jsonb)||$1::jsonb)`,[JSON.stringify(patch),updatedBy??null,w.workshop_key,id])).rowCount;
   if(changed)await markCustomFields(client,{entityKind:'objective',workshopKey:w.workshop_key,objectiveId:id},[field]);
   return {changed};
  });
 }
 function updateObjectiveMetadata(key,id,patch,updatedBy){
  if(!patch||typeof patch!=='object'||Array.isArray(patch)||!Object.keys(patch).length
    ||Object.keys(patch).some(field=>!['label','description','category'].includes(field)))throw error('BAD_REQUEST','Invalid objective metadata patch');
  if(patch.label!==undefined&&(typeof patch.label!=='string'||!patch.label.trim()||patch.label.length>240))throw error('BAD_REQUEST','Invalid objective label');
  if(patch.description!==undefined&&(typeof patch.description!=='string'||patch.description.length>4000))throw error('BAD_REQUEST','Invalid objective description');
  if(patch.category!==undefined&&(typeof patch.category!=='string'||patch.category.length>120))throw error('BAD_REQUEST','Invalid objective category');
  return mutate(key,async(client,w)=>{
   const row=await objective(client,w,id);
   const label=patch.label===undefined?row.label:patch.label.trim();
   const description=patch.description===undefined?row.description:patch.description.trim();
   const category=patch.category===undefined?row.category:patch.category.trim();
   const fields=[];
   if(label!==row.label)fields.push('label');
   if(description!==row.description)fields.push('description');
   if(category!==row.category)fields.push('category');
   if(!fields.length)return {changed:0,extra:{metadata:{workshopKey:w.workshop_key,objectiveId:id,label,description,category}}};
   const changed=(await client.query(`UPDATE workshop_platform.objectives SET label=$1,description=$2,category=$3,updated_by=$4,updated_at=now()
    WHERE workshop_key=$5 AND objective_id=$6 AND catalog_active=true
      AND (label,description,category) IS DISTINCT FROM ($1,$2,$3)`,[label,description,category,updatedBy??null,w.workshop_key,id])).rowCount;
   if(changed)await markCustomFields(client,{entityKind:'objective',workshopKey:w.workshop_key,objectiveId:id},fields);
   return {changed,extra:{metadata:{workshopKey:w.workshop_key,objectiveId:id,label,description,category}}};
  });
 }
 function saveSolutionEditor(key,id,patch,options={}){
  validateContentPatch('solution',patch);
  if(!options||typeof options!=='object'||Array.isArray(options))throw error('BAD_REQUEST','Invalid solution editor options');
  if(options.isPublic!==undefined&&typeof options.isPublic!=='boolean')throw error('BAD_REQUEST','isPublic must be a boolean');
  const hasVisibility=options.isPublic!==undefined;
  return mutate(key,async(client,w)=>{
   validateContentPatch('solution',patch,w.workshop_key);
   const row=await objective(client,w,id);
   if(row.solution_content===null)throw error('NOT_FOUND','Objective content does not exist');
   if(options.isPublic===true)requireQualifiedEnable(w,id,true);
   let changed=(await client.query(`UPDATE workshop_platform.objectives SET solution_content=solution_content||$1::jsonb,updated_by=$2,updated_at=now()
     WHERE workshop_key=$3 AND objective_id=$4 AND solution_content IS DISTINCT FROM (solution_content||$1::jsonb)`,
   [JSON.stringify(patch),options.userId??null,w.workshop_key,id])).rowCount;
   if(changed)await markCustomFields(client,{entityKind:'objective',workshopKey:w.workshop_key,objectiveId:id},['solution_content']);
   if(hasVisibility){
    changed+=(await client.query(`UPDATE workshop_platform.objectives SET solution_enabled=$1,updated_by=$2,updated_at=now()
      WHERE workshop_key=$3 AND objective_id=$4 AND solution_enabled IS DISTINCT FROM $1`,
    [options.isPublic,options.userId??null,w.workshop_key,id])).rowCount;
    const show=(await client.query(`SELECT EXISTS(SELECT 1 FROM workshop_platform.objectives WHERE workshop_key=$1 AND catalog_active=true AND solution_enabled=true AND solution_content IS NOT NULL) AS enabled`,[w.workshop_key])).rows[0].enabled;
    changed+=(await client.query(`UPDATE workshop_platform.exercises SET show_solutions=$1,updated_by=$2,updated_at=now() WHERE workshop_key=$3 AND show_solutions IS DISTINCT FROM $1`,[show,options.userId??null,w.workshop_key])).rowCount;
   }
   return {changed};
  });
 }
 async function visibilityMap(key,field){const w=await exercise(pool,key);const snapshot=await getSnapshot();return Object.fromEntries(Object.entries(snapshot.exercises[w.workshop_key].objectives).map(([id,o])=>[id,o[field]]));}
 const api={
  getSnapshot,getRevision:async()=>(await pool.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision,
  getHintVisibilityMap:key=>visibilityMap(key,'hintVisible'),getSolutionVisibilityMap:key=>visibilityMap(key,'solutionVisible'),
  isHintVisible:async(key,id)=>(await visibilityMap(key,'hintVisible'))[id]===true,isSolutionVisible:async(key,id)=>(await visibilityMap(key,'solutionVisible'))[id]===true,
  setExerciseVisibility(key,enabled,updatedBy){boolean(enabled);return mutate(key,async(client,w)=>{requireExerciseReady(w,enabled);return {changed:(await client.query('UPDATE workshop_platform.exercises SET is_visible=$1,updated_by=$2,updated_at=now() WHERE workshop_key=$3 AND is_visible IS DISTINCT FROM $1',[enabled,updatedBy??null,w.workshop_key])).rowCount};});},
  toggleExerciseVisibility:(key,updatedBy)=>mutate(key,async(client,w)=>{requireExerciseReady(w,!w.is_visible);return {changed:(await client.query('UPDATE workshop_platform.exercises SET is_visible=NOT is_visible,updated_by=$1,updated_at=now() WHERE workshop_key=$2',[updatedBy??null,w.workshop_key])).rowCount,extra:{enabled:!w.is_visible}};}),
  updateExercise({key,challengeName,category,difficulty,isVisible,showSolutions,description,route,userId}){
   boolean(isVisible);boolean(showSolutions);
   for(const value of [challengeName,category,difficulty,description,route])if(typeof value!=='string')throw error('BAD_REQUEST','Exercise metadata must be text');
   return mutate(key,async(client,w)=>{
    requireExerciseReady(w,isVisible,route);
    let changed=(await client.query(`UPDATE workshop_platform.exercises SET challenge_name=$1,category=$2,difficulty=$3,is_visible=$4,show_solutions=$5,challenge_description=$6,route=$7,updated_by=$8,updated_at=now()
     WHERE workshop_key=$9 AND (challenge_name,category,difficulty,is_visible,show_solutions,challenge_description,route) IS DISTINCT FROM ($1,$2,$3,$4,$5,$6,$7)`,[challengeName,category,difficulty,isVisible,showSolutions,description,route,userId??null,w.workshop_key])).rowCount;
    if(changed){const fields=[];
     if(w.challenge_name!==challengeName)fields.push('challenge_name');if(w.category!==category)fields.push('category');
     if(w.difficulty!==difficulty)fields.push('difficulty');if(w.challenge_description!==description)fields.push('challenge_description');
     if(w.route!==route)fields.push('route');if(fields.length)await markCustomFields(client,{entityKind:'exercise',workshopKey:w.workshop_key},fields);}
    const qualified=showSolutions&&w.workshop_key===secureShopCurriculum.WORKSHOP_KEY?secureShopCurriculum.QUALIFIED_OBJECTIVE_IDS:null;
    const eligible=qualified?' AND objective_id = ANY($4::text[])':'';
    const params=qualified?[showSolutions,userId??null,w.workshop_key,qualified]:[showSolutions,userId??null,w.workshop_key];
    changed+=(await client.query(`UPDATE workshop_platform.objectives SET solution_enabled=$1,updated_by=$2,updated_at=now() WHERE workshop_key=$3 AND catalog_active=true${eligible} AND solution_enabled IS DISTINCT FROM $1 AND (solution_content IS NOT NULL OR $1=false)`,params)).rowCount;
    return {changed};
   });
  },
  // One admin card controls both XSS curriculum families. Keep their stored
  // identities and per-objective endpoints intact; commit the shared controls
  // under the same configuration lock so a failed write cannot split the card.
  setXssGroupControls(dimension,enabled,updatedBy){
   boolean(enabled);
   if(!['active','hints','solutions','objectives'].includes(dimension))throw error('BAD_REQUEST','Invalid XSS group control');
   const keys=['xss_workshop','xss_email_builder'];
   return mutate(null,async client=>{
    // Validate both active catalog identities before writing either family.
    for(const key of keys)await exercise(client,key);
    let changed=0;
    if(dimension==='active'){
     changed=(await client.query(`UPDATE workshop_platform.exercises SET is_visible=$1,updated_by=$2,updated_at=now()
       WHERE workshop_key=ANY($3::text[]) AND catalog_active=true AND is_visible IS DISTINCT FROM $1`,[enabled,updatedBy??null,keys])).rowCount;
    }else if(dimension==='objectives'){
     changed=(await client.query(`UPDATE workshop_platform.objectives SET is_enabled=$1,updated_by=$2,updated_at=now()
       WHERE workshop_key=ANY($3::text[]) AND catalog_active=true AND is_enabled IS DISTINCT FROM $1`,[enabled,updatedBy??null,keys])).rowCount;
    }else{
     const [master,gate,content]=dimension==='hints'?['show_hints','hint_enabled','hint_content']:['show_solutions','solution_enabled','solution_content'];
     changed=(await client.query(`UPDATE workshop_platform.exercises SET ${master}=$1,updated_by=$2,updated_at=now()
       WHERE workshop_key=ANY($3::text[]) AND catalog_active=true AND ${master} IS DISTINCT FROM $1`,[enabled,updatedBy??null,keys])).rowCount;
     changed+=(await client.query(`UPDATE workshop_platform.objectives SET ${gate}=$1,updated_by=$2,updated_at=now()
       WHERE workshop_key=ANY($3::text[]) AND catalog_active=true AND ${gate} IS DISTINCT FROM $1
         AND (${content} IS NOT NULL OR $1=false)`,[enabled,updatedBy??null,keys])).rowCount;
     if(dimension==='solutions')changed+=(await client.query(`UPDATE workshop_platform.xss_legacy_solution_visibility
       SET solutions_enabled=$1,enabled_by=$2,enabled_at=CASE WHEN $1 THEN now() ELSE enabled_at END,updated_at=now()
       WHERE solutions_enabled IS DISTINCT FROM $1`,[enabled,updatedBy??null])).rowCount;
    }
    return {changed};
   });
  },
  setAllExerciseVisibility(enabled,updatedBy){boolean(enabled);return mutate(null,async client=>{
   const unavailableWorkshops=[];
   if(enabled)for(const row of (await client.query('SELECT workshop_key,route FROM workshop_platform.exercises WHERE catalog_active=true')).rows){
    try{requireExerciseReady(row,true);}catch(err){
     if(err?.code!=='EXERCISE_NOT_READY')throw err;
     unavailableWorkshops.push(row.workshop_key);
    }
   }
   const excluded=enabled&&unavailableWorkshops.length?' AND workshop_key<>ALL($3::text[])':'';
   const params=excluded?[enabled,updatedBy??null,unavailableWorkshops]:[enabled,updatedBy??null];
   return {changed:(await client.query(`UPDATE workshop_platform.exercises SET is_visible=$1,updated_by=$2,updated_at=now() WHERE catalog_active=true AND is_visible IS DISTINCT FROM $1${excluded}`,params)).rowCount,
    extra:{unavailableWorkshops}};
  });},
  setAllHintAndSolutionVisibility(enabled,updatedBy){boolean(enabled);return mutate(null,async client=>{
   let changed=0;
   for(const [master,gate,content] of [['show_hints','hint_enabled','hint_content'],['show_solutions','solution_enabled','solution_content']]){
    changed+=(await client.query(`UPDATE workshop_platform.exercises SET ${master}=$1,updated_by=$2,updated_at=now()
      WHERE catalog_active=true AND ${master} IS DISTINCT FROM $1`,[enabled,updatedBy??null])).rowCount;
    const qualified=enabled?secureShopCurriculum.QUALIFIED_OBJECTIVE_IDS:null;
    const eligible=qualified?' AND (workshop_key<>$3 OR objective_id=ANY($4::text[]))':'';
    const params=qualified?[enabled,updatedBy??null,secureShopCurriculum.WORKSHOP_KEY,qualified]:[enabled,updatedBy??null];
    changed+=(await client.query(`UPDATE workshop_platform.objectives SET ${gate}=$1,updated_by=$2,updated_at=now()
      WHERE catalog_active=true AND ${gate} IS DISTINCT FROM $1 AND (${content} IS NOT NULL OR $1=false)${eligible}`,params)).rowCount;
   }
   return {changed};
  });},
  setAllObjectiveVisibility(key,enabled,updatedBy){boolean(enabled);return mutate(key,async(client,w)=>{
   const qualified=enabled&&w.workshop_key===secureShopCurriculum.WORKSHOP_KEY?secureShopCurriculum.QUALIFIED_OBJECTIVE_IDS:null;
   const eligible=qualified?' AND objective_id = ANY($2::text[])':'';
   const countParams=qualified?[w.workshop_key,qualified]:[w.workshop_key];
   const affectedCount=Number((await client.query(`SELECT count(*)::integer AS count FROM workshop_platform.objectives WHERE workshop_key=$1 AND catalog_active=true${eligible}`,countParams)).rows[0].count);
   if(!affectedCount)throw error('NOT_FOUND','Workshop has no objectives');
   const updateEligible=qualified?' AND objective_id = ANY($4::text[])':'';
   const updateParams=qualified?[enabled,updatedBy??null,w.workshop_key,qualified]:[enabled,updatedBy??null,w.workshop_key];
   const changed=(await client.query(`UPDATE workshop_platform.objectives SET is_enabled=$1,updated_by=$2,updated_at=now() WHERE workshop_key=$3 AND catalog_active=true${updateEligible} AND is_enabled IS DISTINCT FROM $1`,updateParams)).rowCount;
   return {changed,extra:{affectedCount}};
  });},
  resetAllChallengeVisibility:updatedBy=>mutate(null,async client=>{
   const a=await client.query('UPDATE workshop_platform.exercises SET is_visible=(workshop_key<>$2),show_solutions=false,updated_by=$1,updated_at=now() WHERE catalog_active=true AND (is_visible IS DISTINCT FROM (workshop_key<>$2) OR show_solutions=true)',[updatedBy??null,secureShopCurriculum.WORKSHOP_KEY]);
   const b=await client.query('UPDATE workshop_platform.objectives SET solution_enabled=false,updated_by=$1,updated_at=now() WHERE solution_enabled=true',[updatedBy??null]);return {changed:a.rowCount+b.rowCount};
  }),
  setObjectiveVisibility(key,id,enabled,updatedBy){boolean(enabled);return mutate(key,async(client,w)=>{requireQualifiedEnable(w,id,enabled);await objective(client,w,id);return {changed:(await client.query('UPDATE workshop_platform.objectives SET is_enabled=$1,updated_by=$2,updated_at=now() WHERE workshop_key=$3 AND objective_id=$4 AND is_enabled IS DISTINCT FROM $1',[enabled,updatedBy??null,w.workshop_key,id])).rowCount};});},
  updateObjectiveMetadata,
  async getObjectiveMetadata(key,id){const w=await exercise(pool,key),row=await objective(pool,w,id);return {workshopKey:w.workshop_key,objectiveId:id,label:row.label,description:row.description,category:row.category};},
  setMasterHintVisibility:(...args)=>setMaster('hint',...args),setMasterSolutionVisibility:(...args)=>setMaster('solution',...args),
  setObjectiveHintVisibility:(...args)=>setObjectiveGate('hint',...args),setObjectiveSolutionVisibility:(...args)=>setObjectiveGate('solution',...args),
  updateHintContent:(...args)=>updateContent('hint',...args),updateSolutionContent:(...args)=>updateContent('solution',...args),
  saveSolutionEditor,
  async getHintContent(key,id){const w=await exercise(pool,key),row=await objective(pool,w,id);return {workshopKey:w.workshop_key,objectiveId:id,authored:row.hint_content!==null,...(row.hint_content||{})};},
  async getSolutionContent(key,id){const w=await exercise(pool,key),row=await objective(pool,w,id);return {workshopKey:w.workshop_key,objectiveId:id,authored:row.solution_content!==null,...(row.solution_content||{})};},
  async getStudentContent(key,id,kind){if(!['hint','solution'].includes(kind))throw error('BAD_REQUEST','Unknown content kind');const w=await exercise(pool,key),snapshot=await getSnapshot({includeRaw:true}),entry=snapshot.exercises[w.workshop_key]?.objectives[id];if(!entry?.[kind==='hint'?'hintVisible':'solutionVisible'])throw error('FORBIDDEN','Content is hidden');return entry.raw[kind];},
 };
 return api;
}
module.exports={createWorkshopConfigRepository,readConfig};
