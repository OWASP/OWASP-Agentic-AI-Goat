'use strict';
const {withTransaction}=require('./index');
const {createLaunchScope}=require('../../services/secureshopConversationBinding');
const {executionScope,withSceneLease}=require('../../services/secureshopSceneBinding');
const fail=()=>Object.assign(Error('Mail scene unavailable'),{code:'MAIL_SCENE_STALE',executionBoundary:true});
function storage(row){return Object.freeze({targetId:row.target_id,launchId:row.birth_launch_id,
 scenarioId:row.birth_scenario_id,generation:Number(row.birth_generation),
 platformOwnerId:Number(row.original_platform_owner_id),platformSessionId:Number(row.birth_platform_session_id)});}
function createMailSceneRepository({pool,launches}){
 if(typeof pool?.connect!=='function'||typeof launches?.assertCurrent!=='function')throw TypeError('Mail scene identity required');
 function checked(scene){const e=executionScope(scene);if(!scene?.scene)throw fail();return e;}
 async function read(scene){const e=checked(scene);await launches.assertCurrent(e);
  const rows=(await pool.query(`SELECT m.* FROM identity.secureshop_mail_scenes m
   JOIN identity.secureshop_scenes s USING(scene_id)
   WHERE m.scene_id=$1 AND m.original_platform_owner_id=$2 AND s.status='active'
    AND s.scene_generation=$3`,[scene.scene.sceneId,e.platformOwnerId,scene.scene.sceneGeneration])).rows;
  await launches.assertCurrent(e);return rows.length?storage(rows[0]):null;
 }
 return Object.freeze({read,
  async candidates(scene){const e=checked(scene);await launches.assertCurrent(e);
   const rows=(await pool.query(`SELECT r.target_id,r.launch_id AS birth_launch_id,l.scenario_id AS birth_scenario_id,
    r.generation AS birth_generation,r.original_platform_owner_id,l.original_platform_session_id AS birth_platform_session_id,
    EXISTS(SELECT 1 FROM identity.secureshop_scene_execution_grants g WHERE g.scene_id=$2
      AND g.launch_id=r.launch_id AND g.generation=r.generation
      AND g.original_platform_owner_id=r.original_platform_owner_id
      AND g.original_platform_session_id=l.original_platform_session_id) AS associated
    FROM identity.secureshop_target_reservations r JOIN identity.secureshop_launches l USING(launch_id)
    WHERE r.original_platform_owner_id=$1 AND r.target_kind='persona_inbox'
      AND NOT EXISTS(SELECT 1 FROM identity.secureshop_mail_scenes mapped WHERE mapped.target_id=r.target_id)
    ORDER BY r.target_id LIMIT 257`,[e.platformOwnerId,scene.scene.sceneId])).rows;
   if(rows.length>256)throw fail();await launches.assertCurrent(e);
   return rows.map(row=>Object.freeze({...storage(row),associated:row.associated===true}));
  },
  async adopt(scene,input){const e=checked(scene),b=createLaunchScope(input);
   if(b.platformOwnerId!==e.platformOwnerId)throw fail();
   return withSceneLease(scene,()=>withTransaction(pool,async client=>{
    await client.query(`INSERT INTO identity.secureshop_mail_scenes
     (scene_id,target_id,original_platform_owner_id,birth_launch_id,birth_scenario_id,birth_generation,
       birth_platform_session_id,adopted_by_grant_id,adoption_kind)
     SELECT $1,$2,$3,$4,$5,$6,$7,$8,CASE WHEN EXISTS (
       SELECT 1 FROM identity.secureshop_scene_execution_grants g WHERE g.scene_id=$1
       AND g.launch_id=$4 AND g.scenario_id=$5 AND g.generation=$6
       AND g.original_platform_owner_id=$3 AND g.original_platform_session_id=$7)
       THEN 'birth_grant' ELSE 'unique_owner' END
     ON CONFLICT(scene_id) DO NOTHING`,[scene.scene.sceneId,input.targetId,b.platformOwnerId,b.launchId,b.scenarioId,b.generation,b.platformSessionId,scene.scene.grantId]);
    const row=(await client.query('SELECT * FROM identity.secureshop_mail_scenes WHERE scene_id=$1',[scene.scene.sceneId])).rows[0];
    if(!row||JSON.stringify(storage(row))!==JSON.stringify(storage({target_id:input.targetId,birth_launch_id:b.launchId,birth_scenario_id:b.scenarioId,birth_generation:b.generation,original_platform_owner_id:b.platformOwnerId,birth_platform_session_id:b.platformSessionId})))throw fail();
    return storage(row);
   }));
  },
 });
}
module.exports={createMailSceneRepository};
