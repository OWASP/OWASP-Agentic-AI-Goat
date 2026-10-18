'use strict';
const { createLaunchScope } = require('./secureshopConversationBinding');
const { executionScope, withSceneLease } = require('./secureshopSceneBinding');
const trusted = new WeakMap();
const KEYS = ['launchId','scenarioId','generation','platformOwnerId','platformSessionId'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function unavailable() { return Object.assign(Error('Mail scene authority unavailable'), {code:'MAIL_SCENE_STALE',executionBoundary:true}); }
function attach(storage, scene) {
  const original = Object.freeze({...createLaunchScope(storage),targetId:storage.targetId});
  const e = executionScope(scene);
  if (!scene?.scene || !UUID.test(original.targetId) || original.platformOwnerId!==e.platformOwnerId) throw unavailable();
  const binding=Object.freeze({...original});
  trusted.set(binding,Object.freeze({birth:original,scene}));
  return binding;
}
function copy(source, normalized) {
  const held=trusted.get(source);
  if (!held) return Object.freeze(normalized);
  if(normalized.targetId!==held.birth.targetId)throw unavailable();
  const expected=normalized.scope?executionScope(held.scene):held.birth;
  const actual=normalized.scope||normalized;
  if(KEYS.some(key=>actual[key]!==expected[key]))throw unavailable();
  const result=Object.freeze(normalized);trusted.set(result,held);return result;
}
function productScene(binding){return trusted.get(binding)?.scene||null;}
function birth(binding){return trusted.get(binding)?.birth||binding;}
function current(binding){const held=trusted.get(binding);return held?executionScope(held.scene):(binding.scope||binding);}
function withLease(binding,work){const held=trusted.get(binding);return held?withSceneLease(held.scene,work):work();}
async function assertGrant(client,binding){
  const held=trusted.get(binding);if(!held)return;
  const {scene}=held.scene,e=executionScope(held.scene);
  const result=await client.query(`SELECT secureshop_agents.assert_mail_scene_execution_grant(
    $1::uuid,$2::uuid,$3::bigint,$4::uuid,$5::uuid,$6::uuid,$7::bigint,$8::integer,$9::integer) AS allowed`,
  [scene.grantId,scene.sceneId,scene.sceneGeneration,held.birth.targetId,e.launchId,e.scenarioId,e.generation,e.platformOwnerId,e.platformSessionId]);
  if(result.rows[0]?.allowed!==true)throw unavailable();
}
module.exports={attach,copy,productScene,birth,current,withLease,assertGrant};
