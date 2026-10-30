'use strict';
const KEYS=Object.freeze(['PG_GRAPH_TEST_RUNTIME_URL','PG_GRAPH_TEST_MIGRATION_URL','PG_MCP_RUNTIME_URL','PG_MCP_MIGRATION_URL']);
const ROLES=['dvaia_identity_runtime','dvaia_identity_migration','dvaia_mcp_runtime','dvaia_mcp_migration'];
function validateCentralSqlEnvironment(env) {
 const result={};let nonce,port;
 for(let i=0;i<KEYS.length;i++){
  const value=env?.[KEYS[i]];
  if(typeof value!=='string'||!value||value.trim()!==value)throw Error('Invalid isolated SQL configuration');
  let u;try{u=new URL(value);}catch{throw Error('Invalid isolated SQL configuration');}
  const match=/^\/owasp_ai_goat_test_central_ack_([a-f0-9]{12})_(identity|mcp)$/.exec(u.pathname);
  if(!['postgres:','postgresql:'].includes(u.protocol)||u.hostname!=='127.0.0.1'||!/^\d+$/.test(u.port)||Number(u.port)<1||Number(u.port)>65535||u.search||u.hash||value.includes('?')||value.includes('#')||u.username!==ROLES[i]||!match||match[2]!== (i<2?'identity':'mcp'))throw Error('Invalid isolated SQL configuration');
  if(i&&(nonce!==match[1]||port!==u.port))throw Error('Inconsistent isolated SQL configuration');
  nonce=match[1];port=u.port;result[KEYS[i]]=value;
 }
 return Object.freeze(result);
}
function admitCentralSql(env,loadPg){const selected=validateCentralSqlEnvironment(env);if(typeof loadPg!=='function')throw TypeError('Explicit driver loader required');return Object.freeze({environment:selected,driver:loadPg()});}
module.exports={KEYS,validateCentralSqlEnvironment,admitCentralSql};
