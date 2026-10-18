'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createBoundRoleChatRouter } = require('../server/routes/secureshop/boundRoleChat');
const launch = { launchId: '10000000-0000-4000-8000-000000000001',
  scenarioId: '20000000-0000-4000-8000-000000000001', generation: 1,
  platformOwnerId: 4, platformSessionId: 5 };
const personaSession = { sessionId: '30000000-0000-4000-8000-000000000001', authorityVersion: '2' };
const ids = { sessionId: '40000000-0000-4000-8000-000000000001',
  requestId: '50000000-0000-4000-8000-000000000001' };
const headers = { 'content-type': 'application/json', 'x-dvaia-secureshop-launch': 'a'.repeat(43),
  authorization: 'Bearer private-token' };
async function setup(t, overrides = {}, userRole = 'admin') {
  const calls = [];
  const runtime = Object.fromEntries(['createSession', 'run', 'readRequest', 'confirmUserAdministration',
    'confirmPolicy', 'confirmMcpRegistry', 'confirmSystemRestart', 'confirmAcl', 'runAuditJob',
    'readAuditJob', 'readAuditOperation', 'readSystemConfigOperation'].map(key => [key, async () => {}]));
  Object.assign(runtime, {
    async confirmSystemDiagnostic(input) { calls.push(['confirm', input]); return { state: 'pending', operationId: input.proposalId }; },
    async readSystemDiagnostic(input) { calls.push(['read', input]); return { state: 'completed', operationId: input.proposalId }; },
  }, overrides);
  const app = express(); app.use(express.json());
  app.use('/api/secureshop', createBoundRoleChatRouter({ role: 'admin', runtime,
    launches: { async resolveCapability() { return launch; } },
    authenticatePersona(req, _res, next) { req.ssUser = { id: 7, role: userRole }; req.ssPersonaSession = personaSession; next(); } }));
  const server = app.listen(0, '127.0.0.1');
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  await new Promise(resolve => server.once('listening', resolve));
  return { calls, base: `http://127.0.0.1:${server.address().port}/api/secureshop/agents/admin/assistant/system/restart/assess` };
}
test('V04 assessment routes accept only saved IDs and preserve GET replay DTO',async t=>{
 const result={completed:false,status:'unconfirmed',modelEvaluated:false},calls=[];
 const {base}=await setup(t,{async runSystemRestartInjectionAssessment(input){calls.push(input);return result;},async readSystemRestartInjectionAssessment(input){calls.push(input);return result;}});
 const post=await fetch(base,{method:'POST',headers,body:JSON.stringify(ids)});assert.equal(post.status,200);assert.deepEqual(await post.json(),result);
 const get=await fetch(base.replace('/assess','/assessment')+'/'+ids.sessionId+'/'+ids.requestId,{headers});assert.equal(get.status,200);assert.deepEqual(await get.json(),result);
 for(const input of calls){assert.equal(input.scope.launchId,launch.launchId);assert.deepEqual(input.persona,{id:7,role:'admin'});assert.equal(input.proposalId,undefined);}
 for(const extra of [{proposalId:ids.sessionId},{name:'nginx'},{mode:'vuln'},{receipt:{}}]){const denied=await fetch(base,{method:'POST',headers,body:JSON.stringify({...ids,...extra})});assert.equal(denied.status,400);await denied.text();}
 assert.equal(calls.length,2);
});


test('fixed restart confirmation returns a stable policy denial without marking the launch unavailable',async t=>{
 const {base}=await setup(t,{async confirmSystemRestart(){throw Object.assign(Error('fixed'),{code:'SYSTEM_RESTART_FIXED_DENIED'});}});
 const response=await fetch(base.replace('/assess','/confirm'),{method:'POST',headers,
  body:JSON.stringify({...ids,proposalId:ids.sessionId})});
 assert.equal(response.status,403);assert.equal(response.headers.get('x-dvaia-secureshop-launch-state'),null);
 assert.deepEqual(await response.json(),{error:'System restart service name denied in Fixed mode',code:'SYSTEM_RESTART_FIXED_DENIED'});
});
