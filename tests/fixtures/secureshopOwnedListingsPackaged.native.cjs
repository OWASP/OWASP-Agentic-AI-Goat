'use strict';
const assert = require('node:assert/strict');
const { createOwnedListingsExecutor } = require('../../sidecars/sandbox-runner/owned-listings/namespace-executor');
const { createListingOperationExecutor } = require('../../sidecars/sandbox-runner/owned-listings/operation-executor');
const fs = require('node:fs/promises');
(async () => {
 const namespace = createOwnedListingsExecutor({ expectedProfile: process.env.LISTINGS_PROFILE });
 const ready = await namespace.checkReadiness(); assert.equal(ready.ready, true);
 let seq = 1, calls = 0;
 const request = (json_url, xml_url = null) => ({ version: 1, action: 'import', operationId: `10000000-0000-4000-8000-${String(seq++).padStart(12,'0')}`, json_url, xml_url });
 const execute = (request, mode = 'vuln', signal) => { calls++; return namespace.execute({ request, mode }, { signal }); };
 const baseline = await execute(request('http://192.0.2.10/catalog.json'), 'fixed');
 assert.equal(baseline.products[0].name, 'Supplier lamp'); assert.equal(Object.hasOwn(baseline,'namespaceAttested'),false);
 const prototype = await execute(request('http://192.0.2.10/prototype.json'));
 assert.equal(prototype.sources[0].prototypeEffect.observed,true);
 assert.equal(prototype.sources[0].prototypeEffect.inheritedProperties[0].name,'listingTrainingMarker');
 const fixedPrototype = await execute(request('http://192.0.2.10/prototype.json'),'fixed');
 assert.equal(fixedPrototype.sources[0].prototypeEffect.observed,false);
 await assert.rejects(execute(request('http://10.0.1.100:8080/prototype.json')));
 const internal = await execute(request('http://10.0.1.100:8080/catalog.json'));
 assert.equal(internal.products[0].name, 'Internal synthetic catalog');
 await assert.rejects(execute(request('http://10.0.1.100:8080/catalog.json'), 'fixed'), {code:'LISTING_RESOURCE_DENIED'});
 const file = await execute(request(null,'http://192.0.2.10/file.xml'));
 assert.match(file.products[0].description,/OWASP-AI-GOAT synthetic supplier secret/);
 const http = await execute(request(null,'http://192.0.2.10/http.xml'));
 assert.equal(http.products[0].description,'Owned HTTP entity');
 await assert.rejects(execute(request(null,'http://192.0.2.10/file.xml'),'fixed'), {code:'LISTING_XML_ENTITIES_DISABLED'});
 for (const url of ['http://8.8.8.8/catalog.json','http://host.docker.internal/catalog.json','http://127.0.0.1:8095/operations']) await assert.rejects(execute(request(url)));
 const options = { directory: '/journal', identity: ready.runtimeDigest, mode:'vuln', executeImport: ({request,mode,signal}) => execute(request,mode,signal) };
 const journal = await createListingOperationExecutor(options), input = request('http://192.0.2.10/catalog.json');
 const existingReceipt = Boolean(await journal.get(input.operationId));
 const beforeDispatch = calls; const receipt = await journal.execute(input), before = calls;
 if(existingReceipt) assert.equal(calls,beforeDispatch);
 const restarted = await createListingOperationExecutor(options);
 assert.deepEqual(await restarted.execute(input),receipt); assert.equal(calls,before);
 await assert.rejects(execute(request('http://192.0.2.10/slow'),'vuln',AbortSignal.timeout(150)));
 const childFile = `/proc/self/task/${process.pid}/children`;
 assert.equal((await fs.readFile(childFile,'utf8')).trim(),'');
 const { createListingListener } = require('../../sidecars/sandbox-runner/owned-listings/http-listener');
 const listener = await createListingListener({ token:'a'.repeat(43),directory:'/journal',mode:'vuln',identity:'d'.repeat(64),namespace });
 const address=await listener.start(), base=`http://127.0.0.1:${address.port}`, headers={authorization:'Bearer '+'a'.repeat(43)};
 try {
  assert.equal((await fetch(base+'/health')).status,401);
  const health=await (await fetch(base+'/health',{headers})).json();
  assert.equal(health.isolation,'owned-listings.v1'); assert.equal(health.runtimeDigest,ready.runtimeDigest);
  const op=request('http://192.0.2.10/catalog.json');
  const first=await (await fetch(base+'/operations',{method:'POST',headers,body:JSON.stringify(op)})).json();
  if(first.status==='retired') { assert.equal(existingReceipt,true); }
  else { assert.equal(first.status,'completed'); assert.deepEqual(await (await fetch(base+'/operations/'+op.operationId,{headers})).json(),first); }
  const tombstone=await (await fetch(base+'/operations/'+op.operationId+'/retire',{method:'POST',headers,body:'{}'})).json();
  assert.equal(tombstone.status,'retired');assert.equal(Object.hasOwn(tombstone,'result'),false);
  assert.deepEqual(await (await fetch(base+'/operations/'+op.operationId,{headers})).json(),tombstone);
  assert.equal((await journal.get(input.operationId)).status,'completed');
 } finally { await listener.close(); }
 process.stdout.write(JSON.stringify({status:'passed',modelCalls:0,existingReceipt,checks:['real-supplier-prototype-effect','fixed-prototype-no-effect','internal-prototype-route-denial','real-json','internal-ssrf','fixed-denial','real-file-entity','real-http-entity','external-host-denial','restart-no-refetch','timeout-child-cleanup','readonly-write-denial','authenticated-http','retirement-redaction-sibling'],runtimeDigest:ready.runtimeDigest})+'\n');
})().catch(error=>{console.error(error);process.exitCode=1;});
