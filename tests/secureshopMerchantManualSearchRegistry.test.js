'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const {join}=require('node:path');
const {createHash}=require('node:crypto');
const registry=require('../server/services/secureshopBoundAclRegistry');
const v20Registry={...registry,REGISTRY_VERSION:20,REGISTRY_SHA256:registry.MERCHANT_MAIL_PREDECESSOR_REGISTRY_SHA256,
  REGISTRY:registry.REGISTRY.filter(value=>!registry.MERCHANT_MAIL_KEYS.includes(value.toolKey)&&!registry.MERCHANT_MAIL_PREPARE_KEYS.includes(value.toolKey)),
  REGISTRY_UPGRADES:Object.fromEntries(Object.entries(registry.BASE_REGISTRY_UPGRADES)
    .map(([hash,keys])=>[hash,[...keys,registry.MANUAL_SEARCH_KEY]]).concat([[registry.MANUAL_SEARCH_PREDECESSOR_REGISTRY_SHA256,[registry.MANUAL_SEARCH_KEY]]]))};
const migrationPath=join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents/0080_merchant_manual_search_registry_successor.sql');
const readinessPath=join(__dirname,'../server/database/postgres/secureshopBoundToolPolicyReadiness.js');
const expectedGuard='149cfa8e3b5f5cb57dc54581ff08b7fc1643202e6df44ce2646aaba3d4341bc6';
const binarySort=(a,b)=>a.toolKey<b.toolKey?-1:a.toolKey>b.toolKey?1:a.role<b.role?-1:a.role>b.role?1:0;

test('merchant manual-search v20 retains the exact v19 predecessor and default-denies every populated predecessor',()=>{
  const row=v20Registry.REGISTRY.find(value=>value.toolKey===registry.MANUAL_SEARCH_KEY);
  assert.deepEqual(row,{toolKey:'merchant.manual_search',workflow:'merchant-assistant',supported:true,
    roleApplicability:{customer:false,merchant:true,admin:false},defaultAllowed:{customer:false,merchant:true,admin:false}});
  assert.equal(v20Registry.MANUAL_SEARCH_PREDECESSOR_REGISTRY_SHA256,'ac2df913bae81b4ca258cc6b30f6b62ecee9b975b37d30a13b14e2963b393daf');
  assert.equal(v20Registry.MERCHANT_MAIL_PREDECESSOR_REGISTRY_SHA256,'ea01e56229188d248e9513097b5551c2d8eb7363c8790dad66b618a781ec79d8');
  assert.equal(v20Registry.REGISTRY_VERSION,20);
  assert.equal(v20Registry.REGISTRY_SHA256,v20Registry.MERCHANT_MAIL_PREDECESSOR_REGISTRY_SHA256);
  for(const keys of Object.values(v20Registry.REGISTRY_UPGRADES)) assert.deepEqual(keys.slice(-1),[v20Registry.MANUAL_SEARCH_KEY]);
});

test('0080 preserves every published v19 edge and expected-denial branch, then appends exactly nineteen current-target upgrades',()=>{
  const text=readFileSync(migrationPath,'utf8');
  const v19Path=join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents/0079_pricing_compare_prepare_registry_successor.sql');
  const v19=readFileSync(v19Path,'utf8');
  const body=text.match(/FUNCTION secureshop_agents\.guard_bound_tool_registry_upgrade\(\)[\s\S]*?AS \$\$([\s\S]*?)\$\$;/)?.[1];
  assert.equal(createHash('sha256').update(body).digest('hex'),expectedGuard);
  assert.match(text,/DROP CONSTRAINT bound_tool_registry_successor_v19,\s+ADD CONSTRAINT bound_tool_registry_successor_v20 CHECK/);
  const edgePattern=/encode\(predecessor_sha256,'hex'\)='([0-9a-f]{64})' AND encode\(successor_sha256,'hex'\)='([0-9a-f]{64})' AND jsonb_array_length\(added_denials\)=(\d+)/g;
  const edgeSet=source=>new Set([...source.slice(source.indexOf('ADD CONSTRAINT bound_tool_registry_successor_')).matchAll(edgePattern)].map(match=>match.slice(1).join(':')));
  const historic=edgeSet(v19),current=edgeSet(text);
  assert.equal(historic.size,171);assert.ok([...historic].every(edge=>current.has(edge)));
  const expectedDirect=Object.entries(v20Registry.REGISTRY_UPGRADES).map(([predecessor,keys])=>{
    const denials=keys.flatMap(toolKey=>Object.entries(v20Registry.REGISTRY.find(row=>row.toolKey===toolKey).roleApplicability)
      .filter(([,allowed])=>allowed).map(([role])=>({toolKey,role}))).sort(binarySort);
    return {predecessor,denials};
  });
  assert.deepEqual([...current].filter(edge=>!historic.has(edge)).sort(),expectedDirect.map(({predecessor,denials})=>`${predecessor}:${v20Registry.REGISTRY_SHA256}:${denials.length}`).sort());
  const v19Marker="IF encode(NEW.successor_sha256,'hex')='ac2df913bae81b4ca258cc6b30f6b62ecee9b975b37d30a13b14e2963b393daf' THEN";
  const v19Body=v19.match(/FUNCTION secureshop_agents\.guard_bound_tool_registry_upgrade\(\)[\s\S]*?AS \$\$([\s\S]*?)\$\$;/)?.[1];
  assert.equal(body.slice(body.indexOf(v19Marker)),v19Body.slice(v19Body.indexOf(v19Marker)),'the original v19 expected-denial suffix stays byte-identical');
  for(const {predecessor,denials} of expectedDirect)assert.ok(body.includes(`WHEN '${predecessor}' THEN '${JSON.stringify(denials)}'::jsonb`));
  const counts=[...current].map(edge=>Number(edge.split(':').at(-1))).sort((a,b)=>a-b);
  const constraint=text.match(/jsonb_array_length\(added_denials\) IN \(([^)]+)\)/)?.[1].split(',').map(Number);
  assert.deepEqual(constraint,[...new Set(counts)]);
  assert.doesNotMatch(v19,/merchant\.manual_search/);
});

test('readiness pins the latest v36 successor guard while v20 and v22 remain historical',()=>{
  const source=readFileSync(readinessPath,'utf8');
  assert.match(source,/bound_tool_registry_successor_v36/);
  assert.match(source,/fdc3c3b3e51dfc3e2feb57c8ab53ffdce131c2c42032feba9db8a2fea5b0c9c2/);
  assert.match(source,/6830fb9d9680c1150204c3f3991345be6692008cae800e035b5e06e6b1549d95/);
  assert.match(readFileSync(join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents/0084_merchant_mail_prepare_registry_successor.sql'),'utf8'),/bound_tool_registry_successor_v22/);
  assert.match(readFileSync(join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents/0114_customer_agency_role_registry_successor.sql'),'utf8'),/bound_tool_registry_successor_v36/);
});
