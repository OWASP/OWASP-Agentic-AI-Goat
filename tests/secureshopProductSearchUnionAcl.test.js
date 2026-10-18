'use strict';
// Controlled source/registry validation only; no PostgreSQL or model qualification.
const test=require('node:test'),assert=require('node:assert/strict');
const {readFileSync}=require('node:fs'),{join}=require('node:path'),{createHash}=require('node:crypto');
const current=require('../server/services/secureshopBoundAclRegistry');
const legacyTools=new Map(require('../server/data/secureshopAgentSeeds').TOOLS);
const postV29Keys=new Set([current.ARITHMETIC_SUM_KEY,current.AVATAR_UPLOAD_KEY,
 ...current.LISTING_OPTIMIZE_KEYS,current.FILE_SUMMARY_KEY,current.USER_LOOKUP_KEY,
 current.UPLOAD_PREVIEW_KEY,current.AGENCY_ROLE_KEY]);
const historicalRow=row=>Object.freeze({toolKey:row.toolKey,
 workflow:null,supported:false,roleApplicability:Object.freeze({customer:false,merchant:false,admin:false}),
 defaultAllowed:Object.freeze(Object.fromEntries(current.ROLES.map(role=>[role,legacyTools.get(row.toolKey)?.[role]===true]))),
 unavailableReason:'No supported bound execution workflow'});
const R={...current,REGISTRY_VERSION:29,REGISTRY_SHA256:current.ARITHMETIC_SUM_PREDECESSOR_REGISTRY_SHA256,
 REGISTRY:current.REGISTRY.flatMap(row=>!postV29Keys.has(row.toolKey)?[row]:legacyTools.has(row.toolKey)?[historicalRow(row)]:[]),
 REGISTRY_UPGRADES:current.PRE_ARITHMETIC_REGISTRY_UPGRADES};
const base=join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents');
const read=name=>readFileSync(join(base,name),'utf8');
const hash=s=>createHash('sha256').update(s).digest('hex');
function literals(sql){
 const out={};
 for(const m of sql.matchAll(/(\w+) (?:constant )?text := (E)?'((?:''|[^'])*)';/g)){
  let value=m[3].replaceAll("''","'");
  if(m[2])value=value.replace(/\\([nrt\\])/g,(_,c)=>({n:'\n',r:'\r',t:'\t','\\':'\\'})[c]);
  out[m[1]]=value;
 }
 return out;
}
function originalGuard(){
 let body=read('0082_merchant_mail_reads_registry_successor.sql').match(/FUNCTION secureshop_agents\.guard_bound_tool_registry_upgrade\(\)[\s\S]*?AS \$\$([\s\S]*?)\$\$;/)[1];
 for(const file of ['0084_merchant_mail_prepare_registry_successor.sql','0085_merchant_listing_setup_registry_successor.sql','0087_customer_coupon_prepare_registry_successor.sql','0088_customer_ticket_prepare_registry_successor.sql','0089_admin_system_diagnostic_prepare_registry_successor.sql','0092_mail_summary_registry_successor.sql']){
  const sql=read(file),v=literals(sql),b=sql.match(/guard_source:=replace\(guard_source,(v\d+_branch),(v\d+_branch)\|\|/);
  assert.equal(hash(body),v.old_guard_sha256,file+' prior hash');
  body=body.replaceAll(v.old_edge,v.old_edge+'\n'+v.new_edges).replaceAll(v[b[1]],v[b[2]]+v[b[1]]);
  assert.equal(hash(body),v.upgraded_guard_sha256,file+' resulting hash');
 }
 const v=literals(read('0096_coupon_probe_registry_successor.sql'));
 assert.equal(hash(body),v.old_guard_hash);
 const anchor=` IF encode(NEW.successor_sha256,'hex')='${v.old_hash}' THEN`;
 return body.replaceAll(anchor,v.branch+anchor);
}
const legacySearch={toolKey:'product-search.search',workflow:null,supported:false,roleApplicability:{customer:false,merchant:false,admin:false},defaultAllowed:{customer:true,merchant:true,admin:true},unavailableReason:'No supported bound execution workflow'};
test('v29 changes exactly one legacy row, preserves the complete v28 registry golden and exact customer workflow',()=>{
 const old=R.REGISTRY.map(row=>row.toolKey===R.PRODUCT_SEARCH_UNION_KEY?legacySearch:row);
 assert.equal(hash(JSON.stringify({version:28,rows:old})),R.PRODUCT_SEARCH_UNION_PREDECESSOR_REGISTRY_SHA256);
 assert.equal(R.REGISTRY_VERSION,29);assert.equal(R.REGISTRY_SHA256,'bc8edf04a8a13b42871d01699c19c0782d6093fc190df49c999a8d877228fd71');
 const resolver=R.createBoundAclResolver({workflow:'product-search-union',declaredTools:[{agent:'product-search',tool:'search'}]});
 assert.equal(resolver.resolve('product-search','search').toolKey,R.PRODUCT_SEARCH_UNION_KEY);
 for(const role of R.ROLES)assert.equal(resolver.isRoleApplicable(role),role==='customer');
 assert.equal(resolver.resolve('product-search','similar'),null);
 for(const declaredTools of [[],[{agent:'product-search',tool:'similar'}],[{agent:'product-search',tool:'search'},{agent:'product-search',tool:'search'}]])assert.throws(()=>R.createBoundAclResolver({workflow:'product-search-union',declaredTools}));
});
test('all v29 predecessor denials preserve historical keys and add only missing coupon/search capabilities',()=>{
 const previous=R.PRE_PRODUCT_SEARCH_REGISTRY_UPGRADES;
 assert.equal(Object.keys(R.REGISTRY_UPGRADES).length,Object.keys(previous).length+1);
 for(const [prior,keys] of Object.entries(previous))assert.deepEqual(R.REGISTRY_UPGRADES[prior],[...new Set([...keys,R.COUPON_PROBE_KEY,R.PRODUCT_SEARCH_UNION_KEY])]);
 assert.deepEqual(R.REGISTRY_UPGRADES[R.PRODUCT_SEARCH_UNION_PREDECESSOR_REGISTRY_SHA256],[R.PRODUCT_SEARCH_UNION_KEY]);
 assert.deepEqual(R.REGISTRY_UPGRADES[R.COUPON_PROBE_PREDECESSOR_REGISTRY_SHA256],[R.COUPON_PROBE_KEY,R.PRODUCT_SEARCH_UNION_KEY]);
});
test('0098 reconstructs exact guard, retains every historical byte and checks every new legal edge/denial set',()=>{
 const sql=read('0098_product_search_union_registry_successor.sql'),v=literals(sql),old=originalGuard();
 assert.equal(hash(old),v.old_guard_sha256);
 assert.equal(old.split(v.old_edge).length,2);assert.equal(old.split(v.v28_branch).length,2);assert.equal(old.split(v.denial_anchor).length,2);
 const next=old.replaceAll(v.old_edge,v.old_edge+'\n'+v.new_edges).replaceAll(v.v28_branch,v.v29_branch+v.v28_branch).replaceAll(v.denial_anchor,'\n END IF;'+v.denial_anchor);
 assert.equal(hash(next),v.upgraded_guard_sha256);
 assert.equal(next.replace(v.old_edge+'\n'+v.new_edges,v.old_edge).replace(v.v29_branch+v.v28_branch,v.v28_branch).replace('\n END IF;'+v.denial_anchor,v.denial_anchor),old);
 assert.ok(next.indexOf(v.new_edges)<next.indexOf(v.v29_branch),'new branch cannot bypass the common legal-edge/owner/version/digest guard');
 assert.doesNotMatch(v.v29_branch,/RETURN NEW/,'v29 uses common complete snapshot validation');
 for(const [prior,keys] of Object.entries(R.REGISTRY_UPGRADES)){
  const denials=R.REGISTRY.filter(row=>keys.includes(row.toolKey)).flatMap(row=>R.ROLES.filter(role=>row.roleApplicability[role]).map(role=>({toolKey:row.toolKey,role})));
  assert.equal(denials.length,keys.length);
  assert.ok(v.new_edges.includes(`(encode(NEW.predecessor_sha256,'hex')='${prior}' AND encode(NEW.successor_sha256,'hex')='${R.REGISTRY_SHA256}')`));
  assert.ok(v.v29_branch.includes(`WHEN '${prior}' THEN '${JSON.stringify(denials)}'::jsonb`));
  assert.ok(v.constraint_additions.includes(`encode(predecessor_sha256,'hex')='${prior}' AND encode(successor_sha256,'hex')='${R.REGISTRY_SHA256}' AND jsonb_array_length(added_denials)=${denials.length}`));
 }
 assert.match(sql,/regexp_count\(constraint_def,'jsonb_array_length'\)<>352/);
 assert.match(sql,/ADD CONSTRAINT bound_tool_registry_successor_v29/);
 assert.match(sql,/DROP CONSTRAINT bound_tool_registry_successor_v28/);
 assert.match(sql,/REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade\(\)\s+FROM PUBLIC,dvaia_secureshop_agents_runtime/);
 assert.doesNotMatch(sql,/GRANT|UPDATE secureshop_agents|DELETE FROM|INSERT INTO/);
 const readiness=readFileSync(join(__dirname,'../server/database/postgres/secureshopBoundToolPolicyReadiness.js'),'utf8');
 assert.ok(readiness.includes(`bound_tool_registry_successor_v${current.REGISTRY_VERSION}`));assert.ok(current.REGISTRY_VERSION>R.REGISTRY_VERSION);
 assert.doesNotMatch(readiness,/upgrade_guard_coupon_probe/,'presence of a hash substring is not readiness');
});
