'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{randomUUID}=require('node:crypto'),{Pool}=require('pg'),express=require('express');
const CURRENT_MAIN_DIRECTORY=process.env.SECURESHOP_ADMIN_DIRECTORY_ISOLATION_NATIVE==='1';
const STORE_NAMES={IDENTITY:'identity',FRESH:'secureshop_agents',COMMERCE:'secureshop',REVIEW:'secureshop_review'};
test(CURRENT_MAIN_DIRECTORY?'current-main protected admin directory excludes a foreign registered tenant while preserving owned controls':'persona-bound account and commerce preserve exact session and branded API authority',{skip:!CURRENT_MAIN_DIRECTORY&&process.env.PERSONA_ACCOUNT_COMMERCE_NATIVE!=='1',timeout:120000},async t=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
 const workspace=process.env[CURRENT_MAIN_DIRECTORY?'OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE':'OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE'];
 assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(workspace));
 const evidencePath=CURRENT_MAIN_DIRECTORY?process.env.SECURESHOP_ADMIN_DIRECTORY_ISOLATION_EVIDENCE_PATH:null;
 if(CURRENT_MAIN_DIRECTORY){assert.ok(path.isAbsolute(evidencePath));assert.ok(!path.resolve(evidencePath).startsWith(`${process.cwd()}${path.sep}`));assert.equal(fs.existsSync(evidencePath),false);}
 let nonce,port;
 const pool=(store,role)=>{const u=new URL(process.env[`PERSONA_${store}_${role}_URL`]);assert.equal(u.hostname,'127.0.0.1');
  if(CURRENT_MAIN_DIRECTORY){assert.equal(u.protocol,'postgresql:');assert.equal(u.password,'');assert.equal(u.search,'');assert.equal(u.hash,'');assert.equal(u.username,`dvaia_${STORE_NAMES[store]}_${role.toLowerCase()}`);
   const match=new RegExp(`^/owasp_ai_goat_test_agent_host_([0-9a-f]{12})_${STORE_NAMES[store]}$`).exec(u.pathname);assert.ok(match);nonce??=match[1];port??=u.port;assert.equal(match[1],nonce);assert.equal(u.port,port);
  }else assert.match(u.pathname,/^\/owasp_ai_goat_test_persona_[a-f0-9]+_(identity|commerce|fresh|review)$/);
  const p=new Pool({connectionString:u.href,max:3,statement_timeout:8000});t.after(()=>p.end());return p;};
 const identity=pool('IDENTITY','RUNTIME'),im=pool('IDENTITY','MIGRATION'),agents=pool('FRESH','RUNTIME'),am=pool('FRESH','MIGRATION'),source=pool('COMMERCE','RUNTIME'),cm=pool('COMMERCE','MIGRATION'),review=pool('REVIEW','RUNTIME'),rm=pool('REVIEW','MIGRATION'),{migrate}=require('../../db/postgres/migrate');await migrate(im,'db/postgres/identity-migrations');await migrate(cm,'db/postgres/workshop-migrations/secureshop');await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);await migrate(am,'db/postgres/workshop-migrations/secureshop_agents');await migrate(rm,'db/postgres/workshop-migrations/secureshop_review');
 const assertAdministrationReady=require('../../server/database/postgres/secureshopBoundUserAdministrationRepository').assertUserAdministrationReadiness;
 const missingGrantChecks=[
  ['REVOKE SELECT ON secureshop_agents.bound_persona_admin_operations FROM dvaia_secureshop_agents_runtime','GRANT SELECT ON secureshop_agents.bound_persona_admin_operations TO dvaia_secureshop_agents_runtime'],
  ['REVOKE INSERT ON secureshop_agents.bound_persona_state FROM dvaia_secureshop_agents_runtime','GRANT INSERT ON secureshop_agents.bound_persona_state TO dvaia_secureshop_agents_runtime'],
  ['REVOKE EXECUTE ON FUNCTION secureshop_agents.revoke_admin_target_api_keys(uuid,uuid,bigint,integer,integer,integer,uuid,integer) FROM dvaia_secureshop_agents_runtime','GRANT EXECUTE ON FUNCTION secureshop_agents.revoke_admin_target_api_keys(uuid,uuid,bigint,integer,integer,integer,uuid,integer) TO dvaia_secureshop_agents_runtime'],
 ];
 for(const [revoke,grant]of missingGrantChecks){await am.query(revoke);try{await assert.rejects(assertAdministrationReady(agents));}finally{await am.query(grant);}}
 assert.deepEqual(await assertAdministrationReady(agents),{ready:true});
 const assertPersonaReady=require('../../server/database/postgres/secureshopBoundPersonaAuthority').assertAuthorityReady;
 const expectedAgentsDatabase=new URL(process.env.PERSONA_FRESH_RUNTIME_URL).pathname.slice(1);
 for(const privilege of ['INSERT','UPDATE']){
  await am.query(`REVOKE ${privilege} ON secureshop_agents.bound_persona_state FROM dvaia_secureshop_agents_runtime`);
  try{await assert.rejects(assertPersonaReady({pool:agents,expectedDatabase:expectedAgentsDatabase}),{code:'PERSONA_AUTHORITY_NOT_READY'});}
  finally{await am.query(`GRANT ${privilege} ON secureshop_agents.bound_persona_state TO dvaia_secureshop_agents_runtime`);}
 }
 assert.deepEqual(await assertPersonaReady({pool:agents,expectedDatabase:expectedAgentsDatabase}),{ready:true,database:expectedAgentsDatabase});
 const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity),launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity),checkCurrent=s=>launches.assertCurrent(s),auditFactory=require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore,authority=require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:agents,checkCurrent}),personas=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:source,agentsPool:agents,personaAuthority:authority,auditStore:auditFactory({store:'agents',pool:agents})});await personas.ensureTemplates();
 const agentsAudit=auditFactory({store:'agents',pool:agents}),auth=require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,personaAuthority:authority,launches,jwtSecret:'owned-account-commerce-native-secret-at-least-32'}),productRepository=require('../../server/database/postgres/secureshopBoundProductRepository').createSecureShopBoundProductRepository(review,{checkCurrent,checkCleanup:async()=>{throw Error('No cleanup');}}),catalog=require('../../server/services/secureshopBoundCatalog').createSecureShopBoundCatalog({sourcePool:source,repository:productRepository,personaAuthority:authority,checkCurrent,resolveTarget:s=>launches.reserveProductsTarget({...s,expectedGeneration:s.generation})}),commerceRepository=require('../../server/database/postgres/secureshopBoundCommerceRepository').createSecureShopBoundCommerceRepository(review,{checkCurrent,effectTimeoutMs:3000,auditStore:auditFactory({store:'review',pool:review})}),commerce=require('../../server/services/secureshopBoundCommerce').createSecureShopBoundCommerce({repository:commerceRepository,catalog,personaAuthority:authority,resolveExistingTarget:s=>launches.readExistingProductsTarget(s)}),accountRepository=require('../../server/database/postgres/secureshopBoundAccountRepository').createSecureShopBoundAccountRepository(review,{checkCurrent,effectTimeoutMs:3000,auditStore:auditFactory({store:'review',pool:review})}),account=require('../../server/services/secureshopBoundAccount').createSecureShopBoundAccount({repository:accountRepository,personaRepository:personas,catalog,personaAuthority:authority}),administrationRepository=require('../../server/database/postgres/secureshopBoundUserAdministrationRepository').createSecureShopBoundUserAdministrationRepository({pool:agents,auditStore:agentsAudit,checkCurrent}),adminReads=require('../../server/database/postgres/secureshopBoundAdminReadRepository').createSecureShopBoundAdminReadRepository({agentsPool:agents,reviewPool:review}),admin=require('../../server/services/secureshopBoundAdmin').createSecureShopBoundAdmin({launches,personas,account,catalog,commerceRepository,personaAuthority:authority,accountRepository,administrationRepository,readAdapter:require('../../server/services/secureshopBoundAdminReadAdapter').createSecureShopBoundAdminReadAdapter({repository:adminReads,mcpConfigured:false,readRuntimeHealth:require('../../server/services/secureshopBoundRuntimeHealth').createSecureShopBoundRuntimeHealth({repository:adminReads,provider:{name:'controlled-native-no-model'},isServing:()=>true})})}),userAdministration=require('../../server/services/secureshopBoundUserAdministration').createSecureShopBoundUserAdministration({repository:administrationRepository,personaAuthority:authority,directory:admin});
 const owner=async (name,username='student_customer')=>{const hash=await require('bcryptjs').hash('owned-only',4),user=await users.createUser({username:name,email:name+'@example.invalid',passwordHash:hash}),token=randomUUID(),expiresAt=new Date(Date.now()+600000).toISOString(),session=await users.createSession({userId:user.id,token,expiresAt,expectedPasswordHash:hash}),issued=await launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,expiresAt}),logged=await auth.login({scope:issued.binding,username,password:'student123'}),verified=await auth.authenticateBoundToken({scope:issued.binding,token:logged.token});return{user,issued,persona:logged.user,token:logged.token,personaSession:{sessionId:verified.sessionId,authorityVersion:verified.authorityVersion}};};
 const router=require('../../server/routes/secureshop/boundGateway').createSecureShopBoundGateway({launches,authenticatePersona:auth.authenticatePersona,personaAuth:auth,userAdministration,reviewsRouter:express.Router(),browserRouter:express.Router(),catalog,commerce,account,admin}),app=express();app.use(express.json());app.use('/api/secureshop',router);const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});t.after(()=>new Promise(resolve=>server.close(resolve)));const base=`http://127.0.0.1:${server.address().port}/api/secureshop`,sessionHeaders=(o,json=false)=>({'x-owasp-ai-goat-secureshop-launch':o.issued.bearer,authorization:`Bearer ${o.token}`,...(json?{'content-type':'application/json'}:{})}),apiHeaders=(o,key)=>({'x-owasp-ai-goat-secureshop-launch':o.issued.bearer,'x-api-key':key});
 const live=await owner('account-commerce-live'),before=await identity.query("SELECT count(*)::int n FROM identity.secureshop_target_reservations WHERE launch_id=$1 AND target_kind='products'",[live.issued.binding.launchId]);assert.equal(before.rows[0].n,0);
 const initialKey=await fetch(`${base}/v2/auth/users/me/api-keys`,{headers:sessionHeaders(live)});assert.deepEqual(await initialKey.json(),{api_key:null,created_at:null,version:null});
 const rotated=await fetch(`${base}/v2/auth/users/me/api-keys/rotate`,{method:'POST',headers:sessionHeaders(live,true),body:'{}'}),key=(await rotated.json()).api_key;assert.match(key,/^sk_ss_live_/);
 const empty=await fetch(`${base}/v2/api/orders`,{headers:apiHeaders(live,key)});assert.equal(empty.status,200);assert.deepEqual(await empty.json(),{orders:[]});assert.equal((await identity.query("SELECT count(*)::int n FROM identity.secureshop_target_reservations WHERE launch_id=$1 AND target_kind='products'",[live.issued.binding.launchId])).rows[0].n,0,'API resolver must not provision');
 const profile=await fetch(`${base}/v2/auth/users/me`,{method:'PUT',headers:sessionHeaders(live,true),body:JSON.stringify({full_name:'Owned Customer',email:'owned-customer@example.invalid',phone:'555-0101'})});assert.equal(profile.status,200);assert.equal((await profile.json()).user.email,'owned-customer@example.invalid');
 const address=await fetch(`${base}/v2/auth/users/me/addresses`,{method:'POST',headers:sessionHeaders(live,true),body:JSON.stringify({label:'Home',line1:'1 Owned Way',line2:null,city:'Test',state:'CA',zip:'90001',phone:null,is_default:true})});assert.equal(address.status,200);assert.ok((await address.json()).id>0);
 const productId=Number((await source.query("SELECT id FROM secureshop.products WHERE status='active' ORDER BY id LIMIT 1")).rows[0].id),cart=await fetch(`${base}/cart`,{method:'POST',headers:sessionHeaders(live,true),body:JSON.stringify({product_id:productId,quantity:1})});assert.equal(cart.status,200);const checkout=await fetch(`${base}/orders`,{method:'POST',headers:sessionHeaders(live,true),body:JSON.stringify({shipping_address:'1 Owned Way',payment_method:'test-card',operationId:randomUUID()})});assert.equal(checkout.status,200);const orderId=(await checkout.json()).order_id;
 const apiOrder=await fetch(`${base}/v2/api/orders/${orderId}`,{headers:apiHeaders(live,key)});assert.equal(apiOrder.status,200);assert.equal((await apiOrder.json()).order.id,orderId);
 const rotatedAgain=await fetch(`${base}/v2/auth/users/me/api-keys/rotate`,{method:'POST',headers:sessionHeaders(live,true),body:'{}'}),nextKey=(await rotatedAgain.json()).api_key;assert.notEqual(nextKey,key);assert.equal((await fetch(`${base}/v2/api/orders`,{headers:apiHeaders(live,key)})).status,401);assert.equal((await fetch(`${base}/v2/api/orders`,{headers:apiHeaders(live,nextKey)})).status,200);
 const sibling=await owner('account-commerce-sibling');assert.deepEqual(await (await fetch(`${base}/v2/api/orders`,{headers:apiHeaders(sibling,(await (await fetch(`${base}/v2/auth/users/me/api-keys/rotate`,{method:'POST',headers:sessionHeaders(sibling,true),body:'{}'})).json()).api_key)})).json(),{orders:[]});
 await personas.revokeOwnedSession({scope:live.issued.binding,shopUserId:live.persona.id,sessionId:live.personaSession.sessionId});const denied=await fetch(`${base}/cart`,{method:'POST',headers:sessionHeaders(live,true),body:JSON.stringify({product_id:productId,quantity:2})});assert.equal(denied.status,401);assert.deepEqual((await commerceRepository.listCart({...live.issued.binding,targetId:(await launches.readExistingProductsTarget(live.issued.binding)).targetId},live.persona.id)).items,[],'checkout emptied cart; revoked mutation must not add items');
 const merchant=await owner('catalog-merchant-live','student_merchant'),merchantSibling=await owner('catalog-merchant-sibling','student_merchant');
 const stages=[];const saveMerchant=()=>{if(!CURRENT_MAIN_DIRECTORY)fs.writeFileSync('persona-merchant-catalog-result.json',JSON.stringify({scope:'Mounted real credential/catalog/SQL; no model or browser',stages},null,2)+'\n',{mode:0o600});};t.after(saveMerchant);
 const listing={title:'Owned listing',description:'<img src=x onerror="teaching()">',price:12.5,images:[],category:'training',template_source:'{{raw}}',retailer_id:merchant.persona.id};
 const submit=async value=>{const response=await fetch(`${base}/merchant/products`,{method:'POST',headers:sessionHeaders(value,true),body:JSON.stringify(listing)});assert.equal(response.status,200);return(await response.json()).product_id;};
 const listingId=await submit(merchant),siblingId=await submit(merchantSibling);
 const merchantTarget={...merchant.issued.binding,targetId:(await launches.readExistingProductsTarget(merchant.issued.binding)).targetId},siblingTarget={...merchantSibling.issued.binding,targetId:(await launches.readExistingProductsTarget(merchantSibling.issued.binding)).targetId};
 const original=await productRepository.get(merchantTarget,listingId);assert.equal(original.description,listing.description);assert.equal(original.template_source,'{{raw}}');assert.equal(original.retailer_id,merchant.persona.id);
 const siblingBefore=await productRepository.get(siblingTarget,siblingId);
 const list=await fetch(`${base}/merchant/products?per_page=100`,{headers:sessionHeaders(merchant)});assert.equal(list.status,200);assert.ok((await list.json()).products.some(row=>row.id===listingId));
 const patch={description:'<svg onload="teaching()"> unchanged owned markup',template_source:'{{raw teaching}}'};
 const updated=await fetch(`${base}/merchant/products/${listingId}`,{method:'PUT',headers:sessionHeaders(merchant,true),body:JSON.stringify({patch})});assert.equal(updated.status,200);const after=await productRepository.get(merchantTarget,listingId);assert.equal(after.description,patch.description);assert.equal(after.template_source,patch.template_source);stages.push({case:'mounted_merchant_create_update_private_list',ownedOverlay:true,teachingBytesPreserved:true});saveMerchant();
 // Intentional retailer selector may observe a decoy within this owned target.
 const decoy=(await review.query('SELECT retailer_id FROM secureshop_review.product_target_products WHERE target_id=$1 AND retailer_id<>$2 LIMIT 1',[merchantTarget.targetId,merchant.persona.id])).rows[0];assert.ok(decoy);
 const idor=await fetch(`${base}/merchant/products?retailer_id=${decoy.retailer_id}&per_page=100`,{headers:sessionHeaders(merchant)});assert.equal(idor.status,200);assert.ok((await idor.json()).products.length>0);stages.push({case:'intentional_owned_retailer_idor_preserved'});
 const archived=await fetch(`${base}/merchant/products/${listingId}`,{method:'DELETE',headers:sessionHeaders(merchant)});assert.equal(archived.status,200);assert.equal(await productRepository.get(merchantTarget,listingId),null);
 const archivedRow=(await review.query('SELECT status,archived_at FROM secureshop_review.product_target_listing_overlays WHERE target_id=$1 AND product_id=$2',[merchantTarget.targetId,listingId])).rows[0];assert.equal(archivedRow.status,'archived');assert.ok(archivedRow.archived_at);stages.push({case:'mounted_merchant_archive'});
 await personas.revokeOwnedSession({scope:merchant.issued.binding,shopUserId:merchant.persona.id,sessionId:merchant.personaSession.sessionId});
 const deniedCreate=await fetch(`${base}/merchant/products`,{method:'POST',headers:sessionHeaders(merchant,true),body:JSON.stringify(listing)});assert.equal(deniedCreate.status,401);
 await assert.rejects(catalog.createMerchantProduct({scope:merchant.issued.binding,persona:merchant.persona,personaSession:merchant.personaSession,listing:{name:listing.title,description:listing.description,price:12.5,images:[],category:'training',templateSource:'{{raw}}'}}),{code:'SHOP_AUTH_INVALID'});
 assert.equal((await fetch(`${base}/merchant/products`,{headers:sessionHeaders(merchant)})).status,401);
 assert.deepEqual(await productRepository.get(siblingTarget,siblingId),siblingBefore);assert.equal((await fetch(`${base}/merchant/products`,{headers:sessionHeaders(merchantSibling)})).status,200);
 stages.push({case:'revoked_http_and_service_write_denied_sibling_preserved'});saveMerchant();

 const sessionFence=await owner('account-session-fence'),secondLogin=await auth.login({scope:sessionFence.issued.binding,username:'student_customer',password:'student123'}),secondVerified=await auth.authenticateBoundToken({scope:sessionFence.issued.binding,token:secondLogin.token});
 const sessionsResponse=await fetch(`${base}/v2/auth/users/me/sessions`,{headers:sessionHeaders(sessionFence)});assert.equal(sessionsResponse.status,200);const sessionRows=(await sessionsResponse.json()).sessions;assert.equal(sessionRows.length,2);assert.equal(sessionRows.filter(row=>row.is_current).length,1);
 const versionedKeyResponse=await fetch(`${base}/v2/auth/users/me/api-keys`,{headers:sessionHeaders(sessionFence)});assert.equal(versionedKeyResponse.status,200);assert.deepEqual(await versionedKeyResponse.json(),{api_key:null,created_at:null,version:null});
 const staleActing=Object.freeze({sessionId:sessionFence.personaSession.sessionId,role:'customer',authorityVersion:sessionFence.personaSession.authorityVersion}),freshActing=Object.freeze({sessionId:secondVerified.sessionId,role:'customer',authorityVersion:secondVerified.authorityVersion});
 assert.equal(await personas.revokeOwnedSession({scope:sessionFence.issued.binding,shopUserId:sessionFence.persona.id,sessionId:staleActing.sessionId,actingCredential:staleActing}),true);
 await assert.rejects(personas.revokeOwnedSession({scope:sessionFence.issued.binding,shopUserId:sessionFence.persona.id,sessionId:freshActing.sessionId,actingCredential:staleActing}),{code:'SHOP_AUTH_INVALID'});
 assert.equal((await auth.authenticateBoundToken({scope:sessionFence.issued.binding,token:secondLogin.token})).sessionId,freshActing.sessionId,'stale actor denial must preserve the target session');
 assert.equal(await personas.revokeOwnedSession({scope:sessionFence.issued.binding,shopUserId:sessionFence.persona.id,sessionId:freshActing.sessionId,actingCredential:freshActing}),true);
 stages.push({case:'stale_acting_session_revoke_denied',twoActualSessions:true,targetPreserved:true,freshSelfRevoke:true,sessionAndApiVersionFromMiddleware:true});saveMerchant();

 const adminStages=[];let q50Passed=false;const saveAdmin=()=>fs.writeFileSync(CURRENT_MAIN_DIRECTORY?evidencePath:'persona-protected-admin-result.json',JSON.stringify(CURRENT_MAIN_DIRECTORY?{scope:'current-main disposable four-store protected admin directory; controlled service and mounted HTTP; no model or browser',passed:q50Passed,stages:adminStages}:{scope:'Mounted real gateway, repositories and persona authority; controlled observations only; no model',stages:adminStages},null,2)+'\n',{mode:0o600});t.after(saveAdmin);
 const projected=await owner('protected-admin-projection'),projectionSibling=await owner('protected-admin-sibling');
 const adminLogin=await auth.login({scope:projected.issued.binding,username:'student_admin',password:'student123'}),adminActor=await auth.authenticateBoundToken({scope:projected.issued.binding,token:adminLogin.token});
 const adminHttp={...projected,token:adminLogin.token,persona:adminLogin.user};
 const projectedProfile=await fetch(`${base}/v2/auth/users/me`,{method:'PUT',headers:sessionHeaders(projected,true),body:JSON.stringify({full_name:'Projected Customer',email:'projected-admin@example.invalid',phone:'555-0199'})});assert.equal(projectedProfile.status,200);
 const roleOperation=randomUUID(),roleBody={role:'admin',operationId:roleOperation,expectedVersion:'1'},roleResponse=await fetch(`${base}/admin/users/${projected.persona.id}/role`,{method:'POST',headers:sessionHeaders(adminHttp,true),body:JSON.stringify(roleBody)});assert.equal(roleResponse.status,200);const roleReceipt=await roleResponse.json();assert.equal(roleReceipt.receipt.role,'admin');assert.equal(roleReceipt.replayed,false);
 const observedRole=await fetch(`${base}/admin/users/operations/${roleOperation}`,{headers:sessionHeaders(adminHttp)});assert.equal(observedRole.status,200);assert.equal((await observedRole.json()).receipt.operationId,roleOperation);
 const replayRole=await fetch(`${base}/admin/users/${projected.persona.id}/role`,{method:'POST',headers:sessionHeaders(adminHttp,true),body:JSON.stringify(roleBody)});assert.equal(replayRole.status,200);assert.equal((await replayRole.json()).replayed,true);
 const conflictRole=await fetch(`${base}/admin/users/${projected.persona.id}/role`,{method:'POST',headers:sessionHeaders(adminHttp,true),body:JSON.stringify({...roleBody,role:'merchant'})});assert.equal(conflictRole.status,409);assert.equal((await conflictRole.json()).code,'OPERATION_CONFLICT');
 const staleVersion=await fetch(`${base}/admin/users/${projected.persona.id}/role`,{method:'POST',headers:sessionHeaders(adminHttp,true),body:JSON.stringify({role:'admin',operationId:randomUUID(),expectedVersion:'1'})});assert.equal(staleVersion.status,409);assert.equal((await staleVersion.json()).code,'REVISION_CONFLICT');
 const banOperation=randomUUID(),banResponse=await fetch(`${base}/admin/users/12/ban`,{method:'POST',headers:sessionHeaders(adminHttp,true),body:JSON.stringify({reason:'owned protected directory qualification',operationId:banOperation,expectedVersion:'1'})});assert.equal(banResponse.status,200);assert.ok((await banResponse.json()).receipt.bannedAt);
 const observedBan=await fetch(`${base}/admin/users/operations/${banOperation}`,{headers:sessionHeaders(adminHttp)});assert.equal(observedBan.status,200);assert.equal((await observedBan.json()).receipt.action,'ban');
 assert.equal((await fetch(`${base}/admin/users`,{headers:sessionHeaders(projected)})).status,401,'promoted persona old session must be revoked');
 const promotedLogin=await auth.login({scope:projected.issued.binding,username:'student_customer',password:'student123'});assert.equal(promotedLogin.user.role,'admin');const promoted={...projected,token:promotedLogin.token,persona:promotedLogin.user};
 const directoryResponse=await fetch(`${base}/admin/users?pageSize=25`,{headers:sessionHeaders(promoted)});assert.equal(directoryResponse.status,200);const directory=await directoryResponse.json(),promotedRow=directory.users.find(row=>row.id===projected.persona.id),bannedMerchant=directory.users.find(row=>row.id===12);assert.equal(promotedRow.role,'admin');assert.equal(promotedRow.email,'projected-admin@example.invalid');assert.equal(promotedRow.full_name,'Projected Customer');assert.equal(promotedRow.authority_version,'2');assert.equal(bannedMerchant.role,'merchant');assert.ok(bannedMerchant.banned_at);assert.equal(bannedMerchant.authority_version,'2');
 const kpis=await fetch(`${base}/admin/overview/kpis`,{headers:sessionHeaders(promoted)});assert.equal(kpis.status,200);const kpiBody=await kpis.json();assert.equal(kpiBody.total_users,3);assert.equal(kpiBody.admin_count,2);assert.equal(kpiBody.banned_count,1);assert.ok(kpiBody.total_products>0);
 const health=await fetch(`${base}/admin/agent-host/health`,{headers:sessionHeaders(promoted)});assert.equal(health.status,200);assert.equal((await health.json()).status,'SERVICE_READY');
 const siblingAdminLogin=await auth.login({scope:projectionSibling.issued.binding,username:'student_admin',password:'student123'}),siblingAdmin={...projectionSibling,token:siblingAdminLogin.token,persona:siblingAdminLogin.user},siblingResponse=await fetch(`${base}/admin/users`,{headers:sessionHeaders(siblingAdmin)});assert.equal(siblingResponse.status,200);const siblingDirectory=await siblingResponse.json();assert.equal(siblingDirectory.users.find(row=>row.id===11).role,'customer');assert.equal(siblingDirectory.users.find(row=>row.id===12).banned_at,null);
 const foreignPrincipalId=randomUUID(),foreignTenantId=randomUUID(),foreignSuffix=randomUUID().slice(0,8),foreignUsername=`foreign_q50_${foreignSuffix}`,foreignEmail=`${foreignUsername}@example.invalid`;
 const foreign=(await im.query(`INSERT INTO secureshop_auth.principals(principal_id,username,email,password_hash,role)
  VALUES($1,$2,$3,$4,'customer') RETURNING owner_id,shop_user_id`,[foreignPrincipalId,foreignUsername,foreignEmail,await require('bcryptjs').hash('foreign-directory-fixture',4)])).rows[0];
 // A seed merchant must already be an active member of this tenant. Create
 // its own registered merchant, then set the immutable seed after membership.
 // Catalog provisioning copies the shared source into this tenant's own scene.
 const foreignTenant=(await im.query(`INSERT INTO secureshop_auth.tenants(tenant_id,slug)
  VALUES($1,$2) RETURNING owner_id,seed_merchant_id`,[foreignTenantId,`foreign_q50_${foreignSuffix}`])).rows[0];
 assert.equal(foreignTenant.seed_merchant_id,null);
 const foreignMerchantPrincipalId=randomUUID(),foreignMerchantUsername=`foreign_merchant_${foreignSuffix}`;
 const foreignMerchant=(await im.query(`INSERT INTO secureshop_auth.principals(principal_id,username,email,password_hash,role)
  VALUES($1,$2,$3,$4,'merchant') RETURNING owner_id,shop_user_id`,[foreignMerchantPrincipalId,
  foreignMerchantUsername,`${foreignMerchantUsername}@example.invalid`,await require('bcryptjs').hash('foreign-merchant-fixture',4)])).rows[0];
 assert.ok(Number.isSafeInteger(foreignMerchant.shop_user_id)&&foreignMerchant.shop_user_id>=1000000000);
 assert.notEqual(foreignMerchant.shop_user_id,foreign.shop_user_id);
 await im.query(`INSERT INTO secureshop_auth.tenant_memberships(tenant_id,principal_id,shop_user_id,role)
  VALUES($1,$2,$3,'merchant')`,[foreignTenantId,foreignMerchantPrincipalId,foreignMerchant.shop_user_id]);
 const foreignSeed=(await im.query(`UPDATE secureshop_auth.tenants SET seed_merchant_id=$2
  WHERE tenant_id=$1 AND seed_merchant_id IS NULL RETURNING seed_merchant_id`,
 [foreignTenantId,foreignMerchant.shop_user_id])).rows[0];
 assert.equal(foreignSeed.seed_merchant_id,foreignMerchant.shop_user_id);
 await am.query(`INSERT INTO secureshop_agents.bound_actor_identities
  (shop_user_id,username,email,base_role,principal_id,original_platform_owner_id)
  VALUES($1,$2,$3,'merchant',$4,$5)`,[foreignMerchant.shop_user_id,foreignMerchantUsername,
  `${foreignMerchantUsername}@example.invalid`,foreignMerchantPrincipalId,foreignMerchant.owner_id]);
 await am.query(`INSERT INTO secureshop_agents.bound_actor_tenant_memberships
  (tenant_owner_id,tenant_id,shop_user_id,principal_id,principal_owner_id,membership_version,role)
  VALUES($1,$2,$3,$4,$5,1,'merchant')`,[foreignTenant.owner_id,foreignTenantId,
  foreignMerchant.shop_user_id,foreignMerchantPrincipalId,foreignMerchant.owner_id]);
 await im.query(`INSERT INTO secureshop_auth.tenant_memberships(tenant_id,principal_id,shop_user_id,role)
  VALUES($1,$2,$3,'customer')`,[foreignTenantId,foreignPrincipalId,foreign.shop_user_id]);
 await am.query(`INSERT INTO secureshop_agents.bound_actor_identities
  (shop_user_id,username,email,base_role,principal_id,original_platform_owner_id)
  VALUES($1,$2,$3,'customer',$4,$5)`,[foreign.shop_user_id,foreignUsername,foreignEmail,foreignPrincipalId,foreign.owner_id]);
 await am.query(`INSERT INTO secureshop_agents.bound_actor_tenant_memberships
  (tenant_owner_id,tenant_id,shop_user_id,principal_id,principal_owner_id,membership_version,role)
  VALUES($1,$2,$3,$4,$5,1,'customer')`,[foreignTenant.owner_id,foreignTenantId,foreign.shop_user_id,foreignPrincipalId,foreign.owner_id]);
 const foreignOwnership=await agents.query(`SELECT secureshop_agents.bound_actor_in_owner($1,$2) AS current_owned,
  secureshop_agents.bound_actor_in_owner($1,$3) AS foreign_owned`,[foreign.shop_user_id,projected.user.id,foreignTenant.owner_id]);
 assert.deepEqual(foreignOwnership.rows[0],{current_owned:false,foreign_owned:true});
 const foreignSearch=await fetch(`${base}/admin/users?search=${encodeURIComponent(foreignUsername)}`,{headers:sessionHeaders(promoted)});
 assert.equal(foreignSearch.status,200);const foreignSearchBody=await foreignSearch.json();
 assert.equal(foreignSearchBody.total,0);assert.deepEqual(foreignSearchBody.users,[]);
 assert.equal((await personas.listActors(projected.issued.binding)).some(row=>row.id===foreign.shop_user_id),false);
 assert.equal(await personas.readPersona(foreign.shop_user_id,projected.issued.binding),null);
 await assert.rejects(administrationRepository.readEffectivePersona({scope:projected.issued.binding,shopUserId:foreign.shop_user_id}),{code:'PERSONA_UNAVAILABLE'});
 const foreignSelectionOperation=randomUUID();
 await assert.rejects(userAdministration.mutate({scope:projected.issued.binding,persona:adminLogin.user,
  personaSession:{sessionId:adminActor.sessionId,authorityVersion:adminActor.authorityVersion},
  targetId:foreign.shop_user_id,operationId:foreignSelectionOperation,expectedVersion:'1',action:'set_role',role:'merchant'}),{code:'PERSONA_UNAVAILABLE'});
 assert.equal((await agents.query(`SELECT count(*)::int AS n FROM secureshop_agents.bound_persona_admin_operations
  WHERE operation_id=$1`,[foreignSelectionOperation])).rows[0].n,0);
 assert.equal((await im.query(`SELECT role FROM secureshop_auth.tenant_memberships
  WHERE tenant_id=$1 AND principal_id=$2`,[foreignTenantId,foreignPrincipalId])).rows[0].role,'customer');
 const ownedSearch=await fetch(`${base}/admin/users?search=student_customer`,{headers:sessionHeaders(promoted)});
 assert.equal(ownedSearch.status,200);assert.ok((await ownedSearch.json()).users.some(row=>row.id===projected.persona.id));

 // Q05/Q07 native authority matrix. All proposal setup below invokes canonical
 // services with current DB authority; it supplies no graph terminal/Judge rows.
 const matrixScenes=require('../../server/services/secureshopScenes').createSecureShopScenes({repository:
  require('../../server/database/postgres/secureshopSceneRepository').createSecureShopSceneRepository({pool:identity,launches}),reviewPool:review,launches});
 const matrixCatalog=require('../../server/services/secureshopBoundCatalog').createSecureShopBoundCatalog({sourcePool:source,
  repository:productRepository,personaAuthority:authority,checkCurrent,scenes:matrixScenes,
  resolveTarget:s=>launches.reserveProductsTarget({...s,expectedGeneration:s.generation})});
 const matrixCommerce=require('../../server/services/secureshopBoundCommerce').createSecureShopBoundCommerce({repository:commerceRepository,
  catalog:matrixCatalog,personaAuthority:authority,resolveExistingTarget:s=>matrixScenes.readExisting(s)});
 const matrixDomain=require('../../server/services/secureshopConversationalCommerce').createConversationalCommerce({commerce:matrixCommerce});
 // Reuse the already-owned server and its real gateway, with the canonical
 // scene-aware commerce assembly needed by chat operation receipts.
 app.use('/q05-q07',require('../../server/routes/secureshop/boundGateway').createSecureShopBoundGateway({launches,
  authenticatePersona:auth.authenticatePersona,personaAuth:auth,reviewsRouter:express.Router(),browserRouter:express.Router(),
  catalog:matrixCatalog,commerce:matrixCommerce,account,admin,userAdministration,scenes:matrixScenes}));
 const matrixBase=base.replace('/api/secureshop','/q05-q07');
 const context=o=>({scope:o.issued.binding,persona:o.persona,personaSession:o.personaSession});
 const matrixFetch=(o,pathname,body)=>fetch(matrixBase+pathname,{headers:sessionHeaders(o,body!==undefined),
  ...(body===undefined?{}:{method:'POST',body:JSON.stringify(body)})});
 const snapshotTables=async(pool,schema,tables)=>Object.fromEntries(await Promise.all(tables.map(async table=>[table,
  (await pool.query(`SELECT to_jsonb(t) AS value FROM ${schema}.${table} t ORDER BY to_jsonb(t)::text`)).rows])));
 const matrixEffects=async()=>({review:await snapshotTables(review,'secureshop_review',[
  'product_target_products','product_target_listing_overlays','product_target_cart_items','product_target_orders','product_target_order_items',
  'practice_payment_methods','chat_commerce_operations','bound_audit_events']),agents:await snapshotTables(agents,'secureshop_agents',[
  'bound_persona_state','bound_persona_admin_operations','bound_audit_events'])});
 const product=(await source.query("SELECT id,name FROM secureshop.products WHERE status='active' AND stock_quantity>0 ORDER BY id LIMIT 1")).rows[0];assert.ok(product);
 const prepareCart=async(o)=>{
  await matrixCatalog.prepareTarget(context(o));
  const found=await matrixCommerce.conversational({...context(o),method:'search',args:{search:product.name}});
  const index=found.products.findIndex(row=>Number.isSafeInteger(row.product_id)&&row.product_id===product.id);assert.ok(index>=0);assert.ok(found.cards[index]);
  const operationId=randomUUID(),before=(await review.query('SELECT to_jsonb(c) AS value FROM secureshop_review.product_target_cart_items c ORDER BY to_jsonb(c)::text')).rows;
  const prepared=await matrixCommerce.conversational({...context(o),method:'prepareCart',args:{operationId,action:'add',choiceId:found.cards[index].choiceId,quantity:1}});
  assert.equal(prepared.status,'prepared');assert.equal(prepared.proposalId,operationId);
  assert.deepEqual((await review.query('SELECT to_jsonb(c) AS value FROM secureshop_review.product_target_cart_items c ORDER BY to_jsonb(c)::text')).rows,before,'canonical preparation has no cart effect');
  assert.equal((await matrixDomain.readOperation({...context(o),args:{operationId}})).status,'prepared');return operationId;
 };
 const customerMatrix=await owner('q05-q07-customer-confirmation'),customerOperation=await prepareCart(customerMatrix);
 const preparedCustomer=(await review.query('SELECT * FROM secureshop_review.chat_commerce_operations WHERE operation_id=$1',[customerOperation])).rows[0];
 assert.equal(preparedCustomer.state,'prepared');assert.equal(preparedCustomer.result_json,null);
 assert.equal(await personas.revokeOwnedSession({scope:customerMatrix.issued.binding,shopUserId:customerMatrix.persona.id,
  sessionId:customerMatrix.personaSession.sessionId,actingCredential:{...customerMatrix.personaSession,role:'customer'}}),true);
 assert.equal(await personas.readSession({scope:customerMatrix.issued.binding,jti:require('jsonwebtoken').decode(customerMatrix.token).jti}),null);
 const revokedCustomerBefore=await matrixEffects();
 assert.equal((await matrixFetch(customerMatrix,'/customer/commerce/cart/confirm',{proposalId:customerOperation})).status,401);
 assert.equal((await matrixFetch(customerMatrix,`/customer/commerce/operations/${customerOperation}`)).status,401);
 await assert.rejects(matrixDomain.confirmCart({...context(customerMatrix),args:{proposalId:customerOperation}}),{code:'SHOP_AUTH_INVALID'});
 await assert.rejects(matrixDomain.readOperation({...context(customerMatrix),args:{operationId:customerOperation}}),{code:'SHOP_AUTH_INVALID'});
 assert.deepEqual(await matrixEffects(),revokedCustomerBefore,'revoked customer POST/GET/service cannot touch any effect or prepared receipt');
 const customerAgain=await auth.login({scope:customerMatrix.issued.binding,username:'student_customer',password:'student123'});
 const customerAgainVerified=await auth.authenticateBoundToken({scope:customerMatrix.issued.binding,token:customerAgain.token});
 const freshCustomer={...customerMatrix,token:customerAgain.token,persona:customerAgain.user,
  personaSession:{sessionId:customerAgainVerified.sessionId,authorityVersion:customerAgainVerified.authorityVersion}};
 const freshOperation=await prepareCart(freshCustomer),freshConfirmed=await matrixFetch(freshCustomer,'/customer/commerce/cart/confirm',{proposalId:freshOperation});
 assert.equal(freshConfirmed.status,200);const freshReceipt=await freshConfirmed.json();assert.equal(freshReceipt.status,'completed');assert.equal(freshReceipt.replayed,false);
 const freshBefore=await matrixEffects(),freshGet=await matrixFetch(freshCustomer,`/customer/commerce/operations/${freshOperation}`);
 assert.equal(freshGet.status,200);const freshSaved=await freshGet.json();assert.equal(freshSaved.status,'completed');assert.equal(freshSaved.scopeKey,freshReceipt.scopeKey);
 const {scopeKey:_freshScope,...freshPublicReceipt}=freshReceipt;assert.deepEqual(freshSaved.receipt,{...freshPublicReceipt,replayed:true});
 assert.deepEqual(await matrixEffects(),freshBefore,'fresh customer exact GET has no effect');
 assert.deepEqual((await review.query('SELECT * FROM secureshop_review.chat_commerce_operations WHERE operation_id=$1',[customerOperation])).rows,[preparedCustomer],'new session cannot alter the revoked session prepared receipt');

 const adminCredential={sessionId:adminActor.sessionId,authorityVersion:adminActor.authorityVersion};
 const nativeAdmin={...adminHttp,personaSession:adminCredential};
 const adminIntent={scope:projected.issued.binding,persona:adminLogin.user,personaSession:adminCredential,
  targetId:projected.persona.id,operationId:randomUUID(),expectedVersion:'2',action:'set_role',role:'customer'};
 assert.equal((await administrationRepository.readEffectivePersona({scope:projected.issued.binding,shopUserId:projected.persona.id})).version,'2');
 assert.equal(await personas.revokeOwnedSession({scope:projected.issued.binding,shopUserId:adminLogin.user.id,
  sessionId:adminCredential.sessionId,actingCredential:{...adminCredential,role:'admin'}}),true);
 const revokedAdminBefore=await matrixEffects();
 assert.equal((await matrixFetch(nativeAdmin,`/admin/users/${adminIntent.targetId}/role`,{operationId:adminIntent.operationId,expectedVersion:'2',role:'customer'})).status,401);
 assert.equal((await matrixFetch(nativeAdmin,`/admin/users/operations/${roleOperation}`)).status,401);
 await assert.rejects(userAdministration.mutate(adminIntent),{code:'SHOP_AUTH_INVALID'});
 await assert.rejects(userAdministration.operation({...context(nativeAdmin),operationId:roleOperation}),{code:'SHOP_AUTH_INVALID'});
 assert.deepEqual(await matrixEffects(),revokedAdminBefore,'revoked admin write/read cannot touch persona state, audit or any effect');
 const freshAdminLogin=await auth.login({scope:projected.issued.binding,username:'student_admin',password:'student123'});
 const freshAdminVerified=await auth.authenticateBoundToken({scope:projected.issued.binding,token:freshAdminLogin.token});
 const freshAdmin={...nativeAdmin,token:freshAdminLogin.token,persona:freshAdminLogin.user,
  personaSession:{sessionId:freshAdminVerified.sessionId,authorityVersion:freshAdminVerified.authorityVersion}};
 const adminPositive=await matrixFetch(freshAdmin,`/admin/users/${adminIntent.targetId}/role`,{operationId:adminIntent.operationId,expectedVersion:'2',role:'customer'});
 assert.equal(adminPositive.status,200);const adminPositiveBody=await adminPositive.json();assert.equal(adminPositiveBody.replayed,false);assert.equal(adminPositiveBody.receipt.role,'customer');
 const adminAfter=await matrixEffects();
 const adminSaved=await matrixFetch(freshAdmin,`/admin/users/operations/${adminIntent.operationId}`);assert.equal(adminSaved.status,200);assert.deepEqual((await adminSaved.json()).receipt,adminPositiveBody.receipt);
 const adminReplay=await matrixFetch(freshAdmin,`/admin/users/${adminIntent.targetId}/role`,{operationId:adminIntent.operationId,expectedVersion:'2',role:'customer'});
 assert.equal(adminReplay.status,200);assert.equal((await adminReplay.json()).replayed,true);assert.deepEqual(await matrixEffects(),adminAfter);

 // The foreign principal is authenticated under its actual distinct tenant,
 // rather than substituting launch fields or treating a same-tenant sibling as foreign.
 const foreignStandalone=require('../../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({repository:
  require('../../server/database/postgres/secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({pool:identity,executionTenantSlug:`foreign_q50_${foreignSuffix}`})});
 const foreignAuthenticated=await foreignStandalone.login({username:foreignUsername,password:'foreign-directory-fixture'});
 const foreignExecution=await foreignStandalone.establishTenantContext(foreignAuthenticated.context);
 assert.equal(foreignExecution.tenantId,foreignTenantId);assert.equal(foreignExecution.ownerId,Number(foreignTenant.owner_id));
 assert.notEqual(foreignExecution.ownerId,customerMatrix.issued.binding.platformOwnerId);
 const foreignIssued=await launches.issueOrRenew({platformOwnerId:foreignExecution.ownerId,platformSessionId:foreignExecution.sessionId,
  expiresAt:new Date(Date.now()+600000).toISOString(),shopPrincipal:foreignExecution});
 const foreignSession=await auth.establishSession({scope:foreignIssued.binding,shopPrincipal:foreignExecution});
 const foreignVerified=await auth.authenticateBoundToken({scope:foreignIssued.binding,token:foreignSession.token});
 const actualForeign={issued:foreignIssued,persona:foreignSession.user,token:foreignSession.token,
  personaSession:{sessionId:foreignVerified.sessionId,authorityVersion:foreignVerified.authorityVersion}};
 assert.equal(actualForeign.persona.id,Number(foreign.shop_user_id));
 const foreignOwnOperation=await prepareCart(actualForeign);
 const foreignOwnPositive=await matrixFetch(actualForeign,'/customer/commerce/cart/confirm',{proposalId:foreignOwnOperation});assert.equal(foreignOwnPositive.status,200);assert.equal((await foreignOwnPositive.json()).status,'completed');
 const foreignOwnRead=await matrixFetch(actualForeign,`/customer/commerce/operations/${foreignOwnOperation}`);assert.equal(foreignOwnRead.status,200);assert.equal((await foreignOwnRead.json()).status,'completed');
 const foreignBefore=await matrixEffects();
 await assert.rejects(matrixDomain.confirmCart({...context(actualForeign),args:{proposalId:freshOperation}}),
  {code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN'});
 // The cross-store authority fence deliberately reports uncertainty until the
 // protected readback below proves absence for this independently valid actor.
 const foreignConfirm=await matrixFetch(actualForeign,'/customer/commerce/cart/confirm',{proposalId:freshOperation});assert.equal(foreignConfirm.status,503);
 assert.deepEqual(await foreignConfirm.json(),{error:'Bound SecureShop operation unavailable'});
 const foreignRead=await matrixFetch(actualForeign,`/customer/commerce/operations/${freshOperation}`);assert.equal(foreignRead.status,200);const foreignAbsent=await foreignRead.json();assert.equal(foreignAbsent.operationId,freshOperation);assert.equal(foreignAbsent.status,'not_found');
 assert.equal((await matrixFetch(actualForeign,`/admin/users/operations/${adminIntent.operationId}`)).status,403,'authenticated foreign customer is not an administrator');
 assert.deepEqual(await matrixEffects(),foreignBefore,'valid authenticated foreign tenant cannot alter or recover the owned customer/admin effects');
 const foreignAdminPrincipal=randomUUID(),foreignAdminUsername=`foreign_admin_${foreignSuffix}`;
 const foreignAdminIdentity=(await im.query(`INSERT INTO secureshop_auth.principals(principal_id,username,email,password_hash,role)
  VALUES($1,$2,$3,$4,'admin') RETURNING owner_id,shop_user_id`,[foreignAdminPrincipal,foreignAdminUsername,
   `${foreignAdminUsername}@example.invalid`,await require('bcryptjs').hash('foreign-admin-native-only',4)])).rows[0];
 await im.query(`INSERT INTO secureshop_auth.tenant_memberships(tenant_id,principal_id,shop_user_id,role)
  VALUES($1,$2,$3,'admin')`,[foreignTenantId,foreignAdminPrincipal,foreignAdminIdentity.shop_user_id]);
 await am.query(`INSERT INTO secureshop_agents.bound_actor_identities(shop_user_id,username,email,base_role,principal_id,original_platform_owner_id)
  VALUES($1,$2,$3,'admin',$4,$5)`,[foreignAdminIdentity.shop_user_id,foreignAdminUsername,`${foreignAdminUsername}@example.invalid`,foreignAdminPrincipal,foreignAdminIdentity.owner_id]);
 await am.query(`INSERT INTO secureshop_agents.bound_actor_tenant_memberships(tenant_owner_id,tenant_id,shop_user_id,principal_id,principal_owner_id,membership_version,role)
  VALUES($1,$2,$3,$4,$5,1,'admin')`,[foreignTenant.owner_id,foreignTenantId,foreignAdminIdentity.shop_user_id,foreignAdminPrincipal,foreignAdminIdentity.owner_id]);
 const foreignAdminLogin=await foreignStandalone.login({username:foreignAdminUsername,password:'foreign-admin-native-only'});
 const foreignAdminExecution=await foreignStandalone.establishTenantContext(foreignAdminLogin.context);
 assert.equal(foreignAdminExecution.tenantId,foreignTenantId);assert.equal(foreignAdminExecution.ownerId,foreignExecution.ownerId);
 assert.notEqual(foreignAdminExecution.ownerId,projected.issued.binding.platformOwnerId);
 const foreignAdminIssued=await launches.issueOrRenew({platformOwnerId:foreignAdminExecution.ownerId,platformSessionId:foreignAdminExecution.sessionId,
  expiresAt:new Date(Date.now()+600000).toISOString(),shopPrincipal:foreignAdminExecution});
 const foreignAdminSession=await auth.establishSession({scope:foreignAdminIssued.binding,shopPrincipal:foreignAdminExecution});
 const foreignAdminVerified=await auth.authenticateBoundToken({scope:foreignAdminIssued.binding,token:foreignAdminSession.token});
 const actualForeignAdmin={issued:foreignAdminIssued,persona:foreignAdminSession.user,token:foreignAdminSession.token,
  personaSession:{sessionId:foreignAdminVerified.sessionId,authorityVersion:foreignAdminVerified.authorityVersion}};
 assert.equal(actualForeignAdmin.persona.role,'admin');assert.equal(actualForeignAdmin.persona.id,Number(foreignAdminIdentity.shop_user_id));
 const ownForeignDirectory=await matrixFetch(actualForeignAdmin,'/admin/users');assert.equal(ownForeignDirectory.status,200);
 assert.ok((await ownForeignDirectory.json()).users.some(row=>row.id===actualForeignAdmin.persona.id),'authenticated foreign administrator has legitimate owned directory access');
 const foreignAdminBefore=await matrixEffects();
 assert.equal((await matrixFetch(actualForeignAdmin,`/admin/users/operations/${adminIntent.operationId}`)).status,404);
 assert.equal(await userAdministration.operation({...context(actualForeignAdmin),operationId:adminIntent.operationId}),null);
 assert.equal((await matrixFetch(actualForeignAdmin,'/customer/commerce/cart/confirm',{proposalId:freshOperation})).status,403);
 assert.deepEqual(await matrixEffects(),foreignAdminBefore,'valid same-role foreign administrator cannot read original receipt or alter customer effect');

 // Existing closed Q50 stages stay byte-compatible; this separate private
 // receipt records controlled native setup and cannot claim model/chat evidence.
 if(CURRENT_MAIN_DIRECTORY)fs.writeFileSync(path.join(path.dirname(evidencePath),'q05-q07-native-authority.json'),JSON.stringify({
  scope:'current-main native canonical customer/admin services and protected HTTP; no RoleChat terminal, model, browser or Judge proof',
  passed:true,revokedCustomerConfirmationAndGet:true,revokedAdminMutationAndGet:true,
  freshCustomerAndAdminPositive:true,exactSavedReceiptsNoReplay:true,authenticatedDistinctTenantPositive:true,
  foreignCustomerConfirmationAndGetDenied:true,foreignCustomerAdminRoleDenied:true,authenticatedForeignAdminOwnRead:true,
  sameRoleForeignAdminSavedGetDenied:true,foreignAdminCustomerRoleDenied:true,immutableEffectsPreserved:true,
 },null,2)+'\n',{mode:0o600});
 adminStages.push({case:'mounted_role_ban_controls',operationRead:true,replay:true,operationConflict:true,revisionConflict:true},{case:'promoted_admin_directory_and_kpis',oldSessionDenied:true,overlayProjected:true,effectiveRoleProjected:true,banProjected:true},{case:'protected_operational_read',status:'SERVICE_READY',provider:'controlled-native-no-model'},{case:'sibling_launch_preserved'},{case:'foreign_registered_tenant_directory_denied',actualForeignMembership:true,searchDenied:true,selectionDenied:true,scopedReadDenied:true,ownedSearchPreserved:true});q50Passed=true;saveAdmin();

});
