'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {requiredStoreManifest}=require('../db/postgres/initialize-application');
const {MODEL_DIGEST}=require('./fixtures/fullBackendSecureShopAdmission');
const {selectSecureShop,prepareSecureShopStartup,assertSecureShopReadiness,unavailableRenderedSecureShop}=require('./fixtures/fullBackendSecureShopStartup');
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
function fixture(t){
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'ss-startup-'))),sourceRoot=root+'/source',evidenceRoot=root+'/runtime',renderer=root+'/renderer';
 fs.mkdirSync(sourceRoot);fs.mkdirSync(evidenceRoot,{mode:0o700});fs.mkdirSync(renderer);
 const source='client/src/pages/secureshop/components/ReviewCard.jsx';fs.mkdirSync(path.dirname(sourceRoot+'/'+source),{recursive:true});fs.writeFileSync(sourceRoot+'/'+source,'controlled source');
 fs.writeFileSync(renderer+'/renderer.cjs','controlled artifact, never executed');
 const manifest={version:1,component:'SecureShop.ReviewCard',source,sourceSha256:hash('controlled source'),artifact:'renderer.cjs',artifactSha256:hash('controlled artifact, never executed')};
 fs.writeFileSync(renderer+'/manifest.json',JSON.stringify(manifest));fs.chmodSync(renderer+'/renderer.cjs',0o444);fs.chmodSync(renderer+'/manifest.json',0o444);fs.chmodSync(renderer,0o555);fs.chmodSync(sourceRoot,0o555);
 t.after(()=>{function remove(p){fs.chmodSync(p,0o700);for(const e of fs.readdirSync(p,{withFileTypes:true}))if(e.isDirectory())remove(path.join(p,e.name));fs.rmSync(p,{recursive:true,force:true});}remove(root);});
 const endpoints={version:1,postgres:{host:'127.0.0.1',port:35001},agentHost:{host:'127.0.0.1',port:35002},model:{host:'127.0.0.1',port:11434},fixtures:[]};
 const env={PG_FULL_BACKEND_SECURESHOP:'1',PG_FULL_BACKEND_AUTH:'1',PG_FULL_BACKEND_RENDERED:'1',PG_TEST_DISPOSABLE:'yes',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',SS_PERSONA_INBOX_READY:'true',SS_MCP_TRUST_READY:'true',SS_CONTROLLED_SSRF_READY:'true',AI_PROVIDER:'ollama',OLLAMA_MODEL:'llama3.1:8b',JUDGE_PROVIDER:'ollama',JUDGE_MODEL:'llama3.1:8b',OLLAMA_BASE_URL:'http://127.0.0.1:11434',PG_FULL_BACKEND_SECURESHOP_MODEL_DIGEST:MODEL_DIGEST,OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE:sourceRoot,OWASP_AI_GOAT_FULL_BACKEND_RUNTIME_ROOT:evidenceRoot,SS_AGENT_HOST_PORT:'35002',SS_MCP_TRUST_FIXTURE_ROOT:evidenceRoot+'/secureshop-mcp-trust',SS_CONTROLLED_SSRF_FIXTURE_ROOT:evidenceRoot+'/secureshop-ssrf',SECURESHOP_REVIEW_RENDERER_ROOT:renderer,PG_FULL_BACKEND_SECURESHOP_RENDERER_MANIFEST_SHA256:hash(JSON.stringify(manifest)),PG_FULL_BACKEND_SECURESHOP_ENDPOINTS_JSON:JSON.stringify(endpoints)};
 for(const row of requiredStoreManifest){env[row.runtimeVariable]=`postgresql://${row.runtimeRole}@127.0.0.1:35001/owasp_ai_goat_test_full_backend_${row.schema}`;env[row.migrationVariable]=`postgresql://dvaia_${row.schema}_migration@127.0.0.1:35001/owasp_ai_goat_test_full_backend_${row.schema}`;}
 return{env,options:{sourceRoot,evidenceRoot}};
}
test('optional selector leaves defaults unchanged and rejects MCP overlap',()=>{
 assert.equal(selectSecureShop({}),false);
 for(const env of [{PG_FULL_BACKEND_SECURESHOP:'0'},{PG_FULL_BACKEND_SECURESHOP:'1'},{PG_FULL_BACKEND_SECURESHOP:'1',PG_FULL_BACKEND_RENDERED:'1',PG_FULL_BACKEND_MCP_INDIRECT:'1'}])assert.throws(()=>selectSecureShop(env));
});
test('all sixteen pairs and pinned external renderer produce only explicit mainserver overrides',t=>{
 const f=fixture(t);f.env.UNRELATED='not forwarded';const result=prepareSecureShopStartup(f.env,f.options);
 assert.equal(result.admission.readinessVerified,false);assert.equal(result.mainEnv.SS_ENABLE,'true');assert.equal(result.mainEnv.SS_ENABLE_REAL_MCP_SPAWN,'false');assert.equal(result.mainEnv.UNRELATED,undefined);assert.equal(result.mainEnv.NODE_OPTIONS,undefined);assert.equal(result.renderer.manifestSha256,f.env.PG_FULL_BACKEND_SECURESHOP_RENDERER_MANIFEST_SHA256);
});
test('renderer digest mismatch rejects admission',t=>{const f=fixture(t);f.env.PG_FULL_BACKEND_SECURESHOP_RENDERER_MANIFEST_SHA256='a'.repeat(64);assert.throws(()=>prepareSecureShopStartup(f.env,f.options));});
test('actual readiness requires every panel and never substitutes for rendered qualification',()=>{
 const value={status:200,body:{ready:true,panels:Object.fromEntries(['catalog','review','storedBrowser','personaInbox','mcpTrust','controlledSsrf'].map(k=>[k,true]))}};
 assert.doesNotThrow(()=>assertSecureShopReadiness(value));for(const k of Object.keys(value.body.panels)){const bad=structuredClone(value);bad.body.panels[k]=false;assert.throws(()=>assertSecureShopReadiness(bad));}
 assert.throws(()=>unavailableRenderedSecureShop(),e=>e.code==='SECURESHOP_RENDERED_QUALIFICATION_UNAVAILABLE');
});
