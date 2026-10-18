'use strict';
const assert=require('node:assert/strict'),path=require('node:path'),{randomUUID}=require('node:crypto');
// Same platform origin/auth/offline contract as the passed Listings full-index fixture.
// SecureShop is disabled, but its named origin option also feeds platform CORS.
function createDpiFullAppEnvironment({parent=process.env,home,root,port,origin,sharedModelContext}) {
 const url=new URL(origin);assert.equal(url.protocol,'http:');assert.equal(url.hostname,'127.0.0.1');assert.equal(Number(url.port),port);assert.equal(url.origin,origin);assert.ok(Number.isInteger(port)&&port>0&&port<=65535);assert.ok(path.isAbsolute(home)&&path.isAbsolute(root));
 if(sharedModelContext!==undefined)assert.ok([20480,32768].includes(sharedModelContext),'Only bounded shared 20K or 32K profiles are supported');
 return {...(sharedModelContext!==undefined?{OLLAMA_CONTEXT_WINDOW:String(sharedModelContext),JUDGE_CONTEXT_TOKENS:String(sharedModelContext)}:{}),PATH:parent.PATH,HOME:home,NODE_ENV:'test',PORT:String(port),PG_TEST_DISPOSABLE:'yes',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',SS_ALLOWED_ORIGINS:origin,SS_ENABLE:'false',SS_BOUND_REVIEWS_ENABLED:'false',MCP_WORKSHOP_AUTOSTART:'false',MCP_SIDECARS_AUTOSTART:'false',AI_PROVIDER:'mock',OLLAMA_BASE_URL:'http://127.0.0.1:1',AWS_EC2_METADATA_DISABLED:'true',HF_HUB_OFFLINE:'1',TRANSFORMERS_OFFLINE:'1',EVENT_GATE_ENABLED:'false',JWT_SECRET:randomUUID()+randomUUID(),LANGCHAIN_TRACING_V2:'false',LANGSMITH_TRACING:'false',DVAIA_APP_DATA_ROOT:path.join(root,'app-data'),LOGS_DIR:path.join(root,'logs'),LEGACY_SENSITIVE_FILES_ROOT:path.join(root,'legacy-sensitive')};
}
module.exports={createDpiFullAppEnvironment};
