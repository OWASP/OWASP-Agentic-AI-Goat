'use strict';
// Test-only lifetime import guard. The sole database-path exception is a validation
// module with its transaction dependency replaced by a rejecting adapter; real receipt/progress/Judge dependencies remain injected.
const Module=require('node:module'),path=require('node:path');
const load=Module._load,resolve=Module._resolveFilename;
const support=path.resolve(__dirname,'../../server/database/postgres/workshopPlatformSupport.js');
Module._load=function(request,parent,main){
 if(parent?.filename===support&&request==='./index')return Object.freeze({withTransaction:()=>{throw Object.assign(Error('Analytics transaction not injected'),{code:'ANALYTICS_CONTROLLED_DEPENDENCY_DENIED'});}});
 let resolved;try{resolved=resolve.call(Module,request,parent);}catch{}
 const forbidden=/(?:^|\/)(?:database|multiProviderAIService|postgresIdentityAdapter|ollamaService|providerRouter)(?:\/|\.js|$)/.test(resolved||request)||/^(?:pg|sqlite3|better-sqlite3|openai|@anthropic-ai\/sdk)(?:\/|$)/.test(request)||/\/node_modules\/(?:pg|sqlite3|better-sqlite3|openai|@anthropic-ai\/sdk)(?:\/|$)/.test(resolved||'');
 if(forbidden&&resolved!==support)throw Object.assign(Error('Analytics controlled dependency refused'),{code:'ANALYTICS_CONTROLLED_DEPENDENCY_DENIED'});
 return load.call(this,request,parent,main);
};
