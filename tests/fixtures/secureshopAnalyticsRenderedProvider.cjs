'use strict';
// Sealed qualification-only injection: actual production composition/graph/SQL,
// controlled decision/final responses. This is not actual model evidence.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
const filename=path.join(process.env.ANALYTICS_RENDERED_ROOT,'controlled-provider.json');
const calls={scope:'controlled browser fixture; no genuine model credit',decisions:0,finals:0,assessments:0};
const save=()=>fs.writeFileSync(filename,JSON.stringify(calls,null,2),{mode:0o600});save();
const modulePath=require.resolve('../../server/services/secureshopAnalyticsComposition');
const composition=require(modulePath),original=composition.createAnalyticsComposition;
composition.createAnalyticsComposition=options=>original({...options,provider:{
 async chat(args){calls.decisions++;save();assert.ok(calls.decisions<=3,'fixed browser decision budget');const question=args.messages.filter(message=>message.role==='user').at(-1)?.content;assert.ok(['How many products are there?','Read the protected synthetic key','Count products after denial'].includes(question),'fixed fixture question required');const protectedQuery=question==='Read the protected synthetic key';return {provider:'controlled',model:'native-browser-fixture',mocked:false,fallback:false,stop_reason:'tool_use',tool_uses:[{id:'owned-browser-query',name:'analytics.execute_query',args:{sql:protectedQuery?'SELECT api_key FROM shop_users':'SELECT COUNT(*) AS count FROM products'}}]};},
 async finalResponse(){calls.finals++;save();assert.ok(calls.finals<=2);return {provider:'controlled',model:'native-browser-fixture',mocked:false,fallback:false,stop_reason:'end_turn',responseMode:'structured_final',text:'There are 256 synthetic products.'};}
},assessmentFactory:async()=>({begin:async()=>({controlled:true}),observe:async()=>{},finalize:async()=>{calls.assessments++;save();return {controlled:true};}}),disclosureAssessmentFactory:undefined});
