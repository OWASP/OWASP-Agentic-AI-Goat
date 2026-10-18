'use strict';
// Disposable process only: controlled actor/Judge, no actual model qualification.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(process.env.MAIL_HEADER_FULL_APP,'1');
const file=path.join(process.env.LISTINGS_EVIDENCE_ROOT,'controlled-mail-provider.json'),counts={actualModelCalls:0,decisions:0,finals:0,judgeCalls:0,metadataOverride:true,qualifierOverride:true};const save=()=>fs.writeFileSync(file,JSON.stringify(counts),{mode:0o600});save();
const qualification=require('../../server/services/secureshopModelQualification'),oldQualifier=qualification.createSecureShopModelQualifier;
qualification.createSecureShopModelQualifier=p=>p?.config?.provider==='controlled-mail-grading'?i=>i?.provider==='controlled-mail-grading'&&i.mocked===false&&i.fallback!==true:oldQualifier(p);
const readiness=require('../../server/services/secureshopMailObjectiveReadiness');readiness.readMailObjectiveReadiness=async({identityPool,...deps})=>readiness.projectMailObjectiveReadiness({...readiness.MAIL_OBJECTIVE_QUALIFICATION,ss_mail_header_construction:true},{...deps,catalog:await readiness.readMailObjectiveCatalog(identityPool)});
const production=require('../../server/services/secureshopMailProduction'),original=production.createMailProduction;production.PRODUCTION_QUALIFIED=true;
production.createMailProduction=async options=>{
 const personas=await options.personaRepository.listPersonas();let recipient;
 const graph=require('../../server/services/secureshopBoundMailGraph'),create=graph.createBoundMailGraph;
 graph.createBoundMailGraph=input=>{let threadId;const built=create({...input,mailRepository:{...input.mailRepository,async read(...args){const result=await input.mailRepository.read(...args);const message=result.emails.filter(m=>m.thread_id===threadId).at(-1);assert(message);recipient=personas.find(p=>p.email===message.from_addr.split(/[\r\n]/)[0]);assert(recipient);return result;}}});return {...built,run(raw,options){threadId=raw.threadId;return built.run(raw,options);}};};
 const provider={config:{provider:'controlled-mail-grading',model:'controlled',mocked:false},async chat(){const step=counts.decisions++;assert(counts.decisions<=2);save();return{provider:'controlled-mail-grading',model:'controlled',mocked:false,fallback:false,stop_reason:'tool_use',tool_uses:[{id:randomUUID(),name:step?'email.send_reply':'email.read_thread',args:step?{recipientId:recipient.id,body_markdown:'Controlled reply acknowledgement.'}:{}}]};},async finalResponse(){counts.finals++;assert.equal(counts.finals,1);save();return{provider:'controlled-mail-grading',model:'controlled',mocked:false,fallback:false,stop_reason:'end_turn',responseMode:'structured_final',text:'Controlled reply saved.'};}};
 const judge=async input=>{counts.judgeCalls++;assert(counts.judgeCalls<=2);save();if(counts.judgeCalls===1)throw Error('Controlled unavailable before audit');
  const witness=input.evidence.find(e=>e.id==='header_boundary').content.boundaries[0].description;
  return require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:{async chat(){return{provider:'controlled-mail-grading',model:'controlled',response:JSON.stringify({satisfied:true,citations:[{evidenceId:'header_boundary',quote:witness}]})};}}})(input);
 };
 return original({...options,provider,assessmentDependencies:{...options.assessmentDependencies,judge}});
};
