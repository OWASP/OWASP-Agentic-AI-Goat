'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const base=fs.readFileSync(path.join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents/0039_mail_reply_purpose.sql'),'utf8');
const next=fs.readFileSync(path.join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents/0043_mail_snapshot_integrity.sql'),'utf8');
const start='CREATE OR REPLACE FUNCTION secureshop_agents.bound_lab_mail(';
test('forward repair retains exact qualified authority/IDOR/send/replay body except added read integrity guard',()=>{
 const added=next.slice(next.indexOf('  -- Authenticate returned bytes'),next.indexOf("  SELECT COALESCE(jsonb_agg(jsonb_build_object('id',m.message_id"));
 assert(added.includes("USING ERRCODE='P0001'"));assert.equal(next.slice(next.indexOf(start)).replace(added,''),base.slice(base.indexOf(start)));
 assert(!next.includes('GRANT '));assert(!next.includes('ALTER TABLE'));assert(!next.includes('UPDATE secureshop_agents.lab_mail_operation_receipts'));
});
test('guard binds PostgreSQL canonical bytes to both immutable send digests and exact message metadata',()=>{
 for(const text of ["'from',m.from_addr,'to',m.to_addr,'subject',m.subject","'body_markdown',m.body_markdown,'body_html',m.body_html,'headers_raw',m.headers_raw","(fields.base), (fields.base||jsonb_build_object('threadId',m.thread_id))","sent.target_id=m.target_id","sent.action='send'","sent.caller_id=m.sender_id","sent.result->>'email_id'=m.message_id::text","sent.result->>'thread_id'=m.thread_id::text","sent.result->>'senderId'=m.sender_id::text","sent.result->>'recipientId'=m.recipient_id::text","sent.result->>'contentSha256'=encode(m.content_sha256,'hex')","m.content_sha256=sha256(convert_to(candidate.payload::text,'UTF8'))","sent.request_sha256=sha256(convert_to(jsonb_build_array('send',candidate.payload)::text,'UTF8'))"]){assert(next.includes(text),text);}
});
test('supported send serializer has precisely the reconstructed payload forms',()=>{
 const {prepareSend}=require('../server/database/postgres/secureshopBoundMailRepository');const input={from:'merchant@example.invalid',to:'customer@example.invalid',subject:'unicode 🌍\r\ntraining',body_markdown:'quoted "text"\nline'};
 const plain=prepareSend(input),reply=prepareSend({...input,threadId:7});assert.deepEqual(Object.keys(plain).sort(),['body_html','body_markdown','from','headers_raw','subject','to']);assert.deepEqual(reply,{...plain,threadId:7});assert.throws(()=>prepareSend({...input,threadId:'7'}));
});
test('native fixture retains strict tamper negatives and safe assertion location without raw stack retention',()=>{
 const fixture=fs.readFileSync(path.join(__dirname,'postgres/secureshopMailDisclosure.native.js'),'utf8');for(const label of ["['subject',","['body',","['digest',","['body-and-digest',"]){assert(fixture.includes(label));}
 assert(fixture.includes("e.code==='P0001'&&e.message==='Mail snapshot integrity failure'"));assert(fixture.includes('threadId:originalSend.thread_id'));assert(fixture.includes("stage('migration-tamper-'+label)"));assert(fixture.includes("file:'tests/postgres/secureshopMailDisclosure.native.js',line:Number(location[1]),column:Number(location[2])"));assert(!fixture.includes('stack:error.stack'));
});

test('populated qualification seeds supported receipts before0043 and checks immutable upgrade/replay/noop separately from fresh',()=>{
 const fixture=fs.readFileSync(path.join(__dirname,'postgres/secureshopMailDisclosure.native.js'),'utf8');
 for(const ceiling of [37,42,43])assert(fixture.includes(`createAgentsMigrationView(${ceiling})`));
 assert(fixture.includes('const migrateAgents=(pool,directory)=>agentsMigrationView?agentsMigrationView.migrate(pool,directory):migrate(pool,directory)'));
 const send=fixture.indexOf('const originalSend=await mail.send'),read=fixture.indexOf('const readId=randomUUID()'),upgrade=fixture.indexOf("['0043_mail_snapshot_integrity.sql']");
 assert(send>0&&read>send&&upgrade>read);
 const blockStart=fixture.indexOf(" if(populatedState){\n  stage('populated-pre0043"),blockEnd=fixture.indexOf(" stage('runtime-message-select-denied')");
 assert(blockStart>=0&&blockEnd>blockStart);
 const block=fixture.slice(blockStart,blockEnd);
 for(const text of ['savedSend.replayed,true','savedReply.replayed,true','savedRead.replayed,true','mail.send(first,message),savedSend','mail.send(replyBinding,replyMessage),savedReply','mail.read(binding,customer.id),savedRead','reader.readDisclosure(binding),evidence','persistedSnapshot(),beforeUpgrade','ledgerBefore','upgradedLedger','snapshotIntegrityUpgradeNoop=true'])assert(block.includes(text),text);
 assert(block.includes("await migrate(am,'db/postgres/workshop-migrations/secureshop_agents'),[]"));
});

test('virtual migration views expose exact immutable prefixes through 0037, 0042 and 0043',async()=>{
 const {createAgentsMigrationView}=require('./helpers/secureshopAgentsMigrationView');
 const directory=path.join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents');
 const full=(await require('../db/postgres/migrate').readMigrations(directory)).map(row=>({name:row.name,checksum:row.checksum}));
 for(const ceiling of [37,42,43]){
  const view=createAgentsMigrationView(ceiling);
  assert.equal(view.directory,directory);
  const visible=(await view.readMigrations(directory)).map(row=>({name:row.name,checksum:row.checksum}));
  assert.deepEqual(visible,full.filter(row=>Number(row.name.slice(0,4))<=ceiling));
 }
 const before42=full.filter(row=>Number(row.name.slice(0,4))<=42);
 const through43=full.filter(row=>Number(row.name.slice(0,4))<=43);
 assert.deepEqual(through43.slice(0,before42.length),before42);
 assert.deepEqual(through43.slice(before42.length).map(row=>row.name),['0043_mail_snapshot_integrity.sql']);
});
