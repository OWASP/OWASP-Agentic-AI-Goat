'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const root=path.join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents');
const purposes=name=>{
 const source=fs.readFileSync(path.join(root,name),'utf8');
 const list=/conversation_purpose IN \(\s*([\s\S]*?)\s*\)\s*AND/.exec(source)?.[1];
 assert.ok(list,`${name} has a closed conversation purpose constraint`);
 return new Set([...list.matchAll(/'([^']+)'/g)].map(match=>match[1]));
};
test('new audit purposes preserve every IDOR and mail-summary predecessor purpose',()=>{
 const idor=purposes('0086_idor_lesson_conversation_purpose.sql');
 const mail=purposes('0091_mail_summary_conversation_purpose.sql');
 const next=purposes('0093_audit_unbounded_and_timing_purposes.sql');
 for(const purpose of new Set([...idor,...mail]))assert.ok(next.has(purpose),`lost ${purpose}`);
 assert.ok(next.has('secureshop_idor_lesson'));
 assert.deepEqual([...next].filter(value=>!idor.has(value)&&!mail.has(value)).sort(),
  ['secureshop_audit_sql_timing','secureshop_audit_unbounded']);
});
