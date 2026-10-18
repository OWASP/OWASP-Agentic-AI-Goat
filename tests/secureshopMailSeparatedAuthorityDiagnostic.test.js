'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{createHash}=require('node:crypto'),{spawnSync}=require('node:child_process');
const {prepare}=require('./postgres/secureshopMailSeparatedAuthorityCalibration');
const bytes=fs.readFileSync(path.join(__dirname,'fixtures/mailSeparatedAuthorityIdentities.json')),sha=createHash('sha256').update(bytes).digest('hex');
test('dedicated v15 preflight validates exact synthetic identities and makes zero calls',()=>{
 const result=prepare(bytes,sha);assert.equal(result.cases.length,4);assert.deepEqual(result.http,[]);assert.equal(result.actualActorCalls,0);assert.equal(result.creditWrites,0);assert(result.cases.every(c=>c.diagnosticPacketSynthetic&&!c.canonicalProof));assert.throws(()=>prepare(bytes,'0'.repeat(64)));
 const wrong=Buffer.from(bytes.toString().replace('157','158'));assert.throws(()=>prepare(wrong,createHash('sha256').update(wrong).digest('hex')));
});
test('preflight executable returns before transport; launcher denies unreviewed mode before resource creation',()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'mail-heldout-control-'));try{const input=path.join(root,'input.json'),result=path.join(root,'result.json');fs.writeFileSync(input,bytes);const r=spawnSync(process.execPath,['tests/postgres/secureshopMailSeparatedAuthorityCalibration.js'],{encoding:'utf8',env:{...process.env,MAIL_CALIBRATION_INPUT:input,MAIL_CALIBRATION_INPUT_SHA:sha,MAIL_CALIBRATION_RESULT:result,MAIL_CALIBRATION_PREFLIGHT_ONLY:'1'}});assert.equal(r.status,0,r.stderr);assert.deepEqual(JSON.parse(fs.readFileSync(result)).http,[]);
 const denied=spawnSync('python3',['-B','tests/postgres/run-mail-judge-calibration.py','--mode','authority-v15','--preflight-only'],{encoding:'utf8'});assert.equal(denied.status,2);assert.match(denied.stderr,/requires reviewed source\/dependency byte digests/);
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});
