const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const hints = require('../server/data/workshopHints');
const { objectiveSolutions: csrfSolutions } = require('../server/data/csrfWorkshopSolutions');
const { WORKSHOP_OBJECTIVES } = require('../server/config/workshopCatalog');

test('canonical catalog distinguishes SecureShop qualified and pending objectives', () => {
  // Four builder catalog aliases reuse existing legacy exercise objectives.
  assert.equal(Object.values(WORKSHOP_OBJECTIVES).flat().length, 179);
  assert.equal(WORKSHOP_OBJECTIVES.xss_email_builder.length, 4);
  assert.equal(Object.entries(WORKSHOP_OBJECTIVES).filter(([key]) => key !== 'xss_email_builder').flatMap(([, rows]) => rows).length, 175);
  const secureShop = WORKSHOP_OBJECTIVES.secureshop_agent_security;
  assert.equal(secureShop.length, 64);
  assert.equal(secureShop.filter(row => row.qualification !== 'pending').length, 55);
  assert.deepEqual(secureShop.filter(row => row.qualification === 'pending').map(row => row.id), [
    'ss_file_upload_instruction_adoption', 'ss_pricing_false_grounding',
    'ss_pricing_manual_injection', 'ss_manual_rag_instruction_adoption',
    'ss_product_description_instruction_adoption', 'ss_idor_order_status_disclosure',
    'ss_mcp_description_instruction_adoption', 'ss_policy_final_html_execution',
    'ss_user_lookup_sensitive_disclosure',
  ]);
  assert.ok(secureShop.every(row => row.defaultEnabled === false));
  assert.equal(WORKSHOP_OBJECTIVES.secureshop_agent_security.find(row => row.id === 'ss_audit_instruction_followed').qualification, 'native-browser-judge');
});

test('shared XSS hints describe the actual nine stored, generated, and email objectives', () => {
  const expectedTitles = {
    xss_s1: 'View Your Profile',
    xss_s2: 'Store an Event-Handler Payload',
    xss_s3: 'Trigger the Stored XSS',
    xss_g1: 'Meet the QA Content Generator',
    xss_g2: 'Have the LLM Generate and Store XSS',
    xss_g3: 'Trigger the LLM-Generated Stored XSS',
    xss_e1: 'List Your Workshop Inbox',
    xss_e2: 'Send the XSS Attack Email',
    xss_e3: 'Retrieve, Render, and Trigger Email XSS',
  };
  for (const [id, title] of Object.entries(expectedTitles)) {
    assert.equal(hints.xss_workshop[id].title, title, id);
    assert.ok(hints.xss_workshop[id].hints.length >= 3, id);
  }
});

test('IPI email objectives all have source-accurate hint contracts', () => {
  const ids = ['email_create_inbox', 'email_send_attack', 'email_retrieve', 'email_trigger_injection', 'email_understand_defense'];
  for (const id of ids) assert.ok(hints.indirect_prompt_injection[id], id);
  const retrieval = hints.indirect_prompt_injection.email_retrieve.hints.join(' ');
  assert.match(retrieval, /manual/i);
  assert.match(retrieval, /does not prove mail-provider delivery/i);
  assert.equal(
    WORKSHOP_OBJECTIVES.indirect_prompt_injection.find(({ id }) => id === 'email_retrieve').text,
    'Email Agent — Load Retrieved or Manual Email',
  );
});

test('FinFlow hint IDs exactly match its canonical objectives and avoid a fixed provider claim', () => {
  const catalogIds = WORKSHOP_OBJECTIVES.sensitive_info_disclosure.map(({ id }) => id).sort();
  assert.deepEqual(Object.keys(hints.sensitive_info_disclosure).sort(), catalogIds);
  assert.doesNotMatch(hints.sensitive_info_disclosure.ssrf_internal.hints.join(' '), /runs on AWS Bedrock/i);
  assert.match(hints.sensitive_info_disclosure.ssrf_ollama.hints.join(' '), /Ollama.*Bedrock/i);
});

test('CSRF RAG server-interpreted exercises do not claim browser execution proof', () => {
  for (const id of ['csrf_i2', 'csrf_i3']) {
    assert.match(hints.csrf_workshop[id].hints.join(' '), /server/i, id);
    assert.match(hints.csrf_workshop[id].hints.join(' '), /not .*browser|does not prove .*browser/i, id);
    const solution = csrfSolutions.find(item => item.objective_id === id);
    assert.ok(solution, id);
    assert.match(`${solution.hint} ${solution.explanation}`, /server/i, id);
    assert.match(`${solution.hint} ${solution.explanation}`, /not independent browser|does not prove independent browser|browser execution remains|independent browser execution remains/i, id);
  }
  const page = fs.readFileSync(path.join(__dirname, '../client/src/pages/challenges/CSRFWorkshop.js'), 'utf8');
  assert.match(page, /server-interpreter path/);
  assert.doesNotMatch(page, /XSS runs as Jordan|answer renders the embedded XSS|XSS re-renders/);
});

test('CSRF email teaching distinguishes original-message browser effects from optional summaries', () => {
  const solution = csrfSolutions.find(item => item.objective_id === 'csrf_x3');
  assert.ok(solution);
  for (const content of [hints.csrf_workshop.csrf_x3.hints.join(' '), `${solution.hint} ${solution.explanation}`]) {
    assert.match(content, /managed browser renders its original HTML/);
    assert.match(content, /read alone earns no exploit credit/);
    assert.match(content, /Fixed mode.*escaped inert text/);
    assert.match(content, /refuses or is unavailable.*no exploit credit/);
    assert.match(content, /not a requirement for the model to reproduce malicious HTML/);
  }
});

test('PostgreSQL content migration is additive and guards legacy rows', () => {
  const sql = fs.readFileSync(path.join(__dirname, '../db/postgres/identity-migrations/0023_workshop_teaching_content.sql'), 'utf8');
  assert.match(sql, /hint_content=\$json\$.*\$json\$::jsonb/s);
  assert.match(sql, /updated_by IS NULL AND hint_content IS NULL/);
  assert.match(sql, /solution_content=\$json\$.*WHERE.*solution_content=\$json\$/s);
  assert.doesNotMatch(sql, /DELETE\s+FROM\s+workshop_platform\.objectives/i);
});

test('CodeBot JavaScript objective migration preserves instructor content and bumps only on change', () => {
  const sql = fs.readFileSync(path.join(__dirname, '../db/postgres/identity-migrations/0024_codebot_javascript_objective.sql'), 'utf8');
  assert.match(sql, /objective_id='rce_cmd'/);
  assert.match(sql, /label='Achieve RCE — arbitrary command execution'/);
  assert.match(sql, /hint_content=\$json\$.*RCE — Shell Command Execution.*\$json\$::jsonb/s);
  assert.match(sql, /solution_content=\$json\$.*Execute System Commands via RCE.*\$json\$::jsonb/s);
  assert.match(sql, /WHERE id=1 AND EXISTS\(SELECT 1 FROM changed\)/);
  assert.doesNotMatch(sql, /DELETE\s+FROM\s+workshop_platform\.objectives/i);
});

test('IPI fresh seed resolves all five email solutions and keeps the five RAG siblings',()=>{
  const {solutionFixtures}=require('../server/database/postgres/workshopPlatformSeed');
  const {resolveObjectiveContent}=require('../server/database/postgres/workshopPlatformSeedCore');
  const solutions=solutionFixtures(),ids=WORKSHOP_OBJECTIVES.indirect_prompt_injection.map(x=>x.id);
  assert.deepEqual(Object.keys(solutions.indirect_prompt_injection).sort(),[...ids].sort());
  for(const objectiveId of ids.filter(x=>x.startsWith('email_'))){
    const content=resolveObjectiveContent({workshopKey:'indirect_prompt_injection',objectiveId,hints,solutions});
    assert.equal(content.hintPresent,true);assert(content.hint.hints.length);
    assert.equal(content.solutionPresent,true);assert(content.solution.title);assert(content.solution.approach);
    assert(content.solution.examples.every(x=>x.prompt&&x.explanation));
  }
  const email=solutions.indirect_prompt_injection;
  assert.match(email.email_create_inbox.approach,/local Mailpit.*read-only/s);
  assert.match(email.email_retrieve.approach,/Manual input.*cannot establish SMTP/s);
  assert.match(email.email_trigger_injection.approach,/inconclusive.*not a pass/);
  assert.match(email.email_understand_defense.approach,/same Summarize Email/);
  assert.match(hints.indirect_prompt_injection.email_create_inbox.hints[0],/local mode.*external provider/);
});

test('IPI email defaults use production provenance: fresh adoption, unchanged no-op and instructor preservation',async()=>{
  const p=require('../server/database/postgres/catalogDefaultProvenance');
  const solutions=require('../server/database/postgres/workshopPlatformSeed').solutionFixtures().indirect_prompt_injection;
  for(const objectiveId of Object.keys(solutions).filter(x=>x.startsWith('email_'))){
    const value=solutions[objectiveId],base={entityKind:'objective',workshopKey:'indirect_prompt_injection',objectiveId,fieldName:'solution_content',sourceValue:value,sourceVersion:'current-default'};
    const inserted=[];await p.adoptInsertedField({query:async(sql,args)=>{if(sql.startsWith('SELECT revision'))return {rows:[{revision:1}],rowCount:1};if(sql.includes('SELECT solution_content AS value'))return {rows:[{value}],rowCount:1};inserted.push({sql,args});return {rows:[],rowCount:1};}},base);
    assert.equal(inserted.length,1);assert.match(inserted[0].sql,/catalog_field_defaults/);assert(inserted[0].args.includes(p.hashDocument(p.document(value))));
    let managedCurrent=null,managedHash=p.hashDocument(p.document(null)),objectiveWrites=0,metadataWrites=0;
    const managedClient={query:async(sql,args)=>{
      if(sql.startsWith('SELECT revision'))return {rows:[{revision:1}],rowCount:1};
      if(sql.includes('SELECT solution_content AS value'))return {rows:[{value:managedCurrent}],rowCount:1};
      if(sql.includes('SELECT * FROM workshop_platform.catalog_field_defaults'))return {rows:[{provenance_state:'managed',applied_default_hash:managedHash}],rowCount:1};
      if(sql.startsWith('UPDATE workshop_platform.objectives')){assert.equal(args[0],base.workshopKey);assert.equal(args[1],objectiveId);assert.equal(args[3],null);managedCurrent=JSON.parse(args[2]);objectiveWrites++;return {rows:[],rowCount:1};}
      assert(sql.startsWith('UPDATE workshop_platform.catalog_field_defaults'));const changed=managedHash!==args[5];managedHash=args[5];metadataWrites+=Number(changed);return {rows:[],rowCount:Number(changed)};
    }};
    assert.deepEqual(await p.reconcileField(managedClient,base),{changed:true,decision:'upgrade'});
    assert.deepEqual(managedCurrent,value);assert.equal(objectiveWrites,1);assert.equal(metadataWrites,1);
    assert.deepEqual(await p.reconcileField(managedClient,base),{changed:false,decision:'record'});
    assert.equal(objectiveWrites,1);assert.equal(metadataWrites,1);
    for(const [current,state,expected]of [[value,'managed','record'],[{...value,approach:'Instructor-owned explanation'},'custom','preserve'],[null,'custom','preserve'],[null,'legacy_unknown','preserve']]){
      const writes=[];const client={query:async(sql,args)=>{
        if(sql.startsWith('SELECT revision'))return {rows:[{revision:1}],rowCount:1};
        if(sql.includes('SELECT solution_content AS value'))return {rows:[{value:current}],rowCount:1};
        if(sql.includes('SELECT * FROM workshop_platform.catalog_field_defaults'))return {rows:[{provenance_state:state,applied_default_hash:p.hashDocument(p.document(value))}],rowCount:1};
        writes.push(sql);assert(!sql.includes('UPDATE workshop_platform.objectives'));return {rows:[],rowCount:0};
      }};
      assert.deepEqual(await p.reconcileField(client,base),{changed:false,decision:expected});
      assert(writes.every(sql=>sql.includes('catalog_field_defaults')));
    }
  }
});
