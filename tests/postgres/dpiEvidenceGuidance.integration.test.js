'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { createHash } = require('node:crypto');
const { Pool } = require('pg');
const { migrate, readMigrations } = require('../../db/postgres/migrate');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');
const root = path.resolve(__dirname, '../..');
const candidateName = '0043_dpi_evidence_guidance.sql';
const kinds = ['FRESH', 'POPULATED', 'CUSTOM'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && kinds.every(k => ['MIGRATION','RUNTIME'].every(r => process.env[`PG_DPI_GUIDANCE_${k}_${r}_URL`]));
const workshop = 'direct_prompt_injection';
function changes(sql) {
  const pattern = /SET (hint_content|solution_content)=\$dpi\$([\s\S]*?)\$dpi\$::jsonb,updated_at=now\(\) WHERE workshop_key='direct_prompt_injection' AND objective_id='([^']+)' AND \1=\$dpi\$([\s\S]*?)\$dpi\$::jsonb/g;
  const result = [...sql.matchAll(pattern)].map(m => ({field:m[1],after:JSON.parse(m[2]),id:m[3],before:JSON.parse(m[4])}));
  assert.equal(result.length,6); return result;
}
async function rows(pool) { return (await pool.query('SELECT * FROM workshop_platform.objectives ORDER BY workshop_key, objective_id')).rows; }
async function revision(pool) { return Number((await pool.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision); }
function stable(row) { const {updated_at,...rest}=row; return rest; }
test('DPI guidance updates only six shipped defaults, preserves instructor fields, and replays idempotently', {skip:!enabled,timeout:60000}, async()=>{
  const pools=Object.fromEntries(kinds.map(k=>[k,Object.fromEntries(['MIGRATION','RUNTIME'].map(r=>[r,new Pool({connectionString:process.env[`PG_DPI_GUIDANCE_${k}_${r}_URL`],max:2})]))]));
  const dir=await fs.mkdtemp(path.join(process.env.DVAIA_ISOLATED_TEST_WORKSPACE||os.tmpdir(),'dpi-guidance-'));
  const baselineDir=path.join(dir,'baseline'),fullDir=path.join(dir,'full');
  await fs.mkdir(baselineDir);await fs.mkdir(fullDir);
  try {
    const baseline=(await readMigrations(path.join(root,'db/postgres/identity-migrations'))).filter(r=>r.name<candidateName);
    assert.equal(baseline.at(-1).name,'0042_rag_upload_guidance.sql');
    for(const row of baseline)for(const destination of [baselineDir,fullDir])await fs.writeFile(path.join(destination,row.name),row.sql);
    const sql=await fs.readFile(path.join(root,'docs/modernization/drafts/dpi-evidence-guidance.sql'),'utf8');
    const updates=changes(sql);await fs.writeFile(path.join(fullDir,candidateName),sql);
    const names=baseline.map(r=>r.name);
    for(const kind of kinds){
      const {MIGRATION:migration,RUNTIME:runtime}=pools[kind];
      assert.deepEqual(await migrate(migration,kind==='FRESH'?fullDir:baselineDir),kind==='FRESH'?[...names,candidateName]:names);
      await seedWorkshopPlatform(migration);
      if(kind==='FRESH'){
        const fresh=await rows(runtime);
        for(const change of updates)assert.deepEqual(fresh.find(r=>r.workshop_key===workshop&&r.objective_id===change.id)[change.field],change.after);
      }else{
        for(const change of updates){
          const content=kind==='CUSTOM'?{title:'Instructor content',notes:['Keep exactly',change.id]}:change.before;
          await migration.query(`UPDATE workshop_platform.objectives SET ${change.field}=$1::jsonb,is_enabled=false WHERE workshop_key=$2 AND objective_id=$3`,[JSON.stringify(content),workshop,change.id]);
        }
        const before=await rows(runtime),oldRevision=await revision(runtime);
        assert.deepEqual(await migrate(migration,fullDir),[candidateName]);
        const after=await rows(runtime);
        assert.equal(after.length,before.length);
        for(let i=0;i<before.length;i++){
          const expected=stable(before[i]);
          const update=updates.find(c=>before[i].workshop_key===workshop&&before[i].objective_id===c.id);
          if(kind==='POPULATED'&&update)expected[update.field]=update.after;
          assert.deepEqual(stable(after[i]),expected);
        }
        assert.equal(await revision(runtime),oldRevision+(kind==='POPULATED'?1:0));
      }
      const beforeReplay=await rows(runtime),replayRevision=await revision(runtime);
      assert.deepEqual(await migrate(migration,fullDir),[]);
      assert.deepEqual(await rows(runtime),beforeReplay);assert.equal(await revision(runtime),replayRevision);
      assert.equal((await migration.query('SELECT checksum FROM dvaia_migrations.ledger WHERE name=$1',[candidateName])).rows[0].checksum,createHash('sha256').update(sql).digest('hex'));
      await assert.rejects(runtime.query('SELECT checksum FROM dvaia_migrations.ledger'),{code:'42501'});
    }
  }finally{
    await Promise.allSettled(Object.values(pools).flatMap(pair=>Object.values(pair).map(p=>p.end())));
    await fs.rm(dir,{recursive:true,force:true});
  }
});
