'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const os=require('node:os');
const {migrate}=require('../../db/postgres/migrate');

async function qualifyAuditMigration({migration,root}){
  const directory=await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-audit-ledger-'));
  const baseline=path.join(root,'db/postgres/workshop-migrations/secureshop_agents');
  const name='0021_secureshop_audit_run_storage.sql';
  const snapshot=async()=>{
    const result={};
    for(const table of ['agent_sessions','bound_audit_events','bound_mcp_targets']){
      result[table]=(await migration.query(`SELECT count(*)::integer AS count,
        md5(string_agg(md5(row_to_json(t)::text),'' ORDER BY md5(row_to_json(t)::text))) AS digest
        FROM secureshop_agents.${table} t`)).rows[0];
    }
    return result;
  };
  try{
    for(const file of (await fs.readdir(baseline)).filter(file=>file.endsWith('.sql')&&file<name))
      await fs.copyFile(path.join(baseline,file),path.join(directory,file));
    const ledger=(await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
    const before=await snapshot();
    assert.ok(before.bound_audit_events.count>0,'upgrade must retain populated audit sources');
    await fs.copyFile(path.join(root,'docs/modernization/drafts/secureshop-audit-runs/0021_secureshop_audit_run_storage.candidate.sql'),path.join(directory,name));
    assert.deepEqual(await migrate(migration,directory),[name]);
    assert.deepEqual(await migrate(migration,directory),[]);
    assert.deepEqual(await snapshot(),before);
    const after=(await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
    assert.deepEqual(after.slice(0,-1),ledger);assert.equal(after.at(-1).name,name);
  }finally{await fs.rm(directory,{recursive:true,force:true});}
}
module.exports={qualifyAuditMigration};
