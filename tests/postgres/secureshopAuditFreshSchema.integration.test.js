'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const os=require('node:os');
const {Pool}=require('pg');
const {migrate}=require('../../db/postgres/migrate');
const prefix='PG_SECURESHOP_BOUND_AUDIT_';
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&['AGENTS','REVIEW'].every(store=>['RUNTIME','MIGRATION'].every(role=>process.env[`${prefix}${store}_${role}_URL`]));
test('fresh audit migration chain and exact no-op replay qualify runtime readiness',{skip:!enabled},async()=>{
  const pools=[],directory=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-audit-fresh-'));
  try{
    const stores={};
    for(const store of ['AGENTS','REVIEW']){
      stores[store]={};
      for(const role of ['RUNTIME','MIGRATION']){
        const url=new URL(process.env[`${prefix}${store}_${role}_URL`]);
        assert.equal(url.hostname,'127.0.0.1');assert.match(url.pathname,/^\/dvaia_test_[a-z0-9_]+$/);
        const pool=new Pool({connectionString:url.href,max:2,statement_timeout:15000});pools.push(pool);stores[store][role]=pool;
      }
    }
    assert.equal((await stores.AGENTS.MIGRATION.query("SELECT to_regclass('secureshop_agents.agent_sessions') AS table_name")).rows[0].table_name,null);
    const root=path.resolve(__dirname,'../..');
    const baseline=path.join(root,'db/postgres/workshop-migrations/secureshop_agents');
    for(const name of (await fs.readdir(baseline)).filter(name=>name.endsWith('.sql')))await fs.copyFile(path.join(baseline,name),path.join(directory,name));
    const candidate='0021_secureshop_audit_run_storage.sql';
    assert.deepEqual(await fs.readFile(path.join(directory,candidate)),await fs.readFile(path.join(root,'docs/modernization/drafts/secureshop-audit-runs/0021_secureshop_audit_run_storage.candidate.sql')),'promoted migration must match qualified bytes');
    const expected=(await fs.readdir(directory)).sort();
    assert.deepEqual(await migrate(stores.AGENTS.MIGRATION,directory),expected);
    const ledger=(await stores.AGENTS.MIGRATION.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
    assert.deepEqual(await migrate(stores.AGENTS.MIGRATION,directory),[]);
    assert.deepEqual((await stores.AGENTS.MIGRATION.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows,ledger);
    await migrate(stores.REVIEW.MIGRATION,path.join(root,'db/postgres/workshop-migrations/secureshop_review'));
    await require('../../server/services/secureshopBoundAuditComposition').assertSecureShopBoundAuditReadiness({agentsPool:stores.AGENTS.RUNTIME,reviewPool:stores.REVIEW.RUNTIME,includeRunArtifacts:true});
  }finally{await Promise.all(pools.map(pool=>pool.end()));await fs.rm(directory,{recursive:true,force:true});}
});
