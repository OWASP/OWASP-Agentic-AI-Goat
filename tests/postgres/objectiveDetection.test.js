'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
// Load only the actual pure detector, avoiding route imports that initialize user databases.
const source=fs.readFileSync(path.join(__dirname,'../../server/routes/sqlWorkshop.js'),'utf8');
const start=source.indexOf('function detectCompletedObjectives(');
const end=source.indexOf('// ── GET',start);
function detector(engine) {
  return vm.runInNewContext(`(${source.slice(start,end).trim()})`,{process:{env:{WORKSHOP_DATABASE_ENGINE:engine}}});
}
test('PostgreSQL route grades version/catalog/schema/exfil objectives and fixed mode does not grade',()=>{
  const detect=detector('postgres');
  const pairs=[
    ["%' UNION SELECT NULL,NULL,version(),NULL,NULL,NULL,NULL,NULL--",'sqli_7'],
    ["%' UNION SELECT NULL,NULL,tablename,NULL,NULL,NULL,NULL,NULL FROM pg_catalog.pg_tables WHERE schemaname='aria'--",'sqli_8'],
    ["%' UNION SELECT NULL,NULL,column_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.columns WHERE table_schema='aria' AND table_name='orders'--",'sqli_9'],
    ["%' UNION SELECT NULL,NULL,order_number,user_id,total_amount,NULL,NULL,NULL FROM aria.orders--",'sqli_10'],
  ];
  for(const [payload,id] of pairs) {
    assert.ok(detect(payload,'search_products',[{name:'proof'}],'vuln').includes(id));
    assert.equal(detect(payload,'search_products',[{name:'proof'}],'fixed').length,0);
    assert.ok(!detect(payload,'search_products',{error:'failed'},'vuln').includes(id));
    assert.ok(!detect(payload,'search_products',[],'vuln').includes(id));
  }
  assert.ok(!detect('sqlite_version()','search_products',[{}],'vuln').includes('sqli_7'));
  assert.ok(detector('sqlite')('sqlite_version()','search_products',[{}],'vuln').includes('sqli_7'));
});
