const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const test=require('node:test');
const source=fs.readFileSync('tests/postgres/secureshopStandaloneListingsRendered.integration.test.js','utf8');
const start=source.indexOf('          await frame.waitForFunction(id=>{',source.indexOf('status.physicalArchiveConfirmed=true;'));
const end=source.indexOf('},{timeout:20000},productId);',start);
const expression=source.slice(start,end+1).replace('          await frame.waitForFunction(','');
function check({status='archived',filter='archived',row=true}={}) {
  const document={querySelectorAll:selector=>{
    assert.equal(selector,'label');
    return [{querySelector:s=>s==='.ss-card__meta'?{textContent:'Status'}:{value:filter}}];
  },querySelector:selector=>{
    assert.equal(selector,'#p42');
    return row?{innerText:'Archived product name',querySelector:s=>{
      assert.equal(s,'td:nth-child(6) > span');return {textContent:status};
    }}:null;
  }};
  return vm.runInNewContext(`(${expression})`,{document})(42);
}
test('actual selected UI status is raw semantic text with uppercase styling',()=>{
  const ui=fs.readFileSync('client/src/pages/secureshop/pages/merchant/Listings.jsx','utf8');
  assert.match(ui,/<td style=\{tdStyle\}><StatusPill status=\{p.status\} \/><\/td>/);
  assert.match(ui,/textTransform: 'uppercase'/);
  assert.match(ui,/\}\}>\{status \|\| '—'\}<\/span>/);
  assert.equal(check(),true);
});
test('name-only archived text with active badge is rejected',()=>assert.equal(check({status:'active'}),false));
test('archived badge with non-archived filter is rejected',()=>assert.equal(check({filter:'active'}),false));
test('missing exact owned row is rejected',()=>assert.equal(Boolean(check({row:false})),false));
test('unknown or titlecase badge cannot pass semantic archived assertion',()=>{
  assert.equal(check({status:'Archived'}),false);assert.equal(check({status:''}),false);
});
test('single replacement preserves original limits and all other assertions',()=>{
  assert.match(source,/assert.equal\(archived\?\.status,'archived'\);assert.ok\(archived.archived_at\)/);
  assert.match(source,/assert.deepEqual\(await independentOverlays\(\),siblingOverlaysBefore\)/);
});
