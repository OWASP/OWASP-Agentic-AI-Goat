'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopBoundCatalog } = require('../server/services/secureshopBoundCatalog');

const scope = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000081',
  scenarioId: '20000000-0000-4000-8000-000000000081', generation: 3,
  platformOwnerId: 81, platformSessionId: 801 });
const reservation = Object.freeze({ targetId: '30000000-0000-4000-8000-000000000081',
  kind: 'products', launchId: scope.launchId, scenarioId: scope.scenarioId, generation: scope.generation });
function source(id, retailerId, role, name) {
  return { id, retailer_id: retailerId, retailer_role: role, name, description: 'body',
    description_html: '<img src=x onerror=owned()>', price: '12.50', category: 'Home',
    image_url: '/image.png', images: ['/image.png'], stock_quantity: 4, status: 'active',
    template_source: '{{raw}}', created_at: new Date('2026-01-01T00:00:00Z'),
    updated_at: new Date('2026-01-02T00:00:00Z') };
}
function fixture(options = {}) {
  const calls = { checks: [], source: 0, provision: [], list: [], categories: [] };
  let opened = null;
  const rows = [source(7, 5, 'merchant', 'Own source'), source(8, 9, 'merchant', 'Decoy source')];
  const repository = {
    async open() { return opened; },
    async provision(binding, value) {
      calls.provision.push([binding, value]);
      opened = { ...binding, ownMerchantId: value.ownMerchantId, sourceCount: value.products.length };
      rows.splice(0, rows.length, ...value.products.map(product => ({ id: product.id,
        name: product.name, category: product.category, description_html: product.descriptionHtml,
        retailer_id: product.retailerId, status: product.status })));
      return opened;
    },
    async list(_binding, options) {
      calls.list.push(options);
      const selected = rows.filter(row => options.retailerId == null || row.retailer_id === options.retailerId);
      return { rows: selected, total: selected.length, categories: ['Home'] };
    },
    async listMerchantChoices(_binding, options) {
      calls.list.push(options);
      const selected=rows.filter(row=>row.retailer_id===options.retailerId&&!row.archived_at
        &&(options.status==='all'||row.status===options.status));
      const page=selected.filter(row=>options.afterProductId===undefined||row.id>options.afterProductId).sort((a,b)=>a.id-b.id);
      return {rows:page.slice(0,5),total:selected.length,nextProductId:page.length>5?page[4].id:null};
    },
    async get(_binding, id) { return rows.find(row => row.id === id) || null; },
    async categories(binding) {
      calls.categories.push(binding);
      if (options.categoryNames) return options.categoryNames;
      return [...new Set(rows.map(row => row.category).filter(Boolean))].sort();
    },
    async createListing(_binding, _actor, value) {
      const id = 9; rows.push({ id, name: value.name, retailer_id: 12, category: value.category }); return id;
    },
    async updateListing(_binding, _actor, id, value) {
      const row = rows.find(item => item.id === id); if (!row) return null; Object.assign(row, value); return id;
    },
    async archiveListing(_binding, _actor, id) {
      const index = rows.findIndex(item => item.id === id); if (index < 0) return 0; rows.splice(index, 1); return 1;
    },
  };
  const catalog = createSecureShopBoundCatalog({ repository,
    sourcePool: { async query(sql, args) {
      if (sql.includes('FROM secureshop.categories')) {
        assert.deepEqual(args, [options.categoryNames || ['Home']]);
        assert.match(sql, /name = ANY\(\$1::text\[\]\)/);
        if (options.onMetadataRead) await options.onMetadataRead();
        return { rows: options.categoryRows || [{ id: 1, name: 'Home', description: 'Home category' }] };
      }
      calls.source += 1; assert.doesNotMatch(sql, /secureshop\.reviews/i); assert.deepEqual(args, [257]);
      return { rows: [source(7, 5, 'merchant', 'Own source'), source(8, 9, 'merchant', 'Decoy source')] };
    } },
    resolveTarget: async () => reservation,
    checkCurrent: async value => {
      calls.checks.push(value);
      if (options.checkCurrent) await options.checkCurrent(value);
    }, ownMerchantId: 12 });
  return { catalog, calls, rows };
}

test('catalog snapshots real source rows once and maps a nonempty own merchant plus same-target decoy', async () => {
  const { catalog, calls } = fixture();
  const own = await catalog.listMerchantProducts({ scope, persona: { id: 12, role: 'merchant' },
    query: { retailerId: null, page: 1, perPage: 20, sort: 'updated_desc', search: null,
      status: null, category: null } });
  assert.equal(own.products.length, 1);
  assert.equal(own.products[0].retailer_id, 12);
  assert.equal(own.products[0].description_html, '<img src=x onerror=owned()>');
  assert.equal(calls.provision[0][1].products[0].sourceRetailerId, 5);

  const decoy = await catalog.listMerchantProducts({ scope, persona: { id: 12, role: 'merchant' },
    query: { retailerId: 9, page: 1, perPage: 20, sort: 'updated_desc', search: null,
      status: null, category: null } });
  assert.equal(decoy.products.length, 1);
  assert.equal(decoy.products[0].retailer_id, 9);
  assert.equal(calls.source, 1, 'reopen must not reseed from mutable shared commerce');
  assert.ok(calls.checks.length >= 4);
});

test('customer product identity and review validator use the same target snapshot', async () => {
  const { catalog } = fixture();
  const listed = await catalog.listProducts({ scope, persona: { id: 11, role: 'customer' },
    query: { category: null, search: null, sort: '', page: 1, limit: 24, offset: 0 } });
  assert.deepEqual(listed.products.map(row => row.id), [7, 8]);
  assert.equal(await catalog.hasProduct({ scope, persona: { id: 11, role: 'customer' }, productId: 7 }), true);
  assert.equal(await catalog.hasProduct({ scope, persona: { id: 11, role: 'customer' }, productId: 999 }), false);
});

test('standalone merchant receives its own immutable product ownership without a demo alias', async () => {
  const { catalog, calls } = fixture();
  const merchant = { id: 1000000001, role: 'merchant' };
  const listed = await catalog.listMerchantProducts({ scope, persona: merchant,
    query: { page: 1, perPage: 20, sort: 'updated_desc' } });
  assert.equal(calls.provision[0][1].ownMerchantId, merchant.id);
  assert.equal(listed.products.length, 1);
  assert.equal(listed.products[0].retailer_id, merchant.id);
  await assert.rejects(catalog.listMerchantProducts({ scope, persona: { id: 1000000002, role: 'merchant' },
    query: { page: 1, perPage: 20, sort: 'updated_desc' } }), { code: 'PRODUCT_TARGET_MISMATCH' });
});

test('catalog forwards bounded rating and price constraints to its owned target', async () => {
  const { catalog, calls } = fixture();
  await catalog.listProducts({ scope, persona: { id: 12, role: 'merchant' },
    query: { category: null, search: null, minRating: 5, maxPrice: 2000,
      sort: '', page: 1, limit: 24, offset: 0 } });
  assert.equal(calls.list[0].minRating, 5);
  assert.equal(calls.list[0].maxPrice, 2000);
  await assert.rejects(catalog.listProducts({ scope, persona: { id: 12, role: 'merchant' },
    query: { category: null, search: null, minRating: 6, maxPrice: 2000,
      sort: '', page: 1, limit: 24, offset: 0 } }), { code: 'INVALID_ARGUMENT' });
  assert.equal(calls.list.length, 1);
});

test('customer categories come only from the current launch target', async () => {
  const { catalog, calls } = fixture();
  const result = await catalog.categories({ scope, persona: { id: 11, role: 'customer' } });
  assert.deepEqual(result, { categories: [{ id: 1, name: 'Home', description: 'Home category' }] });
  assert.deepEqual(calls.categories, [{ ...scope, targetId: reservation.targetId }]);
});

test('categories admit valid shop personas but reject malformed persona before target reads', async () => {
  const { catalog, calls } = fixture();
  assert.equal((await catalog.categories({ scope, persona: { id: 12, role: 'merchant' } })).categories[0].name, 'Home');
  assert.equal((await catalog.categories({ scope, persona: { id: 13, role: 'admin' } })).categories[0].name, 'Home');
  await assert.rejects(catalog.categories({ scope, persona: { id: 12, role: 'outsider' } }),
    { code: 'INVALID_ARGUMENT' });
  assert.equal(calls.categories.length, 2);
});

test('categories discard stale results when the launch resets during metadata lookup', async () => {
  let reset = false;
  const { catalog } = fixture({
    onMetadataRead: async () => { reset = true; },
    checkCurrent: async () => {
      if (reset) throw Object.assign(new Error('Launch reset'), { code: 'STALE_GENERATION' });
    },
  });
  await assert.rejects(catalog.categories({ scope, persona: { id: 11, role: 'customer' } }),
    { code: 'STALE_GENERATION' });
});

test('category metadata is projected and cannot introduce another target category', async () => {
  const { catalog } = fixture({ categoryRows: [
    { id: 1, name: 'Home', description: null, internal: 'private metadata' },
  ] });
  assert.deepEqual(await catalog.categories({ scope, persona: { id: 11, role: 'customer' } }),
    { categories: [{ id: 1, name: 'Home', description: null }] });
  const other = fixture({ categoryRows: [{ id: 2, name: 'Unrelated', description: null }] });
  await assert.rejects(other.catalog.categories({ scope, persona: { id: 11, role: 'customer' } }),
    { code: 'PRODUCT_SOURCE_UNAVAILABLE' });
});

test('custom and case-distinct owned categories remain visible without rewriting metadata identities', async () => {
  const { catalog } = fixture({ categoryNames: ['Books', 'books'], categoryRows: [
    { id: 7, name: 'Books', description: 'Books category' },
  ] });
  assert.deepEqual(await catalog.categories({ scope, persona: { id: 11, role: 'customer' } }), {
    categories: [
      { id: 7, name: 'Books', description: 'Books category' },
      { id: 'books', name: 'books', description: null },
    ],
  });
});

test('catalog rejects malformed and non-owner merchant requests before target reads', async () => {
  const { catalog, calls } = fixture();
  await assert.rejects(catalog.listProducts({ scope, persona: { id: 1, role: 'customer' },
    query: { category: null, search: null, sort: 'DROP TABLE', page: 1, limit: 24, offset: 0 } }),
  { code: 'INVALID_ARGUMENT' });
  await assert.rejects(catalog.listMerchantProducts({ scope, persona: { id: 5, role: 'merchant' },
    query: { retailerId: null, page: 1, perPage: 20, sort: 'updated_desc', search: null,
      status: null, category: null } }), { code: 'OWNER_MISMATCH' });
  assert.equal(calls.list.length, 0);
});

test('merchant listing writes use only the trusted owner persona and retain raw teaching fields', async () => {
  const { catalog } = fixture();
  const authority = { scope, persona: { id: 12, role: 'merchant' } };
  const created = await catalog.createMerchantProduct({ ...authority, listing: {
    name: 'Owned listing', description: '<img src=x onerror=owned()>', price: 19.25,
    category: 'Home', templateSource: '{{ constructor.constructor("return 1")() }}', images: ['/owned.png'],
  } });
  assert.equal(created.productId, 9);
  assert.deepEqual(await catalog.updateMerchantProduct({ ...authority, productId: 9,
    patch: { name: 'Renamed', description: '<svg onload=owned()>', templateSource: '{{raw}}' } }),
  { productId: 9 });
  assert.equal(await catalog.archiveMerchantProduct({ ...authority, productId: 9 }), true);
  assert.equal(await catalog.updateMerchantProduct({ ...authority, productId: 999,
    patch: { name: 'missing' } }), null);
  await assert.rejects(catalog.createMerchantProduct({ scope, persona: { id: 9, role: 'merchant' },
    listing: { name: 'foreign' } }), { code: 'OWNER_MISMATCH' });
});

test('merchant listing reads accept the visible stock sorts and archived filter', async () => {
  const { catalog, calls } = fixture();
  const authority = { scope, persona: { id: 12, role: 'merchant' } };
  for (const sort of ['stock_desc', 'stock_asc']) {
    await catalog.listMerchantProducts({ ...authority, query: { retailerId: null, page: 1,
      perPage: 20, sort, search: null, status: 'archived', category: null } });
  }
  assert.deepEqual(calls.list.slice(-2).map(value => [value.sort, value.status]), [
    ['stock_desc', 'archived'], ['stock_asc', 'archived'],
  ]);
});


test('manual ingestion ownership requires the authenticated own merchant and active own product', async () => {
  const { catalog } = fixture();
  const request = { scope, persona: { id: 12, role: 'merchant' }, productId: 7 };
  const owned = await catalog.getOwnedMerchantProduct(request);
  assert.equal(owned.product.retailer_id, 12);
  assert.equal(owned.binding.targetId, reservation.targetId);
  for (const override of [{ productId: 8 }, { productId: 999 },
    { persona: { id: 9, role: 'merchant' } }]) {
    await assert.rejects(catalog.getOwnedMerchantProduct({ ...request, ...override }), { code: 'OWNER_MISMATCH' });
  }
  await assert.rejects(catalog.getOwnedMerchantProduct({ ...request,
    persona: { id: 12, role: 'customer' } }), { code: 'INVALID_ARGUMENT' });
});
test('chat expected scene is checked inside catalog provisioning lease before target open or seed',async()=>{
  const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
  const actual=createSceneBinding({...scope,targetId:reservation.targetId},{sceneId:'40000000-0000-4000-8000-000000000081',
    sceneGeneration:1,grantId:'50000000-0000-4000-8000-000000000081',execution:scope,withLease:async work=>work()});
  let opened=0,provisioned=0,sourced=0,leases=0;
  const repository={async open(){opened++;return null;},async provision(){provisioned++;},async list(){},async get(){},
    async categories(){},async createListing(){},async updateListing(){},async archiveListing(){}};
  const scenes={withProvisionLease:async(_scope,work)=>{leases++;return work();},resolve:async()=>actual,finalize:async()=>actual};
  const catalog=createSecureShopBoundCatalog({repository,scenes,sourcePool:{async query(){sourced++;return{rows:[]};}},
    resolveTarget:async()=>reservation,checkCurrent:async()=>{}});
  await assert.rejects(catalog.prepareTarget({scope,persona:{id:12,role:'merchant'},expectedScene:{targetId:reservation.targetId,
    sceneId:'60000000-0000-4000-8000-000000000081',sceneGeneration:1}}),{code:'SHOP_SCENE_STALE'});
  assert.deepEqual({leases,opened,provisioned,sourced},{leases:1,opened:0,provisioned:0,sourced:0});
});


test('merchant discovery pages only owned products including read-only inactive selection',async()=>{
 const f=fixture(),input={scope,persona:{id:12,role:'merchant'}};
 await f.catalog.listMerchantProducts({...input,query:{page:1,perPage:5,sort:'updated_desc'}});
 f.rows.splice(0,f.rows.length,...Array.from({length:7},(_,i)=>({id:i+1,retailer_id:12,status:i===6?'inactive':'active',name:'Same'})),
  {id:8,retailer_id:9,status:'active',name:'Other'},{id:9,retailer_id:12,status:'active',archived_at:'retired',name:'Archived'});
 const first=await f.catalog.searchMerchantProducts({...input,query:{search:'Same',status:'all'}});
 assert.equal(first.total,7);assert.deepEqual(first.products.map(row=>row.id),[1,2,3,4,5]);assert.equal(first.nextProductId,5);
 const next=await f.catalog.searchMerchantProducts({...input,query:{search:'Same',status:'all',afterProductId:5}});
 assert.equal(next.total,7);assert.deepEqual(next.products.map(row=>row.id),[6,7]);assert.equal(next.nextProductId,null);
 const inactive=await f.catalog.searchMerchantProducts({...input,query:{search:'Same',status:'inactive'}});
 assert.deepEqual(inactive.products.map(row=>row.id),[7]);
 assert.equal((await f.catalog.getOwnedMerchantCatalogProduct({...input,productId:7})).product.status,'inactive');
 await assert.rejects(f.catalog.getOwnedMerchantProduct({...input,productId:7}),{code:'OWNER_MISMATCH'});
 await assert.rejects(f.catalog.getOwnedMerchantCatalogProduct({...input,productId:8}),{code:'OWNER_MISMATCH'});
 for(const query of [{search:'Same',status:'archived'},{search:'Same',status:'all',retailerId:9},{search:'Same',status:'all',afterProductId:0}])
  await assert.rejects(f.catalog.searchMerchantProducts({...input,query}),{code:'INVALID_ARGUMENT'});
 await assert.rejects(f.catalog.searchMerchantProducts({...input,persona:{id:12,role:'customer'},query:{search:'Same',status:'all'}}),{code:'INVALID_ARGUMENT'});
 assert.equal(f.calls.list.at(-1).retailerId,12);
});
