'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopBoundProductRepository } = require('../server/database/postgres/secureshopBoundProductRepository');

const binding = Object.freeze({
  targetId: '30000000-0000-4000-8000-000000000081',
  launchId: '10000000-0000-4000-8000-000000000081',
  scenarioId: '20000000-0000-4000-8000-000000000081',
  generation: 3, platformOwnerId: 81, platformSessionId: 801,
});

test('bound category names use only the exact product target in the review store', async () => {
  const queries = [];
  const client = {
    async query(sql, args) {
      queries.push([sql, args]);
      if (sql === 'BEGIN' || sql === 'COMMIT' || sql === 'ROLLBACK') return { rows: [] };
      if (sql.includes('FROM secureshop_review.product_targets')) {
        return { rows: [{ ...binding, lifecycle: 'active' }] };
      }
      assert.doesNotMatch(sql, /secureshop\.categories/);
      if (sql.includes('FROM secureshop_review.product_target_products')) {
        return { rows: [
          { category: 'Home' },
          { category: 'Outdoors' },
        ] };
      }
      throw new Error(`unexpected query: ${sql}`);
    },
    release() {},
  };
  const pool = { async query() { throw new Error('categories must use a transaction'); },
    async connect() { return client; } };
  const repository = createSecureShopBoundProductRepository(pool,
    { checkCurrent: async () => {}, checkCleanup: async () => {} });
  const categories = await repository.categories(binding);
  assert.deepEqual(categories, ['Home', 'Outdoors']);
  const categoryQuery = queries.find(([sql]) => sql.includes('FROM secureshop_review.product_target_products'));
  assert.deepEqual(categoryQuery[1], [binding.targetId]);
  assert.match(categoryQuery[0], /product_target_products[\s\S]*target_id=\$1/);
});

test('bound catalog filters owned approved ratings and price before count and pagination', async () => {
  const queries = [];
  const client = {
    async query(sql, args) {
      queries.push([sql, args]);
      if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql)
          || sql.startsWith('SET TRANSACTION')) return { rows: [] };
      if (sql.includes('FROM secureshop_review.product_targets') && !sql.includes('WITH effective')) {
        return { rows: [{ ...binding, lifecycle: 'active' }] };
      }
      if (sql.includes('SELECT count(*)::integer AS count FROM effective')) return { rows: [{ count: 1 }] };
      if (sql.includes('SELECT * FROM effective')) return { rows: [{ product_id: 7, name: 'Owned',
        price: '1999.99', category: 'Home', status: 'active', images: [], avg_rating: '5.00',
        review_count: '2' }] };
      throw Error(`unexpected query: ${sql}`);
    }, release() {},
  };
  const pool = { async query() { throw Error('catalog must use a transaction'); },
    async connect() { return client; } };
  const repository = createSecureShopBoundProductRepository(pool,
    { checkCurrent: async () => {}, checkCleanup: async () => {} });
  const result = await repository.list(binding, { limit: 12, offset: 12, retailerId: null,
    status: 'active', category: null, search: null, minRating: 5, maxPrice: 2000, sort: '' });
  assert.equal(result.total, 1);
  assert.equal(result.rows[0].avg_rating, 5);
  assert.equal(result.rows[0].review_count, 2);
  assert(queries.some(([sql]) => sql === 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ'));
  const listed = queries.find(([sql]) => sql.includes('SELECT * FROM effective'));
  const counted = queries.find(([sql]) => sql.includes('SELECT count(*)::integer AS count FROM effective'));
  assert.deepEqual(listed[1], [binding.targetId, null, 'active', null, null, 5, 2000, 12, 12]);
  assert.deepEqual(counted[1], listed[1].slice(0, 7));
  for (const [sql] of [listed, counted]) {
    assert.match(sql, /scene_review_targets srt[\s\S]*srt\.product_target_id=t\.target_id/);
    assert.match(sql, /rt\.target_id=COALESCE\(srt\.review_target_id/);
    assert.match(sql, /WHERE srt\.scene_id IS NULL AND legacy\.launch_id=t\.launch_id/);
    assert.match(sql, /legacy\.scenario_id=t\.scenario_id AND legacy\.generation=t\.generation/);
    assert.match(sql, /legacy\.original_platform_owner_id=t\.original_platform_owner_id/);
    assert.match(sql, /legacy\.original_platform_session_id=t\.original_platform_session_id/);
    assert.match(sql, /legacy\.lifecycle='active'\)\) AND rt\.lifecycle='active'/);
    assert.match(sql, /r\.target_id=rt\.target_id[\s\S]*r\.product_id=p\.product_id AND r\.status='approved'/);
    assert.match(sql, /COALESCE\(ratings\.avg_rating,0\) AS avg_rating_raw/);
    assert.match(sql, /COALESCE\(round\(ratings\.avg_rating,2\),0\) AS avg_rating/);
    assert.match(sql, /\(\$6::integer IS NULL OR avg_rating_raw >= \$6\)/);
    assert.match(sql, /\(\$7::numeric IS NULL OR price <= \$7\)/);
  }
  assert.match(listed[0], /LIMIT \$8 OFFSET \$9/);
  assert.doesNotMatch(counted[0], /LIMIT \$8 OFFSET \$9/);
});

test('merchant choice pages use one exact owned count and stable IDs without changing list ordering',async()=>{
 let catalogTotal;
 const queries=[],products=Array.from({length:7},(_,i)=>({product_id:i+1,retailer_id:12,name:'Same name',
  description:'literal query',price:'12.34',status:i===6?'inactive':'active',stock_quantity:5}));
 products.push({product_id:8,retailer_id:9,name:'Same name',status:'active'},
  {product_id:9,retailer_id:12,name:'Same name',status:'active',archived_at:'retired'});
 const client={async query(sql,args=[]){
  queries.push([sql,args]);
  if(['BEGIN','COMMIT','ROLLBACK'].includes(sql)||sql.startsWith('SET TRANSACTION'))return{rows:[]};
  if(sql.includes('FROM secureshop_review.product_targets')&&!sql.includes('WITH effective'))return{rows:[{...binding,lifecycle:'active'}]};
  assert.match(sql,/catalog_matches AS/);
  assert.match(sql,/target_id=\$1 AND retailer_id=\$2[\s\S]*archived_at IS NULL/);
  assert.match(sql,/\(\$3::text='all' OR status=\$3\)/);
  assert.match(sql,/name ILIKE \$4 OR description ILIKE \$4/);
  assert.match(sql,/SELECT count\(\*\)::integer FROM catalog_matches/);
  assert.match(sql,/product_id>\$5[\s\S]*ORDER BY product_id LIMIT 6/);
  assert.doesNotMatch(sql,/OFFSET/);
  assert.equal(args[0],binding.targetId);assert.equal(args[1],12);
  const matches=products.filter(row=>row.retailer_id===args[1]&&!row.archived_at&&(args[2]==='all'||row.status===args[2]));
  const page=matches.filter(row=>args[4]===null||row.product_id>args[4]).sort((a,b)=>a.product_id-b.product_id).slice(0,6);
  return{rows:page.length?page.map(row=>({...row,matched_total:catalogTotal??matches.length})):[{product_id:null,matched_total:catalogTotal??matches.length}]};
 },release(){}};
 const repository=createSecureShopBoundProductRepository({async query(){throw Error("must transact");},async connect(){return client;}},
  {checkCurrent:async()=>{},checkCleanup:async()=>{}});
 const first=await repository.listMerchantChoices(binding,{retailerId:12,search:'Same name',status:'all'});
 assert.equal(first.total,7);assert.deepEqual(first.rows.map(row=>row.id),[1,2,3,4,5]);assert.equal(first.nextProductId,5);
 assert.equal(first.rows[0].price,12.34);assert.equal(Object.hasOwn(first.rows[0],'matched_total'),false);
 const last=await repository.listMerchantChoices(binding,{retailerId:12,search:'Same name',status:'all',afterProductId:5});
 assert.equal(last.total,7);assert.deepEqual(last.rows.map(row=>row.id),[6,7]);assert.equal(last.nextProductId,null);
 const empty=await repository.listMerchantChoices(binding,{retailerId:12,search:'Same name',status:'all',afterProductId:7});
 assert.equal(empty.total,7);assert.deepEqual(empty.rows,[]);assert.equal(empty.nextProductId,null);
 const inactive=await repository.listMerchantChoices(binding,{retailerId:12,search:'Same name',status:'inactive'});
 assert.equal(inactive.total,1);assert.deepEqual(inactive.rows.map(row=>row.id),[7]);
 const before=queries.length;
 for(const options of [{retailerId:0,status:'active'},{retailerId:12,status:'archived'},{retailerId:12,status:'all',afterProductId:'5'}])
  await assert.rejects(repository.listMerchantChoices(binding,options),{code:'INVALID_ARGUMENT'});
 assert.equal(queries.length,before);
 assert.ok(queries.some(([sql])=>sql==='SET TRANSACTION ISOLATION LEVEL REPEATABLE READ'));
 for(const invalidTotal of ['9007199254740992','invalid',-1]){
  catalogTotal=invalidTotal;
  await assert.rejects(repository.listMerchantChoices(binding,{retailerId:12,status:'all'}),{code:'PRODUCT_DATA_INVALID'});
 }
});
