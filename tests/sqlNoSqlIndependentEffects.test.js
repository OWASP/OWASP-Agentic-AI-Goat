'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { OBJECTIVE_IDS, verifySqlNoSqlIndependentEffect: verify } = require('./fixtures/sqlNoSqlIndependentEffects');
const sqlRow = name => ({ id: null, product_id: null, name, category: null, price: null, description: null, stock: null, available: null });
const product = { id: 1, product_id: 'P1', name: 'Laptop', category: 'computers', price: '9', description: 'test', stock: 1, available: 1 };
const papers = [{ paper_id: 'PAPER-1', title: 'First', year: 2020, access_level: 'public' }, { paper_id: 'PAPER-2', title: 'Second', year: 2021, access_level: 'restricted' }];
const authors = [{ author_id: 'AUTHOR-1', name: 'Fixture', email: 'fixture@example.invalid' }];
const reference = { products: [product], orders: [{ order_number: 'ORD-1', user_id: 2, total_amount: '9' }],
  ariaVersion: 'PostgreSQL 18.0 test', ariaTables: ['products', 'orders'], orderColumns: ['order_number', 'user_id'],
  papers, authors, literalBaseline: [], novaVersion: '18.0',
  novaCollections: [{ name: 'papers', documents: 2, indexes: 1 }],
  novaSchema: ['papers', 'authors'].map(collection => ({ type: 'schema_info', collection, fields: [{ name: 'id', type: 'Integer', indexed: true, unique: true }] })),
};
const cases = [
 ['sqli_1', "'", { error: 'syntax error at or near test', code: '42601' }],
 ['sqli_2', "%' OR '1'='1'--", [product]],
 ['sqli_3', "%' ORDER BY 9--", { error: 'ORDER BY position 9 is not in select list' }, [{ query: "%' ORDER BY 8--", output: [product] }]],
 ['sqli_4', "%' UNION SELECT NULL--", { error: 'each UNION query must have the same number of columns', code: '42601' }],
 ['sqli_5', "%' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--", [sqlRow(null)]],
 ['sqli_6', "%' UNION SELECT NULL,NULL,'SQLI_TEST',NULL,NULL,NULL,NULL,NULL--", [sqlRow('SQLI_TEST')]],
 ['sqli_7', "%' UNION SELECT NULL,NULL,version(),NULL,NULL,NULL,NULL,NULL--", [sqlRow(reference.ariaVersion)]],
 ['sqli_8', "%' UNION SELECT NULL,NULL,tablename,NULL,NULL,NULL,NULL,NULL FROM pg_catalog.pg_tables WHERE schemaname='aria'--", [sqlRow('orders')]],
 ['sqli_9', "%' UNION SELECT NULL,NULL,column_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.columns WHERE table_schema='aria' AND table_name='orders'--", [sqlRow('order_number')]],
 ['sqli_10', "%' UNION SELECT NULL,NULL,order_number,user_id,total_amount,NULL,NULL,NULL FROM aria.orders--", [{ ...sqlRow('ORD-1'), category: 2, price: '9' }]],
 ['nosqli_1', '{"$":"test"}', { error: 'MongoServerError: unknown operator: $' }],
 ['nosqli_2', '{"title":{"$gt":""}}', papers],
 ['nosqli_3', '{"title":{"$regex":".*"}}', papers],
 ['nosqli_4', '{"$where":"db.version()"}', [{ type: 'db_metadata', db_version: reference.novaVersion, storage_engine: 'PostgreSQL', simulation: 'MongoDB-style operator injection on PostgreSQL', collections: reference.novaCollections }]],
 ['nosqli_5', '{"$where":"Object.keys(this)"}', reference.novaSchema],
 ['nosqli_6', '{"title":{"$ne":"Missing"}}', papers],
 ['nosqli_7', '{"$where":"this.year > 2020"}', papers],
 ['nosqli_8', '{"year":{"$in":[2020,2021]}}', papers],
 ['nosqli_9', '{"email":{"$regex":".*@.*"}}', authors],
 ['nosqli_10', '{"access_level":{"$ne":"public"}}', papers],
];
const input = ([objectiveId, query, output, history = []]) => ({ objectiveId, query, output, history, ownerId: 1, reference });

test('independent snapshot oracle recognizes all twenty exact native teaching effects', () => {
  assert.deepEqual(cases.map(row => row[0]), OBJECTIVE_IDS);
  for (const fixture of cases) assert.equal(verify(input(fixture)), true, fixture[0]);
});

test('all twenty require observed output, not the requested payload', () => {
  for (const fixture of cases) assert.equal(verify({ ...input(fixture), output: [], history: [] }), false, fixture[0]);
});

test('metadata disclosure rejects fabricated extra rows and fields', () => {
  const fixture = input(cases.find(row => row[0] === 'nosqli_4'));
  assert.equal(verify({ ...fixture, output: [...fixture.output, { invented: 'metadata' }] }), false);
  assert.equal(verify({ ...fixture, output: [{ ...fixture.output[0], invented: 'metadata' }] }), false);
  assert.equal(verify({ ...fixture, output: [null, ...fixture.output] }), false);
});

test('fabricated versions/catalog/schema and unrecognized rows fail independent binding', () => {
  for (const id of ['sqli_7', 'sqli_8', 'sqli_9']) {
    const fixture = cases.find(row => row[0] === id);
    assert.equal(verify({ ...input(fixture), output: [sqlRow('invented')] }), false, id);
  }
  const meta = input(cases.find(row => row[0] === 'nosqli_4'));
  for (const patch of [{ db_version: '99.0' }, { collections: [{ name: 'papers', documents: 999, indexes: 1 }] }, { storage_engine: 'MongoDB' }]) {
    assert.equal(verify({ ...meta, output: [{ ...meta.output[0], ...patch }] }), false);
  }
  const schema = input(cases.find(row => row[0] === 'nosqli_5'));
  assert.equal(verify({ ...schema, output: [{ ...schema.output[0], fields: [{ name: 'invented' }] }, schema.output[1]] }), false);
  for (const id of ['nosqli_2', 'nosqli_3', 'nosqli_6', 'nosqli_7', 'nosqli_8', 'nosqli_9', 'nosqli_10']) {
    const fixture = input(cases.find(row => row[0] === id));
    assert.equal(verify({ ...fixture, output: fixture.output.map(row => ({ ...row, title: 'fabricated' })) }), false, id);
  }
});

test('distinct membership, valid boundary pair, literal broadening and cross-owner order are required', () => {
  const membership = input(cases.find(row => row[0] === 'nosqli_8'));
  for (const requested of [[2020,2020],[2020,'2020'],[2020,2099]]) {
    assert.equal(verify({ ...membership, query: JSON.stringify({ year: { $in: requested } }) }), false);
  }
  const boundary = input(cases.find(row => row[0] === 'sqli_3'));
  assert.equal(verify({ ...boundary, history: [] }), false);
  assert.equal(verify({ ...boundary, history: [{ query: "%' ORDER BY 7--", output: [product] }] }), false);
  for (const id of ['sqli_2','nosqli_2','nosqli_3','nosqli_6']) {
    const fixture = input(cases.find(row => row[0] === id));
    assert.equal(verify({ ...fixture, reference: { ...reference, literalBaseline: fixture.output } }), false);
  }
  const order = input(cases.find(row => row[0] === 'sqli_10'));
  assert.equal(verify({ ...order, ownerId: 2 }), false);
  assert.equal(verify({ ...order, output: [{ ...order.output[0], price: '999' }] }), false);
});

test('simulator error names must match an actually malformed or unsupported request', () => {
  const fixture = input(cases.find(row => row[0] === 'nosqli_1'));
  assert.equal(verify({ ...fixture, query: '{"title":{"$gt":""}}' }), false);
  assert.equal(verify({ ...fixture, output: { error: 'MongoServerError: unknown operator: $invented' } }), false);
  assert.equal(verify({ ...fixture, query: '{bad}', output: { error: 'MongoServerError: Failed to parse query: expected property' } }), true);
});

test('order disclosure binds every returned row and every projected null field', () => {
  const fixture = input(cases.find(row => row[0] === 'sqli_10'));
  const valid = fixture.output[0];
  assert.equal(verify({ ...fixture, output: [product, valid] }), true);
  const ownOrder = { order_number: 'ORD-OWN', user_id: 1, total_amount: '5' };
  const ownRow = { ...sqlRow('ORD-OWN'), category: 1, price: '5' };
  const refs = { ...reference, orders: [...reference.orders, ownOrder] };
  assert.equal(verify({ ...fixture, reference: refs, output: [ownRow, valid] }), true);
  assert.equal(verify({ ...fixture, reference: refs, output: [ownRow] }), false);
  for (const fabricated of [
    { ...valid, name: 'ORD-INVENTED' }, { ...valid, category: 999 }, { ...valid, price: '999' },
    { ...product, description: 'invented' }, { unexpected: 'row' },
    ...['id', 'product_id', 'description', 'stock', 'available'].map(key => ({ ...valid, [key]: 'invented' })),
  ]) {
    assert.equal(verify({ ...fixture, output: [valid, fabricated] }), false, JSON.stringify(fabricated));
  }
});
