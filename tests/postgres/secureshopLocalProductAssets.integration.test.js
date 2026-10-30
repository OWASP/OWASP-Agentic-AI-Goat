'use strict';

// DRAFT-ONLY native qualification. The test applies the adjacent unregistered
// candidate to an owned disposable SecureShop database. It does not register a
// canonical migration or touch an application database.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { createHash } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');

const root = path.resolve(__dirname, '../..');
const connectionString = process.env.PG_SECURESHOP_LOCAL_ASSETS_MIGRATION_URL;
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && !!connectionString;
const localAsset = '/secureshop/product-placeholder.svg';

function candidateDefaults(sql) {
  const productSection = /WITH product_defaults\(id,prior_url\) AS \(VALUES\n([\s\S]*?)\n\),\nchanged_products/.exec(sql);
  const imageSection = /image_defaults\(id,product_id,prior_path,prior_mime\) AS \(VALUES\n([\s\S]*?)\n\)\nUPDATE/.exec(sql);
  assert(productSection && imageSection, 'candidate default tables required');
  return {
    products: [...productSection[1].matchAll(/\((\d+),'([^']+)'\)/g)]
      .map(match => ({ id: Number(match[1]), url: match[2] })),
    images: [...imageSection[1].matchAll(/\((\d+),(\d+),'([^']+)','([^']+)'\)/g)]
      .map(match => ({ id: Number(match[1]), productId: Number(match[2]), path: match[3], mime: match[4] })),
  };
}

async function rows(pool) {
  return {
    products: (await pool.query(`SELECT id,image_url,updated_at FROM secureshop.products
      ORDER BY id`)).rows,
    images: (await pool.query(`SELECT id,product_id,path,mime,uploaded_by,uploaded_at
      FROM secureshop.product_images ORDER BY id`)).rows,
  };
}

test('local product asset candidate uses the real loader, rolls back, preserves custom/imported rows, and replays', {
  skip: !enabled,
  timeout: 60_000,
}, async () => {
  const url = new URL(connectionString);
  const database = decodeURIComponent(url.pathname.slice(1));
  assert.match(database, /^owasp_ai_goat_secureshop_assets_[a-f0-9]{12}$/,
    'owned disposable database required');
  assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname), 'loopback PostgreSQL required');
  assert.equal(url.search, '');
  assert.equal(url.hash, '');
  const pool = new Pool({ connectionString, max: 1 });
  const stagedRoot = await fs.mkdtemp(path.join(
    process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE || os.tmpdir(), 'secureshop-assets-loader-'));
  const baselineDir = path.join(stagedRoot, 'baseline');
  const fullDir = path.join(stagedRoot, 'full');
  const failingDir = path.join(stagedRoot, 'failing');
  await Promise.all([baselineDir, fullDir, failingDir].map(directory => fs.mkdir(directory)));
  try {
    assert.equal((await pool.query('SELECT current_database() AS name')).rows[0].name, database);
    const baseNames = ['0001_schema.sql', '0002_import_history.sql'];
    for (const name of baseNames) {
      const sql = await fs.readFile(path.join(root,
        'db/postgres/workshop-migrations/secureshop', name), 'utf8');
      for (const directory of [baselineDir, fullDir, failingDir]) {
        await fs.writeFile(path.join(directory, name), sql);
      }
    }
    const candidateName = '0003_local_product_assets.sql';
    const candidate = await fs.readFile(path.join(root,
      'db/postgres/workshop-migrations/secureshop/0003_local_product_assets.sql'), 'utf8');
    assert.doesNotMatch(candidate, /(^|\n)\s*(?:BEGIN|COMMIT)\s*;/i,
      'migrate() owns the transaction boundary');
    await fs.writeFile(path.join(fullDir, candidateName), candidate);
    await fs.writeFile(path.join(failingDir, candidateName),
      `${candidate}\nDO $rollback$ BEGIN RAISE EXCEPTION 'loader rollback sentinel'; END $rollback$;\n`);
    assert.deepEqual(await migrate(pool, baselineDir), baseNames);
    assert.deepEqual(await migrate(pool, baselineDir), []);
    const defaults = candidateDefaults(candidate);
    assert.equal(defaults.products.length, 125);
    assert.equal(defaults.images.length, 375);

    for (const row of defaults.products) {
      await pool.query(`INSERT INTO secureshop.products
        (id,name,price,image_url,updated_at) VALUES($1,$2,1,$3,to_timestamp($4))`,
      [row.id, `product-${row.id}`, row.url, 1_700_000_000 + row.id]);
    }
    for (const row of defaults.images) {
      await pool.query(`INSERT INTO secureshop.product_images
        (id,product_id,path,mime,uploaded_at) VALUES($1,$2,$3,$4,to_timestamp($5))`,
      [row.id, row.productId, row.path, row.mime, 1_700_001_000 + row.id]);
    }
    await pool.query("UPDATE secureshop.products SET image_url='https://merchant.example/custom.png' WHERE id=6");
    await pool.query("UPDATE secureshop.product_images SET path='https://merchant.example/custom-detail.png' WHERE id=16");
    await pool.query(`INSERT INTO secureshop.products(id,name,price,image_url)
      VALUES(1001,'imported custom',1,'https://picsum.photos/seed/ss_custom_import/600/800')`);
    await pool.query(`INSERT INTO secureshop.product_images(id,product_id,path,mime)
      VALUES(1001,1001,'https://picsum.photos/seed/ss_custom_import/600/800','image/jpeg')`);

    const beforeFailure = await rows(pool);
    await assert.rejects(migrate(pool, failingDir), /loader rollback sentinel/);
    assert.deepEqual(await rows(pool), beforeFailure, 'failed candidate must roll back every row change');
    assert.deepEqual((await pool.query(
      'SELECT name FROM dvaia_migrations.ledger WHERE name=$1', [candidateName])).rows, [],
    'failed candidate must not enter the ledger');

    assert.deepEqual(await migrate(pool, fullDir), [candidateName]);
    assert.deepEqual((await pool.query(
      'SELECT name,checksum FROM dvaia_migrations.ledger WHERE name=$1', [candidateName])).rows,
    [{ name: candidateName, checksum: createHash('sha256').update(candidate).digest('hex') }]);
    const first = await rows(pool);
    for (const row of first.products) {
      if (row.id === 6) assert.equal(row.image_url, 'https://merchant.example/custom.png');
      else if (row.id === 1001) assert.equal(row.image_url, 'https://picsum.photos/seed/ss_custom_import/600/800');
      else assert.equal(row.image_url, localAsset, `product ${row.id}`);
    }
    for (const row of first.images) {
      if (row.id === 16) assert.equal(row.path, 'https://merchant.example/custom-detail.png');
      else if (row.id === 1001) assert.equal(row.path, 'https://picsum.photos/seed/ss_custom_import/600/800');
      else {
        assert.equal(row.path, localAsset, `image ${row.id} path`);
        assert.equal(row.mime, 'image/svg+xml', `image ${row.id} mime`);
      }
    }
    assert.deepEqual(await migrate(pool, fullDir), []);
    assert.deepEqual(await rows(pool), first, 'second run must preserve all values and timestamps');

    // Recreate a populated pre-candidate store and prove reviewed import
    // history suppresses every default rewrite while the loader still records
    // the successfully evaluated no-op candidate.
    await pool.query('DELETE FROM dvaia_migrations.ledger WHERE name=$1', [candidateName]);
    for (const row of defaults.products) {
      await pool.query('UPDATE secureshop.products SET image_url=$2 WHERE id=$1', [row.id, row.url]);
    }
    for (const row of defaults.images) {
      await pool.query('UPDATE secureshop.product_images SET path=$2,mime=$3 WHERE id=$1',
        [row.id, row.path, row.mime]);
    }
    await pool.query(`INSERT INTO secureshop.import_batches
      (archive_sha256,counts,review_metadata) VALUES($1,$2::jsonb,$3::jsonb)`,
    ['a'.repeat(64), '{}', '{"fixture":"owned-disposable"}']);
    const importedBefore = await rows(pool);
    assert.deepEqual(await migrate(pool, fullDir), [candidateName]);
    assert.deepEqual(await rows(pool), importedBefore,
      'presence of a reviewed import batch must suppress all default rewriting');
    assert.deepEqual(await migrate(pool, fullDir), []);
  } finally {
    await pool.end();
    await fs.rm(stagedRoot, { recursive: true, force: true });
  }
});
