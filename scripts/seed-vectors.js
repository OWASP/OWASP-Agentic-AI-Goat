#!/usr/bin/env node
/**
 * scripts/seed-vectors.js
 *
 * Post-DB-init step. Reads seeded manuals from server/uploads/secureshop/seed_manuals,
 * copies them under product_manuals/<product_id>/, and indexes them into the
 * `manuals` corpus of the vector store. Also embeds seeded reviews and
 * policies into their corpora.
 *
 * Run manually via `npm run seed:vectors` after `npm run db:initialize-all`.
 */

const fs = require('node:fs');
const path = require('node:path');

const REPO = path.resolve(__dirname, '..');
const SEED_MANUAL_DIR = path.join(REPO, 'server/uploads/secureshop/seed_manuals');
const PRODUCT_MANUAL_DIR = path.join(REPO, 'server/uploads/secureshop/product_manuals');

async function main() {
  const { VectorStore, chunkText } = require(path.join(REPO, 'server/services/secureshop/vectorStore.js'));

  // ---- manuals ----
  const manualsStore = new VectorStore({ corpus: 'manuals' });
  await manualsStore.rebuild();

  const seedFiles = fs.existsSync(SEED_MANUAL_DIR)
    ? fs.readdirSync(SEED_MANUAL_DIR).filter(f => f.endsWith('.txt'))
    : [];

  // File name convention: NN_<slug>_<productid?>.txt — we look for a product_id
  // hint in the mapping table below. Fallback: product_id = 1.
  const PRODUCT_ID_MAP = {
    '01_clearsound_headphones.txt': 1,
    '02_coffee_mug.txt': 2,
    '03_yoga_mat.txt': 3,
    '04_poisoned_reference_guide.txt': 1,
    '05_competitor_recommendation.txt': 2,
  };

  let manualChunks = 0;
  for (const f of seedFiles) {
    const abs = path.join(SEED_MANUAL_DIR, f);
    const productId = PRODUCT_ID_MAP[f] || 1;
    const productDir = path.join(PRODUCT_MANUAL_DIR, String(productId));
    if (!fs.existsSync(productDir)) fs.mkdirSync(productDir, { recursive: true });
    const dest = path.join(productDir, f);
    try { fs.copyFileSync(abs, dest); } catch {}
    const text = fs.readFileSync(abs, 'utf8');
    const chunks = chunkText(text, 500);
    for (let i = 0; i < chunks.length; i++) {
      // eslint-disable-next-line no-await-in-loop
      await manualsStore.add({ sourceKind: 'manual', sourceId: productId, chunkIndex: i, text: chunks[i] });
      manualChunks += 1;
    }
  }
  console.log(`[seed-vectors] manuals: indexed ${seedFiles.length} files, ${manualChunks} chunks`);

  // ---- reviews ----
  const reviewsStore = new VectorStore({ corpus: 'reviews' });
  const r = await reviewsStore.rebuild();
  console.log(`[seed-vectors] reviews: rebuilt ${r.count} rows`);

  // ---- policies ----
  const policiesStore = new VectorStore({ corpus: 'policies' });
  const p = await policiesStore.rebuild();
  console.log(`[seed-vectors] policies: rebuilt ${p.count} rows`);

  // ---- products ----
  const productsStore = new VectorStore({ corpus: 'products' });
  const pr = await productsStore.rebuild();
  console.log(`[seed-vectors] products: rebuilt ${pr.count} rows`);

  console.log('[seed-vectors] done');
}

if (require.main === module) {
  main().catch((e) => {
    console.error('[seed-vectors] failed:', e);
    process.exit(1);
  });
}

module.exports = { main };
