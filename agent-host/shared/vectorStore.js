/**
 * Thin re-export of the server-side vector store so agent-host tools
 * (uploads.upload_product_manual, product-search.similar) can share the
 * exact same implementation without maintaining two copies.
 *
 * Path is server/services/secureshop/vectorStore.js from repo root.
 */

const path = require('node:path');

const REPO = path.resolve(__dirname, '../..');
module.exports = require(path.join(REPO, 'server/services/secureshop/vectorStore.js'));
