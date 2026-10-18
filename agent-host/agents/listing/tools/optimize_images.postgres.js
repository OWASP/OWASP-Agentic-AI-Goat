const commerce=require('../../../../server/database/postgres/secureshopCommerceDb').getSecureShopCommerceDb();
/**
 * listing.optimize_images — shells to ImageMagick `convert` with an unsanitized
 * filename read from the product row. Command injection sink.
 *
 * @intentional-vulnerability command-injection-image-optimize
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/listing/tools/optimize_images.js
 * intentional — path is concatenated into a shell string then passed to
 * child_process.exec. If the merchant sets image_url to `foo.jpg; rm -rf /tmp/x`
 * the shell dispatches both commands.
 *
 * Safety guard: we honor SS_LISTING_ALLOW_EXEC=false at test time so the shell
 * command is CONSTRUCTED and returned but not actually executed. Real
 * production would remove the guard — the vuln surface is the concatenation.
 */

const { exec } = require('node:child_process');


async function optimize_images({ product_id } = {}) {
  const row = product_id ? await commerce.listing_optimize_images_1(product_id) : null;
  return new Promise((resolve) => {
    if (!product_id) return resolve({ ok: false, error: 'product_id required' });
    const db = null;
    if (!row) return resolve({ ok: false, error: 'unknown product_id' });

    const filename = row.image_url || `product_${product_id}.jpg`;
    // intentional — concatenated into a shell string; no escaping.
    const cmd = `convert ${filename} -strip -quality 82 ${filename}.opt.jpg`;

    if (process.env.SS_LISTING_ALLOW_EXEC !== 'true') {
      // Guarded path — return the constructed command so tests can prove
      // the injection payload survived into the shell without actually running it.
      return resolve({
        ok: true,
        product_id,
        filename,
        cmd,
        executed: false,
        note: 'exec guarded by SS_LISTING_ALLOW_EXEC (test-safe); vuln surface = the constructed cmd string',
      });
    }

    exec(cmd, { timeout: 4000, maxBuffer: 1024 * 200 }, (err, stdout, stderr) => {
      resolve({
        ok: !err,
        product_id,
        filename,
        cmd,
        executed: true,
        stdout: String(stdout || '').slice(0, 2000),
        stderr: String(stderr || '').slice(0, 2000),
        error: err ? err.message : null,
      });
    });
  });
}

module.exports = { optimize_images };
