'use strict';
const fs = require('node:fs/promises');
const { createHash } = require('node:crypto');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function createOwnedMigrationStaging() {
  const owned = new Map();
  return {
    async assertAbsent(files) {
      for (const file of files) {
        try { await fs.lstat(file); } catch (error) {
          if (error.code === 'ENOENT') continue;
          throw error;
        }
        throw new Error('Migration staging destination already exists: ' + file);
      }
    },
    async write(file, bytes) {
      const handle = await fs.open(file, 'wx', 0o600);
      try {
        const stat = await handle.stat();
        owned.set(file, { dev: stat.dev, ino: stat.ino, hash: hash(bytes) });
        await handle.writeFile(bytes);
      } finally { await handle.close(); }
    },
    async cleanup() {
      const errors = [];
      for (const [file, expected] of owned) {
        try {
          const stat = await fs.lstat(file);
          if (!stat.isFile() || stat.dev !== expected.dev || stat.ino !== expected.ino
              || hash(await fs.readFile(file)) !== expected.hash) {
            throw new Error('Migration staging ownership changed; retained: ' + file);
          }
          await fs.unlink(file);
          owned.delete(file);
        } catch (error) {
          if (error.code === 'ENOENT') owned.delete(file);
          else errors.push(error);
        }
      }
      if (errors.length) throw new AggregateError(errors, 'Migration staging cleanup retained changed files');
    },
  };
}
module.exports = { createOwnedMigrationStaging };
