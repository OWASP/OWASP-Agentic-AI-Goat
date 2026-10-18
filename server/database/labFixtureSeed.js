'use strict';
const fs = require('node:fs');
const path = require('node:path');

// Bootstrap adds missing teaching artifacts. Existing files (including edited
// exercise inputs) belong to the installation and are never truncated here.
function seedMissingLabFiles(root, files) {
  const base = path.resolve(root);
  function directory(location) {
    try { fs.mkdirSync(location); }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
    const stat = fs.lstatSync(location);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Lab fixture directory must be a real directory');
  }
  directory(base);
  for (const [relative, content] of Object.entries(files)) {
    const segments = relative.split('/');
    if (path.isAbsolute(relative) || segments.some(segment => !segment || segment === '.' || segment === '..' || segment.includes('\\'))) {
      throw new TypeError('Invalid lab fixture path');
    }
    let parent = base;
    for (const segment of segments.slice(0, -1)) {
      parent = path.join(parent, segment);
      directory(parent);
    }
    const destination = path.join(parent, segments.at(-1));
    try { fs.writeFileSync(destination, content, { encoding: 'utf8', flag: 'wx' }); }
    catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const stat = fs.lstatSync(destination);
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('Lab fixture must be a regular file');
    }
  }
}
module.exports = { seedMissingLabFiles };
