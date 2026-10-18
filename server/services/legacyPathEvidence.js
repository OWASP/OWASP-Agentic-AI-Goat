'use strict';
const fs = require('node:fs');
const path = require('node:path');

// Evidence classification only: intentionally vulnerable reads remain unchanged.
// Call after a successful read. Names and traversal tokens alone prove no escape.
function didReadOutsideRoot(root, accessedPath) {
  const relative = path.relative(fs.realpathSync(root), fs.realpathSync(accessedPath));
  return relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative);
}
module.exports = { didReadOutsideRoot };
