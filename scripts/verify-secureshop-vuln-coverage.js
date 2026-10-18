#!/usr/bin/env node
/*
 * verify-secureshop-vuln-coverage.js
 *
 * Verify that every strictly annotated SecureShop vulnerability in the same
 * source inventory used by the vulnerability-map generator has a matching
 * strictly annotated behavioral proof under tests/secureshop.
 */

const fs = require('node:fs');

const { SCAN_DIRS, TEST_DIR, walk, extractTags } = require('./generate-vuln-map.js');

function collectTags(files) {
  const tags = new Map(); // id -> Set(file)
  for (const f of files) {
    let content;
    try { content = fs.readFileSync(f, 'utf8'); } catch { continue; }
    for (const tag of extractTags(content)) {
      const id = tag.id;
      if (!tags.has(id)) tags.set(id, new Set());
      tags.get(id).add(f);
    }
  }
  return tags;
}

function main() {
  const codeFiles = SCAN_DIRS.flatMap(dir => walk(dir));
  const testFiles = walk(TEST_DIR);

  const codeTags = collectTags(codeFiles);
  const testTags = collectTags(testFiles);

  let missing = 0;
  const requiredIds = [...new Set([...codeTags.keys(), ...testTags.keys()])].sort();
  for (const id of requiredIds) {
    const inCode = codeTags.has(id);
    const inTest = testTags.has(id);
    const ok = inCode && inTest;
    const badge = ok ? '  OK' : 'MISS';
    if (!ok) missing += 1;
    const codeFiles = inCode ? [...codeTags.get(id)].length : 0;
    const testFilesCount = inTest ? [...testTags.get(id)].length : 0;
    console.log(`${badge}  ${id.padEnd(30)}  code:${codeFiles}  tests:${testFilesCount}`);
    if (!inCode) console.log(`       missing @intentional-vulnerability ${id} in any code file`);
    if (!inTest) console.log(`       missing @intentional-vulnerability ${id} in any tests/secureshop/vuln/ file`);
  }

  if (missing > 0) {
    console.log(`\nFAIL: ${missing} vuln id(s) lack matching code+test annotations`);
    process.exit(1);
  }
  console.log(`\nPASS: ${requiredIds.length} vuln id(s) fully annotated`);
}

if (require.main === module) main();
module.exports = { main, collectTags };
