const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

// Installed target: tests/secureshopListingsArchivePhysical.contract.test.js.
// The normal path reads the actual selected integration fixture. The stdin
// override only lets the unapplied proposal be checked without editing it.
const source = process.env.LISTINGS_ARCHIVE_CONTRACT_SOURCE_STDIN === '1'
  ? fs.readFileSync(0, 'utf8')
  : fs.readFileSync(path.join(__dirname, 'postgres',
    'secureshopStandaloneListingsRendered.integration.test.js'), 'utf8');
const start = source.indexOf('        const archiveDialog=async(label)=>{');
const end = source.indexOf("        page.on('request',observeArchive);", start);

test('archive branch is tied to existing physical merchant Listings cohort', () => {
  assert.ok(start >= 0 && end > start);
  assert.match(source, /const CHAT_LISTINGS_FLAGS = Object\.freeze\([^\n]*'archiveCancelNoEffect','physicalArchiveConfirmed','archivedOwnedReadback'/);
  assert.match(source, /const archivePath=`\/api\/secureshop\/merchant\/products\/\$\{productId\}`/);
  assert.match(source, /assert\.deepEqual\(await archiveRow\(\),beforeArchive\)/);
  assert.match(source, /assert\.deepEqual\(await independentOverlays\(\),siblingOverlaysBefore\)/);
  assert.match(source, /statusFilter\.asElement\(\)\.select\('archived'\)/);
  assert.ok(source.indexOf('const controller=new AbortController();', start)
    < source.indexOf("await archiveDialog('Archive')", start));
  assert.match(source.slice(start), /finally\{controller\.abort\(\);await response;\}/);
});

async function controlled({ title = 'Archive "Supplier lamp"?', buttons = ['Cancel'],
  hidden = false, occluded = false } = {}) {
  let clicks = 0;
  const nodes = buttons.map(label => ({ textContent: label, disabled: false,
    getClientRects: () => [1], scrollIntoView() {},
    getBoundingClientRect: () => ({ left: 0, top: 0, width: 20, height: 20 }),
    contains: () => false, click: async () => { clicks++; } }));
  const dialog = { getClientRects: () => hidden ? [] : [1],
    querySelector: selector => selector === 'h2' ? { textContent: title } : null,
    querySelectorAll: selector => selector === 'button' ? nodes : [] };
  const context = { assert, archiveName: 'Supplier lamp',
    document: { querySelectorAll: selector => selector === '[role="dialog"]' ? [dialog] : [],
      elementFromPoint: () => occluded ? {} : nodes[0] },
    frame: { waitForFunction: async (fn, _opts, ...args) => {
      const value = fn(...args);
      return { asElement: () => value };
    } } };
  const helper = vm.runInNewContext(`${source.slice(start, end)}\narchiveDialog`, context);
  if (title !== 'Archive "Supplier lamp"?' || hidden || occluded || buttons.length !== 1
    || buttons[0] !== 'Cancel') await assert.rejects(helper('Cancel'));
  else await helper('Cancel');
  return clicks;
}

test('exact visible archive dialog clicks one physical Cancel', async () =>
  assert.equal(await controlled(), 1));
test('wrong product title is denied', async () =>
  assert.equal(await controlled({ title: 'Archive "Other"?' }), 0));
test('missing Cancel is denied', async () =>
  assert.equal(await controlled({ buttons: [] }), 0));
test('duplicate Cancel is denied', async () =>
  assert.equal(await controlled({ buttons: ['Cancel', 'Cancel'] }), 0));
test('hidden dialog is denied', async () =>
  assert.equal(await controlled({ hidden: true }), 0));
test('occluded physical control is denied', async () =>
  assert.equal(await controlled({ occluded: true }), 0));
