'use strict';
// Execute the checked-in tool in memory against synthetic teaching data only.
// The original single-pass sanitizer, file IO and output remain unchanged.
const fs = require('node:fs'), path = require('node:path'), os = require('node:os');
const Module = require('node:module');
const assert = require('node:assert/strict');
module.exports = function syntheticSystemConfig() {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'ss-config-proof-')));
  try {
    const base = path.join(dir, 'server'); fs.mkdirSync(base);
    fs.writeFileSync(path.join(base, 'platform_secrets.json'), JSON.stringify({marker:'DV-AI{admin_secret_M4}',aws:'AKIA_FAKE_XXXXXXXX',bearer:'int_bearer_c0ffee'}));
    fs.writeFileSync(path.join(dir, '.env'), 'SYNTHETIC_TEACHING_VALUE=owned-fixture\n');
    const filename = path.resolve(__dirname, '../../../agent-host/agents/system/tools/index.js');
    const source = fs.readFileSync(filename, 'utf8');
    const needle = "const BASE = path.join(REPO, 'server');";
    assert.equal(source.split(needle).length, 2, 'exact source BASE seam');
    const loaded = new Module(filename, module); loaded.filename=filename; loaded.paths=Module._nodeModulePaths(path.dirname(filename));
    loaded._compile(source.replace(needle, 'const BASE = '+JSON.stringify(base)+';'), filename);
    return {...loaded.exports, close(){ fs.rmSync(dir,{recursive:true,force:true}); }};
  } catch(error) { fs.rmSync(dir,{recursive:true,force:true}); throw error; }
};
