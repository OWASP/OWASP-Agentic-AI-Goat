'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { admitRendered } = require('./helpers/secureshopAuditSqlRenderedQualification');

test('rendered admission accepts private sibling assets and profile but rejects both nesting directions', () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'audit-admission-')));
  const keys = ['TMPDIR', 'AUDIT_SQL_RENDERED_WORKSPACE', 'AUDIT_SQL_BUILD_ROOT',
    'AUDIT_SQL_BROWSER_PROFILE', 'AUDIT_SQL_BUILD_SHA256', 'PUPPETEER_EXECUTABLE_PATH', 'AUDIT_SQL_ACTUAL_MODEL','AUDIT_SQL_ACTUAL_INTENT','AUDIT_SQL_PARITY','OLLAMA_BASE_URL'];
  const before = Object.fromEntries(keys.map(key => [key, process.env[key]]));
  try {
    delete process.env.AUDIT_SQL_ACTUAL_INTENT;delete process.env.AUDIT_SQL_PARITY;
    const workspace = path.join(root, 'workspace');
    const build = path.join(workspace, 'build'), profile = path.join(workspace, 'profile');
    for (const directory of [workspace, build, profile]) fs.mkdirSync(directory, { mode: 0o700 });
    const rows = ['index.html', 'secureshop-frame.html'].map(name => {
      const body = '<!doctype html><title>Owned admission fixture</title>';
      fs.writeFileSync(path.join(build, name), body);
      return [name, crypto.createHash('sha256').update(body).digest('hex')];
    });
    Object.assign(process.env, { TMPDIR: root, AUDIT_SQL_RENDERED_WORKSPACE: workspace,
      AUDIT_SQL_BUILD_ROOT: build, AUDIT_SQL_BROWSER_PROFILE: profile,
      AUDIT_SQL_BUILD_SHA256: crypto.createHash('sha256').update(JSON.stringify(rows)).digest('hex'),
      PUPPETEER_EXECUTABLE_PATH: fs.realpathSync(process.execPath), AUDIT_SQL_ACTUAL_MODEL: 'no' });
    assert.deepEqual(admitRendered(), { workspace, build, profile, executablePath: fs.realpathSync(process.execPath) });
    process.env.AUDIT_SQL_ACTUAL_MODEL='yes';process.env.OLLAMA_BASE_URL='http://127.0.0.1:11434';
    assert.throws(()=>admitRendered(),/Parent actual intent required/);
    const intentFile=path.join(root,'actual-intent.json');process.env.AUDIT_SQL_ACTUAL_INTENT=intentFile;
    const intent={version:1,mode:'rendered-actual',actualModel:true,baseUrl:process.env.OLLAMA_BASE_URL,workspace,build,buildSha256:process.env.AUDIT_SQL_BUILD_SHA256,profile,chrome:fs.realpathSync(process.execPath)};
    const write=value=>fs.writeFileSync(intentFile,JSON.stringify(value),{mode:0o600});write(intent);
    assert.equal(admitRendered().build,build);
    for(const changed of [{...intent,mode:'parity'},{...intent,baseUrl:'http://127.0.0.1:1234'},{...intent,buildSha256:'0'.repeat(64)},{...intent,profile:root}]){write(changed);assert.throws(()=>admitRendered());}
    write(intent);process.env.AUDIT_SQL_PARITY='yes';assert.throws(()=>admitRendered(),/Parity cannot run models/);delete process.env.AUDIT_SQL_PARITY;
    process.env.AUDIT_SQL_ACTUAL_MODEL='no';assert.throws(()=>admitRendered(),/Model-free browser cannot carry actual intent/);delete process.env.AUDIT_SQL_ACTUAL_INTENT;
    const nestedProfile = path.join(build, 'browser');
    const nestedBuild = path.join(profile, 'assets');
    fs.mkdirSync(nestedProfile, { mode: 0o700 });
    fs.mkdirSync(nestedBuild, { mode: 0o700 });
    for (const [assets, browser] of [[build, build], [build, nestedProfile], [nestedBuild, profile]]) {
      process.env.AUDIT_SQL_BUILD_ROOT = assets;
      process.env.AUDIT_SQL_BROWSER_PROFILE = browser;
      assert.throws(() => admitRendered(), /Build and browser profile must be disjoint/);
    }
  } finally {
    for (const key of keys) if (before[key] === undefined) delete process.env[key]; else process.env[key] = before[key];
    fs.rmSync(root, { recursive: true, force: true });
  }
});
