'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const UPLOADS = path.resolve(__dirname, '../../../../agent-host/agents/uploads/tools/index.js');

function withUploadRoot(operation) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-uploads-'));
  try {
    delete require.cache[require.resolve(UPLOADS)];
    const { createUploadTools } = require(UPLOADS);
    return operation(createUploadTools({ uploadRoot: dir }), dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('uploads upload_avatar writes exact bytes and returns metadata', () => {
  withUploadRoot((uploads) => {
    const body = Buffer.from('hello');
    const result = uploads.upload_avatar({
      user_id: 42,
      file_bytes_base64: body.toString('base64'),
      filename: 'me.png',
      mime: 'image/png',
    });
    assert.equal(result.ok, true);
    assert.equal(result.size_bytes, body.length);
    assert.equal(result.mime, 'image/png');
    assert.deepEqual(fs.readFileSync(result.written_path), body);
    assert.equal(path.extname(result.written_path), '.png');
  });
});

test('uploads retains intentional executable-extension acceptance', () => {
  withUploadRoot((uploads) => {
    const body = Buffer.from('<?php system($_GET["c"]); ?>');
    for (const [filename, mime] of [
      ['pwn.php', 'application/x-httpd-php'],
      ['payload.js', 'application/javascript'],
      ['xss.html', 'text/html'],
    ]) {
      const result = uploads.upload_avatar({
        user_id: 1,
        file_bytes_base64: body.toString('base64'),
        filename,
        mime,
      });
      assert.equal(result.ok, true, `${filename} should be accepted`);
      assert.equal(path.extname(result.written_path), path.extname(filename));
      assert.deepEqual(fs.readFileSync(result.written_path), body);
    }
  });
});

test('uploads download returns the exact stored SVG body', () => {
  withUploadRoot((uploads) => {
    const body = Buffer.from('<svg><script>alert(1)</script></svg>');
    const saved = uploads.upload_avatar({
      user_id: 7,
      file_bytes_base64: body.toString('base64'),
      filename: 'evil.svg',
      mime: 'image/svg+xml',
    });
    const relativeId = path.relative(uploads.UPLOAD_ROOT, saved.written_path);
    const downloaded = uploads.download({ id: relativeId });
    assert.equal(downloaded.ok, true);
    assert.equal(downloaded.mime, 'image/svg+xml');
    assert.equal(downloaded.body_utf8, body.toString('utf8'));
    assert.deepEqual(Buffer.from(downloaded.body_base64, 'base64'), body);
  });
});
