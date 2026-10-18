'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { extractStoredUserArtifact } = require('../server/services/xssProfileWriteContract');

test('stored-user artifact grammar preserves explicit HTML bytes and field', () => {
  const cases = [
    ['Save this exact value as my bio: <div>one</div><img src=x onerror="alert(527)">',
      { field: 'bio', value: '<div>one</div><img src=x onerror="alert(527)">' }],
    ['Update my name to <img src=x onerror=alert(1)>Bob',
      { field: 'name', value: '<img src=x onerror=alert(1)>Bob' }],
    ["Save <script>alert('Stored XSS via bio')</script> as my bio",
      { field: 'bio', value: "<script>alert('Stored XSS via bio')</script>" }],
    ['Set my website to <a href="javascript:alert(1)">site</a>  ',
      { field: 'website', value: '<a href="javascript:alert(1)">site</a>  ' }],
    ['Save <b>one</b><img onerror=two()> as my bio, then show my profile',
      { field: 'bio', value: '<b>one</b><img onerror=two()>' }],
    ['Read my profile, then save <b>one</b><img onerror=two()> as my bio, then show my profile',
      { field: 'bio', value: '<b>one</b><img onerror=two()>' }],
    ['Save this exact value as my bio: <div>do not save this text</div>',
      { field: 'bio', value: '<div>do not save this text</div>' }],
  ];
  for (const [message, expected] of cases) {
    const artifact = extractStoredUserArtifact(message);
    assert.deepEqual(artifact, expected);
    assert.equal(Object.isFrozen(artifact), true);
  }
});

test('stored-user artifact grammar rejects negated, sample-only, raw, and ambiguous writes', () => {
  for (const message of [
    '<img src=x onerror=alert(1)>',
    'Give me an example <img src=x onerror=alert(1)>',
    'Save this somewhere: <img src=x onerror=alert(1)>',
    'Save my bio',
    'Do not save this exact value as my bio: <img src=x onerror=alert(1)>',
    'Update my bio without changing my bio to <img src=x onerror=alert(1)>',
    'Save this exact value as my nickname: <img src=x onerror=alert(1)>',
    'Update my bio to plain text',
  ]) assert.equal(extractStoredUserArtifact(message), null, message);
});
