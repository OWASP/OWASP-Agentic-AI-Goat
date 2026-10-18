'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { GmailEmailAgentService } = require('../server/services/gmailEmailAgentService');

function serviceFor(receipt, capture = () => {}) {
  return new GmailEmailAgentService({
    initialized: true,
    targetEmail: 'sender@fixture.invalid',
    transporter: {
      async sendMail(options) {
        capture(options);
        return receipt;
      },
      close() {},
    },
  });
}

test('success requires and exposes exact SMTP envelope acceptance without claiming delivery', async () => {
  const body = 'Keep learner payload verbatim: <img src=x onerror="fixture()">';
  let options;
  const service = serviceFor({
    messageId: '  <owned-receipt@fixture.invalid>  ',
    accepted: ['VICTIM@SHARKLASERS.COM'],
    rejected: [],
  }, value => { options = value; });

  const result = await service.sendEmail('  Victim@SharkLasers.com ', 'Fixture subject', body,
    'smtp-acceptance-success');

  assert.equal(options.to, 'victim@sharklasers.com');
  assert.equal(options.from, 'sender@fixture.invalid');
  assert.equal(options.text, body);
  assert.match(options.html, /&lt;img src=x onerror="fixture\(\)"&gt;/);
  assert.deepEqual(result, {
    success: true,
    messageId: '<owned-receipt@fixture.invalid>',
    sentTo: 'victim@sharklasers.com',
    sentFrom: 'sender@fixture.invalid',
    subject: 'Fixture subject',
    remainingSends: 49,
    requestedRecipient: 'victim@sharklasers.com',
    accepted: ['victim@sharklasers.com'],
    rejected: [],
    smtpAccepted: true,
    deliveryConfirmed: false,
  });
});

test('an internal prebuilt HTML wrapper is transmitted exactly while the logical text body stays intact', async () => {
  const body = 'entity teaching payload &lt;script&gt; plus <b>literal</b>';
  const html = '<html><body><pre>entity teaching payload &amp;lt;script&amp;gt; plus &lt;b&gt;literal&lt;/b&gt;</pre></body></html>';
  let options;
  const service = serviceFor({
    messageId: '<exact-html@fixture.invalid>', accepted: ['victim@sharklasers.com'], rejected: [],
  }, value => { options = value; });

  await service.sendEmail('victim@sharklasers.com', 'subject', body, 'smtp-exact-html', { html });
  assert.equal(options.text, body);
  assert.equal(options.html, html);
  assert.throws(() => service.buildMailOptions('victim@sharklasers.com', 'subject', body, { html, headers: {} }),
    /Invalid mail rendering options/);
  assert.throws(() => service.buildMailOptions('victim@sharklasers.com', 'subject', body, { html: null }),
    /Invalid prebuilt HTML body/);
});

test('recipient admission rejects address syntax before SMTP initialization or transport dispatch', async () => {
  let initializeCalls = 0;
  let sendCalls = 0;
  const service = serviceFor({ messageId: '<must-not-send>', accepted: [], rejected: [] }, () => {
    sendCalls += 1;
  });
  service.initialize = async () => { initializeCalls += 1; return true; };
  for (const address of [
    'one@sharklasers.com, two@sharklasers.com',
    'one@sharklasers.com;two@sharklasers.com',
    'Learner <one@sharklasers.com>',
    'one@sharklasers.com\r\nBcc: two@sharklasers.com',
    'one@@sharklasers.com',
  ]) {
    await assert.rejects(service.sendEmail(address, 'subject', 'body', `invalid-${address}`),
      error => error.statusCode === 400 && /Invalid email/.test(error.message));
  }
  assert.equal(initializeCalls, 0);
  assert.equal(sendCalls, 0);

  const plus = serviceFor({ messageId: '<plus>', accepted: ['learner+lab@sharklasers.com'], rejected: [] });
  const result = await plus.sendEmail(' Learner+Lab@SharkLasers.com ', 'subject', 'body', 'valid-plus');
  assert.equal(result.sentTo, 'learner+lab@sharklasers.com');
});

for (const [label, receipt] of [
  ['missing Message-ID', { accepted: ['victim@sharklasers.com'], rejected: [] }],
  ['missing accepted envelope', { messageId: '<id>', accepted: [], rejected: [] }],
  ['different accepted recipient', { messageId: '<id>', accepted: ['other@sharklasers.com'], rejected: [] }],
  ['requested recipient rejected', { messageId: '<id>', accepted: ['victim@sharklasers.com'], rejected: ['victim@sharklasers.com'] }],
  ['partial envelope', { messageId: '<id>', accepted: ['victim@sharklasers.com'], rejected: ['other@sharklasers.com'] }],
  ['unexpected additional acceptance', { messageId: '<id>', accepted: ['victim@sharklasers.com', 'other@sharklasers.com'], rejected: [] }],
]) {
  test(`${label} cannot be reported as successful SMTP acceptance`, async () => {
    const service = serviceFor(receipt);
    await assert.rejects(
      service.sendEmail('victim@sharklasers.com', 'subject', 'body', `smtp-${label}`),
      error => error.code === 'SMTP_ACCEPTANCE_UNVERIFIED' && error.statusCode === 502
        && /exact acceptance receipt/.test(error.message)
    );
  });
}
