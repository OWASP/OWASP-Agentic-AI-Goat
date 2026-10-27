import { EXTERNAL_MAIL_PANEL_CHANNEL, openStandaloneExternalMail } from './externalMailIntent.mjs';

test('merchant iframe can request only an empty parent panel, never a send payload', () => {
  const postMessage = jest.fn();
  const frameWindow = { parent: { postMessage }, location: {
    href: `http://localhost/secureshop-frame.html?standalone=1#${'a'.repeat(64)}`,
    hash: `#${'a'.repeat(64)}` }, document: { baseURI: 'http://localhost/secureshop/' } };
  expect(openStandaloneExternalMail(frameWindow)).toBe(true);
  expect(postMessage).toHaveBeenCalledWith({ channel: EXTERNAL_MAIL_PANEL_CHANNEL,
    type: 'open', nonce: 'a'.repeat(64) }, 'http://localhost');
  expect(Object.keys(postMessage.mock.calls[0][0]).sort()).toEqual(['channel', 'nonce', 'type']);
  expect(openStandaloneExternalMail({ ...frameWindow, location: { ...frameWindow.location,
    href: `http://localhost/secureshop-frame.html#${'a'.repeat(64)}` } })).toBe(false);
  expect(openStandaloneExternalMail({ ...frameWindow, location: { ...frameWindow.location, hash: '#bad' } })).toBe(false);
  expect(postMessage).toHaveBeenCalledTimes(1);
});
