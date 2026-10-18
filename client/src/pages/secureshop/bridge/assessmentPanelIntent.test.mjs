import { ASSESSMENT_PANEL_CHANNEL, isStandaloneShopFrame,
  openStandaloneAssessments } from './assessmentPanelIntent.mjs';

const evaluationId = '7f078c35-0bda-4bb4-9c9f-819807aa2668';
const frame = () => ({
  parent: { postMessage: jest.fn() },
  location: { href: `http://localhost/secureshop-frame.html?standalone=1#${'a'.repeat(64)}`,
    hash: `#${'a'.repeat(64)}` },
  document: { baseURI: 'http://localhost/secureshop-frame.html' },
});

test('standalone frame sends a narrow panel-open intent without an assessment retry', () => {
  const value = frame();
  expect(isStandaloneShopFrame(value)).toBe(true);
  expect(openStandaloneAssessments(evaluationId, value)).toBe(true);
  expect(value.parent.postMessage).toHaveBeenCalledWith({ channel: ASSESSMENT_PANEL_CHANNEL,
    type: 'open', nonce: 'a'.repeat(64), evaluationId }, 'http://localhost');
});

test('legacy frame and malformed evaluation identifiers cannot request the parent panel', () => {
  const value = frame();
  value.location.href = value.location.href.replace('standalone=1', 'guest=1');
  expect(openStandaloneAssessments(evaluationId, value)).toBe(false);
  value.location.href = value.location.href.replace('guest=1', 'standalone=1');
  expect(openStandaloneAssessments('not-an-evaluation', value)).toBe(false);
  expect(value.parent.postMessage).not.toHaveBeenCalled();
});
