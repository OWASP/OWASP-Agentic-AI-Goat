import { isStandaloneShopFrame } from './assessmentPanelIntent.mjs';

export const PASSWORD_RESET_PANEL_CHANNEL = 'dvaia-secureshop-password-reset-panel-v1';

export function openStandalonePasswordReset(targetId, frameWindow = globalThis.window) {
  const nonce = frameWindow.location.hash.slice(1);
  if (!isStandaloneShopFrame(frameWindow) || !/^[a-f0-9]{64}$/i.test(nonce)
    || !Number.isSafeInteger(targetId) || targetId < 1 || targetId > 2147483647) return false;
  const origin = new URL(frameWindow.document.baseURI).origin;
  frameWindow.parent.postMessage({ channel: PASSWORD_RESET_PANEL_CHANNEL, type: 'open', nonce,
    targetId }, origin);
  return true;
}

export function openStandaloneTeachingPasswordReset(targetId, frameWindow = globalThis.window) {
  const nonce = frameWindow.location.hash.slice(1);
  if (!isStandaloneShopFrame(frameWindow) || !/^[a-f0-9]{64}$/i.test(nonce)
    || !Number.isSafeInteger(targetId) || targetId < 1 || targetId > 2147483647) return false;
  frameWindow.parent.postMessage({ channel: PASSWORD_RESET_PANEL_CHANNEL, type: 'open-teaching',
    nonce, targetId }, new URL(frameWindow.document.baseURI).origin);
  return true;
}

export function openStandaloneChatPasswordReset({ sessionId, requestId, choiceId },
  frameWindow = globalThis.window) {
  const nonce = frameWindow.location.hash.slice(1);
  const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
  if (!isStandaloneShopFrame(frameWindow) || !/^[a-f0-9]{64}$/i.test(nonce)
    || ![sessionId, requestId, choiceId].every(value => typeof value === 'string' && uuid.test(value))) return false;
  frameWindow.parent.postMessage({ channel: PASSWORD_RESET_PANEL_CHANNEL, type: 'open-chat',
    nonce, sessionId, requestId, choiceId }, new URL(frameWindow.document.baseURI).origin);
  return true;
}
