import { isStandaloneShopFrame } from './assessmentPanelIntent.mjs';

export const EXTERNAL_MAIL_PANEL_CHANNEL = 'owasp-ai-goat-secureshop-external-mail-panel-v1';

export function openStandaloneExternalMail(frameWindow = globalThis.window) {
  const nonce = frameWindow.location.hash.slice(1);
  if (!isStandaloneShopFrame(frameWindow) || !/^[a-f0-9]{64}$/i.test(nonce)) return false;
  frameWindow.parent.postMessage({ channel: EXTERNAL_MAIL_PANEL_CHANNEL, type: 'open', nonce },
    new URL(frameWindow.document.baseURI).origin);
  return true;
}
