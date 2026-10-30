export const ASSESSMENT_PANEL_CHANNEL = 'owasp-ai-goat-secureshop-assessment-panel-v1';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isStandaloneShopFrame(frameWindow = globalThis.window) {
  return frameWindow.parent !== frameWindow
    && new URL(frameWindow.location.href).searchParams.get('standalone') === '1';
}

export function openStandaloneAssessments(evaluationId = null, frameWindow = globalThis.window) {
  const nonce = frameWindow.location.hash.slice(1);
  if (!isStandaloneShopFrame(frameWindow) || !/^[a-f0-9]{64}$/i.test(nonce)
    || !(evaluationId === null || UUID.test(evaluationId))) return false;
  const origin = new URL(frameWindow.document.baseURI).origin;
  frameWindow.parent.postMessage({ channel: ASSESSMENT_PANEL_CHANNEL, type: 'open', nonce,
    evaluationId }, origin);
  return true;
}
