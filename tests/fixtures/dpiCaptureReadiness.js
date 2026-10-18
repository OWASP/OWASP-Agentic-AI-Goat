'use strict';
// Runs unchanged in the browser and in controlled DOM-shape tests.
function captureReady(element, requireHit = false) {
  if (!element || !element.isConnected) return false;
  const state = window.__dpiCaptureReadiness || (window.__dpiCaptureReadiness = new WeakMap());
  const rect = element.getBoundingClientRect();
  let opacity = 1, visible = true;
  for (let node = element; node; node = node.parentElement) {
    const style = getComputedStyle(node);
    opacity *= Number(style.opacity);
    if (style.display === 'none' || style.visibility !== 'visible') visible = false;
  }
  visible = visible && opacity >= 0.98 && rect.width > 0 && rect.height > 0 &&
    rect.top >= 0 && rect.left >= 0 && rect.bottom <= window.innerHeight && rect.right <= window.innerWidth;
  if (requireHit) {
    const hit = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
    visible = visible && !element.disabled && (hit === element || element.contains(hit));
  }
  const current = [rect.x, rect.y, rect.width, rect.height];
  const previous = state.get(element);
  const stable = visible && previous && current.every((value, index) => Math.abs(value - previous.rect[index]) < 0.25);
  const frames = stable ? previous.frames + 1 : 0;
  state.set(element, { rect: current, frames });
  return visible && frames >= 3;
}
function authenticatedRouteReady(expectedPath) {
  if (!['/workshop-dashboard', '/admin/dashboard'].includes(expectedPath)) return false;
  return Boolean(localStorage.getItem('token')) && location.pathname === expectedPath;
}
module.exports = { captureReady, authenticatedRouteReady };
