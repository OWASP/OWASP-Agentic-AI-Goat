'use strict';

const gmailService = require('./gmailEmailAgentService');
const sharkLasersScraper = require('./sharkLasersScraper');
const {createIpiMailpitProvider} = require('./ipiMailpitProvider');

let local;
function isLocal() { return String(process.env.IPI_EMAIL_PROVIDER || 'gmail').toLowerCase() === 'mailpit'; }
function getIpiEmailProvider() {
  if (isLocal()) {
    if (!local) local = createIpiMailpitProvider();
    return {mode:'mailpit', sender:local, inbox:local, addressFor:local.addressFor};
  }
  return {mode:'gmail', sender:gmailService, inbox:sharkLasersScraper, addressFor:null};
}
function resetIpiEmailProviderForTests() { local?.close?.().catch?.(() => {}); local = null; }
function refreshIpiEmailProvider() {
  const retired = local;
  local = null;
  try {
    const closing = retired?.close?.();
    if (closing && typeof closing.catch === 'function') closing.catch(() => {});
  } catch {}
}
module.exports = {getIpiEmailProvider, isLocal, resetIpiEmailProviderForTests, refreshIpiEmailProvider};
