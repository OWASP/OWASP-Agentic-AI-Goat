'use strict';
const { createFileSummaryAttachment } = require('./secureshopFileSummaryAttachment');
const { createBoundFileSummaryGraph } = require('./secureshopBoundFileSummaryGraph');
const { createFileSummaryExecutionConfig } = require('./secureshopFileSummaryExecutionConfig');
const { createBoundAclResolver } = require('./secureshopBoundAclRegistry');
const { normalizeConversationPurpose } = require('./secureshopConversationPurpose');
const { POLICIES } = require('./secureshopFeatureModeAuthority');
function createFileSummaryComposition({ launches, files, scenes, personaAuthority, modeAuthority,
  conversationRepository, journal, coordinator, provider, toolPolicyRepository } = {}) {
  // No legacy/general fallback when any registration is missing.
  normalizeConversationPurpose('secureshop_file_summary');
  if (POLICIES.file_summary !== 'owned-attachment-untrusted-summary-data-v1') throw TypeError('File summary feature policy unavailable');
  const declaration = createFileSummaryExecutionConfig({ mode: 'fixed', byteCount: 1 }).manifest.getForRole('customer');
  const resolver = createBoundAclResolver({ workflow: 'file-summary', declaredTools: declaration });
  if (!resolver.isRoleApplicable('customer') || resolver.isRoleApplicable('merchant')
      || !resolver.resolve('summarizer', 'summarize_file')?.supported) throw TypeError('File summary ACL unavailable');
  const attachment = createFileSummaryAttachment({ launches, files, scenes, personaAuthority, modeAuthority });
  const graph = createBoundFileSummaryGraph({ launches, scenes, personaAuthority, modeAuthority, attachment,
    conversationRepository, journal, coordinator, provider, toolPolicyRepository });
  // Internal execution composition only. HTTP and canonical grading are added
  // separately; do not advertise this object as a qualified lesson.
  return Object.freeze({ graph, attachment });
}
module.exports = { createFileSummaryComposition };
