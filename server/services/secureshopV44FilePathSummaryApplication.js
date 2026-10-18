'use strict';

function createFilePathSummaryApplication(options = {}) {
  const { identityPool, agentsPool, launches, files, conversationRepository, coordinator, journal,
    personaAuthority, personaBindings, scenes, modeAuthority, receipts, progress, publicationModes,
    judge, qualifyModel, authenticatePersona, provider, toolPolicyRepository } = options;
  const { POLICIES } = require('./secureshopFeatureModeAuthority');
  const { normalizeConversationPurpose } = require('./secureshopConversationPurpose');
  const { createBoundAclResolver } = require('./secureshopBoundAclRegistry');
  const { createFilePathSummaryExecutionConfig } = require('./secureshopV44FilePathSummaryExecutionConfig');
  const { createBoundFilePathSummaryGraph } = require('./secureshopBoundFilePathSummaryGraph');
  normalizeConversationPurpose('secureshop_file_path_summary');
  if (POLICIES.file_path_summary !== 'owned-synthetic-file-path-summary-v1') {
    throw TypeError('File-path summary feature policy unavailable');
  }
  const declared = createFilePathSummaryExecutionConfig({ mode: 'fixed' }).manifest.getForRole('customer');
  const acl = createBoundAclResolver({ workflow: 'file-path-summary', declaredTools: declared });
  if (!acl.isRoleApplicable('customer') || acl.isRoleApplicable('merchant') || acl.isRoleApplicable('admin')
      || !acl.resolve('summarizer', 'summarize_file')?.supported) {
    throw TypeError('File-path summary ACL unavailable');
  }
  const graph = createBoundFilePathSummaryGraph({ launches, conversationRepository, journal, coordinator,
    provider, files, personaAuthority, modeAuthority, scenes, toolPolicyRepository });
  const reader = require('../database/postgres/secureshopV44FilePathSummaryTurnReader')
    .createV44FilePathSummaryTurnReader({ pool: agentsPool });
  const assessmentJournal = Object.freeze({ ...journal, ...reader });
  const sourceReader = require('./secureshopV44FilePathSummarySourceReader')
    .createV44FilePathSummarySourceReader({ launches, files });
  const assessment = require('./secureshopV44FilePathSummaryAssessment').createV44FilePathSummaryAssessment({
    identityPool, agentsPool, launches, conversationRepository, coordinator, journal: assessmentJournal,
    personaAuthority, personaBindings, scenes, modeAuthority, sourceReader, receipts, progress,
    publicationModes, judge, qualifyModel });
  const saved = require('./secureshopV44FilePathSummarySavedTurn').createV44FilePathSummarySavedTurn({
    launches, journal: reader, personaAuthority, modeAuthority, scenes, sourceReader });
  const router = require('../routes/secureshop/boundFilePathSummary').createBoundFilePathSummaryRouter({
    launches, authenticatePersona, graph, saved, assessment, modeAuthority });
  return Object.freeze({ ready: true, router, graph, assessment, saved, sourceReader });
}

module.exports = { createFilePathSummaryApplication };
