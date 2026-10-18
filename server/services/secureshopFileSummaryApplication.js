'use strict';
function createFileSummaryApplication(options = {}) {
  const { identityPool, agentsPool, launches, conversationRepository, coordinator, journal,
    personaAuthority, personaBindings, scenes, modeAuthority, receipts, progress, publicationModes,
    judge, qualifyModel, authenticatePersona } = options;
  const core = require('./secureshopFileSummaryComposition').createFileSummaryComposition(options);
  const reader = require('../database/postgres/secureshopV19FileSummaryTurnReader')
    .createV19FileSummaryTurnReader({ pool: agentsPool });
  const assessmentJournal = Object.freeze({ ...journal, ...reader });
  const sourceReader = require('./secureshopV19FileSummarySourceReader')
    .createV19FileSummarySourceReader({ attachment: core.attachment });
  const assessment = require('./secureshopV19FileSummaryAssessment').createV19FileSummaryAssessment({
    identityPool, agentsPool, launches, conversationRepository, coordinator, journal: assessmentJournal,
    personaAuthority, personaBindings, scenes, modeAuthority, sourceReader, receipts, progress,
    publicationModes, judge, qualifyModel });
  const saved = require('./secureshopV19FileSummarySavedTurn').createV19FileSummarySavedTurn({
    launches, journal: reader, personaAuthority, modeAuthority, scenes, sourceReader });
  const router = require('../routes/secureshop/boundFileSummary').createBoundFileSummaryRouter({
    launches, authenticatePersona, graph: core.graph, saved, assessment, modeAuthority });
  return Object.freeze({ ...core, ready: true, router, assessment, saved, sourceReader });
}
module.exports = { createFileSummaryApplication };
