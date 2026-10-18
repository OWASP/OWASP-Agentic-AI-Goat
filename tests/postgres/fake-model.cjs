'use strict';
// These service regressions test routing/database contracts; live-model tests run separately.
if (process.env.PG_TEST_DISPOSABLE !== 'yes') throw new Error('Fake model is limited to disposable database tests');
require('../../server/services/multiProviderAIService').generateResponse = async () => 'Database tool completed.';
