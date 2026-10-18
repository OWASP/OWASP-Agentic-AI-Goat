import { defineWorkshop } from './experience.mjs';

export const singleScenarioFixture = defineWorkshop({
  schemaVersion: 1,
  experienceVersion: 1,
  workshopKey: 'fixture_single_scenario',
  template: 'single-scenario',
  scenarios: [{
    id: 'chat',
    label: 'Chat scenario',
    workflow: 'chat',
    objectiveSource: 'canonical-catalog',
    resetPolicy: 'fixture-chat',
    navigation: 'manual',
    capabilities: { chat: true, objectiveHelp: true, conversationReset: true },
  }],
});

export const multiScenarioFixture = defineWorkshop({
  schemaVersion: 1,
  experienceVersion: 1,
  workshopKey: 'fixture_multi_scenario',
  template: 'multi-scenario',
  scenarios: [
    {
      id: 'documents',
      label: 'Documents',
      workflow: 'rag',
      objectiveSource: 'canonical-catalog',
      resetPolicy: 'fixture-documents',
      navigation: 'manual',
      capabilities: { upload: true, query: true },
    },
    {
      id: 'messages',
      label: 'Messages',
      workflow: 'email',
      objectiveSource: 'canonical-catalog',
      resetPolicy: 'fixture-messages',
      navigation: 'manual',
      capabilities: { email: true },
    },
  ],
});

export const workshopAuthoringFixtures = Object.freeze([
  singleScenarioFixture,
  multiScenarioFixture,
]);
