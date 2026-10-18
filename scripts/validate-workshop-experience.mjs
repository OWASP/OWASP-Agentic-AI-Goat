#!/usr/bin/env node
import {
  csrfWorkshopExperience,
  directPromptInjectionExperience,
  excessiveAgencyWorkshopExperience,
  indirectPromptInjectionExperience,
  mcpWorkshopExperience,
  noSqlWorkshopExperience,
  sensitiveInfoWorkshopExperience,
  sqlWorkshopExperience,
  supplyChainWorkshopExperience,
  validateWorkshop,
  xssWorkshopExperience,
} from '../client/src/components/workshop/experience.mjs';
import { workshopAuthoringFixtures } from '../client/src/components/workshop/fixtures.mjs';

const definitions = [
  directPromptInjectionExperience,
  indirectPromptInjectionExperience,
  sqlWorkshopExperience,
  noSqlWorkshopExperience,
  sensitiveInfoWorkshopExperience,
  supplyChainWorkshopExperience,
  xssWorkshopExperience,
  csrfWorkshopExperience,
  excessiveAgencyWorkshopExperience,
  mcpWorkshopExperience,
  ...workshopAuthoringFixtures,
];

const failures = [];
for (const definition of definitions) {
  try {
    validateWorkshop(definition);
    if (definition.scenarios.some(({ objectiveSource }) => objectiveSource !== 'canonical-catalog')) {
      failures.push(`${definition.workshopKey}: objectives must come from the canonical server catalog`);
    }
  } catch (error) {
    failures.push(`${definition?.workshopKey || '<unknown>'}: ${error.message}`);
  }
}

if (failures.length) {
  console.error(failures.join('\n'));
  process.exitCode = 1;
} else {
  console.log(`PASS: ${definitions.length} workshop experience definitions validated`);
}
