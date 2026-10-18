export const WORKSHOP_SCHEMA_VERSION = 1;
export const WORKSHOP_EXPERIENCE_VERSION = 1;

export const workshopTokens = Object.freeze({
  version: WORKSHOP_EXPERIENCE_VERSION,
  brand: '#667eea',
  brandEnd: '#764ba2',
  text: '#333333',
  mutedText: '#555555',
  surface: '#ffffff',
  canvas: '#f8f9fa',
  border: '#e9ecef',
  controlBorder: '#e2e8f0',
  complete: '#22c55e',
  completeSurface: '#f0fdf4',
  warning: '#ffc107',
  warningText: '#5f4700',
  danger: '#dc3545',
  dangerEnd: '#c82333',
  focus: '#3347b0',
  disabledOpacity: 0.5,
  cardRadius: '16px',
  controlRadius: '8px',
  mainCollapse: '1024px',
  primaryGradient: 'linear-gradient(135deg, #667eea, #764ba2)',
  secondaryGradient: 'linear-gradient(135deg, #6c757d, #495057)',
  successGradient: 'linear-gradient(135deg, #28a745, #20c997)',
  dangerGradient: 'linear-gradient(135deg, #dc3545, #c82333)',
});

export const WORKSHOP_TEMPLATES = Object.freeze(['single-scenario', 'multi-scenario']);
export const WORKSHOP_WORKFLOWS = Object.freeze(['chat', 'rag', 'email', 'comparison', 'tool-workspace']);
export const WORKSHOP_NAVIGATION_POLICIES = Object.freeze([
  'manual',
  'next-incomplete-after-completion',
  'prerequisite-driven',
]);

function immutableScenario(scenario) {
  return Object.freeze({
    ...scenario,
    capabilities: Object.freeze({ ...(scenario.capabilities || {}) }),
  });
}

export function validateWorkshop(definition) {
  if (!definition || definition.schemaVersion !== WORKSHOP_SCHEMA_VERSION || !definition.workshopKey) {
    throw new TypeError('Versioned workshop key required');
  }
  if (definition.experienceVersion !== WORKSHOP_EXPERIENCE_VERSION) {
    throw new TypeError(`Unsupported workshop experience version: ${definition.experienceVersion}`);
  }
  const { template, scenarios } = definition;
  if (!WORKSHOP_TEMPLATES.includes(template)) throw new TypeError('Unknown workshop template');
  if (!Array.isArray(scenarios) || (template === 'single-scenario' ? scenarios.length !== 1 : scenarios.length < 2)) {
    throw new TypeError('Scenario count does not match template');
  }
  const ids = new Set();
  for (const scenario of scenarios) {
    if (!scenario?.id || ids.has(scenario.id)) throw new TypeError('Scenario IDs must be unique and nonempty');
    if (!WORKSHOP_WORKFLOWS.includes(scenario.workflow)) throw new TypeError('Unknown scenario workflow');
    if (!scenario.resetPolicy || scenario.objectiveSource !== 'canonical-catalog') {
      throw new TypeError('Canonical objectives and reset policy required');
    }
    if (scenario.navigation && !WORKSHOP_NAVIGATION_POLICIES.includes(scenario.navigation)) {
      throw new TypeError('Unknown objective navigation policy');
    }
    ids.add(scenario.id);
  }
  return true;
}

export function defineWorkshop(definition) {
  validateWorkshop(definition);
  return Object.freeze({
    ...definition,
    scenarios: Object.freeze(definition.scenarios.map(immutableScenario)),
  });
}

export function getScenario(definition, scenarioId) {
  validateWorkshop(definition);
  return definition.scenarios.find(({ id }) => id === scenarioId) || null;
}

export const directPromptInjectionExperience = defineWorkshop({
  schemaVersion: 1,
  experienceVersion: 1,
  workshopKey: 'direct_prompt_injection',
  template: 'single-scenario',
  scenarios: [{
    id: 'direct-chat',
    label: 'Prompt Injection Chat',
    workflow: 'chat',
    objectiveSource: 'canonical-catalog',
    resetPolicy: 'dpi',
    navigation: 'next-incomplete-after-completion',
    capabilities: { chat: true, objectiveHelp: true, conversationReset: true },
  }],
});

export const indirectPromptInjectionExperience = defineWorkshop({
  schemaVersion: 1,
  experienceVersion: 1,
  workshopKey: 'indirect_prompt_injection',
  template: 'multi-scenario',
  scenarios: [
    {
      id: 'document',
      label: 'Document Upload (RAG)',
      workflow: 'rag',
      objectiveSource: 'canonical-catalog',
      resetPolicy: 'ipi-rag',
      navigation: 'manual',
      capabilities: { upload: true, query: true, objectiveHelp: true },
    },
    {
      id: 'email',
      label: 'Email Agent',
      workflow: 'email',
      objectiveSource: 'canonical-catalog',
      resetPolicy: 'ipi-email',
      navigation: 'manual',
      capabilities: { email: true, objectiveHelp: false },
    },
  ],
});

const singleScenarioDefinition = (workshopKey, id, label, workflow, resetPolicy, capabilities = {}) => defineWorkshop({
  schemaVersion: 1,
  experienceVersion: 1,
  workshopKey,
  template: 'single-scenario',
  scenarios: [{
    id,
    label,
    workflow,
    objectiveSource: 'canonical-catalog',
    resetPolicy,
    navigation: 'manual',
    capabilities,
  }],
});

export const sqlWorkshopExperience = singleScenarioDefinition(
  'sql_injection_workshop', 'shopfast', 'ShopFast SQL Agent', 'chat', 'sql-workshop',
  { chat: true, toolResults: true, objectiveHelp: true },
);
export const noSqlWorkshopExperience = singleScenarioDefinition(
  'nosql_injection_workshop', 'research-vault', 'ResearchVault NoSQL Agent', 'chat', 'nosql-workshop',
  { chat: true, toolResults: true, objectiveHelp: true },
);
export const sensitiveInfoWorkshopExperience = singleScenarioDefinition(
  'sensitive_info_disclosure', 'vault-corp', 'VaultCorp Banking Agent', 'tool-workspace', 'sensitive-info',
  { chat: true, toolResults: true, objectiveHelp: true },
);
export const supplyChainWorkshopExperience = singleScenarioDefinition(
  'supply_chain_rce', 'package-review', 'Package Supply Chain', 'tool-workspace', 'supply-chain',
  { chat: true, comparison: true, objectiveHelp: true },
);
export const excessiveAgencyWorkshopExperience = singleScenarioDefinition(
  'excessive_agency', 'agent-actions', 'Agent Actions', 'tool-workspace', 'excessive-agency',
  { chat: true, toolResults: true, objectiveHelp: true },
);
export const mcpWorkshopExperience = singleScenarioDefinition(
  'mcp_server_rce', 'mcp-operations', 'MCP Operations', 'tool-workspace', 'mcp-workshop',
  { chat: true, inspector: true, objectiveHelp: true },
);

export const xssWorkshopExperience = defineWorkshop({
  schemaVersion: 1,
  experienceVersion: 1,
  workshopKey: 'reflected_xss_llm',
  template: 'multi-scenario',
  scenarios: [
    ['reflected', 'Reflected XSS', 'chat'],
    ['stored_user', 'Stored XSS: User Payload', 'chat'],
    ['stored_llm', 'Stored XSS: LLM-Generated', 'chat'],
    ['email', 'Email Summarization XSS', 'email'],
    ['email_builder', 'Email Template Builder', 'tool-workspace'],
  ].map(([id, label, workflow]) => ({
    id, label, workflow, objectiveSource: 'canonical-catalog', resetPolicy: `xss-${id}`, navigation: 'manual',
    capabilities: { chat: true, objectiveHelp: true, intentionalHtml: true },
  })),
});

export const csrfWorkshopExperience = defineWorkshop({
  schemaVersion: 1,
  experienceVersion: 1,
  workshopKey: 'csrf_workshop',
  template: 'multi-scenario',
  scenarios: [
    ['get', 'GET CSRF'],
    ['post', 'POST CSRF'],
    ['xss', 'CSRF via XSS (Email)'],
    ['indirect', 'Indirect / RAG'],
  ].map(([id, label]) => ({
    id, label, workflow: 'tool-workspace', objectiveSource: 'canonical-catalog', resetPolicy: `csrf-${id}`, navigation: 'manual',
    capabilities: { chat: true, victimView: true, intentionalHtml: true },
  })),
});

// Captured ownership survives scenario switches and invalidates stale async commits.
export function createScenarioFence() {
  const generations = new Map();
  const keyOf = ({ attendeeId, workshopKey, scenarioId }) => {
    if (attendeeId == null || !workshopKey || !scenarioId) throw new TypeError('Scenario owner required');
    return JSON.stringify([String(attendeeId), workshopKey, scenarioId]);
  };
  return {
    capture(owner) {
      const key = keyOf(owner);
      const generation = generations.get(key) || 0;
      return Object.freeze({
        owner: Object.freeze({ ...owner }),
        generation,
        isCurrent: () => (generations.get(key) || 0) === generation,
      });
    },
    invalidate(owner) {
      const key = keyOf(owner);
      const generation = (generations.get(key) || 0) + 1;
      generations.set(key, generation);
      return generation;
    },
  };
}
