#!/usr/bin/env node
/**
 * Verify Prompt Injection Workshop solutions against the running server and Llama.
 * Ensures at least one example per objective can trigger completion (||SUCCESS|| or detector).
 *
 * Prerequisites:
 * - Server running (npm run server or node server/index.js)
 * - Ollama running with a model (e.g. ollama pull llama3.2 && ollama serve)
 *
 * Usage: node scripts/verify-prompt-injection-solutions.js
 * Optional: BASE_URL=http://localhost:8081 node scripts/verify-prompt-injection-solutions.js
 */

const axios = require('axios');
const { solutions } = require('../server/data/promptInjectionSolutions');

const BASE_URL = process.env.BASE_URL || 'http://localhost:8081';
const CHAT_URL = `${BASE_URL}/api/workshop/prompt-injection/chat`;
const HEALTH_URL = `${BASE_URL}/api/workshop/prompt-injection/health`;

const OBJECTIVE_ORDER = [
  'system_prompt',
  'jailbreak',
  'multi_language',
  'virtualization',
  'role_playing',
  'side_stepping',
  'obfuscation'
];

async function checkHealth() {
  try {
    const { data } = await axios.get(HEALTH_URL, { timeout: 5000 });
    if (!data.ollama?.reachable) {
      console.warn('⚠ Ollama not reachable. Start Ollama (ollama serve) and pull a model (e.g. ollama pull llama3.2).');
      return false;
    }
    console.log('✓ Server and Ollama are reachable.\n');
    return true;
  } catch (err) {
    console.error('✗ Cannot reach server at', BASE_URL, err.code || err.message);
    console.error('  Start the server (e.g. npm run server) and ensure Ollama is running.\n');
    return false;
  }
}

async function testObjective(objectiveId, prompt) {
  try {
    const { data } = await axios.post(
      CHAT_URL,
      {
        userMessage: prompt,
        conversationHistory: [],
        completedObjectives: {},
        activeObjectiveId: objectiveId
      },
      { timeout: 120000 }
    );
    const completed = data.completedObjectiveId === objectiveId;
    const responseSnippet = (data.response || '').slice(0, 120).replace(/\n/g, ' ');
    return { completed, response: data.response, responseSnippet, error: null };
  } catch (err) {
    return {
      completed: false,
      response: null,
      responseSnippet: null,
      error: err.response?.data?.error || err.message
    };
  }
}

async function main() {
  console.log('Prompt Injection Workshop — Solution verification');
  console.log('==================================================');
  console.log('Base URL:', BASE_URL);
  console.log('');

  if (!(await checkHealth())) process.exit(1);

  const results = [];
  for (const objectiveId of OBJECTIVE_ORDER) {
    const meta = solutions[objectiveId];
    const firstPrompt = meta?.examples?.[0]?.prompt;
    if (!firstPrompt) {
      console.log(`[${objectiveId}] No solution example — SKIP`);
      results.push({ objectiveId, name: meta?.title || objectiveId, ok: false, reason: 'No example' });
      continue;
    }
    process.stdout.write(`[${objectiveId}] Testing "${firstPrompt.slice(0, 50)}..." ... `);
    const { completed, responseSnippet, error } = await testObjective(objectiveId, firstPrompt);
    if (error) {
      console.log('ERROR:', error);
      results.push({ objectiveId, name: meta.title, ok: false, reason: error });
    } else if (completed) {
      console.log('PASS (objective completed)');
      results.push({ objectiveId, name: meta.title, ok: true });
    } else {
      console.log('FAIL (no completion)');
      if (responseSnippet) console.log('    Response snippet:', responseSnippet);
      results.push({ objectiveId, name: meta.title, ok: false, reason: 'No completion', responseSnippet });
    }
  }

  console.log('');
  console.log('Summary');
  console.log('-------');
  const passed = results.filter(r => r.ok).length;
  const failed = results.filter(r => !r.ok);
  console.log(`Passed: ${passed}/${results.length}`);
  if (passed >= 6) {
    console.log('Note: Results can vary by model and run. Obfuscation and virtualization may be model-dependent.');
  }
  if (failed.length) {
    console.log('Failed:', failed.map(f => f.objectiveId).join(', '));
    failed.forEach(f => {
      console.log(`  - ${f.objectiveId}: ${f.reason || 'no completion'}`);
    });
  }
  process.exit(failed.length ? 1 : 0);
}

main().catch(err => {
  console.error('Script error:', err);
  process.exit(1);
});
