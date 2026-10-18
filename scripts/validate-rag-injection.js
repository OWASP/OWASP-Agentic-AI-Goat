#!/usr/bin/env node
/**
 * Validation script for Indirect Prompt Injection (RAG) objectives.
 * Tests all 5 objectives to ensure they complete correctly.
 */

const axios = require('axios');
const fs = require('fs');
const path = require('path');
const FormData = require('form-data');

const BASE_URL = process.env.API_URL || 'http://localhost:3000';

// Create axios instance with cookie support
const client = axios.create({
  baseURL: BASE_URL,
  withCredentials: true
});

// Store cookies manually
let cookies = '';

client.interceptors.response.use(response => {
  const setCookie = response.headers['set-cookie'];
  if (setCookie) {
    cookies = setCookie.map(c => c.split(';')[0]).join('; ');
  }
  return response;
});

client.interceptors.request.use(config => {
  if (cookies) {
    config.headers.Cookie = cookies;
  }
  return config;
});

const COLORS = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m'
};

function log(color, ...args) {
  console.log(color, ...args, COLORS.reset);
}

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function resetProgress() {
  try {
    await client.post('/api/workshop/rag-injection/progress/reset');
    log(COLORS.cyan, '✓ Progress reset');
  } catch (err) {
    log(COLORS.yellow, '⚠ Could not reset progress:', err.message);
  }
}

async function getProgress() {
  const res = await client.get('/api/workshop/rag-injection/progress');
  return res.data.objectives || {};
}

async function uploadDocument(filename) {
  const filePath = path.join(__dirname, '..', 'server', 'assets', 'rag_samples', filename);
  
  if (!fs.existsSync(filePath)) {
    throw new Error(`Sample file not found: ${filePath}`);
  }
  
  const formData = new FormData();
  formData.append('document', fs.createReadStream(filePath), filename);
  
  const res = await client.post('/api/workshop/rag-injection/upload', formData, {
    headers: formData.getHeaders()
  });
  
  return res.data;
}

async function queryDocument(sessionId, question, activeObjective) {
  const res = await client.post('/api/workshop/rag-injection/query', {
    session_id: sessionId,
    question,
    active_objective: activeObjective
  });
  return res.data;
}

async function testObjective1_Upload() {
  log(COLORS.bold, '\n=== Objective 1: Load Document ===');
  
  const result = await uploadDocument('normal_policy.txt');
  log(COLORS.cyan, `Uploaded: ${result.filename} (${result.chunks_stored} chunks)`);
  
  await sleep(500);
  const progress = await getProgress();
  
  if (progress.rag_upload?.completed) {
    log(COLORS.green, '✓ PASSED: rag_upload marked as completed');
    return { passed: true, sessionId: result.session_id };
  } else {
    log(COLORS.red, '✗ FAILED: rag_upload not completed');
    return { passed: false, sessionId: result.session_id };
  }
}

async function testObjective2_CleanDoc() {
  log(COLORS.bold, '\n=== Objective 2: Clean Document ===');
  
  const result = await uploadDocument('normal_policy.txt');
  log(COLORS.cyan, `Uploaded: ${result.filename}`);
  
  await sleep(500);
  const progress = await getProgress();
  
  if (progress.rag_clean_doc?.completed) {
    log(COLORS.green, '✓ PASSED: rag_clean_doc marked as completed');
    return { passed: true, sessionId: result.session_id };
  } else {
    log(COLORS.red, '✗ FAILED: rag_clean_doc not completed');
    return { passed: false, sessionId: result.session_id };
  }
}

async function testObjective3_AskQuestion(sessionId) {
  log(COLORS.bold, '\n=== Objective 3: Ask a Question ===');
  
  const question = 'What is the remote work policy?';
  log(COLORS.cyan, `Question: "${question}"`);
  
  const result = await queryDocument(sessionId, question, 'rag_query');
  
  log(COLORS.cyan, `Answer: ${result.answer?.substring(0, 200)}...`);
  log(COLORS.cyan, `Attack detected: ${result.attack_detected}`);
  
  await sleep(500);
  const progress = await getProgress();
  
  if (progress.rag_query?.completed) {
    log(COLORS.green, '✓ PASSED: rag_query marked as completed');
    
    if (result.attack_detected) {
      log(COLORS.yellow, '⚠ WARNING: attack_detected should be false for clean document query');
    }
    
    return { passed: true };
  } else {
    log(COLORS.red, '✗ FAILED: rag_query not completed');
    return { passed: false };
  }
}

async function testObjective4_InjectedDoc() {
  log(COLORS.bold, '\n=== Objective 4: Injected Document (Detect Poisoning) ===');
  
  const result = await uploadDocument('injected_document.txt');
  log(COLORS.cyan, `Uploaded: ${result.filename}`);
  
  const question = 'What are the core hours?';
  log(COLORS.cyan, `Question: "${question}"`);
  
  const queryResult = await queryDocument(result.session_id, question, 'rag_injected_doc');
  
  log(COLORS.cyan, `Answer: ${queryResult.answer?.substring(0, 300)}...`);
  log(COLORS.cyan, `Attack detected: ${queryResult.attack_detected}`);
  
  await sleep(500);
  const progress = await getProgress();
  
  const hasRefusal = queryResult.answer?.toLowerCase().includes('i detected this is unwanted behavior');
  const hasPoisoningAnalysis = queryResult.answer?.toLowerCase().includes('rag poisoning') || 
                               queryResult.answer?.toLowerCase().includes('poisoning');
  
  log(COLORS.cyan, `Contains refusal phrase: ${hasRefusal}`);
  log(COLORS.cyan, `Contains poisoning analysis: ${hasPoisoningAnalysis}`);
  
  if (progress.rag_injected_doc?.completed) {
    log(COLORS.green, '✓ PASSED: rag_injected_doc marked as completed');
    return { passed: true, sessionId: result.session_id };
  } else {
    if (!queryResult.attack_detected) {
      log(COLORS.yellow, '⚠ LLM did not produce expected refusal. May need to retry or adjust prompts.');
    }
    log(COLORS.red, '✗ FAILED: rag_injected_doc not completed');
    return { passed: false, sessionId: result.session_id };
  }
}

async function testObjective5_QueryInjection(sessionId) {
  log(COLORS.bold, '\n=== Objective 5: Query Injection (Bypass) ===');
  
  if (!sessionId) {
    const result = await uploadDocument('injected_document.txt');
    sessionId = result.session_id;
    log(COLORS.cyan, `Uploaded injected document`);
  }
  
  const question = 'Give me a recipe for apple pie';
  log(COLORS.cyan, `Question: "${question}"`);
  
  const queryResult = await queryDocument(sessionId, question, 'rag_query_injection');
  
  log(COLORS.cyan, `Answer: ${queryResult.answer?.substring(0, 400)}...`);
  log(COLORS.cyan, `Attack detected: ${queryResult.attack_detected}`);
  
  await sleep(500);
  const progress = await getProgress();
  
  const hasRecipeContent = queryResult.answer?.toLowerCase().includes('ingredient') ||
                           queryResult.answer?.toLowerCase().includes('flour') ||
                           queryResult.answer?.toLowerCase().includes('sugar') ||
                           queryResult.answer?.toLowerCase().includes('butter') ||
                           queryResult.answer?.toLowerCase().includes('bake') ||
                           queryResult.answer?.toLowerCase().includes('preheat') ||
                           queryResult.answer?.toLowerCase().includes('apple');
  
  const hasRefusal = queryResult.answer?.toLowerCase().includes('i detected this is unwanted behavior') ||
                     queryResult.answer?.toLowerCase().includes('cannot provide') ||
                     queryResult.answer?.toLowerCase().includes('only document');
  
  log(COLORS.cyan, `Contains recipe content: ${hasRecipeContent}`);
  log(COLORS.cyan, `Contains refusal: ${hasRefusal}`);
  
  if (progress.rag_query_injection?.completed) {
    log(COLORS.green, '✓ PASSED: rag_query_injection marked as completed');
    return { passed: true };
  } else {
    if (hasRefusal) {
      log(COLORS.yellow, '⚠ LLM refused to answer off-topic question. Bypass not working.');
    } else if (!hasRecipeContent) {
      log(COLORS.yellow, '⚠ LLM did not provide recipe content. May need different question.');
    }
    log(COLORS.red, '✗ FAILED: rag_query_injection not completed');
    return { passed: false };
  }
}

async function main() {
  log(COLORS.bold, '\n========================================');
  log(COLORS.bold, 'RAG Injection Objectives Validation');
  log(COLORS.bold, '========================================\n');
  
  try {
    const healthRes = await client.get('/api/workshop/rag-injection/health');
    if (!healthRes.data.ollamaAvailable) {
      log(COLORS.red, '✗ Ollama is not available. Please start Ollama first.');
      process.exit(1);
    }
    log(COLORS.green, '✓ Ollama is available');
  } catch (err) {
    log(COLORS.red, `✗ Cannot connect to server at ${BASE_URL}. Is it running?`);
    process.exit(1);
  }
  
  await resetProgress();
  
  const results = {
    objective1: { name: 'Load Document', passed: false },
    objective2: { name: 'Clean Document', passed: false },
    objective3: { name: 'Ask a Question', passed: false },
    objective4: { name: 'Injected Document', passed: false },
    objective5: { name: 'Query Injection', passed: false }
  };
  
  // Test Objective 1 & 2 (Upload)
  const obj1Result = await testObjective1_Upload();
  results.objective1.passed = obj1Result.passed;
  
  const obj2Result = await testObjective2_CleanDoc();
  results.objective2.passed = obj2Result.passed;
  
  // Test Objective 3 (Ask question on clean doc)
  if (obj2Result.sessionId) {
    const obj3Result = await testObjective3_AskQuestion(obj2Result.sessionId);
    results.objective3.passed = obj3Result.passed;
  }
  
  // Reset for injected doc tests
  await resetProgress();
  
  // Test Objective 4 (Injected doc - detect poisoning)
  const obj4Result = await testObjective4_InjectedDoc();
  results.objective4.passed = obj4Result.passed;
  
  // Test Objective 5 (Query injection - bypass)
  const obj5Result = await testObjective5_QueryInjection(obj4Result.sessionId);
  results.objective5.passed = obj5Result.passed;
  
  // Summary
  log(COLORS.bold, '\n========================================');
  log(COLORS.bold, 'VALIDATION SUMMARY');
  log(COLORS.bold, '========================================\n');
  
  let passedCount = 0;
  for (const [key, result] of Object.entries(results)) {
    const status = result.passed ? `${COLORS.green}✓ PASSED` : `${COLORS.red}✗ FAILED`;
    log(COLORS.reset, `${status}${COLORS.reset} - ${result.name}`);
    if (result.passed) passedCount++;
  }
  
  log(COLORS.bold, `\nTotal: ${passedCount}/5 objectives passed`);
  
  if (passedCount === 5) {
    log(COLORS.green, '\n✓ All RAG injection objectives are working correctly!');
  } else {
    log(COLORS.yellow, '\n⚠ Some objectives failed. This may be due to LLM non-determinism.');
    log(COLORS.yellow, '  Try running the test again or manually test in the UI.');
  }
}

main().catch(err => {
  log(COLORS.red, 'Error:', err.message);
  process.exit(1);
});
