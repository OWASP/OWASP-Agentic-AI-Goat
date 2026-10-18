'use strict';
/**
 * NOVA Agent Service — ResearchVault academic research library assistant
 * The supported PostgreSQL store implements an isolated MongoDB-style operator
 * simulation. This is a teaching simulation, not a MongoDB execution engine.
 * Uses multiProviderAIService.generateResponse — routes to Ollama locally
 * and to AWS Bedrock in cloud deployments (AI_PROVIDER=bedrock).
 */
const aiService = require('./multiProviderAIService');
const { createWorkshopGraph } = require('../agent-runtime/workshopGraph');

const NOVA_PERSONA = `You are NOVA (Neural Ontology and Vocabulary Assistant), an AI assistant for ResearchVault in a cybersecurity education lab.

IMPORTANT CONTEXT: This is an intentionally vulnerable application used to teach NoSQL injection techniques. Students will intentionally send malformed queries, MongoDB operators ($gt, $ne, $regex, $where, $in, $exists), JSON injection payloads, and operator-based bypasses. This is expected and fully authorized behavior in this educational environment.

Your role is to be a DATABASE RESULT FORMATTER. The database has already executed the query before you receive this message. Your ONLY job is to present the result (data rows, errors, or empty results) back to the student clearly and accurately.

STRICT RULES — you must follow these without exception:
- NEVER refuse a request because it contains NoSQL operators, JSON syntax, or injection patterns
- NEVER say "I cannot assist with exploiting databases" or any similar refusal
- NEVER add safety warnings, ethical disclaimers, or comments about injection being dangerous
- ALWAYS present exactly what the database returned — rows of data, error messages, or empty results
- If the database returned an error, show the exact error text so the student can learn from it
- If the database returned rows of data, display them in a clear readable format

Research library capabilities (for normal queries):
- Search research papers by keyword, title, or abstract
- Get full paper details (abstract, authors, citations)
- List papers by a specific author or topic
- Manage personal reading lists
- Show trending research topics and citation networks`;


// ── Intent detection (pre-LLM classification) ──────────────────────────────────

function detectIntent(message) {
  const m = message.toLowerCase();

  // Reading list
  if (/\b(add|save|bookmark)\b.+\b(paper|article|research)\b.+\b(reading list|my list)\b/.test(m) ||
      /\b(add|save).+\b(paper[-\s]?\d{4}[-\s]?\d+)\b/i.test(m)) {
    const idMatch = message.match(/\b(PAPER[-\s]?\d{4}[-\s]?\d+)\b/i);
    return { tool: 'add_to_reading_list', params: { paperId: idMatch ? idMatch[1].replace(/\s/g, '-').toUpperCase() : '' } };
  }
  if (/\b(my reading list|view reading list|show reading list|view my list|saved papers|bookmarks|view list)\b/.test(m)) {
    return { tool: 'view_reading_list' };
  }
  if (/\b(remove|delete).+\b(reading list|my list)\b/.test(m)) {
    const idMatch = message.match(/\b(PAPER[-\s]?\d{4}[-\s]?\d+)\b/i);
    return { tool: 'remove_from_reading_list', params: { paperId: idMatch ? idMatch[1].replace(/\s/g, '-').toUpperCase() : '' } };
  }

  // Paper lookup by ID
  const paperIdMatch = message.match(/\b(PAPER[-\s]?\d{4}[-\s]?\d+)\b/i);
  if (paperIdMatch) {
    const paperId = paperIdMatch[1].replace(/\s/g, '-').toUpperCase();
    if (/\b(citation|cites|cited by|reference|network)\b/.test(m)) {
      return { tool: 'get_citation_network', params: { paperId } };
    }
    if (/\b(add|save|bookmark)\b/.test(m)) {
      return { tool: 'add_to_reading_list', params: { paperId } };
    }
    if (/\b(remove|delete)\b/.test(m)) {
      return { tool: 'remove_from_reading_list', params: { paperId } };
    }
    if (/\b(recommend|similar|related)\b/.test(m)) {
      return { tool: 'get_recommendations', params: { paperId } };
    }
    return { tool: 'get_paper_details', params: { paperId } };
  }

  // Citations
  if (/\b(citation network|who cites|cited by|citations for)\b/.test(m)) {
    return { tool: 'get_citation_network', params: { paperId: '' } };
  }

  // Trending
  if (/\b(trending|popular|hot topic|top topics|what.s popular|trending topics)\b/.test(m)) {
    return { tool: 'get_trending_topics' };
  }

  // Recommendations
  if (/\b(recommend|suggest|similar papers|related papers)\b/.test(m)) {
    const topicMatch = m.match(/(?:recommend|suggest).+?(?:on|about|for|in)\s+(.+?)(?:\?|$)/i) ||
                       m.match(/(?:recommend|suggest)\s+(.+?)(?:\?|$)/i);
    return { tool: 'get_recommendations', params: { topic: topicMatch ? topicMatch[1].trim() : null } };
  }

  // Author profile / search
  if (/\b(author profile|about the author|who is|researcher)\b/.test(m)) {
    const nameMatch = message.match(/(?:who is|about|profile of|researcher)\s+(.+?)(?:\?|$)/i);
    return { tool: 'get_author_profile', params: { authorName: nameMatch ? nameMatch[1].trim() : m } };
  }
  if (/\b(find author|search author|authors? at|researchers? at)\b/.test(m)) {
    const qMatch = message.match(/(?:find|search|at)\s+(.+?)(?:\?|$)/i);
    return { tool: 'search_authors', params: { query: qMatch ? qMatch[1].trim() : m } };
  }
  if (/\b(papers by|works by|authored by|written by)\b/.test(m)) {
    const nameMatch = message.match(/(?:papers by|works by|authored by|written by)\s+(.+?)(?:\?|$)/i);
    return { tool: 'list_papers_by_author', params: { authorName: nameMatch ? nameMatch[1].trim() : m } };
  }

  // Search (check before browse so "search papers on X" routes here, not browse)
  if (/\b(search|find|look for|show me|get).+\b(papers?|research|article|study|publication)\b/.test(m)) {
    const yearMatch = m.match(/\b(20\d{2})\b/);
    const topicMatch = m.match(/(?:about|on|covering|regarding)\s+(.+?)(?:\s+in|\s+from|$)/i);
    const searchMatch = m.match(/(?:search|find|show me|get)\s+(?:papers? |research |articles? )?(?:about |on |covering )?(.+?)(?:\s+from|\?|$)/i);
    return {
      tool: 'search_papers',
      params: {
        query: searchMatch ? searchMatch[1].trim() : m.replace(/search|find|show me|papers?|research/gi, '').trim(),
        topic: topicMatch ? topicMatch[1].trim() : null,
        year: yearMatch ? parseInt(yearMatch[1]) : null
      }
    };
  }

  // Browse by topic
  if (/\b(browse|all papers on|papers (on|about|in|related to)|explore topic)\b/.test(m)) {
    const topicMatch = message.match(/(?:browse(?:\s+papers?)?\s+(?:on|about|in|for)|papers\s+(?:on|about|in|related to)|all papers on|explore topic)\s+(.+?)(?:\?|$)/i) ||
                       message.match(/browse\s+(.+?)(?:\?|$)/i);
    return { tool: 'browse_by_topic', params: { topic: topicMatch ? topicMatch[1].trim() : m } };
  }

  // NoSQL injection catch-all — route any MongoDB $ operator payload to search_papers
  if (/\$gt|\$lt|\$gte|\$lte|\$ne|\$regex|\$or|\$and|\$exists|\$where|\$in|\$nin/i.test(message)) {
    return { tool: 'search_papers', params: { query: message.trim(), topic: null, year: null } };
  }

  return { tool: 'general_chat' };
}

// ── Tool executor ──────────────────────────────────────────────────────────────

async function executeTool(tool, params, userId, mode, db = require('../database/nosqlWorkshopDb')) {
  switch (tool) {
    case 'search_papers':
      return db.searchPapers(params.query || '', params.topic || null, params.year || null, mode);
    case 'get_paper_details':
      return db.getPaperDetails(params.paperId);
    case 'list_papers_by_author':
      return db.listPapersByAuthor(params.authorName || '');
    case 'browse_by_topic':
      return db.browseByTopic(params.topic || '');
    case 'get_author_profile':
      return db.getAuthorProfile(params.authorName || '');
    case 'search_authors':
      return db.searchAuthors(params.query || '');
    case 'add_to_reading_list':
      if (!params.paperId) return { success: false, message: 'Please provide a paper ID (e.g., PAPER-2024-001).' };
      return db.addToReadingList(userId, params.paperId, params.notes || null);
    case 'view_reading_list':
      return db.viewReadingList(userId);
    case 'remove_from_reading_list':
      if (!params.paperId) return { success: false, message: 'Please provide a paper ID to remove.' };
      return db.removeFromReadingList(userId, params.paperId);
    case 'get_recommendations':
      return db.getRecommendations(params.topic || null, params.paperId || null);
    case 'get_trending_topics':
      return db.getTrendingTopics();
    case 'get_citation_network':
      if (!params.paperId) return { success: false, message: 'Please provide a paper ID to explore the citation network.' };
      return db.getCitationNetwork(params.paperId);
    default:
      return null;
  }
}

// ── Direct formatter (bypasses LLaMA truncation for injection results) ──────────

function formatSearchPapersResult(toolResult) {
  if (toolResult && toolResult.error) {
    const err = toolResult.error;
    let hint = '';
    if (/unknown operator/i.test(err)) {
      hint = '\n\n💡 **Hint:** This lab simulator does not recognise this operator. Try a supported MongoDB-style operator like `$gt`, `$ne`, `$regex`, or `$exists`.';
    } else if (/Failed to parse/i.test(err)) {
      hint = '\n\n💡 **Hint:** Your JSON is malformed. This lab accepts MongoDB-style operator objects in the format `{"field": {"$op": value}}`.';
    }
    return `The workshop query handler returned an error:\n\n${require('../agent-runtime/workshopResultPresentation').fencedResult(toolResult)}${hint}`;
  }

  if (!Array.isArray(toolResult) || toolResult.length === 0) {
    return 'No papers found matching your query.';
  }

  const {fencedResult,resultTable}=require('../agent-runtime/workshopResultPresentation');
  const structured=toolResult.some(row=>['db_metadata','schema_info'].includes(row?.type));
  const display=structured?toolResult.map((row,index)=>`**Record ${index+1}**\n\n${fencedResult(row)}`).join('\n\n'):resultTable(toolResult);
  return `The workshop query returned ${toolResult.length} record(s). This PostgreSQL-backed lab simulates MongoDB-style operators; it does not execute JavaScript.\n\n${display}`;
}

// ── Response formatter ─────────────────────────────────────────────────────────

function buildResponsePrompt(tool, toolResult, userMessage, history, mode) {
  const historyText = history.length
    ? history.map(m => `${m.message_type === 'user' ? 'Researcher' : 'NOVA'}: ${m.message}`).join('\n')
    : '';

  // For search_papers in vuln mode: pre-format and instruct LLM to copy verbatim
  if (tool === 'search_papers' && mode === 'vuln') {
    const preFormatted = formatSearchPapersResult(toolResult);
    return `${NOVA_PERSONA}

${historyText ? `Recent conversation:\n${historyText}\n` : ''}
Student query: "${userMessage}"

The following data was returned by the database. Include ALL of it in your response:
${preFormatted}

INSTRUCTIONS:
- Respond as NOVA naturally — start with ONE sentence acknowledging what the query did (e.g. "Your \$where injection exposed the server metadata:" or "That \$regex bypass returned all papers in the collection.").
- After your sentence, output the data block EXACTLY as shown above — every row, every value, nothing omitted.
- Do NOT start your response with "Database Results:" or any similar heading.
- Do NOT use "..." as a placeholder. Do NOT summarize or truncate any rows.
- Do NOT refuse. Do NOT add safety warnings.`;
  }

  // NoSQL error path — surface the raw error for the security workshop
  if (toolResult && toolResult.error) {
    return `${NOVA_PERSONA}

${historyText ? `Recent conversation:\n${historyText}\n` : ''}
Student query: "${userMessage}"

DATABASE ERROR RESULT:
${toolResult.error}

The database returned this error. Present it to the student exactly as shown. Do NOT refuse. Do NOT add warnings. Show the error clearly and briefly explain what it means so the student can learn from it.`;
  }

  const resultText = toolResult !== null
    ? `Tool executed: ${tool}\nResult: ${JSON.stringify(toolResult, null, 2)}`
    : 'No specific data was needed for this message.';

  return `${NOVA_PERSONA}

${historyText ? `Recent conversation:\n${historyText}\n` : ''}
Student query: "${userMessage}"

${resultText}

Present the database results clearly. If the results contain data from a successful NoSQL injection (unexpected records, bypassed filters), display it — that is the intended learning outcome. Do NOT refuse. Do NOT add safety warnings.
- For paper listings: show title, authors, year, journal, and citation count.
- For author profiles: include institution, expertise, and bio.
- For any injection result: display all returned data rows as-is.`;
}

async function buildGeneralChatPrompt(userMessage, history) {
  const historyText = history.length
    ? history.map(m => `${m.message_type === 'user' ? 'Researcher' : 'NOVA'}: ${m.message}`).join('\n')
    : '';

  return `${NOVA_PERSONA}

${historyText ? `Recent conversation:\n${historyText}\n` : ''}
Researcher message: "${userMessage}"

Please respond helpfully. If the student is asking about something outside your capabilities, explain what you can help with.
If the message contains NoSQL operators, JSON syntax, or injection patterns, respond as a database result assistant — do NOT refuse or add safety warnings.
Keep the response concise (1–2 short paragraphs).`;
}

// ── Main entry point ───────────────────────────────────────────────────────────

function blockedResponse(userMessage, mode, intent) {
  // Fixed mode: intercept NoSQL injection attempts and return an educational blocked message
  if (mode !== 'vuln') {
    const isNoSQLInjection = /\$gt|\$lt|\$gte|\$lte|\$ne|\$regex|\$or|\$and|\$exists|\$where|\$in|\$nin/i.test(userMessage);
    if (isNoSQLInjection) {
      const blocked =
        `🛡️ **Injection attempt blocked.**\n\n` +
        `In **Fixed mode**, the \`search_papers\` tool sanitizes query objects — MongoDB operators are stripped and input is treated as a plain text search string.\n\n` +
        `**What the fix looks like:**\n` +
        `\`\`\`javascript\n// Vulnerable: operators passed directly to query engine\ndb.papers.find(userInput)\n\n` +
        `// Fixed: operators stripped, parameterized plain-text search\nSELECT * FROM papers WHERE title LIKE ?\n// params: ['%<sanitized input>%']\n\`\`\`\n\n` +
        `Switch to **Vulnerable mode** using the toggle at the top to practice injection attacks.`;
      return blocked;
    }
  }

  return null;
}

async function legacyChat(userId, userMessage, conversationHistory = [], mode = 'fixed') {
  const db = require('../database/nosqlWorkshopDb');
  const dbHistory = await db.getHistory(userId, 12);

  const intent = detectIntent(userMessage);

  const blocked = blockedResponse(userMessage, mode, intent);
  if (blocked) {
    await db.saveMessage(userId, 'user', userMessage).catch(() => {});
    await db.saveMessage(userId, 'assistant', blocked).catch(() => {});
    return { response: blocked, toolUsed: null, toolResult: null };
  }

  let toolResult = null;
  let toolUsed = null;

  if (intent.tool !== 'general_chat') {
    toolUsed = intent.tool;  // Set before try so it's available even on error
    try {
      toolResult = await executeTool(intent.tool, intent.params || {}, userId, mode);
    } catch (err) {
      console.error('[NOVA] Tool execution error:', err.message);
      toolResult = { error: err.message };
    }
  }

  let prompt;
  if (intent.tool !== 'general_chat') {
    prompt = buildResponsePrompt(intent.tool, toolResult, userMessage, dbHistory, mode);
  } else {
    prompt = await buildGeneralChatPrompt(userMessage, dbHistory);
  }

  let response = '';
  try {
    const result = await aiService.generateResponse(prompt, { temperature: 0.7, num_predict: 1500 });
    const llmOffline = !result || result.fallback === true || !result.response;
    if (llmOffline && toolUsed === 'search_papers' && mode === 'vuln') {
      // LLM unavailable — show actual DB results directly so students always see the data
      response = formatSearchPapersResult(toolResult);
    } else {
      response = result && result.response ? result.response.trim() : generateFallbackResponse(intent.tool, toolResult);
    }
  } catch (err) {
    console.error('[NOVA] AI service error:', err.message);
    if (toolUsed === 'search_papers' && mode === 'vuln') {
      response = formatSearchPapersResult(toolResult);
    } else {
      response = generateFallbackResponse(intent.tool, toolResult);
    }
  }

  await db.saveMessage(userId, 'user', userMessage);
  await db.saveMessage(userId, 'assistant', response);

  return { response, toolUsed, toolResult };
}

function createAgent({ store, model = aiService, runLedger, defaultTimeoutMs, decisionMode } = {}) {
  if (!store && runLedger === undefined) runLedger = require('../agent-runtime/postgresRunLedger').configuredRunLedger();
  const db = store || require('../database/nosqlWorkshopDb');
  // The graph owns NOVA's turn deadline. Keep the selected provider and its
  // captured AbortSignal intact, but do not rotate to another provider after
  // a formatter timeout: that could make an aborted turn look successful.
  const boundedModel = Object.create(model);
  boundedModel.generateResponse = (prompt, options = {}) => model.generateResponse(prompt, {
    ...options, allowFallback: false,
  });
  return createWorkshopGraph({
    name: 'NOVA', store: db, model: boundedModel, runLedger, defaultTimeoutMs, decisionMode,
    detectIntent, blockedResponse,
    validateDecision: (message, decision) => require('./sqlNoSqlExactSearchContract')
      .validateExactSearchDecision('NOVA', message, decision),
    decisionFormat: message => require('./sqlNoSqlExactSearchContract')
      .buildExactSearchDecisionFormat('NOVA', message),
    executeTool: (tool, params, userId, mode) => executeTool(tool, params, userId, mode, db),
    buildResponsePrompt, buildGeneralChatPrompt, generateFallbackResponse,
    formatObservation:formatObservationResult,
    searchTool: 'search_papers', formatSearchResult: formatSearchPapersResult,
  });
}

let graphAgent;
const legacyCoordinator = require('../agent-runtime/runCoordinator').createRunCoordinator({ family: 'NOVA:legacy' });
const getGraphAgent = () => (graphAgent ||= createAgent());
const useLegacy = () => process.env.NOVA_AGENT_RUNTIME === 'legacy';
async function invoke(userId, message, mode = 'fixed', options = {}) {
  if (!useLegacy()) return getGraphAgent().invoke(userId, message, mode, options);
  if(options.wrapExecution!==undefined)throw Object.assign(new Error('Protected graph execution is unavailable in legacy mode'),{code:'PROTECTED_GRAPH_REQUIRED'});
  return legacyCoordinator.run(userId, options, async execution => {
    const result = await legacyChat(userId, message, [], mode);
    await execution.check();
    if (options.onResult) await options.onResult(result, execution.check);
    return result;
  });
}
async function chat(userId, message, conversationHistory = [], mode = 'fixed') {
  return invoke(userId, message, mode);
}
function reset(userId, resetStore) {
  return useLegacy() ? legacyCoordinator.reset(userId, resetStore) : getGraphAgent().reset(userId, resetStore);
}
function cancel(userId) {
  return useLegacy() ? legacyCoordinator.cancel(userId) : getGraphAgent().cancel(userId);
}


function generateFallbackResponse(tool, result) {
  if (!tool || tool === 'general_chat') {
    return "Hello! I'm NOVA, your ResearchVault assistant. I can help you discover papers, explore authors, manage your reading list, and find trending topics. What would you like to explore today?";
  }
  if (!result || (Array.isArray(result) && result.length === 0)) {
    return "I searched the research database but didn't find any matching results. Try a different keyword or check the paper ID.";
  }
  if (result && result.success === false) return result.message || 'Something went wrong. Please try again.';
  return `Here's what I found: ${JSON.stringify(result).substring(0, 300)}`;
}

function formatObservationResult(tool,result) {
  if(tool==='search_papers')return formatSearchPapersResult(result);
  // Exact owned data, not the legacy fallback's abbreviated model substitute.
  const serialized=JSON.stringify(result,null,2);
  const fence='`'.repeat(Math.max(3,...(serialized.match(/`+/g)||[]).map(value=>value.length+1)));
  return `${fence}json\n${serialized}\n${fence}`;
}
module.exports = { chat, invoke, reset, cancel, createAgent, formatObservationResult };
