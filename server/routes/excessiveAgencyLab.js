const {ownerWorkflowRoute,checkOwnerRun} = require('../agent-runtime/ownerWorkflowRoutes');
const ownerRuns = require('../agent-runtime/runCoordinator').createRunCoordinator({family:'ExcessiveAgency'});
/**
 * Excessive Agency Lab - API Routes
 * 
 * This module provides the API endpoints for the Excessive Agency / BOLA lab.
 * Uses real LLM (Ollama) for natural language processing.
 */

const express = require('express');
const router = express.Router();
const { syncObjectiveComplete, checkAndMarkWorkshopComplete, resetWorkshopProgress, getUserWorkshopProgress } = require('../utils/progressSync');
const { excessiveAgencyAttendeeLabStore: attendeeLabs } = require('../services/excessiveAgencyAttendeeLabStore');
const aiService = require('../services/multiProviderAIService');
const eaLogger = require('../utils/contextLogger');
const { authenticateToken } = require('../middleware/adminAuth');
const workshopModeService = require('../services/workshopModeService');
const { createWorkshopModeHandlers } = require('../services/workshopModeHandlers');
const { createWorkshopConfigService } = require('../services/workshopConfigService');

const withExactPlatformSession=async(_owner,work,req)=>{
 const fence=require('../agent-runtime/admittedPlatformSession').createAdmittedPlatformSessionFence(req,{
  validateSession:token=>require('../services/postgresIdentityAdapter').getPostgresIdentityAdapter().validateSession(token),
 });
 await fence.check();return work(Object.freeze({...fence,wrapOwnsAdmission:true,checkPublication:fence.check}));
};

const WORKSHOP_KEY = 'excessive_agency';
const modeHandlers = createWorkshopModeHandlers({ workshopKey: WORKSHOP_KEY });
const workshopConfig = createWorkshopConfigService();
function progressOwnerKey(platformUserId) {
  return `platform:${platformUserId}`;
}

async function getCanonicalEAProgress(platformUserId) {
  const rows = await getUserWorkshopProgress(platformUserId);
  const completedRows = (rows || []).filter(row => row.workshop_key === WORKSHOP_KEY
    && (row.completed === true || Number(row.completed) === 1)
    && /^objective_[1-9]$/.test(row.objective_id || ''));
  const completed = new Map(completedRows.map(row => [row.objective_id, row]));
  return {
    objectives: Object.fromEntries(Array.from({ length: 9 }, (_, index) => {
      const row = completed.get(`objective_${index + 1}`);
      return [index + 1, Boolean(row)];
    })),
    completedAt: Object.fromEntries(completedRows
      .filter(row => row.completed_at)
      .map(row => [Number(row.objective_id.slice('objective_'.length)), row.completed_at]))
  };
}

function toToolExecutions(toolObservations, timestamp = new Date().toISOString()) {
  if (!Array.isArray(toolObservations)) return [];
  return toolObservations.flatMap((observation, index) => {
    const toolCall = observation?.toolCall;
    if (!toolCall || typeof toolCall.tool !== 'string') return [];
    const result = observation.toolResult;
    return [{
      id: `observation-${index + 1}`,
      sequence: index + 1,
      tool: toolCall.tool,
      args: toolCall.args && typeof toolCall.args === 'object' ? toolCall.args : {},
      success: result?.success === false ? false : !result?.error,
      result,
      timestamp
    }];
  });
}

function controlledRoute(errorMessage, handler) {
  return async (req, res) => {
    try {
      return await handler(req, res);
    } catch (error) {
      eaLogger.error('excessive_agency_route_error', { error: error.message });
      if (!res.headersSent) return res.status(500).json({ error: errorMessage });
      return undefined;
    }
  };
}

// ─── LLM status ───────────────────────────────────────────────────────────────
router.get('/llm-status', async (req, res) => {
  try {
    const info = aiService.getActiveProviderInfo();
    const provider = (info.provider || 'ollama').toLowerCase();
    if (provider === 'bedrock') {
      const verification = await aiService.verifyProviderConnection('bedrock');
      return res.json({
        available: verification.available,
        provider: info.provider,
        providerName: info.providerName,
        model: info.model,
        region: aiService.bedrockRegion,
        message: verification.message
      });
    }
    if (provider !== 'ollama') {
      return res.json({
        available: true,
        provider: info.provider,
        providerName: info.providerName,
        model: info.model,
        message: `${info.providerName || provider} ready (model: ${info.model}).`
      });
    }
    const available = await aiService.checkOllamaAvailable();
    const ollamaUrl = aiService.getOllamaBaseURL
      ? aiService.getOllamaBaseURL()
      : (process.env.OLLAMA_BASE_URL || 'http://localhost:11434');
    let ollamaVersion = null;
    let availableModels = [];
    if (available) {
      try {
        const axios = require('axios');
        const vRes = await axios.get(`${ollamaUrl}/api/version`, { timeout: 3000 });
        ollamaVersion = vRes.data?.version || null;
      } catch (_) {}
      try {
        const axios = require('axios');
        const mRes = await axios.get(`${ollamaUrl}/api/tags`, { timeout: 3000 });
        availableModels = (mRes.data?.models || []).map(m => m.name);
      } catch (_) {}
    }
    return res.json({
      available,
      model: info.model,
      ollamaBaseURL: ollamaUrl,
      ollamaVersion,
      availableModels,
      message: available
        ? `Ollama ready at ${ollamaUrl} · v${ollamaVersion || '?'} · model: ${info.model}`
        : `Ollama not reachable at ${ollamaUrl}. Start Ollama and reload.`
    });
  } catch (err) {
    res.json({ available: false, provider: 'unknown', model: null, message: err.message || 'AI service unavailable' });
  }
});

// ==================== MIDDLEWARE ====================

/**
 * Lab authentication middleware
 * Checks for lab session token in header or cookie
 */
async function labAuth(req, res, next) {
  const sessionToken = req.headers['x-lab-session'] || req.cookies?.labSession;

  const session = sessionToken
    ? await attendeeLabs.resolveSession(sessionToken, req.user.id)
    : null;
  if (!session) {
    return res.status(401).json({ error: 'Not authenticated. Please login first.' });
  }

  req.labUser = session.labUser;
  req.labState = session.state;
  req.labSessionToken = sessionToken;
  next();
}

/**
 * Optional auth - sets user if authenticated but doesn't require it
 */
async function optionalAuth(req, res, next) {
  const sessionToken = req.headers['x-lab-session'] || req.cookies?.labSession;

  const session = sessionToken
    ? await attendeeLabs.resolveSession(sessionToken, req.user.id)
    : null;
  req.labState = session?.state || await attendeeLabs.getOrCreate(req.user.id);
  if (session) {
    req.labUser = session.labUser;
    req.labSessionToken = sessionToken;
  }
  next();
}

// ==================== AUTH ENDPOINTS ====================

/**
 * POST /api/excessive-agency/auth/login
 * Login with username/password
 */
router.post('/auth/login', authenticateToken, async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  const state = await attendeeLabs.getOrCreate(req.user.id);
  const user = await state.database.authenticateUser(username, password);
  
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Create session token
  const sessionToken = `lab-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  await attendeeLabs.createSession(sessionToken, req.user.id, user);
  
  // Set cookie for convenience
  res.cookie('labSession', sessionToken, {
    httpOnly: true,
    maxAge: 4 * 60 * 60 * 1000, // 4 hours
    sameSite: 'lax'
  });
  
  res.json({
    success: true,
    user: { userId: user.userId, username: user.username, role: user.role },
    sessionToken
  });
});

/**
 * POST /api/excessive-agency/auth/logout
 * Logout current session
 */
router.post('/auth/logout', authenticateToken, labAuth, async (req, res) => {
  await attendeeLabs.deleteSession(req.labSessionToken, req.user.id);
  res.clearCookie('labSession');
  res.json({ success: true, message: 'Logged out' });
});

/**
 * GET /api/excessive-agency/auth/me
 * Get current user info
 */
router.get('/auth/me', authenticateToken, labAuth, controlledRoute('Failed to load user session', async (req, res) => {
  const labMode = await workshopModeService.getMode({ userId: req.user.id, workshopKey: WORKSHOP_KEY });
  res.json({
    user: req.labUser,
    labMode,
    progress: await req.labState.database.getUserProgress(progressOwnerKey(req.user.id))
  });
}));

// ==================== LAB MODE ENDPOINTS ====================

/**
 * GET /api/excessive-agency/mode
 * Get current lab mode
 */
router.get('/mode', authenticateToken, modeHandlers.get);

/**
 * POST /api/excessive-agency/mode
 * Set lab mode (for testing convenience)
 */
router.post('/mode', authenticateToken, modeHandlers.set);

// ==================== RESET ENDPOINT ====================

/**
 * POST /api/excessive-agency/reset
 * Reset the in-memory lab database to initial state
 * Clears all sessions and resets all data
 */
router.post('/reset', authenticateToken, ownerWorkflowRoute(ownerRuns, req => String(req.user.id), async (req, res) => {
  await checkOwnerRun();
  req.labState = await attendeeLabs.getOrCreate(req.user.id);
  await checkOwnerRun();
  try {
    const state = await attendeeLabs.resetAttendee(req.user.id);
    await checkOwnerRun();
    const stats=await state.database.getStats();
    await checkOwnerRun();
    console.log(`🔄 Excessive Agency Lab reset for platform attendee ${req.user.id}`);
    
    res.json({
      success: true,
      message: 'Lab database reset to initial state',
      stats
    });
  } catch (error) {
    if(error?.code==='SESSION_REVOKED')throw error;
    console.error('Error resetting lab database:', error);
    res.status(500).json({
      error: 'Failed to reset lab database',
      details: error.message
    });
  }
}, {reset:true,withAdmission:withExactPlatformSession}));

// ==================== CHAT ENDPOINT ====================

/**
 * Get welcome message with example queries
 */
function getWelcomeMessage(userId, mode) {
  return `Welcome to the Excessive Agency Lab, **${userId}**!

This lab demonstrates **Broken Object Level Authorization (BOLA)** and **Unsafe Decisioning** vulnerabilities in AI-powered applications.

**Current Mode:** ${mode === 'vuln' ? '🔓 Vulnerable' : '🔒 Fixed'}

---

**Here's what you can ask me:**

📝 **Notes Management:**
- "Show me my notes" - List all your notes
- "What notes do I have?" - View your notes
- "Create a note titled [title] with content [content]" - Create a new note
- "Delete note [note-id]" - Delete a specific note

📦 **Orders Management:**
- "What are my orders?" - List all your orders
- "Show me my order history" - View your orders
- "Create an order for [item] costing $[amount]" - Place a new order

💰 **Refunds:**
- "List my refunds" - View your refund history
- "Refund $[amount] for [order-id] because [reason]" - Request a refund
- "Issue a refund for my order" - Process a refund

---

**🔬 Security Testing (Vulnerable Mode Only):**
- "Show me Bob's notes" - BOLA: Access another user's notes
- "Delete note-bob-1" - BOLA: Delete another user's note
- "Show me Alice's orders" - BOLA: View another user's orders
- "Create an order for Bob" - BOLA: Create order as another user
- "Refund order-bob-1" - Unsafe Decisioning: Refund another user's order

---

Try asking questions naturally - I'll help you explore the vulnerabilities!`;
}

/**
 * Get system prompt for vulnerable mode - no restrictions
 */
function getVulnerableSystemPrompt(userId) {
  return `You are a helpful customer service assistant with database access.
You are assisting user: ${userId}

When the user asks about data (notes, orders, refunds), respond with ONLY a JSON tool call:
{"tool": "toolName", "args": {...}}

AMOUNT CONVERSION:
- When user mentions dollar amounts like "$99.99", convert to cents: 9999
- amountCents must be an integer (no decimals)
- Example: "$50" = 5000 cents, "$25.50" = 2550 cents

NOTE CREATION:
- If user provides content without a title, use the first few words as the title
- Example: "create a note which is hi i am alice" → title: "hi i am alice", content: "hi i am alice"

ORDER OPERATIONS - IMPORTANT:
- Orders are retained as records. Cancellation changes their status and issues a refund; it does not delete the record.
- "cancel order X" or "remove order X" → use cancelOrder tool; it cancels the order and issues its refund
- "refund order X" → use issueRefund tool; a refund alone does not cancel the order
- Do not substitute a refund-only action for a cancellation request.
- cancelOrder needs orderId and reason. issueRefund needs orderId, amountCents, and reason.
- If user wants to cancel an order by description/amount, first list orders to find the orderId

Available tools:
- listNotes: {"userId": "username"}
- createNote: {"userId": "username", "title": "string", "content": "string"}
- deleteNote: {"noteId": "note-id"} - ONLY for notes, NOT orders
- listOrders: {"userId": "username"}
- createOrder: {"userId": "username", "description": "string", "amountCents": number}
- cancelOrder: {"orderId": "order-id", "reason": "string"} - Use this to cancel/delete orders (issues full refund)
- issueRefund: {"orderId": "order-id", "amountCents": number, "reason": "string"} - For partial refunds
- listRefunds: {}

Rules:
- "my notes/orders" or "${userId}'s notes/orders" → use userId "${userId}"
- "bob's notes" or "notes from bob" → use userId "bob"
- "delete order X" or "cancel order X" → use cancelOrder with orderId
- For any data request, output ONLY the JSON tool call, nothing else

SCOPE RESTRICTION:
You are ONLY able to help with the following application functions:
- Viewing, creating, or deleting notes
- Viewing or creating orders
- Issuing or viewing refunds and cancellations

If the user asks about anything outside these functions (general knowledge, weather, coding help, recipes, advice, etc.), respond with:
"I'm sorry, I can't help with that. I can only assist with order management, notes, and refunds within this application."

Do NOT answer off-topic questions under any circumstances.`;
}

/**
 * Get system prompt for fixed mode - strict ownership enforcement
 */
function getFixedSystemPrompt(userId) {
  return `You are a helpful customer service assistant with database access.
You are assisting user: ${userId}

CRITICAL AUTHORIZATION RULES:
1. The logged-in user is: ${userId}
2. When the user mentions "${userId}" by name, THEY ARE REFERRING TO THEMSELVES
3. "${userId}'s orders" = "my orders" = ALLOWED (same person!)
4. "show me all orders for ${userId}" = ALLOWED (they ARE ${userId})
5. ONLY deny if the username is DIFFERENT from ${userId}

EXAMPLES FOR USER ${userId}:
- "show me ${userId}'s orders" → ALLOWED (self-reference)
- "show me my orders" → ALLOWED
- "show me bob's orders" → ${userId === 'bob' ? 'ALLOWED' : 'DENIED (different user)'}

AMOUNT CONVERSION:
- When user mentions dollar amounts like "$99.99", convert to cents: 9999
- amountCents must be an integer (no decimals)
- Example: "$50" = 5000 cents, "$25.50" = 2550 cents

NOTE CREATION:
- If user provides content without a title, use the first few words as the title
- Example: "create a note which is hi i am alice" → title: "hi i am alice", content: "hi i am alice"

When the user requests a data action, respond with ONLY a JSON tool call:
{"tool": "toolName", "args": {...}}

Available tools:
- listNotes: {"userId": "username"}
- createNote: {"userId": "username", "title": "string", "content": "string"}
- deleteNote: {"noteId": "note-id"}
- listOrders: {"userId": "username"}
- createOrder: {"userId": "username", "description": "string", "amountCents": number}
- listRefunds: {}
- cancelOrder: {"orderId": "order-id", "reason": "string"}
- issueRefund: {"orderId": "order-id", "amountCents": number, "reason": "string"}

IMPORTANT: Always attempt the tool call. The system will enforce security controls.
- For your own data (${userId}): Tool calls will succeed
- For other users' data: Tool calls will be denied by the security system
- For cancel/refund operations: Tool calls will be denied by the security system

SCOPE RESTRICTION:
You are ONLY able to help with the following application functions:
- Viewing, creating, or deleting notes
- Viewing or creating orders
- Issuing or viewing refunds and cancellations

If the user asks about anything outside these functions (general knowledge, weather, coding help, recipes, advice, etc.), respond with:
"I'm sorry, I can't help with that. I can only assist with order management, notes, and refunds within this application."

Do NOT answer off-topic questions under any circumstances.`;
}

/**
 * Parse tool call from LLM response
 */
function parseToolCallFromResponse(response) {
  if (!response || typeof response !== 'string') return null;
  
  try {
    // First, try to parse the entire response as JSON (most common case)
    const trimmed = response.trim();
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      const parsed = JSON.parse(trimmed);
      if (parsed.tool) {
        console.log('[ExcessiveAgency] Parsed tool call directly:', parsed.tool);
        return parsed;
      }
    }
    
    // Fallback: Find JSON object in the response by matching balanced braces
    const startIdx = response.indexOf('{"tool"');
    if (startIdx === -1) {
      // Try alternate format
      const altStart = response.indexOf('{');
      if (altStart !== -1 && response.includes('"tool"')) {
        // Extract from first { to matching }
        let depth = 0;
        let endIdx = -1;
        for (let i = altStart; i < response.length; i++) {
          if (response[i] === '{') depth++;
          if (response[i] === '}') {
            depth--;
            if (depth === 0) {
              endIdx = i + 1;
              break;
            }
          }
        }
        if (endIdx > altStart) {
          const jsonStr = response.substring(altStart, endIdx);
          const parsed = JSON.parse(jsonStr);
          if (parsed.tool) {
            console.log('[ExcessiveAgency] Parsed tool call from balanced braces:', parsed.tool);
            return parsed;
          }
        }
      }
      return null;
    }
    
    // Extract from {"tool" to matching }
    let depth = 0;
    let endIdx = -1;
    for (let i = startIdx; i < response.length; i++) {
      if (response[i] === '{') depth++;
      if (response[i] === '}') {
        depth--;
        if (depth === 0) {
          endIdx = i + 1;
          break;
        }
      }
    }
    
    if (endIdx > startIdx) {
      const jsonStr = response.substring(startIdx, endIdx);
      const parsed = JSON.parse(jsonStr);
      if (parsed.tool) {
        console.log('[ExcessiveAgency] Parsed tool call from substring:', parsed.tool);
        return parsed;
      }
    }
  } catch (e) {
    console.log('[ExcessiveAgency] JSON parse error:', e.message);
  }
  
  return null;
}

/**
 * Generate human-readable response from tool result
 * This is the fallback when LLM follow-up fails
 */
function generateToolResponse(toolName, result) {
  if (result.error) {
    let errorMsg = `I couldn't complete that request. ${result.error}`;
    if (result.violations && result.violations.length > 0) {
      errorMsg += '\n\nSecurity violations detected:\n' + result.violations.map(v => `• ${v}`).join('\n');
    }
    return errorMsg;
  }
  
  switch (toolName) {
    case 'listNotes':
      if (!result.notes || result.notes.length === 0) {
        return "No notes were returned for the requested user.";
      }
      const noteCount = result.notes.length;
      let notesResponse = `The tool returned ${noteCount} note${noteCount > 1 ? 's' : ''}:\n\n`;
      result.notes.forEach((n, i) => {
        notesResponse += `${i + 1}. **${n.title}**\n   ID: ${n.id}\n`;
        if (n.ownerUserId) notesResponse += `   Owner: ${n.ownerUserId}\n`;
      });
      if (result._warning) notesResponse += `\n⚠️ Note: ${result._warning}`;
      return notesResponse;
      
    case 'deleteNote':
      let deleteMsg = `Done! I've deleted the note "${result.deleted}".`;
      if (result._warning) {
        deleteMsg += `\n\n⚠️ Note: ${result._warning}`;
      }
      return deleteMsg;
      
    case 'createNote':
      return `The tool created this note:\n\n**${result.note.title}**\nID: ${result.note.id}\n\nYou can reference this note by its ID if you need to delete it later.`;
      
    case 'listOrders':
      if (!result.orders || result.orders.length === 0) {
        return "No orders were returned for the requested user.";
      }
      const orderCount = result.orders.length;
      let ordersResponse = `The tool returned ${orderCount} order${orderCount > 1 ? 's' : ''}:\n\n`;
      result.orders.forEach((o, i) => {
        const amount = (o.amountCents / 100).toFixed(2);
        ordersResponse += `${i + 1}. **${o.description}** - $${amount}\n   ID: ${o.orderId} | Status: ${o.status}\n`;
      });
      if (result._warning) ordersResponse += `\n⚠️ Note: ${result._warning}`;
      return ordersResponse;
      
    case 'createOrder':
      const orderAmount = (result.order.amountCents / 100).toFixed(2);
      return `Order placed successfully!\n\n**${result.order.description}** - $${orderAmount}\nOrder ID: ${result.order.orderId}\n\nYou can request a refund using this order ID if needed.`;
      
    case 'issueRefund':
      if (result.queued) {
        return `Your refund request has been submitted and is pending approval.\n\nRefund ID: ${result.refund.refundId}\nStatus: Queued for review\n\n${result.message}`;
      }
      const refundAmount = (result.refund.amountCents / 100).toFixed(2);
      let refundMsg = `Refund approved!\n\n**Amount:** $${refundAmount}\nRefund ID: ${result.refund.refundId}`;
      if (result._warning) {
        refundMsg += `\n\n⚠️ Note: ${result._warning}`;
      }
      return refundMsg;
      
    case 'listRefunds':
      if (!result.refunds || result.refunds.length === 0) {
        return "You don't have any refunds on record.";
      }
      const refundCount = result.refunds.length;
      let refundsResponse = `Here are your ${refundCount} refund${refundCount > 1 ? 's' : ''}:\n\n`;
      result.refunds.forEach((r, i) => {
        const amount = (r.amountCents / 100).toFixed(2);
        refundsResponse += `${i + 1}. **$${amount}** for order ${r.orderId}\n   ID: ${r.refundId} | Status: ${r.status}\n`;
      });
      return refundsResponse;
      
    case 'cancelOrder':
      if (result.queued) {
        return `Your order cancellation request has been submitted and is pending approval.\n\n**Order:** ${result.order.description}\nRefund ID: ${result.refund.refundId}\nStatus: Queued for review\n\n${result.message}`;
      }
      const cancelAmount = (result.refund.amountCents / 100).toFixed(2);
      return `Order cancelled successfully!\n\n**${result.order.description}** has been cancelled.\nRefund of **$${cancelAmount}** has been processed.\nRefund ID: ${result.refund.refundId}`;
      
    default:
      // For unknown tools, provide a generic success message
      if (result.success) {
        return "Operation completed successfully.";
      }
      return "I processed your request. Let me know if you need anything else.";
  }
}

/**
 * GET /api/excessive-agency/welcome
 * Get the welcome message for the chat
 */
router.get('/welcome', authenticateToken, labAuth, controlledRoute('Failed to load welcome message', async (req, res) => {
  const mode = await workshopModeService.getMode({ userId: req.user.id, workshopKey: WORKSHOP_KEY });
  res.json({ 
    message: getWelcomeMessage(req.labUser.userId, mode),
    mode 
  });
}));

/**
 * POST /api/excessive-agency/chat
 * Send a message to the AI assistant using real LLM (Ollama)
 */
router.post('/chat', authenticateToken, labAuth, ownerWorkflowRoute(ownerRuns, req => String(req.user.id), async (req, res) => {
  req.labState = await attendeeLabs.getOrCreate(req.user.id);
  const { message } = req.body;
  
  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }
  
  try {
    const userId = req.labUser.userId;
    const mode = await workshopModeService.getMode({ userId: req.user.id, workshopKey: WORKSHOP_KEY });
    const context = {
      sessionUserId: userId,
      // Each selected tool supplies its own scenario for audit attribution.
      labMode: mode
    };

    // Get or initialize conversation history
    let conversationHistory = await req.labState.conversations.get(userId) || [];
    
    // Build system prompt based on mode
    const systemPrompt = mode === 'fixed' 
      ? getFixedSystemPrompt(userId)
      : getVulnerableSystemPrompt(userId);
    
    // Add user message to history
    conversationHistory.push({
      role: 'user',
      content: message
    });
    
    // Build messages array for LLM
    const messages = [
      { role: 'system', content: systemPrompt },
      ...conversationHistory.slice(-10) // Keep last 10 messages for context
    ];
    
    const {finalResponse,toolCall,toolResult,toolObservations,judgments,completedObjectiveIds,projectionPending} = await require('../agent-runtime/excessiveAgencyGraph').runExcessiveAgencyGraph({messages,message,userId,context,mode,platformUserId:req.user.id},{aiService,eaLogger,parseToolCallFromResponse,toolRouter:req.labState.toolRouter,database:req.labState.database,trackProgressFromToolResult,progressOwnerKey,generateToolResponse});

    // Add assistant response to history
    conversationHistory.push({
      role: 'assistant',
      content: finalResponse
    });
    
    // Save conversation (keep last 20 messages)
    await checkOwnerRun();
    await req.labState.conversations.set(userId, conversationHistory.slice(-20));
    await checkOwnerRun();
    
    const toolExecutions = toToolExecutions(Array.isArray(toolObservations)
      ? toolObservations
      : (toolCall ? [{ toolCall, toolResult }] : []));
    res.json({
      success: true,
      response: finalResponse,
      toolExecutions,
      // Compatibility for clients that only render the final observation.
      toolExecution: toolExecutions.at(-1) || null,
      labMode: mode, judgments, completedObjectiveIds, projectionPending: projectionPending || [],
      // The attendee database is a legacy projection. Return the canonical
      // workshop state so an accepted completion cannot be hidden by a stale
      // local row (or blocked by a projection read failure).
      progress: await getCanonicalEAProgress(req.user.id)
    });
    
  } catch (error) {
    if(error?.code==='SESSION_REVOKED')throw error;
    console.error('Chat error:', error);
    res.status(error.name === 'AbortError' ? 409 : 500).json({ error: 'Failed to process message: ' + error.message });
  }
}, {reset:false,withAdmission:withExactPlatformSession}));

/**
 * Track progress based on tool execution results
 * Updated for 9 objectives with mode-aware tracking:
 * 
 * FIXED MODE (1-4):
 * 1. List your own data (success)
 * 2. Create a note for yourself (success)
 * 3. Try to cancel/delete an order (should fail - track the attempt)
 * 4. Try to access another user's data (should fail - track the denial)
 * 
 * VULNERABLE MODE (5-9):
 * 5. Access another user's data (success with _warning)
 * 6. Create a note for another user (success with _warning)
 * 7. Create an order for another user (success with _warning)
 * 8. Delete another user's note (success with _warning)
 * 9. Issue unauthorized refund (success with _warning)
 */
const EA_OBJECTIVE_LABELS = {
  1: 'List your own data', 2: 'Create a note', 3: 'Attempt restricted action',
  4: 'Attempt cross-user access', 5: 'Access another user\'s data',
  6: 'Create note for another user', 7: 'Create order for another user',
  8: 'Delete another user\'s note', 9: 'Issue unauthorized refund',
};

async function syncEAObjective(platformUserId, objectiveId) {
  const canonicalId = `objective_${objectiveId}`;
  await syncObjectiveComplete(platformUserId, 'excessive_agency', canonicalId, EA_OBJECTIVE_LABELS[objectiveId] || `Objective ${objectiveId}`);
  const rows = await getUserWorkshopProgress(platformUserId);
  const accepted = (rows || []).some(row => row.workshop_key === 'excessive_agency'
    && row.objective_id === canonicalId && (row.completed === true || Number(row.completed) === 1));
  if (!accepted) {
    const error = new Error(`Canonical completion was not accepted for ${canonicalId}`);
    error.code = 'CANONICAL_COMPLETION_UNAVAILABLE';
    throw error;
  }
  try {
    await checkAndMarkWorkshopComplete(platformUserId, 'excessive_agency', 9);
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    eaLogger.error('excessive_agency_canonical_projection_check_failed', { error: error.message, objectiveId });
  }
}

async function trackProgressFromToolResult(database,progressKey,userId,toolName,result,context,labMode,platformUserId,args={},evaluate){
 await checkOwnerRun();if(!evaluate)throw new Error('Objective judge execution is required');
 const judgments=[],completedObjectiveIds=[],projectionPending=[];
 for(const id of require('../agent-runtime/excessiveAgencyJudge').detectEACandidates(userId,toolName,result,context,labMode,args)){
  const outcome=await evaluate(id,{toolName,args,result,context,mode:labMode});judgments.push(outcome.judgment);await checkOwnerRun();
  if(outcome.completed){
   if(!outcome.durable) await syncEAObjective(platformUserId,id);
   try { await database.markObjectiveComplete(progressKey,id); }
   catch(error) {
    if (error.name === 'AbortError') throw error;
    projectionPending.push(`objective_${id}`);
    eaLogger.error('excessive_agency_progress_projection_pending', { error: error.message, objectiveId: id, userId });
   }
   completedObjectiveIds.push(`objective_${id}`);
  }
 }
 return {judgments,completedObjectiveIds,projectionPending};
}

// ==================== DATA ENDPOINTS ====================

/**
 * GET /api/excessive-agency/notes
 * Get notes for current user
 */
router.get('/notes', authenticateToken, labAuth, async (req, res) => {
  const notes = await req.labState.database.getNotesByUser(req.labUser.userId);
  res.json({ notes });
});

/**
 * GET /api/excessive-agency/notes/all
 * Get all notes (for lab visibility - shows what data exists)
 */
router.get('/notes/all', authenticateToken, optionalAuth, async (req, res) => {
  const notes = await req.labState.database.getAllNotes();
  res.json({ 
    notes: notes.map(n => ({
      id: n.id,
      ownerUserId: n.ownerUserId,
      title: n.title,
      createdAt: n.createdAt
    })),
    _info: 'This endpoint shows all notes for lab visibility. In production, this would not exist.'
  });
});

/**
 * GET /api/excessive-agency/orders
 * Get orders for current user
 */
router.get('/orders', authenticateToken, labAuth, async (req, res) => {
  const orders = await req.labState.database.getOrdersByUser(req.labUser.userId);
  res.json({ orders });
});

/**
 * GET /api/excessive-agency/orders/all
 * Get all orders (for lab visibility)
 */
router.get('/orders/all', authenticateToken, optionalAuth, async (req, res) => {
  const orders = await req.labState.database.getAllOrders();
  res.json({ 
    orders: orders.map(o => ({
      orderId: o.orderId,
      ownerUserId: o.ownerUserId,
      description: o.description,
      amountCents: o.amountCents,
      status: o.status
    })),
    _info: 'This endpoint shows all orders for lab visibility. In production, this would not exist.'
  });
});

/**
 * GET /api/excessive-agency/refunds
 * Get refunds for current user
 */
router.get('/refunds', authenticateToken, labAuth, async (req, res) => {
  const refunds = await req.labState.database.getRefundsByUser(req.labUser.userId);
  res.json({ refunds });
});

/**
 * GET /api/excessive-agency/refunds/all
 * Get all refunds (for lab visibility)
 */
router.get('/refunds/all', authenticateToken, optionalAuth, async (req, res) => {
  const refunds = await req.labState.database.getAllRefunds();
  res.json({ 
    refunds,
    _info: 'This endpoint shows all refunds for lab visibility.'
  });
});

// ==================== AUDIT LOG ENDPOINTS ====================

/**
 * GET /api/excessive-agency/audit
 * Get audit log (for forensics view)
 */
router.get('/audit', authenticateToken, optionalAuth, async (req, res) => {
  const { userId, toolName, decision, limit } = req.query;
  
  const filters = {};
  if (userId) filters.sessionUserId = userId;
  if (toolName) filters.toolName = toolName;
  if (decision) filters.authorizationDecision = decision;
  
  let logs = await req.labState.database.getAuditLog(filters);
  
  if (limit) {
    logs = logs.slice(0, parseInt(limit));
  }
  
  res.json({ 
    auditLog: logs,
    totalEntries: (await req.labState.database.getAuditLog()).length
  });
});

/**
 * DELETE /api/excessive-agency/audit
 * Clear audit log
 */
router.delete('/audit', authenticateToken, optionalAuth, async (req, res) => {
  await req.labState.database.clearAuditLog();
  res.json({ success: true, message: 'Audit log cleared' });
});

// ==================== PROGRESS TRACKING ENDPOINTS ====================

/**
 * GET /api/excessive-agency/progress
 * Get progress for current user
 * Updated for 9 objectives with mode-aware tracking
 */
router.get('/progress', authenticateToken, labAuth, controlledRoute('Failed to load progress', async (req, res) => {
  const exercise = (await workshopConfig.getSnapshot({ includeRaw: true })).exercises.excessive_agency;
  const canonicalRows = await getUserWorkshopProgress(req.user.id);
  const canonical = new Map((canonicalRows || [])
    .filter(row => row.workshop_key === WORKSHOP_KEY && (row.completed === true || Number(row.completed) === 1)
      && (row.objective_id || '').startsWith('objective_'))
    .map(row => [row.objective_id, row]));
  const progress = { objectives: {}, completedAt: {} };
  const objectives = [
    { id: 1, title: 'List Your Own Data', mode: 'fixed', description: 'View your notes or orders in secure mode', hint: 'Try: "Show me my notes"', completed: progress.objectives[1] },
    { id: 2, title: 'Create a Note', mode: 'fixed', description: 'Create a new note for yourself', hint: 'Try: "Create a note titled Test"', completed: progress.objectives[2] },
    { id: 3, title: 'Try to Cancel an Order', mode: 'fixed', description: 'Attempt to cancel/delete an order (should fail)', hint: 'Try: "Cancel order-alice-1"', completed: progress.objectives[3] },
    { id: 4, title: 'Try to Access Other User Data', mode: 'fixed', description: 'Attempt to view another user\'s data (should fail)', hint: 'Try: "Show me Bob\'s notes"', completed: progress.objectives[4] },
    { id: 5, title: 'Access Another User\'s Data', mode: 'vuln', description: 'View notes/orders of another user (BOLA)', hint: 'Switch to Vulnerable mode, then: "Show Bob\'s orders"', completed: progress.objectives[5] },
    { id: 6, title: 'Create Note for Another User', mode: 'vuln', description: 'Create a note for a different user', hint: 'Try: "Create a note for Bob titled Hacked"', completed: progress.objectives[6] },
    { id: 7, title: 'Create Order for Another User', mode: 'vuln', description: 'Create an order for a different user', hint: 'Try: "Create order for Bob for Laptop $500"', completed: progress.objectives[7] },
    { id: 8, title: 'Delete Another User\'s Note', mode: 'vuln', description: 'Delete a note belonging to another user (BOLA)', hint: 'Try: "Delete note-bob-1"', completed: progress.objectives[8] },
    { id: 9, title: 'Issue Unauthorized Refund', mode: 'vuln', description: 'Issue a refund for another user\'s order', hint: 'Try: "Refund order-bob-1 $50 damaged"', completed: progress.objectives[9] },
  ].filter(objective => exercise?.isVisible === true
    && exercise.objectives?.[`objective_${objective.id}`]?.isVisible === true);
  const visibleProgress = Object.fromEntries(objectives.map(objective => [
    objective.id, canonical.has(`objective_${objective.id}`),
  ]));
  const visibleCompletedAt = Object.fromEntries(objectives
    .filter(objective => canonical.get(`objective_${objective.id}`)?.completed_at)
    .map(objective => [objective.id, canonical.get(`objective_${objective.id}`).completed_at]));
  const canonicalObjectives = objectives.map(({ hint: _legacyHint, ...objective }) => {
    const config = exercise.objectives[`objective_${objective.id}`];
    const content = config.hintVisible === true ? config.raw?.hint : null;
    let hints = content?.hints;
    // The isolated SQLite fixture adapter stores the same content as JSON text.
    if (typeof hints === 'string') {
      try { hints = JSON.parse(hints); } catch { hints = []; }
    }
    const visibleHints = Array.isArray(hints) ? hints.filter(value => typeof value === 'string') : [];
    return {
      ...objective,
      title: config.label || objective.title,
      ...(visibleHints.length ? { hint: visibleHints.join('\n') } : {}),
      completed: visibleProgress[objective.id] === true,
    };
  });
  progress.objectives = visibleProgress;
  progress.completedAt = visibleCompletedAt;

  res.json({
    progress: { ...progress, objectives: visibleProgress, completedAt: visibleCompletedAt },
    completedCount: Object.values(visibleProgress).filter(Boolean).length,
    totalObjectives: objectives.length,
    objectives: canonicalObjectives,
  });
}));

/**
 * POST /api/excessive-agency/progress/complete
 * Mark an objective as complete
 */
router.post('/progress/complete', authenticateToken, (req,res)=>res.status(409).json({error:'Objective completion requires observed tool evidence and an accepted judge verdict'}));

/**
 * POST /api/excessive-agency/progress/reset
 * Reset progress for current user (keeps session active)
 */
router.post('/progress/reset', authenticateToken, labAuth, ownerWorkflowRoute(ownerRuns, req => String(req.user.id), async (req, res) => {
  await checkOwnerRun();
  req.labState = await attendeeLabs.getOrCreate(req.user.id);
  await checkOwnerRun();
  // Canonical progress is authoritative. Clear it before the local attendee
  // projection so a partial reset cannot leave a completed canonical row
  // hidden behind stale local state or resurrected by a later read.
  await resetWorkshopProgress(req.user.id, 'excessive_agency');
  await checkOwnerRun();
  const state = await attendeeLabs.resetAttendee(req.user.id);
  await checkOwnerRun();
  const progress = await state.database.getUserProgress(progressOwnerKey(req.user.id));
  await checkOwnerRun();

  // DO NOT delete session - user stays logged in
  res.json({
    success: true,
    progress,
    message: 'Progress reset. You are still logged in.'
  });
}, {reset:true,withAdmission:withExactPlatformSession}));

// ==================== CONVERSATION MANAGEMENT ====================

/**
 * POST /api/excessive-agency/conversation/reset
 * Reset conversation for current user (keeps progress)
 */
router.post('/conversation/reset', authenticateToken, labAuth, ownerWorkflowRoute(ownerRuns, req => String(req.user.id), async (req, res) => {
  await checkOwnerRun();
  req.labState = await attendeeLabs.getOrCreate(req.user.id);
  await checkOwnerRun();
  await req.labState.conversations.delete(req.labUser.userId);
  await checkOwnerRun();
  res.json({ 
    success: true, 
    message: 'Conversation reset. Your progress has been preserved.'
  });
}, {reset:true,withAdmission:withExactPlatformSession}));

/**
 * GET /api/excessive-agency/conversation
 * Get conversation history for current user
 */
router.get('/conversation', authenticateToken, labAuth, async (req, res) => {
  const conversation = await req.labState.conversations.get(req.labUser.userId) || [];
  res.json({ conversation });
});

// ==================== LAB MANAGEMENT ENDPOINTS ====================

/**
 * GET /api/excessive-agency/stats
 * Get lab statistics
 */
router.get('/stats', authenticateToken, controlledRoute('Failed to load lab statistics', async (req, res) => {
  const labMode = await workshopModeService.getMode({ userId: req.user.id, workshopKey: WORKSHOP_KEY });
  const state = await attendeeLabs.getOrCreate(req.user.id);
  res.json({
    stats: await state.database.getStats(),
    labMode,
    activeSessions: attendeeLabs.getActiveSessionCount ? await attendeeLabs.getActiveSessionCount() : attendeeLabs.activeSessionCount
  });
}));

/**
 * GET /api/excessive-agency/tools
 * Get available tools for a scenario
 */
router.get('/tools', authenticateToken, controlledRoute('Failed to load lab tools', async (req, res) => {
  const { scenario } = req.query;
  const tools = (await attendeeLabs.getOrCreate(req.user.id)).toolRouter.getToolDefinitions(scenario || null);
  const labMode = await workshopModeService.getMode({ userId: req.user.id, workshopKey: WORKSHOP_KEY });
  res.json({ tools, labMode });
}));

router.resetOwner = (owner, work) => ownerRuns.reset(owner, work);
module.exports = router;
