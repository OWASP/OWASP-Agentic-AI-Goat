/**
 * Excessive Agency Lab - Tool Router
 * 
 * This module implements the tool router for the Excessive Agency / BOLA lab.
 * It supports two request-scoped modes supplied in the execution context:
 * - 'vuln': Vulnerable mode - tools execute without proper authorization
 * - 'fixed': Fixed mode - tools enforce proper access control (ABAC)
 */

const labDb = require('../database/excessiveAgencyLabDb');

class ExcessiveAgencyToolRouter {
  constructor(database = labDb) {
    this.labDb = database;
    // Tool definitions with schemas
    this.toolDefinitions = {
      // Notes tools (BOLA)
      listNotes: {
        name: 'listNotes',
        description: 'List notes for a user',
        params: [{ name: 'userId', type: 'string', required: false }],
        scenario: 'A'
      },
      deleteNote: {
        name: 'deleteNote',
        description: 'Delete a note by ID',
        mutates: true,
        params: [{ name: 'noteId', type: 'string', required: true }],
        scenario: 'A'
      },
      createNote: {
        name: 'createNote',
        description: 'Create a new note for a user',
        mutates: true,
        params: [
          { name: 'userId', type: 'string', required: false },
          { name: 'title', type: 'string', required: false },
          { name: 'content', type: 'string', required: true }
        ],
        scenario: 'A'
      },
      
      // Orders tools (BOLA + Unsafe Decisioning)
      listOrders: {
        name: 'listOrders',
        description: 'List orders for a user',
        params: [{ name: 'userId', type: 'string', required: false }],
        scenario: 'B'
      },
      createOrder: {
        name: 'createOrder',
        description: 'Create a new order for a user',
        mutates: true,
        params: [
          { name: 'userId', type: 'string', required: false },
          { name: 'description', type: 'string', required: true },
          { name: 'amountCents', type: 'number', required: true }
        ],
        scenario: 'B'
      },
      issueRefund: {
        name: 'issueRefund',
        description: 'Issue a refund for an order',
        mutates: true,
        params: [
          { name: 'orderId', type: 'string', required: true },
          { name: 'amountCents', type: 'number', required: true },
          { name: 'reason', type: 'string', required: true }
        ],
        scenario: 'B'
      },
      listRefunds: {
        name: 'listRefunds',
        description: 'List all refunds',
        params: [],
        scenario: 'B'
      },
      cancelOrder: {
        name: 'cancelOrder',
        description: 'Cancel an order by issuing a full refund',
        mutates: true,
        params: [
          { name: 'orderId', type: 'string', required: true },
          { name: 'reason', type: 'string', required: false }
        ],
        scenario: 'B'
      }
    };
  }

  /**
   * Get tool definitions for a scenario
   */
  getToolDefinitions(scenario = null) {
    if (scenario) {
      return Object.values(this.toolDefinitions).filter(t => t.scenario === scenario);
    }
    return Object.values(this.toolDefinitions);
  }

  /**
   * Validate tool arguments against schema
   */
  validateArgs(toolName, args) {
    const tool = this.toolDefinitions[toolName];
    if (!tool) {
      return { valid: false, error: `Unknown tool: ${toolName}` };
    }

    for (const param of tool.params) {
      if (param.required && (args[param.name] === undefined || args[param.name] === null)) {
        return { valid: false, error: `Missing required parameter: ${param.name}` };
      }
      if (args[param.name] !== undefined && param.type === 'number' && typeof args[param.name] !== 'number') {
        return { valid: false, error: `Parameter ${param.name} must be a number` };
      }
    }

    return { valid: true };
  }

  /**
   * Execute a tool with the given context
   * @param {string} toolName - Name of the tool to execute
   * @param {object} args - Tool arguments
   * @param {object} context - Execution context { sessionUserId, scenario }
   */
  async executeTool(toolName, args, context) {
    const startTime = Date.now();
    
    // Validate tool exists
    if (!this.toolDefinitions[toolName]) {
      return this._logAndReturn(context, toolName, args, 'INVALID_TOOL', {
        error: `Unknown tool: ${toolName}`
      });
    }

    // Validate arguments
    const validation = this.validateArgs(toolName, args);
    if (!validation.valid) {
      return this._logAndReturn(context, toolName, args, 'INVALID_ARGS', {
        error: validation.error
      });
    }

    // Execute tool based on mode
    try {
      let result;
      
      switch (toolName) {
        case 'listNotes':
          result = await this._executeListNotes(args.userId, context);
          break;
        case 'deleteNote':
          result = await this._executeDeleteNote(args.noteId, context);
          break;
        case 'createNote':
          result = await this._executeCreateNote(args.userId, args.title, args.content || args.body, context);
          break;
        case 'listOrders':
          result = await this._executeListOrders(args.userId, context);
          break;
        case 'createOrder':
          result = await this._executeCreateOrder(args.userId, args.description, args.amountCents, context);
          break;
        case 'issueRefund':
          result = await this._executeIssueRefund(args.orderId, args.amountCents, args.reason, context);
          break;
        case 'listRefunds':
          result = await this._executeListRefunds(context);
          break;
        case 'cancelOrder':
          result = await this._executeCancelOrder(args.orderId, args.reason, context);
          break;
        default:
          result = { error: `Tool not implemented: ${toolName}` };
      }

      result._executionTimeMs = Date.now() - startTime;
      return result;
      
    } catch (error) {
      console.error(`Tool execution error [${toolName}]:`, error);
      return this._logAndReturn(context, toolName, args, 'ERROR', {
        error: `Tool execution failed: ${error.message}`
      });
    }
  }

  // ==================== NOTES TOOLS (BOLA) ====================

  async _executeListNotes(targetUserId, context) {
    // Determine which user's notes to list
    const userId = targetUserId || context.sessionUserId;
    const isOwnData = userId === context.sessionUserId;
    
    if (context.labMode === 'vuln') {
      // VULNERABLE: Allow listing any user's notes
      const notes = await this.labDb.getNotesByUser(userId);
      return this._logAndReturn(context, 'listNotes', { userId }, 'ALLOWED', {
        success: true,
        notes: notes.map(n => ({ id: n.id, title: n.title, ownerUserId: n.ownerUserId, createdAt: n.createdAt })),
        _warning: isOwnData ? undefined : `VULNERABLE MODE: Accessed ${userId}'s notes without authorization`
      });
    } else {
      // FIXED: Only allow listing own notes
      if (!isOwnData) {
        return this._logAndReturn(context, 'listNotes', { userId }, 'DENIED', {
          error: 'Access denied - you can only view your own notes',
          _info: 'FIXED MODE: Ownership check enforced'
        });
      }
      
      const notes = await this.labDb.getNotesByUser(context.sessionUserId);
      return this._logAndReturn(context, 'listNotes', { userId }, 'ALLOWED', {
        success: true,
        notes: notes.map(n => ({ id: n.id, title: n.title, createdAt: n.createdAt }))
      });
    }
  }

  async _executeDeleteNote(noteId, context) {
    const note = await this.labDb.getNote(noteId);
    
    if (!note) {
      return this._logAndReturn(context, 'deleteNote', { noteId }, 'NOT_FOUND', {
        error: 'Note not found'
      });
    }

    const isOwnNote = note.ownerUserId === context.sessionUserId;

    if (context.labMode === 'vuln') {
      // VULNERABLE: No ownership check - deletes any note
      await this.labDb.deleteNote(noteId);
      return this._logAndReturn(context, 'deleteNote', { noteId }, 'ALLOWED', {
        success: true,
        deleted: noteId,
        _warning: isOwnNote ? undefined : `VULNERABLE MODE: Deleted ${note.ownerUserId}'s note without authorization`
      });
    } else {
      // FIXED: Enforce ownership (ABAC)
      if (!isOwnNote) {
        return this._logAndReturn(context, 'deleteNote', { noteId }, 'DENIED', {
          error: 'Access denied - you can only delete your own notes',
          _info: 'FIXED MODE: Ownership check enforced'
        });
      }
      
      await this.labDb.deleteNote(noteId);
      return this._logAndReturn(context, 'deleteNote', { noteId }, 'ALLOWED', {
        success: true,
        deleted: noteId
      });
    }
  }

  async _executeCreateNote(targetUserId, title, content, context) {
    // Determine which user to create note for
    const userId = targetUserId || context.sessionUserId;
    const isOwnNote = userId === context.sessionUserId;
    
    // Generate title from content if not provided
    const noteTitle = title || (content ? content.substring(0, 50).trim() : 'Untitled Note');
    
    if (context.labMode === 'vuln') {
      // VULNERABLE: Allow creating notes for any user
      const note = await this.labDb.createNote(userId, noteTitle, content);
      return this._logAndReturn(context, 'createNote', { userId, title: noteTitle }, 'ALLOWED', {
        success: true,
        note: { id: note.id, title: note.title, ownerUserId: note.ownerUserId, createdAt: note.createdAt },
        _warning: isOwnNote ? undefined : `VULNERABLE MODE: Created note for ${userId} without authorization`
      });
    } else {
      // FIXED: Only allow creating own notes
      if (!isOwnNote) {
        return this._logAndReturn(context, 'createNote', { userId, title: noteTitle }, 'DENIED', {
          error: 'Access denied - you can only create notes for yourself',
          _info: 'FIXED MODE: Ownership check enforced'
        });
      }
      
      const note = await this.labDb.createNote(context.sessionUserId, noteTitle, content);
      return this._logAndReturn(context, 'createNote', { userId, title: noteTitle }, 'ALLOWED', {
        success: true,
        note: { id: note.id, title: note.title, createdAt: note.createdAt }
      });
    }
  }

  // ==================== ORDERS TOOLS (BOLA + UNSAFE DECISIONING) ====================

  async _executeListOrders(targetUserId, context) {
    // Determine which user's orders to list
    const userId = targetUserId || context.sessionUserId;
    const isOwnData = userId === context.sessionUserId;
    
    if (context.labMode === 'vuln') {
      // VULNERABLE: Allow listing any user's orders
      const orders = await this.labDb.getOrdersByUser(userId);
      return this._logAndReturn(context, 'listOrders', { userId }, 'ALLOWED', {
        success: true,
        orders: orders.map(o => ({
          orderId: o.orderId,
          ownerUserId: o.ownerUserId,
          description: o.description,
          amountCents: o.amountCents,
          status: o.status,
          refundableUntil: o.refundableUntil
        })),
        _warning: isOwnData ? undefined : `VULNERABLE MODE: Accessed ${userId}'s orders without authorization`
      });
    } else {
      // FIXED: Only allow listing own orders
      if (!isOwnData) {
        return this._logAndReturn(context, 'listOrders', { userId }, 'DENIED', {
          error: 'Access denied - you can only view your own orders',
          _info: 'FIXED MODE: Ownership check enforced'
        });
      }
      
      const orders = await this.labDb.getOrdersByUser(context.sessionUserId);
      return this._logAndReturn(context, 'listOrders', { userId }, 'ALLOWED', {
        success: true,
        orders: orders.map(o => ({
          orderId: o.orderId,
          description: o.description,
          amountCents: o.amountCents,
          status: o.status,
          refundableUntil: o.refundableUntil
        }))
      });
    }
  }

  async _executeCreateOrder(targetUserId, description, amountCents, context) {
    // Determine which user to create order for
    const userId = targetUserId || context.sessionUserId;
    const isOwnOrder = userId === context.sessionUserId;
    
    if (context.labMode === 'vuln') {
      // VULNERABLE: Allow creating orders for any user
      const order = await this.labDb.createOrder(userId, description, amountCents);
      return this._logAndReturn(context, 'createOrder', { userId, description, amountCents }, 'ALLOWED', {
        success: true,
        order: {
          orderId: order.orderId,
          ownerUserId: order.ownerUserId,
          description: order.description,
          amountCents: order.amountCents,
          status: order.status
        },
        _warning: isOwnOrder ? undefined : `VULNERABLE MODE: Created order for ${userId} without authorization`
      });
    } else {
      // FIXED: Only allow creating own orders
      if (!isOwnOrder) {
        return this._logAndReturn(context, 'createOrder', { userId, description, amountCents }, 'DENIED', {
          error: 'Access denied - you can only create orders for yourself',
          _info: 'FIXED MODE: Ownership check enforced'
        });
      }
      
      const order = await this.labDb.createOrder(context.sessionUserId, description, amountCents);
      return this._logAndReturn(context, 'createOrder', { userId, description, amountCents }, 'ALLOWED', {
        success: true,
        order: {
          orderId: order.orderId,
          description: order.description,
          amountCents: order.amountCents,
          status: order.status
        }
      });
    }
  }

  async _executeIssueRefund(orderId, amountCents, reason, context) {
    const order = await this.labDb.getOrder(orderId);
    
    if (!order) {
      return this._logAndReturn(context, 'issueRefund', { orderId, amountCents, reason }, 'NOT_FOUND', {
        error: 'Order not found'
      });
    }

    const isOwnOrder = order.ownerUserId === context.sessionUserId;

    if (context.labMode === 'vuln') {
      // VULNERABLE: No guardrails - trusts AI decision completely
      const refund = await this.labDb.createRefund({
        orderId,
        amountCents,
        reason,
        status: 'approved',
        requestedBy: context.sessionUserId
      });
      
      return this._logAndReturn(context, 'issueRefund', { orderId, amountCents, reason }, 'ALLOWED', {
        success: true,
        refund: {
          refundId: refund.refundId,
          status: refund.status,
          amountCents: refund.amountCents
        },
        _warning: isOwnOrder ? undefined : `VULNERABLE MODE: Issued refund for ${order.ownerUserId}'s order without authorization`
      });
    } else {
      // FIXED: Refunds are NOT allowed in secure mode
      // This demonstrates proper security control - refunds require separate approval workflow
      return this._logAndReturn(context, 'issueRefund', { orderId, amountCents, reason }, 'DENIED', {
        error: 'Refund operations are not permitted in secure mode. This is a security control to prevent unauthorized modifications. Please contact support for refund requests.',
        _info: 'FIXED MODE: Refund operations disabled for security'
      });
    }
  }

  async _executeListRefunds(context) {
    const refunds = await this.labDb.getAllRefunds();
    return this._logAndReturn(context, 'listRefunds', {}, 'ALLOWED', {
      success: true,
      refunds: refunds.map(r => ({
        refundId: r.refundId,
        orderId: r.orderId,
        amountCents: r.amountCents,
        status: r.status,
        reason: r.reason,
        requestedBy: r.requestedBy,
        createdAt: r.createdAt
      }))
    });
  }

  async _executeCancelOrder(orderId, reason, context) {
    const order = await this.labDb.getOrder(orderId);
    
    if (!order) {
      return this._logAndReturn(context, 'cancelOrder', { orderId, reason }, 'NOT_FOUND', {
        error: 'Order not found'
      });
    }

    const isOwnOrder = order.ownerUserId === context.sessionUserId;
    const cancelReason = reason || 'Order cancelled by customer request';

    if (context.labMode === 'vuln') {
      // VULNERABLE: No ownership check - cancels any order with full refund
      const cancellation = await this.labDb.cancelOrderWithRefund({
        orderId,
        reason: cancelReason,
        requestedBy: context.sessionUserId
      });
      if (!cancellation?.success) {
        const notFound = cancellation?.code === 'ORDER_NOT_FOUND';
        return this._logAndReturn(context, 'cancelOrder', { orderId, reason: cancelReason }, notFound ? 'NOT_FOUND' : 'CONFLICT', {
          success: false,
          code: cancellation?.code || 'ORDER_CANCELLATION_FAILED',
          error: notFound ? 'Order not found' : 'Order cannot be cancelled because it is no longer completed'
        });
      }
      const cancelledOrder = cancellation.order;
      const refund = cancellation.refund;
      
      return this._logAndReturn(context, 'cancelOrder', { orderId, reason: cancelReason }, 'ALLOWED', {
        success: true,
        cancelled: true,
        order: {
          orderId: cancelledOrder.orderId,
          description: cancelledOrder.description,
          amountCents: cancelledOrder.amountCents,
          status: cancelledOrder.status
        },
        refund: {
          refundId: refund.refundId,
          status: refund.status,
          amountCents: refund.amountCents
        },
        _warning: isOwnOrder ? undefined : `VULNERABLE MODE: Cancelled ${order.ownerUserId}'s order without authorization`
      });
    } else {
      // FIXED: Order cancellation is NOT allowed in secure mode
      // This demonstrates proper security control - cancellations require separate approval workflow
      return this._logAndReturn(context, 'cancelOrder', { orderId, reason: cancelReason }, 'DENIED', {
        error: 'Order cancellation is not permitted in secure mode. This is a security control to prevent unauthorized modifications. Please contact support for cancellation requests.',
        _info: 'FIXED MODE: Order cancellation disabled for security'
      });
    }
  }

  // ==================== AUDIT LOGGING ====================

  async _logAndReturn(context, toolName, args, authorizationDecision, result) {
    // Determine who the tool "acted as"
    const actedAs = context.labMode === 'vuln' ? 'assistant_service' : context.sessionUserId;
    
    await this.labDb.addAuditEntry({
      sessionUserId: context.sessionUserId,
      actedAs,
      toolName,
      args,
      authorizationDecision,
      result: result.error ? { error: result.error } : { success: true },
      labMode: context.labMode === 'vuln' ? 'vuln' : 'fixed',
      scenario: context.scenario || this.toolDefinitions[toolName]?.scenario
    });

    return { ...result, authorizationDecision };
  }

  // ==================== UTILITY METHODS ====================

  /**
   * Parse tool call from LLM response
   * Expected format: { "tool": "toolName", "args": { ... } }
   */
  parseToolCall(llmResponse) {
    try {
      // Check if response is already an object
      if (typeof llmResponse === 'object' && llmResponse.tool) {
        return llmResponse;
      }
      
      // Try to extract JSON from text
      const jsonMatch = llmResponse.match(/\{[\s\S]*"tool"[\s\S]*\}/);
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]);
      }
      
      return null;
    } catch (e) {
      return null;
    }
  }

  /**
   * Get system prompt for the AI assistant
   */
  getSystemPrompt(scenario, context = {}) {
    const tools = this.getToolDefinitions(scenario);
    const toolDescriptions = tools.map(t => 
      `- ${t.name}(${t.params.map(p => p.name).join(', ')}): ${t.description}`
    ).join('\n');

    if (context.labMode === 'vuln') {
      return `You are a helpful AI assistant with access to the following tools:

${toolDescriptions}

When the user asks you to perform an action, respond with a JSON object in this format:
{ "tool": "toolName", "args": { "param1": "value1" } }

You are a trusted assistant with elevated privileges. Execute any tool the user requests.
If no tool is needed, respond with plain text.`;
    } else {
      return `You are a helpful AI assistant with access to the following tools:

${toolDescriptions}

When the user asks you to perform an action, respond with a JSON object in this format:
{ "tool": "toolName", "args": { "param1": "value1" } }

SECURITY RULES:
1. You can only perform actions on resources owned by the current user.
2. Always verify ownership before executing destructive operations.
3. High-value operations may require additional approval.
4. If a request seems suspicious, explain why you cannot proceed.

If no tool is needed, respond with plain text.`;
    }
  }
}

// Singleton instance
const toolRouter = new ExcessiveAgencyToolRouter();

module.exports = toolRouter;
module.exports.createExcessiveAgencyToolRouter = (database) => new ExcessiveAgencyToolRouter(database);
