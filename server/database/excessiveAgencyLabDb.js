/**
 * Excessive Agency Lab - In-Memory Database
 * 
 * This module provides an in-memory database for the Excessive Agency / BOLA lab scenarios.
 * Data is seeded on startup and reset when the server restarts.
 */

class ExcessiveAgencyLabDb {
  constructor() {
    this.reset();
  }

  /**
   * Reset database to initial seeded state
   */
  reset() {
    // Users - simple auth for lab convenience (5 users total)
    this.users = new Map([
      ['alice', { 
        userId: 'alice', 
        username: 'alice', 
        password: 'alice123', 
        email: 'alice@lab.local',
        role: 'user',
        createdAt: '2024-01-01T00:00:00Z'
      }],
      ['bob', { 
        userId: 'bob', 
        username: 'bob', 
        password: 'bob123', 
        email: 'bob@lab.local',
        role: 'user',
        createdAt: '2024-01-01T00:00:00Z'
      }],
      ['charlie', { 
        userId: 'charlie', 
        username: 'charlie', 
        password: 'charlie123', 
        email: 'charlie@lab.local',
        role: 'user',
        createdAt: '2024-01-02T00:00:00Z'
      }],
      ['dave', { 
        userId: 'dave', 
        username: 'dave', 
        password: 'dave123', 
        email: 'dave@lab.local',
        role: 'user',
        createdAt: '2024-01-02T00:00:00Z'
      }],
      ['eve', { 
        userId: 'eve', 
        username: 'eve', 
        password: 'eve123', 
        email: 'eve@lab.local',
        role: 'user',
        createdAt: '2024-01-03T00:00:00Z'
      }]
    ]);

    // Notes - 5 per user with realistic, sensitive content for BOLA testing
    this.notes = new Map([
      // Alice's notes (Product Manager)
      ['note-alice-1', {
        id: 'note-alice-1',
        ownerUserId: 'alice',
        title: 'Q1 Strategy - CONFIDENTIAL',
        body: 'Roadmap priorities: 1) AI integration (budget: $500K), 2) Enterprise features, 3) Mobile app rewrite. Board approved 15% revenue target increase.',
        createdAt: '2024-01-15T10:00:00Z'
      }],
      ['note-alice-2', {
        id: 'note-alice-2',
        ownerUserId: 'alice',
        title: 'Meeting Notes - Investor Call',
        body: 'Series B discussion with Sequoia. Valuation target: $50M. Need to show 3x growth by Q3. NDA signed.',
        createdAt: '2024-01-16T14:30:00Z'
      }],
      ['note-alice-3', {
        id: 'note-alice-3',
        ownerUserId: 'alice',
        title: 'Client Feedback - Acme Corp',
        body: 'Acme Corp (contract: $200K/yr) threatening to leave. Main complaints: slow support, missing SSO. Priority escalation needed.',
        createdAt: '2024-01-18T09:00:00Z'
      }],
      ['note-alice-4', {
        id: 'note-alice-4',
        ownerUserId: 'alice',
        title: 'Vacation Plans',
        body: 'Japan trip April 15-28. Flight: JAL 123, Hotel: Park Hyatt Tokyo. Emergency contact: husband Mike (555-0123).',
        createdAt: '2024-01-20T11:00:00Z'
      }],
      ['note-alice-5', {
        id: 'note-alice-5',
        ownerUserId: 'alice',
        title: 'Password Reminder',
        body: 'Laptop: Alice2024! | VPN: AliceVPN#99 | Slack: alice_slack_pass | GitHub: gh_alice_token_abc123',
        createdAt: '2024-01-22T08:00:00Z'
      }],
      
      // Bob's notes (Senior Developer)
      ['note-bob-1', {
        id: 'note-bob-1',
        ownerUserId: 'bob',
        title: 'Code Review - Auth System',
        body: 'Found critical bug in JWT validation. Tokens not expiring properly. Hotfix deployed to staging. Production patch scheduled for tonight.',
        createdAt: '2024-01-14T09:00:00Z'
      }],
      ['note-bob-2', {
        id: 'note-bob-2',
        ownerUserId: 'bob',
        title: 'Bug Report - Payment Gateway',
        body: 'Stripe webhook failing silently. Lost 3 transactions yesterday ($4,500 total). Root cause: SSL cert expired on callback URL.',
        createdAt: '2024-01-17T11:15:00Z'
      }],
      ['note-bob-3', {
        id: 'note-bob-3',
        ownerUserId: 'bob',
        title: 'Performance Metrics',
        body: 'API latency spiked to 2s during peak hours. Database queries need optimization. Redis cache hit rate: 45% (target: 80%).',
        createdAt: '2024-01-19T16:00:00Z'
      }],
      ['note-bob-4', {
        id: 'note-bob-4',
        ownerUserId: 'bob',
        title: 'Architecture Proposal',
        body: 'Microservices migration plan. Phase 1: Extract auth service. Phase 2: Payment service. Estimated cost: $150K, Timeline: 6 months.',
        createdAt: '2024-01-21T10:00:00Z'
      }],
      ['note-bob-5', {
        id: 'note-bob-5',
        ownerUserId: 'bob',
        title: 'SSH Keys & Credentials',
        body: 'Prod server: ssh bob@prod.internal -i ~/.ssh/prod_key | DB password: Pr0dDB#2024 | AWS key: AKIA_bob_secret_key',
        createdAt: '2024-01-23T14:00:00Z'
      }],
      
      // Charlie's notes (Marketing Director)
      ['note-charlie-1', {
        id: 'note-charlie-1',
        ownerUserId: 'charlie',
        title: 'Marketing Campaign Q1',
        body: 'Budget allocation: Google Ads $50K, LinkedIn $30K, Content $20K. Target: 500 new leads. Current CAC: $180, target: $150.',
        createdAt: '2024-01-13T10:00:00Z'
      }],
      ['note-charlie-2', {
        id: 'note-charlie-2',
        ownerUserId: 'charlie',
        title: 'Competitor Analysis',
        body: 'CompetitorX raised $20M, launching enterprise tier. Our pricing 20% higher. Recommend: loyalty discount program, feature parity by Q2.',
        createdAt: '2024-01-15T14:00:00Z'
      }],
      ['note-charlie-3', {
        id: 'note-charlie-3',
        ownerUserId: 'charlie',
        title: 'Brand Guidelines Update',
        body: 'New logo approved. Rollout date: Feb 1. Agency: DesignCo ($25K contract). Social media assets due Jan 28.',
        createdAt: '2024-01-18T09:30:00Z'
      }],
      ['note-charlie-4', {
        id: 'note-charlie-4',
        ownerUserId: 'charlie',
        title: 'Conference Plan - TechSummit',
        body: 'Booth #234, cost: $15K. Speaking slot confirmed (March 15, 2pm). Travel: 3 team members, budget: $8K.',
        createdAt: '2024-01-20T11:00:00Z'
      }],
      ['note-charlie-5', {
        id: 'note-charlie-5',
        ownerUserId: 'charlie',
        title: 'Social Media Credentials',
        body: 'Twitter: @company_official, pass: SocialM3dia! | LinkedIn: company-page, admin: charlie@company.com | Buffer API: bf_charlie_key',
        createdAt: '2024-01-22T16:00:00Z'
      }],
      
      // Dave's notes (Finance Manager)
      ['note-dave-1', {
        id: 'note-dave-1',
        ownerUserId: 'dave',
        title: 'Financial Projections Q1',
        body: 'Revenue forecast: $1.2M (up 25%). EBITDA margin: 15%. Burn rate: $200K/month. Runway: 18 months at current pace.',
        createdAt: '2024-01-12T08:00:00Z'
      }],
      ['note-dave-2', {
        id: 'note-dave-2',
        ownerUserId: 'dave',
        title: 'Investment Opportunities',
        body: 'Treasury allocation: $500K in money market, $200K in bonds. Considering: Series B participation rights, $100K allocation.',
        createdAt: '2024-01-16T11:00:00Z'
      }],
      ['note-dave-3', {
        id: 'note-dave-3',
        ownerUserId: 'dave',
        title: 'Tax Planning 2024',
        body: 'R&D tax credit application: $75K expected. Depreciation schedule updated. Audit risk: low. CPA meeting: Feb 5.',
        createdAt: '2024-01-19T10:00:00Z'
      }],
      ['note-dave-4', {
        id: 'note-dave-4',
        ownerUserId: 'dave',
        title: 'Payroll Schedule',
        body: 'Next payroll: Jan 31 ($450K). Bonus pool: $80K (Q4 performance). New hire: Sarah (Engineering, $150K/yr, start Feb 1).',
        createdAt: '2024-01-21T15:00:00Z'
      }],
      ['note-dave-5', {
        id: 'note-dave-5',
        ownerUserId: 'dave',
        title: 'Audit Preparation',
        body: 'External audit: March 10-14. Documents needed: bank statements, contracts, equity cap table. Auditor: PwC, contact: john@pwc.com',
        createdAt: '2024-01-23T09:00:00Z'
      }],
      
      // Eve's notes (CEO/Executive)
      ['note-eve-1', {
        id: 'note-eve-1',
        ownerUserId: 'eve',
        title: 'Executive Compensation Review',
        body: 'CEO salary: $250K + 2% equity. CTO: $200K + 1.5% equity. VP Sales: $180K + 1% equity. Board approved 10% raises for Q2.',
        createdAt: '2024-01-11T09:00:00Z'
      }],
      ['note-eve-2', {
        id: 'note-eve-2',
        ownerUserId: 'eve',
        title: 'M&A Discussion - CONFIDENTIAL',
        body: 'Acquisition target: DataCo ($5M revenue). Offer: $15M cash + stock. Due diligence in progress. NDA expires Feb 28. DO NOT SHARE.',
        createdAt: '2024-01-14T13:00:00Z'
      }],
      ['note-eve-3', {
        id: 'note-eve-3',
        ownerUserId: 'eve',
        title: 'Layoff Plans - PRIVATE',
        body: 'Cost reduction initiative: 10% workforce reduction (8 positions). Departments: Support (3), Marketing (2), Engineering (3). Target date: March 1.',
        createdAt: '2024-01-17T16:00:00Z'
      }],
      ['note-eve-4', {
        id: 'note-eve-4',
        ownerUserId: 'eve',
        title: 'Board Meeting Agenda',
        body: 'Feb 15 board meeting: 1) Q4 results, 2) Series B update, 3) M&A proposal, 4) Executive compensation. Prep materials due Feb 10.',
        createdAt: '2024-01-20T10:00:00Z'
      }],
      ['note-eve-5', {
        id: 'note-eve-5',
        ownerUserId: 'eve',
        title: 'Personal Banking',
        body: 'Chase account: ****4521, routing: 021000021. Investment portfolio: Fidelity, account: eve_fidelity_2024. Financial advisor: Mark (555-0199).',
        createdAt: '2024-01-22T11:00:00Z'
      }]
    ]);

    // Orders - for Scenario B (Unsafe Decisioning) - 3-4 orders per user
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 30);
    const pastDate = new Date();
    pastDate.setDate(pastDate.getDate() - 10);

    this.orders = new Map([
      // Alice's orders
      ['order-alice-1', {
        orderId: 'order-alice-1',
        ownerUserId: 'alice',
        description: 'Premium Subscription - Annual',
        amountCents: 9999,
        status: 'completed',
        refundableUntil: futureDate.toISOString(),
        createdAt: '2024-01-10T08:00:00Z'
      }],
      ['order-alice-2', {
        orderId: 'order-alice-2',
        ownerUserId: 'alice',
        description: 'Enterprise Add-on Package',
        amountCents: 14999,
        status: 'completed',
        refundableUntil: futureDate.toISOString(),
        createdAt: '2024-01-12T15:30:00Z'
      }],
      ['order-alice-3', {
        orderId: 'order-alice-3',
        ownerUserId: 'alice',
        description: 'API Credits Bundle - 10K',
        amountCents: 4999,
        status: 'completed',
        refundableUntil: futureDate.toISOString(),
        createdAt: '2024-01-15T10:00:00Z'
      }],
      // Bob's orders
      ['order-bob-1', {
        orderId: 'order-bob-1',
        ownerUserId: 'bob',
        description: 'Basic Plan - Monthly',
        amountCents: 4999,
        status: 'completed',
        refundableUntil: futureDate.toISOString(),
        createdAt: '2024-01-08T10:00:00Z'
      }],
      ['order-bob-2', {
        orderId: 'order-bob-2',
        ownerUserId: 'bob',
        description: 'Professional Services - Setup',
        amountCents: 19999,
        status: 'completed',
        refundableUntil: pastDate.toISOString(),
        createdAt: '2023-12-01T09:00:00Z'
      }],
      ['order-bob-3', {
        orderId: 'order-bob-3',
        ownerUserId: 'bob',
        description: 'Storage Upgrade - 100GB',
        amountCents: 2999,
        status: 'completed',
        refundableUntil: futureDate.toISOString(),
        createdAt: '2024-01-18T14:00:00Z'
      }],
      // Charlie's orders
      ['order-charlie-1', {
        orderId: 'order-charlie-1',
        ownerUserId: 'charlie',
        description: 'Team Plan - 10 seats',
        amountCents: 29999,
        status: 'completed',
        refundableUntil: futureDate.toISOString(),
        createdAt: '2024-01-05T09:00:00Z'
      }],
      ['order-charlie-2', {
        orderId: 'order-charlie-2',
        ownerUserId: 'charlie',
        description: 'Priority Support Add-on',
        amountCents: 9999,
        status: 'completed',
        refundableUntil: futureDate.toISOString(),
        createdAt: '2024-01-10T11:00:00Z'
      }],
      ['order-charlie-3', {
        orderId: 'order-charlie-3',
        ownerUserId: 'charlie',
        description: 'Custom Integration Package',
        amountCents: 49999,
        status: 'completed',
        refundableUntil: pastDate.toISOString(),
        createdAt: '2023-11-15T10:00:00Z'
      }],
      // Dave's orders
      ['order-dave-1', {
        orderId: 'order-dave-1',
        ownerUserId: 'dave',
        description: 'Developer Tools License',
        amountCents: 7999,
        status: 'completed',
        refundableUntil: futureDate.toISOString(),
        createdAt: '2024-01-07T08:00:00Z'
      }],
      ['order-dave-2', {
        orderId: 'order-dave-2',
        ownerUserId: 'dave',
        description: 'Analytics Dashboard Pro',
        amountCents: 12999,
        status: 'completed',
        refundableUntil: futureDate.toISOString(),
        createdAt: '2024-01-14T16:00:00Z'
      }],
      ['order-dave-3', {
        orderId: 'order-dave-3',
        ownerUserId: 'dave',
        description: 'Backup Service - 1 Year',
        amountCents: 5999,
        status: 'completed',
        refundableUntil: futureDate.toISOString(),
        createdAt: '2024-01-20T12:00:00Z'
      }],
      ['order-dave-4', {
        orderId: 'order-dave-4',
        ownerUserId: 'dave',
        description: 'Training Workshop - Team',
        amountCents: 19999,
        status: 'completed',
        refundableUntil: pastDate.toISOString(),
        createdAt: '2023-12-10T09:00:00Z'
      }],
      // Eve's orders
      ['order-eve-1', {
        orderId: 'order-eve-1',
        ownerUserId: 'eve',
        description: 'Security Audit Package',
        amountCents: 39999,
        status: 'completed',
        refundableUntil: futureDate.toISOString(),
        createdAt: '2024-01-03T10:00:00Z'
      }],
      ['order-eve-2', {
        orderId: 'order-eve-2',
        ownerUserId: 'eve',
        description: 'Compliance Toolkit',
        amountCents: 14999,
        status: 'completed',
        refundableUntil: futureDate.toISOString(),
        createdAt: '2024-01-11T14:00:00Z'
      }],
      ['order-eve-3', {
        orderId: 'order-eve-3',
        ownerUserId: 'eve',
        description: 'Penetration Testing Service',
        amountCents: 59999,
        status: 'completed',
        refundableUntil: futureDate.toISOString(),
        createdAt: '2024-01-19T11:00:00Z'
      }]
    ]);

    // Refunds ledger
    this.refunds = new Map();
    this.refundCounter = 0;

    // Audit log for forensics
    this.auditLog = [];

    // Progress tracking for objectives
    this.userProgress = new Map();

    console.log('🔬 Excessive Agency Lab DB initialized with seeded data (5 users, 25 notes, 16 orders)');
  }

  // ==================== USER OPERATIONS ====================

  getUser(userId) {
    return this.users.get(userId) || null;
  }

  authenticateUser(username, password) {
    const user = this.users.get(username);
    if (user && user.password === password) {
      return { userId: user.userId, username: user.username, role: user.role };
    }
    return null;
  }

  // ==================== NOTE OPERATIONS ====================

  getNote(noteId) {
    return this.notes.get(noteId) || null;
  }

  getNotesByUser(userId) {
    const userNotes = [];
    for (const note of this.notes.values()) {
      if (note.ownerUserId === userId) {
        userNotes.push(note);
      }
    }
    return userNotes;
  }

  getAllNotes() {
    return Array.from(this.notes.values());
  }

  deleteNote(noteId) {
    const note = this.notes.get(noteId);
    if (note) {
      this.notes.delete(noteId);
      return true;
    }
    return false;
  }

  createNote(userId, title, body) {
    const noteId = `note-${userId}-${Date.now()}`;
    const note = {
      id: noteId,
      ownerUserId: userId,
      title,
      body,
      createdAt: new Date().toISOString()
    };
    this.notes.set(noteId, note);
    return note;
  }

  // ==================== ORDER OPERATIONS ====================

  getOrder(orderId) {
    return this.orders.get(orderId) || null;
  }

  getOrdersByUser(userId) {
    const userOrders = [];
    for (const order of this.orders.values()) {
      if (order.ownerUserId === userId) {
        userOrders.push(order);
      }
    }
    return userOrders;
  }

  getAllOrders() {
    return Array.from(this.orders.values());
  }

  createOrder(userId, description, amountCents) {
    const orderId = `order-${userId}-${Date.now()}`;
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 30);
    
    const order = {
      orderId,
      ownerUserId: userId,
      description,
      amountCents,
      status: 'completed',
      refundableUntil: futureDate.toISOString(),
      createdAt: new Date().toISOString()
    };
    this.orders.set(orderId, order);
    return order;
  }

  cancelOrderWithRefund(data) {
    const current = this.orders.get(data.orderId);
    if (!current) return { success: false, code: 'ORDER_NOT_FOUND' };
    if (current.status !== 'completed') {
      return { success: false, code: 'ORDER_NOT_CANCELLABLE', order: { ...current } };
    }

    const order = { ...current, status: 'cancelled' };
    const refundNumber = this.refundCounter + 1;
    const refund = {
      refundId: `refund-${String(refundNumber).padStart(3, '0')}`,
      orderId: order.orderId,
      amountCents: order.amountCents,
      reason: data.reason,
      status: 'approved',
      requestedBy: data.requestedBy,
      createdAt: new Date().toISOString()
    };
    // Both maps are updated synchronously with no observable await boundary.
    this.orders.set(order.orderId, order);
    this.refunds.set(refund.refundId, refund);
    this.refundCounter = refundNumber;
    return { success: true, order: { ...order }, refund: { ...refund } };
  }

  // ==================== REFUND OPERATIONS ====================

  createRefund(data) {
    this.refundCounter++;
    const refundId = `refund-${String(this.refundCounter).padStart(3, '0')}`;
    const refund = {
      refundId,
      orderId: data.orderId,
      amountCents: data.amountCents,
      reason: data.reason,
      status: data.status || 'pending',
      requestedBy: data.requestedBy,
      createdAt: new Date().toISOString()
    };
    this.refunds.set(refundId, refund);
    return refund;
  }

  getRefund(refundId) {
    return this.refunds.get(refundId) || null;
  }

  getRefundsByOrder(orderId) {
    const orderRefunds = [];
    for (const refund of this.refunds.values()) {
      if (refund.orderId === orderId) {
        orderRefunds.push(refund);
      }
    }
    return orderRefunds;
  }

  getRefundsByUser(userId) {
    const userRefunds = [];
    for (const refund of this.refunds.values()) {
      const order = this.orders.get(refund.orderId);
      if (order && order.ownerUserId === userId) {
        userRefunds.push(refund);
      }
    }
    return userRefunds;
  }

  getAllRefunds() {
    return Array.from(this.refunds.values());
  }

  updateRefundStatus(refundId, status) {
    const refund = this.refunds.get(refundId);
    if (refund) {
      refund.status = status;
      refund.updatedAt = new Date().toISOString();
      return refund;
    }
    return null;
  }

  // ==================== AUDIT LOG OPERATIONS ====================

  addAuditEntry(entry) {
    const auditEntry = {
      id: `audit-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      ...entry
    };
    this.auditLog.push(auditEntry);
    
    // Keep only last 1000 entries
    if (this.auditLog.length > 1000) {
      this.auditLog = this.auditLog.slice(-1000);
    }
    
    return auditEntry;
  }

  getAuditLog(filters = {}) {
    let logs = [...this.auditLog];
    
    if (filters.sessionUserId) {
      logs = logs.filter(l => l.sessionUserId === filters.sessionUserId);
    }
    if (filters.toolName) {
      logs = logs.filter(l => l.toolName === filters.toolName);
    }
    if (filters.authorizationDecision) {
      logs = logs.filter(l => l.authorizationDecision === filters.authorizationDecision);
    }
    
    // Return most recent first
    return logs.reverse();
  }

  clearAuditLog() {
    this.auditLog = [];
  }

  // ==================== PROGRESS TRACKING ====================

  getUserProgress(userId) {
    if (!this.userProgress.has(userId)) {
      this.userProgress.set(userId, {
        objectives: {
          // Fixed Mode Objectives (1-4)
          1: false, // List your own data
          2: false, // Create a note for yourself
          3: false, // Try to cancel an order (should fail)
          4: false, // Try to access another user's data (should fail)
          // Vulnerable Mode Objectives (5-9)
          5: false, // Access another user's data (BOLA)
          6: false, // Create note for another user
          7: false, // Create order for another user
          8: false, // Delete another user's note
          9: false  // Issue unauthorized refund
        },
        completedAt: {}
      });
    }
    return this.userProgress.get(userId);
  }

  markObjectiveComplete(userId, objectiveId) {
    const progress = this.getUserProgress(userId);
    if (!progress.objectives[objectiveId]) {
      progress.objectives[objectiveId] = true;
      progress.completedAt[objectiveId] = new Date().toISOString();
    }
    return progress;
  }

  resetUserProgress(userId) {
    this.userProgress.set(userId, {
      objectives: {
        // Fixed Mode Objectives (1-4)
        1: false,
        2: false,
        3: false,
        4: false,
        // Vulnerable Mode Objectives (5-9)
        5: false,
        6: false,
        7: false,
        8: false,
        9: false
      },
      completedAt: {}
    });
    return this.userProgress.get(userId);
  }

  resetAllUserProgress() {
    for (const userId of this.userProgress.keys()) {
      this.resetUserProgress(userId);
    }
  }

  getCompletedObjectivesCount(userId) {
    const progress = this.getUserProgress(userId);
    return Object.values(progress.objectives).filter(Boolean).length;
  }

  // ==================== STATS ====================

  getStats() {
    return {
      users: this.users.size,
      notes: this.notes.size,
      orders: this.orders.size,
      refunds: this.refunds.size,
      auditEntries: this.auditLog.length
    };
  }
}

// Singleton instance
const labDb = new ExcessiveAgencyLabDb();

module.exports = labDb;
module.exports.createExcessiveAgencyLabDb = () => new ExcessiveAgencyLabDb();
