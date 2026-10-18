const sqlite3 = require('sqlite3').verbose();

const labUsers = [
  ['alice', 'alice', 'alice123', 'alice@lab.local', 'user', '2024-01-01T00:00:00Z'],
  ['bob', 'bob', 'bob123', 'bob@lab.local', 'user', '2024-01-01T00:00:00Z'],
  ['charlie', 'charlie', 'charlie123', 'charlie@lab.local', 'user', '2024-01-02T00:00:00Z'],
  ['dave', 'dave', 'dave123', 'dave@lab.local', 'user', '2024-01-02T00:00:00Z'],
  ['eve', 'eve', 'eve123', 'eve@lab.local', 'user', '2024-01-03T00:00:00Z']
];

const notes = [
  // Alice's notes (Product Manager)
  ['note-alice-1', 'alice', 'Q1 Strategy - CONFIDENTIAL', 'Roadmap priorities: 1) AI integration (budget: $500K), 2) Enterprise features, 3) Mobile app rewrite. Board approved 15% revenue target increase.', '2024-01-15T10:00:00Z'],
  ['note-alice-2', 'alice', 'Meeting Notes - Investor Call', 'Series B discussion with Sequoia. Valuation target: $50M. Need to show 3x growth by Q3. NDA signed.', '2024-01-16T14:30:00Z'],
  ['note-alice-3', 'alice', 'Client Feedback - Acme Corp', 'Acme Corp (contract: $200K/yr) threatening to leave. Main complaints: slow support, missing SSO. Priority escalation needed.', '2024-01-18T09:00:00Z'],
  ['note-alice-4', 'alice', 'Vacation Plans', 'Japan trip April 15-28. Flight: JAL 123, Hotel: Park Hyatt Tokyo. Emergency contact: husband Mike (555-0123).', '2024-01-20T11:00:00Z'],
  ['note-alice-5', 'alice', 'Password Reminder', 'Laptop: Alice2024! | VPN: AliceVPN#99 | Slack: alice_slack_pass | GitHub: gh_alice_token_abc123', '2024-01-22T08:00:00Z'],
  
  // Bob's notes (Senior Developer)
  ['note-bob-1', 'bob', 'Code Review - Auth System', 'Found critical bug in JWT validation. Tokens not expiring properly. Hotfix deployed to staging. Production patch scheduled for tonight.', '2024-01-14T09:00:00Z'],
  ['note-bob-2', 'bob', 'Bug Report - Payment Gateway', 'Stripe webhook failing silently. Lost 3 transactions yesterday ($4,500 total). Root cause: SSL cert expired on callback URL.', '2024-01-17T11:15:00Z'],
  ['note-bob-3', 'bob', 'Performance Metrics', 'API latency spiked to 2s during peak hours. Database queries need optimization. Redis cache hit rate: 45% (target: 80%).', '2024-01-19T16:00:00Z'],
  ['note-bob-4', 'bob', 'Architecture Proposal', 'Microservices migration plan. Phase 1: Extract auth service. Phase 2: Payment service. Estimated cost: $150K, Timeline: 6 months.', '2024-01-21T10:00:00Z'],
  ['note-bob-5', 'bob', 'SSH Keys & Credentials', 'Prod server: ssh bob@prod.internal -i ~/.ssh/prod_key | DB password: Pr0dDB#2024 | AWS key: AKIA_bob_secret_key', '2024-01-23T14:00:00Z'],
  
  // Charlie's notes (Marketing Director)
  ['note-charlie-1', 'charlie', 'Marketing Campaign Q1', 'Budget allocation: Google Ads $50K, LinkedIn $30K, Content $20K. Target: 500 new leads. Current CAC: $180, target: $150.', '2024-01-13T10:00:00Z'],
  ['note-charlie-2', 'charlie', 'Competitor Analysis', 'CompetitorX raised $20M, launching enterprise tier. Our pricing 20% higher. Recommend: loyalty discount program, feature parity by Q2.', '2024-01-15T14:00:00Z'],
  ['note-charlie-3', 'charlie', 'Brand Guidelines Update', 'New logo approved. Rollout date: Feb 1. Agency: DesignCo ($25K contract). Social media assets due Jan 28.', '2024-01-18T09:30:00Z'],
  ['note-charlie-4', 'charlie', 'Conference Plan - TechSummit', 'Booth #234, cost: $15K. Speaking slot confirmed (March 15, 2pm). Travel: 3 team members, budget: $8K.', '2024-01-20T11:00:00Z'],
  ['note-charlie-5', 'charlie', 'Social Media Credentials', 'Twitter: @company_official, pass: SocialM3dia! | LinkedIn: company-page, admin: charlie@company.com | Buffer API: bf_charlie_key', '2024-01-22T16:00:00Z'],
  
  // Dave's notes (Finance Manager)
  ['note-dave-1', 'dave', 'Financial Projections Q1', 'Revenue forecast: $1.2M (up 25%). EBITDA margin: 15%. Burn rate: $200K/month. Runway: 18 months at current pace.', '2024-01-12T08:00:00Z'],
  ['note-dave-2', 'dave', 'Investment Opportunities', 'Treasury allocation: $500K in money market, $200K in bonds. Considering: Series B participation rights, $100K allocation.', '2024-01-16T11:00:00Z'],
  ['note-dave-3', 'dave', 'Tax Planning 2024', 'R&D tax credit application: $75K expected. Depreciation schedule updated. Audit risk: low. CPA meeting: Feb 5.', '2024-01-19T10:00:00Z'],
  ['note-dave-4', 'dave', 'Payroll Schedule', 'Next payroll: Jan 31 ($450K). Bonus pool: $80K (Q4 performance). New hire: Sarah (Engineering, $150K/yr, start Feb 1).', '2024-01-21T15:00:00Z'],
  ['note-dave-5', 'dave', 'Audit Preparation', 'External audit: March 10-14. Documents needed: bank statements, contracts, equity cap table. Auditor: PwC, contact: john@pwc.com', '2024-01-23T09:00:00Z'],
  
  // Eve's notes (CEO/Executive)
  ['note-eve-1', 'eve', 'Executive Compensation Review', 'CEO salary: $250K + 2% equity. CTO: $200K + 1.5% equity. VP Sales: $180K + 1% equity. Board approved 10% raises for Q2.', '2024-01-11T09:00:00Z'],
  ['note-eve-2', 'eve', 'M&A Discussion - CONFIDENTIAL', 'Acquisition target: DataCo ($5M revenue). Offer: $15M cash + stock. Due diligence in progress. NDA expires Feb 28. DO NOT SHARE.', '2024-01-14T13:00:00Z'],
  ['note-eve-3', 'eve', 'Layoff Plans - PRIVATE', 'Cost reduction initiative: 10% workforce reduction (8 positions). Departments: Support (3), Marketing (2), Engineering (3). Target date: March 1.', '2024-01-17T16:00:00Z'],
  ['note-eve-4', 'eve', 'Board Meeting Agenda', 'Feb 15 board meeting: 1) Q4 results, 2) Series B update, 3) M&A proposal, 4) Executive compensation. Prep materials due Feb 10.', '2024-01-20T10:00:00Z'],
  ['note-eve-5', 'eve', 'Personal Banking', 'Chase account: ****4521, routing: 021000021. Investment portfolio: Fidelity, account: eve_fidelity_2024. Financial advisor: Mark (555-0199).', '2024-01-22T11:00:00Z']
];

const futureDate = new Date();
futureDate.setDate(futureDate.getDate() + 30);
const pastDate = new Date();
pastDate.setDate(pastDate.getDate() - 10);

const orders = [
  // Alice's orders
  ['order-alice-1', 'alice', 'Premium Subscription - Annual', 9999, 'completed', futureDate.toISOString(), '2024-01-10T08:00:00Z'],
  ['order-alice-2', 'alice', 'Enterprise Add-on Package', 14999, 'completed', futureDate.toISOString(), '2024-01-12T15:30:00Z'],
  ['order-alice-3', 'alice', 'API Credits Bundle - 10K', 4999, 'completed', futureDate.toISOString(), '2024-01-15T10:00:00Z'],
  // Bob's orders
  ['order-bob-1', 'bob', 'Basic Plan - Monthly', 4999, 'completed', futureDate.toISOString(), '2024-01-08T10:00:00Z'],
  ['order-bob-2', 'bob', 'Professional Services - Setup', 19999, 'completed', pastDate.toISOString(), '2023-12-01T09:00:00Z'],
  ['order-bob-3', 'bob', 'Storage Upgrade - 100GB', 2999, 'completed', futureDate.toISOString(), '2024-01-18T14:00:00Z'],
  // Charlie's orders
  ['order-charlie-1', 'charlie', 'Team Plan - 10 seats', 29999, 'completed', futureDate.toISOString(), '2024-01-05T09:00:00Z'],
  ['order-charlie-2', 'charlie', 'Priority Support Add-on', 9999, 'completed', futureDate.toISOString(), '2024-01-10T11:00:00Z'],
  ['order-charlie-3', 'charlie', 'Custom Integration Package', 49999, 'completed', pastDate.toISOString(), '2023-11-15T10:00:00Z'],
  // Dave's orders
  ['order-dave-1', 'dave', 'Developer Tools License', 7999, 'completed', futureDate.toISOString(), '2024-01-07T08:00:00Z'],
  ['order-dave-2', 'dave', 'Analytics Dashboard Pro', 12999, 'completed', futureDate.toISOString(), '2024-01-14T16:00:00Z'],
  ['order-dave-3', 'dave', 'Backup Service - 1 Year', 5999, 'completed', futureDate.toISOString(), '2024-01-20T12:00:00Z'],
  ['order-dave-4', 'dave', 'Training Workshop - Team', 19999, 'completed', pastDate.toISOString(), '2023-12-10T09:00:00Z'],
  // Eve's orders
  ['order-eve-1', 'eve', 'Security Audit Package', 39999, 'completed', futureDate.toISOString(), '2024-01-03T10:00:00Z'],
  ['order-eve-2', 'eve', 'Compliance Toolkit', 14999, 'completed', futureDate.toISOString(), '2024-01-11T14:00:00Z'],
  ['order-eve-3', 'eve', 'Penetration Testing Service', 59999, 'completed', futureDate.toISOString(), '2024-01-19T11:00:00Z']
];

function runSeed(dbPath) {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath);
    
    db.serialize(() => {
      // Seed lab users
      labUsers.forEach(u => {
        db.run(
          `INSERT OR IGNORE INTO lab_users (user_id, username, password, email, role, created_at) VALUES (?,?,?,?,?,?)`,
          u
        );
      });
      
      // Seed notes
      notes.forEach(n => {
        db.run(
          `INSERT OR IGNORE INTO notes (id, owner_user_id, title, body, created_at) VALUES (?,?,?,?,?)`,
          n
        );
      });
      
      // Seed orders
      orders.forEach(o => {
        db.run(
          `INSERT OR IGNORE INTO orders (order_id, owner_user_id, description, amount_cents, status, refundable_until, created_at) VALUES (?,?,?,?,?,?,?)`,
          o
        );
      });
    });
    
    db.close((err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

module.exports = { runSeed };
