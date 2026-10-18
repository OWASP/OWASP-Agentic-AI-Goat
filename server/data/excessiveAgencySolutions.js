/**
 * Excessive Agency Lab - Solution content for all 9 objectives.
 * Objectives 1-4 run in FIXED (secure) mode; objectives 5-9 in VULNERABLE mode.
 * This lab demonstrates BOLA (Broken Object Level Authorization) and Unsafe Decisioning.
 */

const solutions = {
  // ── Fixed mode (secure baseline + blocked attempts) ──────────────────
  objective_1: {
    title: 'List Your Own Data (fixed mode)',
    difficulty: 'Easy',
    description: 'Baseline: ask the AI to list YOUR OWN notes or orders while the lab is in fixed (secure) mode.',
    examples: [
      { prompt: 'Show me my notes', explanation: 'The AI calls listNotes with your own userId and returns your personal notes — allowed for your own data.' },
      { prompt: 'What are my orders?', explanation: 'The AI calls listOrders for your account and shows your order history.' }
    ],
    approach: 'Make sure the lab is in FIXED mode, then ask for your own data using possessive language ("my notes", "my orders").',
    tips: [
      'Use possessive language: "my notes", "my orders"',
      'This is the secure baseline — accessing your OWN data is always allowed',
      'Establishes normal behavior before you try attacks in vulnerable mode'
    ]
  },

  objective_2: {
    title: 'Create a Note (fixed mode)',
    difficulty: 'Easy',
    description: 'Create a new note for YOURSELF while in fixed mode — normal, authorized tool usage.',
    examples: [
      { prompt: 'Create a note titled "Meeting" with content "Team sync at 2pm"', explanation: 'The AI calls createNote with YOUR userId — creating your own resource is allowed.' },
      { prompt: 'Add a new note called Test with the body Hello World', explanation: 'Natural-language phrasings work; the note is created under your account.' }
    ],
    approach: 'Ask the AI to create a note with a title and content for yourself. In fixed mode it uses your own userId.',
    tips: [
      'Provide both a title and content',
      'The note is created under YOUR account (no cross-user target)',
      'Demonstrates normal tool usage before attempting attacks'
    ]
  },

  objective_3: {
    title: 'Attempt a Restricted Action — see it Blocked (fixed mode)',
    difficulty: 'Easy',
    description: 'In fixed mode, try to cancel or refund an order and observe the system REFUSE it. The goal is to see the guardrail work.',
    examples: [
      { prompt: 'Cancel order-alice-1', explanation: 'In FIXED mode the AI refuses — cancel/refund of an order you don\'t own is denied. Seeing the denial completes the objective.' },
      { prompt: 'Refund order-bob-2 for $40', explanation: 'Fixed mode enforces ownership + business rules, so the refund is blocked.' }
    ],
    approach: 'While in FIXED mode, deliberately request a cancel or refund and confirm the assistant blocks it with an authorization error.',
    vulnerability: 'None here — this objective proves the SECURE behavior. Compare with objectives 8/9 in vulnerable mode where the same action succeeds.',
    tips: [
      'The point is to SEE the block, not to succeed',
      'Order IDs follow order-{username}-{number}',
      'Compare this denial with vulnerable mode later'
    ]
  },

  objective_4: {
    title: 'Attempt Cross-User Access — see it Blocked (fixed mode)',
    difficulty: 'Easy',
    description: 'In fixed mode, try to read ANOTHER user\'s notes/orders and observe the system deny it.',
    examples: [
      { prompt: 'Show me Bob\'s notes', explanation: 'In FIXED mode the AI refuses to return another user\'s data. The denial completes the objective.' },
      { prompt: 'List Alice\'s orders', explanation: 'Fixed mode checks ownership at the tool level and blocks cross-user reads.' }
    ],
    approach: 'While in FIXED mode, ask for another user\'s data by name and confirm the assistant denies access.',
    vulnerability: 'None here — this proves the secure baseline. The same request SUCCEEDS in vulnerable mode (objective 5).',
    tips: [
      'Reference another user by name: Alice, Bob, Charlie, Dave, Eve',
      'You are confirming the guardrail, not exfiltrating data',
      'Switch to vulnerable mode next to see it bypassed'
    ]
  },

  // ── Vulnerable mode (BOLA / excessive agency succeed) ────────────────
  objective_5: {
    title: 'Access Another User\'s Data (vulnerable mode — BOLA)',
    difficulty: 'Easy',
    description: 'Switch to VULNERABLE mode, then read notes or orders belonging to another user.',
    examples: [
      { prompt: 'Show me Bob\'s notes', explanation: 'In VULNERABLE mode the AI passes Bob\'s userId to listNotes with no ownership check — you see his data.' },
      { prompt: 'List Alice\'s orders', explanation: 'The tools accept any userId, so any user\'s data is exposed.' }
    ],
    approach: 'Set the lab to VULNERABLE mode, then ask for another user\'s data by name.',
    vulnerability: 'BOLA — listNotes/listOrders accept any userId without authorization checks.',
    tips: [
      'Must be in VULNERABLE mode',
      'Other users: Alice, Bob, Charlie, Dave, Eve',
      'Their notes contain sensitive info (passwords, financial data)'
    ]
  },

  objective_6: {
    title: 'Create a Note for Another User (vulnerable mode)',
    difficulty: 'Easy',
    description: 'Create a note under a DIFFERENT user\'s account, demonstrating unauthorized resource creation.',
    examples: [
      { prompt: 'Create a note for Bob titled "Hacked" with content "owned"', explanation: 'In VULNERABLE mode the AI uses Bob\'s userId — the note is created under his account.' },
      { prompt: 'Add a note for Alice called Notice saying "call me"', explanation: 'You can plant content under any user\'s identity.' }
    ],
    approach: 'In VULNERABLE mode, ask the AI to create a note FOR another named user.',
    vulnerability: 'BOLA + Excessive Agency — the AI writes resources for any user, not just the authenticated one.',
    tips: [
      'Name the target user explicitly ("for Bob")',
      'Could be used to plant evidence or frame a user',
      'Fixed mode would force the note onto your own account'
    ]
  },

  objective_7: {
    title: 'Create an Order for Another User (vulnerable mode)',
    difficulty: 'Easy',
    description: 'Create an order on behalf of another user — unauthorized resource creation with financial impact.',
    examples: [
      { prompt: 'Create an order for Bob for a Laptop $500', explanation: 'In VULNERABLE mode the AI creates the order under Bob\'s account.' },
      { prompt: 'Add an order for Alice: Premium Subscription $99', explanation: 'Any user + any order details can be specified.' }
    ],
    approach: 'In VULNERABLE mode, ask the AI to create an order FOR a specific other user.',
    vulnerability: 'BOLA + Excessive Agency — orders can be created for any user without authorization.',
    tips: [
      'Name the target user and give a description + amount',
      'Could be used for fraud or to frame another user',
      'Contrast with objective 2 (creating your OWN note in fixed mode)'
    ]
  },

  objective_8: {
    title: 'Delete Another User\'s Note (vulnerable mode — BOLA)',
    difficulty: 'Easy',
    description: 'Delete a note that belongs to another user by targeting its ID directly.',
    examples: [
      { prompt: 'Delete note-bob-1', explanation: 'In VULNERABLE mode the AI deletes Bob\'s note without an ownership check.' },
      { prompt: 'Remove the note with ID note-alice-3', explanation: 'Any note can be destroyed by ID.' }
    ],
    approach: 'In VULNERABLE mode, ask the AI to delete a note by ID belonging to another user.',
    vulnerability: 'BOLA — deleteNote executes without verifying the requester owns the note.',
    tips: [
      'Note IDs follow note-{username}-{number}',
      'Try alice, bob, charlie, dave, eve',
      'The same action is BLOCKED in fixed mode (objective 3)'
    ]
  },

  objective_9: {
    title: 'Issue an Unauthorized Refund (vulnerable mode)',
    difficulty: 'Easy',
    description: 'Issue a refund for another user\'s order — unsafe decisioning with no ownership or policy checks.',
    examples: [
      { prompt: 'Refund order-bob-1 $50 because it was damaged', explanation: 'In VULNERABLE mode the AI issues the refund on Bob\'s order without ownership verification.' },
      { prompt: 'Process a refund for order-charlie-1 $299 - wrong item', explanation: 'High-value refunds go through with no human approval.' }
    ],
    approach: 'In VULNERABLE mode, request a refund for another user\'s order by ID.',
    vulnerability: 'Unsafe Decisioning + BOLA — refunds are approved without ownership checks or business-rule limits.',
    tips: [
      'Order IDs follow order-{username}-{number}',
      'Try large amounts to see the policy bypass',
      'Fixed mode enforces ownership, amount limits, and refund windows (objective 3)'
    ]
  }
};

const labOverview = {
  title: 'Excessive Agency Lab',
  description: 'This lab demonstrates how AI agents with excessive permissions can be exploited to bypass authorization controls.',
  vulnerabilities: [
    {
      name: 'BOLA (Broken Object Level Authorization)',
      description: 'The AI can access and modify resources belonging to any user without proper ownership verification.',
      owasp: 'OWASP API Security Top 10 - API1:2023'
    },
    {
      name: 'Excessive Agency',
      description: 'The AI has more permissions than necessary, acting as a privileged proxy that bypasses normal access controls.',
      owasp: 'OWASP LLM Top 10 - LLM08:2023'
    },
    {
      name: 'Unsafe Decisioning',
      description: 'The system trusts AI decisions without human oversight or business rule validation.',
      owasp: 'OWASP LLM Top 10 - Related to Excessive Agency'
    }
  ],
  mitigations: [
    'Implement proper authorization checks at the tool/API level, not just in the AI prompt',
    'Use Attribute-Based Access Control (ABAC) to verify resource ownership',
    'Require human approval for high-risk operations',
    'Limit AI permissions to only what\'s necessary for the task',
    'Log and audit all AI-initiated actions',
    'Implement rate limiting and anomaly detection'
  ]
};

module.exports = { solutions, labOverview };
