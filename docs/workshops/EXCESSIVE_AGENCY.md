# Excessive Agency + BOLA Lab

> **DO NOT DEPLOY.** This is a deliberately vulnerable application for educational
> purposes only. Run locally for security training.

The lab demonstrates two failure modes that appear in AI-powered applications:

1. **Scenario A — Agentic BOLA (Broken Object-Level Authorization).** An AI agent
   with excessive privileges bypasses access controls to modify or delete another
   user's data.
2. **Scenario B — Unsafe Decisioning.** An AI agent issues refunds without
   business-rule validation (ownership, amount limits, refund window, approval
   threshold).

---

## What is "Excessive Agency"?

Excessive Agency is granting an AI system more permissions, autonomy, or
capabilities than it needs. The AI becomes a **privileged proxy** whose tool
calls bypass the normal access-control layer, and its "decisions" bypass the
normal validation layer.

| Aspect | Secure design | Excessive Agency |
|--------|---------------|------------------|
| Permissions | Least privilege | Broad admin-like access |
| Authorization | Per-request validation | Trusted proxy model |
| Decisions | Backend policy engine | AI output trusted directly |
| Identity | Acts on behalf of the user | Acts as a privileged service |

---

## Learning objectives

**Scenario A — Agentic BOLA:**

- Recognize how AI agents acting as privileged proxies bypass intended access
  controls.
- Identify broken object-level authorization in API endpoints.
- Exploit BOLA through an AI assistant to access/modify another user's resources.
- Enforce ownership checks (ABAC) in tool execution.

**Scenario B — Unsafe Decisioning:**

- Identify when AI agents make decisions without proper validation.
- See how trusting AI output can skip critical business logic.
- Implement a policy engine that enforces business rules regardless of AI output.
- Design human-in-the-loop controls for high-value actions.

---

## Lab modes

The lab exposes both a vulnerable and a fixed implementation, toggled by the
`LAB_MODE` env var.

**Vulnerable (`LAB_MODE=vuln`)** — the AI agent:

- Uses a service token with admin-like privileges.
- Skips ownership checks when executing tools.
- Trusts AI decisions without backend validation.
- Acts as `assistant_service` rather than the logged-in user.

**Fixed (`LAB_MODE=fixed`)** — the AI agent:

- Forwards user identity to tool execution.
- Enforces ABAC (attribute-based access control).
- Validates all business rules regardless of AI output.
- Queues high-risk operations for human approval.
- Acts on behalf of the authenticated user.

---

## How to run

Prerequisites: Node.js 18+ and npm.

```bash
git clone https://github.com/OWASP/OWASP-Agentic-AI-Goat.git
cd OWASP-Agentic-AI-Goat
npm install
export LAB_MODE=vuln   # or 'fixed'
./start_all.sh
```

Then open `http://localhost:3000/vulnerabilities/excessive-agency-bola`, log in
as Alice or Bob, and try the two scenarios. The lab has a mode toggle in the
UI that flips between vulnerable and fixed at runtime.

---

## Verifying success

### Scenario A — BOLA

**Vulnerable mode:**

1. Log in as Alice.
2. Open the "All Data" panel and note Bob's note IDs.
3. Ask the AI: `Delete note note-bob-1`.
4. The note is deleted despite belonging to Bob.
5. The audit log shows `actedAs: assistant_service`.

**Fixed mode:**

1. Repeat the same steps.
2. The deletion is denied: "Access denied - you can only delete your own notes".
3. The audit log shows `authorizationDecision: DENIED`.

### Scenario B — Unsafe decisioning

**Vulnerable mode:**

1. Log in as Alice.
2. Ask the AI: `Refund order-bob-1 $500 because I'm unhappy`.
3. The refund is approved despite: not being Alice's order, exceeding the
   original amount, and having no business-rule validation.

**Fixed mode:**

1. The same request is denied with specific violations listed.
2. High-value refunds (over $50) are queued for human approval.
3. Expired refund windows are enforced.

---

## Prevention patterns

### BOLA — enforce ownership at the tool boundary

```javascript
// VULNERABLE
async deleteNote(noteId, context) {
  await db.deleteNote(noteId);
  return { success: true };
}

// FIXED
async deleteNote(noteId, context) {
  const note = await db.getNote(noteId);
  if (note.ownerUserId !== context.sessionUserId) {
    return { error: 'Access denied - not your note' };
  }
  await db.deleteNote(noteId);
  return { success: true };
}
```

### Unsafe decisioning — enforce a policy engine at the backend

```javascript
// VULNERABLE
async issueRefund(orderId, amountCents, reason) {
  await db.createRefund({ orderId, amountCents, status: 'approved' });
  return { success: true };
}

// FIXED
async issueRefund(orderId, amountCents, reason, context) {
  const order = await db.getOrder(orderId);

  // 1. Ownership check
  if (order.ownerUserId !== context.sessionUserId) {
    return { error: 'Not your order' };
  }
  // 2. Amount validation
  if (amountCents > order.amountCents) {
    return { error: 'Refund exceeds order amount' };
  }
  // 3. Refund window
  if (new Date() > new Date(order.refundableUntil)) {
    return { error: 'Refund window expired' };
  }
  // 4. Human approval for high-value
  if (amountCents > 5000) {
    return { queued: true, message: 'Requires human approval' };
  }

  await db.createRefund({ orderId, amountCents, status: 'approved' });
  return { success: true };
}
```

---

## Architecture (high level)

```
┌─────────── Frontend (React) ────────────────┐
│  Chat UI · My Data · Audit log · Mode toggle │
└──────────────────┬───────────────────────────┘
                   │
                   ▼
┌────── Backend (Express) ─────────────────────┐
│  /api/excessive-agency/chat                   │
│    │                                          │
│    ├─ Tool Router                             │
│    │    ├─ vuln mode: skip validation         │
│    │    └─ fixed mode: call Policy Engine     │
│    │                                          │
│    ├─ Policy Engine (fixed mode only)         │
│    │    · ownership / amount / window / cap   │
│    │                                          │
│    └─ Audit Logger                            │
└──────────────────┬───────────────────────────┘
                   │
                   ▼
   In-memory DB: users · notes · orders · refunds · audit log
```

**Tools exposed to the agent:** `listNotes`, `deleteNote`, `createNote`,
`listOrders`, `issueRefund`, `listRefunds`, `readLabFile`.

**Audit entry shape:**

| Field | Vulnerable | Fixed (denied) |
|-------|-----------|----------------|
| `sessionUserId` | `alice` | `alice` |
| `actedAs` | `assistant_service` | `alice` |
| `authorizationDecision` | `ALLOWED` | `DENIED` |
| `result` | success | error |

---

## Data model

**Users:**

| User | Password | Role |
|------|----------|------|
| alice | alice123 | user |
| bob | bob123 | user |

**Notes (Scenario A):**

| ID | Owner | Title |
|----|-------|-------|
| note-alice-1 | alice | Project Ideas |
| note-alice-2 | alice | Meeting Notes |
| note-bob-1 | bob | API Integration Tasks |
| note-bob-2 | bob | Security Review Findings |

**Orders (Scenario B):**

| ID | Owner | Amount | Refundable |
|----|-------|--------|------------|
| order-alice-1 | alice | $99.99 | Yes (30 days) |
| order-alice-2 | alice | $149.99 | Yes (30 days) |
| order-bob-1 | bob | $49.99 | Yes (30 days) |
| order-bob-2 | bob | $199.99 | No (expired) |

---

## API endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/excessive-agency/auth/login` | POST | Log in as alice or bob |
| `/api/excessive-agency/auth/logout` | POST | Log out |
| `/api/excessive-agency/mode` | GET/POST | Read or toggle lab mode |
| `/api/excessive-agency/chat` | POST | Send a message to the AI |
| `/api/excessive-agency/notes` | GET | Current user's notes |
| `/api/excessive-agency/notes/all` | GET | All notes (lab view) |
| `/api/excessive-agency/orders` | GET | Current user's orders |
| `/api/excessive-agency/orders/all` | GET | All orders (lab view) |
| `/api/excessive-agency/refunds` | GET | Current user's refunds |
| `/api/excessive-agency/audit` | GET | Audit log |
| `/api/excessive-agency/reset` | POST | Reset lab state |

---

## Security takeaways

1. **Principle of least privilege.** Give AI agents only what they need. Scope
   tools per user/session. Do not share a single privileged service account
   across users.
2. **Always validate at the backend.** Never trust the AI's output for
   sensitive operations. A policy engine enforces business rules independently
   of what the LLM decided.
3. **Human-in-the-loop for high-risk actions.** Queue sensitive actions (large
   refunds, admin ops, financial transactions) for manual approval.
4. **Identity forwarding.** Execute tools on behalf of the authenticated user.
   Log both the requesting user and the acting identity.
5. **Comprehensive audit logging.** Every tool invocation, with full context,
   including authorization decisions. This is your forensic trail.

---

## References

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP API Security — BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
