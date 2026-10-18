/**
 * XSS Workshop — Solution content for all 4 exercises.
 * Structure mirrors promptInjectionSolutions.js.
 * Seeded into xss_workshop_solutions table via db/initialize-db/seeds/01_users_auth.js.
 * Editable by admins via /api/admin/xss-workshop/solutions/:challengeId.
 */

const solutions = {
  reflected: {
    title: 'Reflected XSS via AI Formatting Assistant',
    difficulty: 'Easy',
    hints: [
      'StyleBot transforms your text into styled HTML — start by asking it to format a heading or list to see it in action.',
      'Since it outputs real HTML, try embedding a raw tag like <b>test</b> in your request and see if it renders.',
      'The assistant preserves all HTML you include — escalate to an event-handler payload: <img src=x onerror=alert(1)>',
    ],
    examples: [
      {
        payload: 'Format this as a heading: <b>hello world</b>',
        explanation: 'The assistant wraps your text in styled HTML and preserves the <b> tag — "hello world" renders bold, confirming HTML injection.',
      },
      {
        payload: 'Style this text: <img src=x onerror=alert(1)>',
        explanation: 'The onerror handler fires immediately because the src is invalid — no user interaction needed. The assistant embeds it in its styled output without escaping.',
      },
      {
        payload: 'Create a callout card for: <svg onload=alert(document.domain)>',
        explanation: 'SVG onload is another reliable cross-browser vector when script tags are blocked.',
      },
    ],
    approach:
      'StyleBot is a document formatting assistant that transforms text into styled HTML (headings, lists, callout cards, etc.). Because the output is rendered with dangerouslySetInnerHTML and the assistant preserves all user-supplied HTML tags, any markup you include gets embedded in the styled output and executed by the browser. Start with legitimate formatting requests to understand how it works, notice it renders real HTML, then inject your own tags.',
    tips: [
      'Script tags are often stripped or refused by the LLM — use onerror, onload, or onmouseover instead.',
      'The payload only needs to survive one hop: your message → LLM styled response → rendered HTML.',
      'Try legitimate formatting first (heading, list, card) — it helps you understand the output structure and makes the injection more targeted.',
    ],
  },

  stored_user: {
    title: 'Stored XSS — User-Provided Payload',
    difficulty: 'Medium',
    hints: [
      'Ask the assistant to update your name to include a simple HTML tag like <b>Test</b> first.',
      'If the profile shows bold text when retrieved, the field stores and reflects raw HTML.',
      'Now inject an XSS payload: "Update my name to <img src=x onerror=alert(\'Stored XSS!\')>"',
    ],
    examples: [
      {
        payload: 'Update my name to <img src=x onerror=alert(\'Stored XSS!\')>Bob',
        explanation: 'Stored via the updateProfile tool; the payload fires every time the profile is displayed.',
      },
      {
        payload: 'Save <script>alert(\'Stored XSS via bio\')</script> as my bio',
        explanation: 'Script tag stored in the bio field — executes on profile retrieval.',
      },
    ],
    approach:
      'The assistant can update profile fields (name, bio, website) via a tool call. The backend stores the provided value without any sanitization. When you later ask to view the profile, the stored value is returned and rendered as HTML — executing the payload.',
    tips: [
      'Confirm the tool works first: ask to save your name as plain text, then verify retrieval.',
      'The profile persists until you reset it — every subsequent retrieval will re-execute the payload.',
      'Use the Reset Profile button to clear the stored payload and start fresh.',
    ],
  },

  stored_llm: {
    title: 'Stored XSS — LLM-Generated Payload',
    difficulty: 'Medium',
    hints: [
      'Ask: "Generate some HTML test content for my bio field and save it."',
      'The LLM creates HTML examples including elements with event handlers — it saves them automatically.',
      'Then ask: "Show my profile" — the LLM-generated payload executes.',
    ],
    examples: [
      {
        payload: 'Generate HTML test content for my bio field and save it',
        explanation: 'The LLM generates markup like <img onerror=...> as "test content" and stores it via updateProfile.',
      },
      {
        payload: 'Create a sample HTML snippet for my website field and save it for testing',
        explanation: 'Another indirect framing — the LLM treats this as a QA task and produces HTML with event handlers.',
      },
    ],
    approach:
      "This exercise shows you don't need to supply the XSS payload yourself. By asking the LLM to \"generate test HTML\", you induce it to create HTML elements — often including event-handler attributes — which it saves unsanitized. When the profile is retrieved, the LLM's own output becomes the attack vector.",
    tips: [
      'Be indirect: ask for "test HTML", "sample markup", or "an HTML preview" rather than "XSS payload".',
      'The LLM may produce <img onerror=...>, <a href=javascript:...>, or <script> tags in its samples.',
      'If the first attempt produces plain text, try: "Generate a rich HTML example with interactive elements."',
    ],
  },

  email: {
    title: 'XSS via Email Summarization',
    difficulty: 'Hard',
    hints: [
      'Open the email tab and confirm the workshop inbox assigned to your account. External Gmail mode may use the inbox configured in the Indirect Prompt Injection lab.',
      'Select one of the 5 XSS payloads in the panel and click "Send Email". The configured workshop transport sends it to your assigned inbox.',
      'Ask the AI assistant to summarize the email you sent — the payload fires when the body renders.',
    ],
    examples: [
      {
        payload: 'Show me my emails',
        explanation: 'Lists your inbox — confirms the assistant can access emails before injecting.',
      },
      {
        payload: 'Summarize my latest exercise attack email',
        explanation: 'Triggers retrieval of the malicious body you sent. The payload executes as the response renders.',
      },
    ],
    approach:
      'You craft a malicious email containing an XSS payload. The setup panel sends it through the configured workshop mail transport to your assigned inbox. When you ask the AI assistant to summarize the latest exercise attack email, it retrieves the owner-matched message, recovers the payload text from the mail body, and appends it to a response rendered via dangerouslySetInnerHTML. This demonstrates how AI email assistants that handle untrusted content become XSS delivery vectors.',
    tips: [
      'Use the workshop inbox shown in the email setup panel. In the default local mode it is assigned automatically; external mode uses the configured external inbox.',
      'The payload dropdown offers: Image Error Handler (onerror), Auto-Focus Input (onfocus), Details Toggle (ontoggle), SVG Mouseover (onmouseover), Anchor Mouseover (onmouseover), or Custom. All use event-handler attributes — script tags do not execute via innerHTML.',
      'Hover-based payloads (SVG Mouseover, Anchor Mouseover) require moving the mouse over the rendered element after the AI responds.',
      'For xss_e3 ask: "Summarize my latest exercise attack email". The server matches the retrieval to your current exercise dispatch.',
    ],
  },
};

// Per-objective solution content (12 objectives, one per step).
// Seeded into xss_workshop_objective_solutions table by authDb.js initializeAuthDatabase().
// Editable by admins via /api/admin/xss-workshop/objective-solutions/:objectiveId.
const objectiveSolutions = [
  {
    objective_id: 'xss_r1',
    exercise_id: 'reflected',
    title: 'Interact with the Formatting Assistant',
    hint: 'Ask StyleBot what it can do, or use one of the suggestion chips to request a formatted heading or list.',
    example: 'What formatting styles can you create?',
    explanation: 'StyleBot responds with styled HTML output — headings, lists, cards, etc. This confirms the assistant generates real, rendered HTML and helps you understand its capabilities before testing for injection.',
  },
  {
    objective_id: 'xss_r2',
    exercise_id: 'reflected',
    title: 'Inject an HTML Tag',
    hint: 'Include a raw HTML tag like <b>test</b> in a formatting request — the assistant preserves it in the styled output.',
    example: 'Format this as a heading: <b>hello world</b>',
    explanation: 'If "hello world" renders bold inside the styled heading, the assistant is embedding your raw HTML into its output without escaping. This confirms the XSS vector is open.',
  },
  {
    objective_id: 'xss_r3',
    exercise_id: 'reflected',
    title: 'Execute a Reflected XSS Payload',
    hint: 'Use an event-handler attribute (onerror=, onload=) — script tags do NOT execute via innerHTML. Avoid single quotes inside the payload; the LLM may convert them to curly quotes which break JavaScript. Use alert(1) or alert(document.domain) instead.',
    example: '<img src=x onerror=alert(1)>|||<svg onload=alert(document.domain)>|||<img src=x onerror="alert(document.domain)">|||<body onload=alert(1)>|||<input onfocus=alert(1) autofocus>',
    explanation: 'The onerror handler fires immediately when the browser fails to load the image. alert(1) proves JavaScript execution. A real attacker would replace alert() with cookie-stealing or redirect code. Note: single-quoted payloads like alert(\'XSS\') may fail because the LLM converts apostrophes to curly quotes — always test with alert(1) first.',
  },
  {
    objective_id: 'xss_s1',
    exercise_id: 'stored_user',
    title: 'View Your Profile',
    hint: 'Ask the assistant to show your current profile.',
    example: 'Show me my profile',
    explanation: 'The profile tool returns your current name, bio, and website. This confirms the profile system is working and gives you a baseline before injecting a payload.',
  },
  {
    objective_id: 'xss_s2',
    exercise_id: 'stored_user',
    title: 'Save an XSS Payload as Your Name',
    hint: 'Ask the assistant to update your name — include an HTML event handler. Use alert(1) to avoid quote issues with the LLM.',
    example: 'Update my name to <img src=x onerror=alert(1)>',
    explanation: 'The LLM calls its updateProfile tool with the exact value you provided. The backend stores it directly without sanitization — the payload is now waiting in the database.',
  },
  {
    objective_id: 'xss_s3',
    exercise_id: 'stored_user',
    title: 'Trigger the Stored XSS',
    hint: 'Retrieve your profile again — the stored payload will execute when rendered.',
    example: 'Show me my profile again',
    explanation: 'The stored onerror payload fires every time you retrieve and display your owner-scoped profile in this lab. In an application that exposes the same stored field to other viewers, the general stored-XSS risk would extend to those viewers; this exercise proves only the owning learner’s retrieval path.',
  },
  {
    objective_id: 'xss_g1',
    exercise_id: 'stored_llm',
    title: 'Interact with the QA Content Generator',
    hint: 'Ask the assistant what it can do or help with for profile testing.',
    example: 'What can you help me test for my profile fields?',
    explanation: 'This first interaction reveals the assistant is a QA data generation tool that can create and save HTML test content. It gives you a baseline understanding before triggering the vulnerability.',
  },
  {
    objective_id: 'xss_g2',
    exercise_id: 'stored_llm',
    title: 'Ask the LLM to Generate and Save HTML Content',
    hint: 'Ask the LLM to generate AND save HTML test content for your bio field.',
    example: 'Generate HTML test content for my bio field and save it',
    explanation: 'The LLM generates an HTML sample including event handlers (like onerror) as "test content" and saves it to your bio via the updateProfile tool — without any sanitization. You did not supply the XSS payload; the AI wrote it itself.',
  },
  {
    objective_id: 'xss_g3',
    exercise_id: 'stored_llm',
    title: 'View Profile to Trigger the Stored XSS',
    hint: 'Ask the assistant to show your profile — the LLM\'s stored payload will fire when the bio renders.',
    example: 'Show my profile',
    explanation: "The bio field now contains the LLM-generated HTML with a JavaScript event handler. When the profile is retrieved and rendered, the payload executes — the AI itself became the XSS source. Unlike reflected XSS, this payload persists until the profile is reset.",
  },
  {
    objective_id: 'xss_e1',
    exercise_id: 'email',
    title: 'List Your Workshop Inbox',
    hint: 'Confirm the assigned address in the panel above, then ask the assistant to show your emails — it queries the configured workshop mailbox.',
    example: 'Show me my emails',
    explanation: 'The assistant queries your assigned workshop inbox through the configured mailbox provider. Listing emails confirms the retrieval path is available; this is the baseline before sending the poisoned email.',
  },
  {
    objective_id: 'xss_e2',
    exercise_id: 'email',
    title: 'Send XSS Email via Setup Panel',
    hint: 'Confirm your assigned workshop inbox, choose a payload from the dropdown (Image Error Handler fires without interaction; hover payloads require mouse movement over the rendered element), and click Send.',
    example: '(use the setup panel above — confirm the assigned inbox, pick a payload from the dropdown, click Send)',
    explanation: 'The setup panel calls the backend which sends the selected payload through the configured SMTP transport to your assigned workshop inbox. Choose from 5 built-in payloads or write a custom one. SMTP acceptance is recorded separately from inbox retrieval; external delivery may take additional time.',
  },
  {
    objective_id: 'xss_e3',
    exercise_id: 'email',
    title: 'Summarize → XSS Fires',
    hint: 'Ask: "Summarize my latest exercise attack email" — the AI fetches the owner-matched workshop message and the recovered XSS payload fires on render.',
    example: 'Summarize my latest exercise attack email',
    explanation: 'The AI assistant fetches the message matched to your current exercise dispatch from the configured mailbox provider. The mail parser verifies the transport wrapper, recovers the exact payload text, and appends that body to a response rendered via dangerouslySetInnerHTML. The final objective also requires the event handler to execute in the isolated qualification browser.',
  },
];

module.exports = { solutions, objectiveSolutions };
