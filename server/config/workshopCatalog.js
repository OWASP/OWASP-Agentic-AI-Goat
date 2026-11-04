// UI challenge key -> canonical workshop key. Supported PostgreSQL progress and
// visibility are stored in workshop_platform; retained legacy fixtures also use
// this mapping. Runtime counts and instructor-edited content come from the DB.
const CHALLENGE_TO_WORKSHOP_KEY = {
  reflected_xss_llm: 'xss_workshop',
  csrf_prompt_injection: 'csrf_workshop',
  mcp_server_rce: 'mcp_workshop',
};

// workshop_key -> ordered [{ id, text }] canonical labels for every objective.
// CTF (ctf_prompt_injection_challenge) is intentionally absent because it has its
// own isolated CTF PostgreSQL progression store (SQLite only in legacy fixtures).
const WORKSHOP_OBJECTIVES = {
  xss_email_builder: require('./xssEmailBuilderCurriculum').OBJECTIVES,
  legacy_sensitive_file_ssi: require('./legacyFileSsiCurriculum').OBJECTIVES,
  secureshop_agent_security: require('./secureshopCurriculum').OBJECTIVES,
  xss_workshop: [
    { id: 'xss_r1', text: 'Reflected XSS 1 — First interaction' },
    { id: 'xss_r2', text: 'Reflected XSS 2 — Send HTML payload' },
    { id: 'xss_r3', text: 'Reflected XSS 3 — XSS event fires' },
    { id: 'xss_s1', text: 'Stored XSS 1 — View profile via tool' },
    { id: 'xss_s2', text: 'Stored XSS 2 — Update profile via tool' },
    { id: 'xss_s3', text: 'Stored XSS 3 — XSS event fires from stored payload' },
    { id: 'xss_g1', text: 'LLM-Generated XSS 1 — First interaction' },
    { id: 'xss_g2', text: 'LLM-Generated XSS 2 — LLM updates profile' },
    { id: 'xss_g3', text: 'LLM-Generated XSS 3 — XSS fires from LLM output' },
    { id: 'xss_e1', text: 'Email XSS 1 — List emails via tool' },
    { id: 'xss_e2', text: 'Email XSS 2 — Send attack email' },
    { id: 'xss_e3', text: 'Email XSS 3 — XSS fires from email summary' },
  ],
  csrf_workshop: [
    { id: 'csrf_g1', text: 'GET · Recon (2-turn)' },
    { id: 'csrf_g2', text: 'GET · <img> pixel forges request' },
    { id: 'csrf_g3', text: 'GET · Defense blocks pixel' },
    { id: 'csrf_p1', text: 'POST · auto-submit <form>' },
    { id: 'csrf_p2', text: 'POST · fetch()+credentials' },
    { id: 'csrf_p3', text: 'POST · Defense blocks form' },
    { id: 'csrf_x1', text: 'Email XSS · set up inbox' },
    { id: 'csrf_x2', text: 'Email XSS · send payload' },
    { id: 'csrf_x3', text: 'Email XSS · trigger read → CSRF' },
    { id: 'csrf_i1', text: 'RAG · poison the KB' },
    { id: 'csrf_i2', text: 'RAG · query fires CSRF' },
    { id: 'csrf_i3', text: 'RAG · persistence (re-fires)' },
  ],
  direct_prompt_injection: [
    { id: 'interact', text: 'Practice Mode', description: 'Ask two AWS questions to complete practice.' },
    { id: 'format_override', text: 'Output Format Attack', description: 'Make the formatter reply with exactly GOAT FORMAT OVERRIDDEN as plain text.' },
    { id: 'classification_override', text: 'Classification Attack', description: 'Make ticket LAB-204 return APPROVED instead of REVIEW.' },
    { id: 'system_prompt', text: 'System Prompt Extraction', description: 'Get the assistant to reveal its hidden instructions.' },
    { id: 'jailbreak', text: 'Jailbreak Attack', description: 'Override the rules and get an answer about a non-AWS topic.' },
    { id: 'multi_language', text: 'Multi-Language Attack', description: 'Ask a non-AWS question in another language.' },
    { id: 'virtualization', text: 'Virtualization Attack', description: 'Use a hypothetical scenario to get a non-AWS answer.' },
    { id: 'role_playing', text: 'Role Playing Attack', description: 'Assign a new role and ask a non-AWS question.' },
    { id: 'side_stepping', text: 'Side Stepping Attack', description: 'Use an AWS comparison or migration question to get competitor details.' },
    { id: 'obfuscation', text: 'Obfuscation Attack', description: 'Encode a non-AWS question and get the assistant to answer it.' },
  ],
  indirect_prompt_injection: [
    { id: 'rag_upload', text: 'Load Document into RAG system' },
    { id: 'rag_clean_doc', text: 'Load Clean Document' },
    { id: 'rag_query', text: 'Ask a question from the RAG database' },
    { id: 'rag_injected_doc', text: 'Detect Injected/Poisoned Document' },
    { id: 'rag_query_injection', text: 'Trigger Bypass via Poisoned RAG' },
    { id: 'email_create_inbox', text: 'Email Agent — Create Temporary Inbox' },
    { id: 'email_send_attack', text: 'Email Agent — Send Attack Email' },
    { id: 'email_retrieve', text: 'Email Agent — Load Retrieved or Manual Email' },
    { id: 'email_trigger_injection', text: 'Email Agent — Trigger Injection' },
    { id: 'email_understand_defense', text: 'Email Agent — Understand Defense' },
  ],
  mcp_workshop: [
    { id: 'mcp_recon', text: 'Recon: ask the assistant in plain English what tools it can use' },
    { id: 'mcp_cmd_injection', text: 'Command injection: escape the "safe command" allowlist to read a restricted file' },
    { id: 'mcp_ssrf', text: 'SSRF: make fetch_url reach an internal-only service / cloud metadata and steal a token' },
    { id: 'mcp_tool_poisoning', text: 'Tool poisoning: trigger the tool whose description hides instructions' },
    { id: 'mcp_indirect_injection', text: 'Indirect injection: read a poisoned support ticket that hijacks the assistant' },
    { id: 'mcp_confused_deputy', text: 'Confused deputy: talk the bot into emailing secrets to an attacker address' },
    { id: 'mcp_broken_authz', text: 'Broken authorization: invoke the admin-only key-rotation tool without admin rights' },
    { id: 'mcp_secret_exposure', text: 'Secret exposure: get the assistant to hand back live tokens/API keys in plaintext' },
    { id: 'mcp_supply_chain', text: 'Supply chain: install a plugin/dependency from an untrusted source and backdoor the server' },
    { id: 'mcp_audit_gap', text: 'Audit gap: disable or clear target-private audit logs without authorization; platform evidence remains retained' },
    { id: 'mcp_shadow_server', text: 'Shadow server: register an unapproved/rogue MCP server the assistant will trust' },
  ],
  excessive_agency: [
    { id: 'objective_1', text: 'List your own data (fixed mode)' },
    { id: 'objective_2', text: 'Create a note (fixed mode)' },
    { id: 'objective_3', text: 'Attempt restricted action — see it blocked' },
    { id: 'objective_4', text: 'Attempt cross-user access — see it blocked' },
    { id: 'objective_5', text: "Access another user's data (vuln mode)" },
    { id: 'objective_6', text: 'Create a note for another user (vuln mode)' },
    { id: 'objective_7', text: 'Create an order for another user (vuln mode)' },
    { id: 'objective_8', text: "Delete another user's note (vuln mode)" },
    { id: 'objective_9', text: 'Issue unauthorized refund (vuln mode)' },
  ],
  sensitive_info_disclosure: [
    { id: 'tool_enum', text: 'Customer Tool Enumeration — list all 5 customer-facing tools' },
    { id: 'llm_identify', text: 'LLM Model Identification — reveal model name and endpoint' },
    { id: 'tool_version', text: 'Tool Version Disclosure — expose tool version numbers' },
    { id: 'traversal_secrets', text: 'Path Traversal — secrets.env' },
    { id: 'traversal_passwd', text: 'Path Traversal — /etc/passwd' },
    { id: 'traversal_llm', text: 'Path Traversal — llm_config.yml' },
    { id: 'ssrf_oob', text: 'SSRF — Out-of-Band' },
    { id: 'ssrf_internal', text: 'SSRF — Internal App API' },
    { id: 'ssrf_ollama', text: 'SSRF — Enumerate Ollama' },
    { id: 'error_leak', text: 'Error Message Info Leakage' },
    { id: 'admin_enum', text: 'Admin — elicit the restricted 8-tool administrative catalog' },
    { id: 'admin_backup', text: 'Admin — Create Database Backup' },
    { id: 'admin_dl_backup', text: 'Admin — Download Backup' },
    { id: 'admin_read_logs', text: 'Admin — Read Application Logs' },
    { id: 'admin_llm_logs', text: 'Admin — Read LLM Request Logs' },
    { id: 'admin_modify_logs', text: 'Admin — Modify / Delete Logs' },
    { id: 'admin_secrets', text: 'Admin — Expose Secrets & Keys' },
    { id: 'admin_dirlist', text: 'Admin — Directory Listing' },
  ],
  supply_chain_rce: [
    { id: 'tool_list', text: 'Enumerate Available Tools' },
    { id: 'pkg_discover', text: 'Discover vulnerable pkg-parse package' },
    { id: 'clean_request', text: 'Trigger a clean baseline request' },
    { id: 'rce_env', text: 'Achieve RCE — exfiltrate env vars' },
    { id: 'rce_ssh', text: 'Achieve RCE — read SSH keys' },
    { id: 'rce_cmd', text: 'Achieve RCE — arbitrary JavaScript evaluation' },
  ],
  sql_injection_workshop: [
    { id: 'sqli_1', text: 'Trigger SQL Syntax Error' },
    { id: 'sqli_2', text: 'Boolean-Based Bypass' },
    { id: 'sqli_3', text: 'Determine Column Count (ORDER BY)' },
    { id: 'sqli_4', text: 'UNION NULL Probe — Wrong Count' },
    { id: 'sqli_5', text: 'Match Column Count with UNION SELECT' },
    { id: 'sqli_6', text: 'Identify String-Compatible Columns' },
    { id: 'sqli_7', text: 'Extract Database Version' },
    { id: 'sqli_8', text: 'Enumerate Database Tables' },
    { id: 'sqli_9', text: 'Dump Column Schema' },
    { id: 'sqli_10', text: 'Extract Sensitive Order Data' },
  ],
  nosql_injection_workshop: [
    { id: 'nosqli_1', text: 'Trigger NoSQL Error' },
    { id: 'nosqli_2', text: 'Boolean Operator Bypass ($gt)' },
    { id: 'nosqli_3', text: 'Regex Wildcard Injection ($regex)' },
    { id: 'nosqli_4', text: 'Database Version Extraction' },
    { id: 'nosqli_5', text: 'Collection Schema Extraction' },
    { id: 'nosqli_6', text: 'Not-Equal Operator Bypass ($ne)' },
    { id: 'nosqli_7', text: 'Where Clause Injection ($where)' },
    { id: 'nosqli_8', text: 'Array Query Injection ($in)' },
    { id: 'nosqli_9', text: 'Extract Author Contact Data' },
    { id: 'nosqli_10', text: 'Extract Restricted Research Data' },
  ],
};

const WORKSHOP_TO_CHALLENGE_KEY = Object.fromEntries(
  Object.entries(CHALLENGE_TO_WORKSHOP_KEY).map(([challengeKey, workshopKey]) => [workshopKey, challengeKey])
);

const toWorkshopKey = (challengeKey) => CHALLENGE_TO_WORKSHOP_KEY[challengeKey] || challengeKey;
const toChallengeKey = (workshopKey) => WORKSHOP_TO_CHALLENGE_KEY[workshopKey] || workshopKey;

// SecureShop retains its canonical curriculum and progress for the separate app.
// Its participation does not contribute to the workshop lists or analytics.
const STANDALONE_APP_WORKSHOP_KEY = 'secureshop_agent_security';
const isWorkshopSurfaceEligible = key => toWorkshopKey(key) !== STANDALONE_APP_WORKSHOP_KEY;
// The column expression is supplied only by repository code, never request input.
const workshopSurfaceSqlCondition = column => `${column}<>'${STANDALONE_APP_WORKSHOP_KEY}'`;

module.exports = {
  WORKSHOP_OBJECTIVES,
  CHALLENGE_TO_WORKSHOP_KEY,
  toWorkshopKey,
  toChallengeKey,
  isWorkshopSurfaceEligible,
  workshopSurfaceSqlCondition,
};
