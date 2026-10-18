'use strict';
// Public solution URL contracts, independent of database storage.
module.exports = {
  xss_email_builder: { statusPrefix: 'xss-email-builder', contentSubpath: '' },
  legacy_sensitive_file_ssi: { statusPrefix: 'legacy-file-ssi', contentSubpath: '' },
  secureshop_agent_security: { statusPrefix: 'secureshop-agent-security', contentSubpath: '' },
  direct_prompt_injection: { statusPrefix: 'prompt-injection', contentSubpath: '' },
  xss_workshop: { statusPrefix: 'xss-workshop', contentSubpath: 'objective/' },
  csrf_workshop: { statusPrefix: 'csrf-workshop', contentSubpath: 'objective/' },
  sensitive_info_disclosure: { statusPrefix: 'sensitive-info', contentSubpath: '' },
  supply_chain_rce: { statusPrefix: 'supply-chain', contentSubpath: '' },
  excessive_agency: { statusPrefix: 'excessive-agency', contentSubpath: '' },
  indirect_prompt_injection: { statusPrefix: 'indirect-pi', contentSubpath: '' },
  mcp_workshop: { statusPrefix: 'mcp-workshop', contentSubpath: '' },
  sql_injection_workshop: { statusPrefix: 'sql-injection', contentSubpath: '' },
  nosql_injection_workshop: { statusPrefix: 'nosql-injection', contentSubpath: '' },
};
