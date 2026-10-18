// Editable family content is fetched only for the open objectives panel.
export const ADMIN_FAMILY_CONTENT = Object.freeze({
 direct_prompt_injection: ['/api/admin/pi-workshop/solutions','challenges','pi'],
 reflected_xss_llm: ['/api/admin/xss-workshop/objective-solutions','objectives','xss'],
 csrf_prompt_injection: ['/api/admin/csrf-workshop/objective-solutions','objectives','csrf'],
 sensitive_info_disclosure: ['/api/admin/finflow-workshop/solutions','objectives','finflow'],
 supply_chain_rce: ['/api/admin/supply-chain-workshop/solutions','solutions','supplyChain'],
 excessive_agency: ['/api/admin/ea-workshop/solutions','objectives','ea'],
 indirect_prompt_injection: ['/api/admin/ipi-workshop/solutions','objectives','ipi'],
 mcp_server_rce: ['/api/admin/mcp-workshop/solutions','objectives','mcp'],
 sql_injection_workshop: ['/api/admin/sql-injection-workshop/solutions','objectives','sql'],
 nosql_injection_workshop: ['/api/admin/nosql-injection-workshop/solutions','objectives','nosql'],
 secureshop_agent_security: ['/api/admin/solutions','solutions','generic'],
 xss_email_builder: ['/api/admin/solutions','solutions','generic'],
 legacy_sensitive_file_ssi: ['/api/admin/solutions','solutions','generic'],
});
export async function readAdminExerciseState({get,config,key,workshopKey}) {
 const selected=key?(ADMIN_FAMILY_CONTENT[key] || ADMIN_FAMILY_CONTENT[workshopKey]):null;
 const reads=[get('/api/admin/challenges',config)];
 if(key){reads.push(get(`/api/admin/workshops/${workshopKey}/objectives`,config),get(`/api/admin/workshops/${workshopKey}/hints`,config));if(selected)reads.push(get(selected[0],config));}
 const [catalog,objectives,hints,content]=await Promise.all(reads);
 if(catalog.data?.success!==true||!Array.isArray(catalog.data.challenges))throw Error('Invalid admin exercise catalog');
 const challenges=[...catalog.data.challenges,...(catalog.data.applications || [])];
 if(!key)return {challenges};
 if(!Array.isArray(objectives.data?.objectives)||!hints.data?.hints||typeof hints.data.hints!=='object')throw Error('Invalid admin objective content');
 if(selected&&!Array.isArray(content.data?.[selected[1]]))throw Error('Invalid admin solution content');
 return {challenges,objectives:objectives.data.objectives,hints:hints.data.hints,
  ...(selected?{content:content.data[selected[1]],target:selected[2]}:{})};
}
