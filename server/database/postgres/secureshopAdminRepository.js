'use strict';
function createSecureShopAdminRepository(commercePool, agentsPool) {
  const all = async (pool, sql, params = []) => (await pool.query(sql, params)).rows;
  return {
    latestTrace: ({userId,role,limit}) => all(agentsPool, `SELECT t.id,t.session_id,s.role AS session_role,t.step,t.actor,t.kind,t.agent_ns,t.tool_name,t.latency_ms,t.tokens_in,t.tokens_out,t.provider,t.ts FROM secureshop_agents.agent_trace t INNER JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id WHERE s.user_id=$1 AND s.role=$2 AND COALESCE(to_jsonb(s)->>'authority_mode','legacy')='legacy' ORDER BY t.ts DESC,t.id DESC LIMIT $3`, [userId,role,limit]),
    trace: sessionId => all(agentsPool, `SELECT t.id,t.session_id,t.step,t.actor,t.kind,t.agent_ns,t.tool_name,t.params_json,t.result_json,t.latency_ms,t.tokens_in,t.tokens_out,t.provider,t.ts FROM secureshop_agents.agent_trace t INNER JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id WHERE t.session_id=$1 AND COALESCE(to_jsonb(s)->>'authority_mode','legacy')='legacy' ORDER BY t.ts,t.id`, [sessionId]),
    async kpis() {
      const [commerce, sessions] = await Promise.all([
        all(commercePool, `SELECT (SELECT count(*)::integer FROM secureshop.shop_users) AS total_users,(SELECT count(*)::integer FROM secureshop.products) AS total_products,(SELECT count(*)::integer FROM secureshop.orders) AS total_orders,(SELECT coalesce(sum(total_amount),0)::float8 FROM secureshop.orders) AS total_revenue,(SELECT count(*)::integer FROM secureshop.shop_users WHERE role='admin') AS admin_count,(SELECT count(*)::integer FROM secureshop.shop_users WHERE banned_at IS NOT NULL) AS banned_count`),
        all(agentsPool, `SELECT count(*)::integer AS active_sessions FROM secureshop_agents.agent_sessions s WHERE s.updated_at>now()-interval '15 minutes' AND COALESCE(to_jsonb(s)->>'authority_mode','legacy')='legacy'`),
      ]);
      return {ok:true,...commerce[0],...sessions[0]};
    },
    providerState: () => all(agentsPool, 'SELECT role,active_provider,last_success_at,fallback_cursor FROM secureshop_agents.agent_provider_state ORDER BY role'),
    async sizes() {
      return Promise.all([commercePool, agentsPool].map(async pool => {
        const [row] = await all(pool, 'SELECT current_database() AS database,pg_database_size(current_database())::float8 AS size_bytes');
        return {...row,size_mb:Math.round(row.size_bytes/1048576*100)/100};
      }));
    },
    async users({search,role,banned,page,pageSize,paginated}) {
      const where=[], params=[];
      if(search){params.push(`%${search}%`);where.push(`(username ILIKE $${params.length} OR email ILIKE $${params.length} OR coalesce(full_name,'') ILIKE $${params.length})`);}
      if(role){params.push(role);where.push(`role=$${params.length}`);}
      if(banned==='true')where.push('banned_at IS NOT NULL');
      if(banned==='false')where.push('banned_at IS NULL');
      const filter=where.length?'WHERE '+where.join(' AND '):'';
      const [count]=await all(commercePool,`SELECT count(*)::integer AS total FROM secureshop.shop_users ${filter}`,params);
      let paging='';if(paginated){params.push(pageSize,(page-1)*pageSize);paging=`LIMIT $${params.length-1} OFFSET $${params.length}`;}
      const rows=await all(commercePool,`SELECT id,username,email,role,full_name,api_key,session_token,pii_json,banned_at,created_at FROM secureshop.shop_users ${filter} ORDER BY id ${paging}`,params);
      return {rows,total:count.total};
    },
    async audit({actor,action,target,q,from,to,limit}) {
      const clauses=[], params=[];
      for(const [field,value] of Object.entries({actor,action,target})){if(value){params.push(`%${value}%`);clauses.push(`${field} ILIKE $${params.length}`);}}
      if(q){params.push(`%${q}%`);const n=params.length;clauses.push(`(actor ILIKE $${n} OR action ILIKE $${n} OR target ILIKE $${n} OR coalesce(params_json,'') ILIKE $${n})`);}
      if(from){params.push(from);clauses.push(`ts >= $${params.length}::timestamptz`);}
      if(to){params.push(to);clauses.push(`ts <= $${params.length}::timestamptz`);}
      params.push(limit);
      return all(agentsPool,`SELECT id,actor,action,target,params_json,ip,user_agent,ts FROM secureshop_agents.audit_events ${clauses.length?'WHERE '+clauses.join(' AND '):''} ORDER BY ts DESC,id DESC LIMIT $${params.length}`,params);
    },
    policies: () => all(commercePool, 'SELECT id,name,markdown_source,injected_into_json,updated_at FROM secureshop.policies ORDER BY updated_at DESC,id'),
    setPolicyTargets: (name,targets) => commercePool.query('UPDATE secureshop.policies SET injected_into_json=$1 WHERE name=$2',[JSON.stringify(targets),name]),
    async deletePolicy(name){const result=await commercePool.query('DELETE FROM secureshop.policies WHERE name=$1',[name]);return {changes:result.rowCount};},
    async enqueueRebuild(jobId,corpus){
      await agentsPool.query("INSERT INTO secureshop_agents.background_jobs(id,kind,payload_json,status) VALUES($1,'rebuild_vector_index',$2,'pending')",[jobId,JSON.stringify({corpus})]);
      const [row]=await all(agentsPool,'SELECT count(*)::integer AS count FROM secureshop_agents.vector_documents d JOIN secureshop_agents.vector_corpora c ON c.corpus=d.corpus AND c.active_generation=d.generation WHERE d.corpus=$1',[corpus]);return row.count;
    },
  };
}
let singleton;
function getSecureShopAdminRepository(){const pools=require('./secureshopPools');return singleton||=createSecureShopAdminRepository(pools.getCommercePool(),pools.getAgentsPool());}
module.exports={createSecureShopAdminRepository,getSecureShopAdminRepository};
