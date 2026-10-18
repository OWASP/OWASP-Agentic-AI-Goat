'use strict';
const { createPool, withTransaction } = require('./index');
const { helpers, singleton, initialize } = require('./workshopSupport');
const fixtures = require('../../../db/postgres/nosqlWorkshopFixtures');
const solutions = require('../../data/postgres/nosqlInjectionWorkshopSolutions')(require('../../data/nosqlInjectionWorkshopSolutions'));
const parse = value => { try { return JSON.parse(value); } catch { return []; } };
const paper = row => row ? {...row,authors:parse(row.authors),topics:parse(row.topics),cited_by:parse(row.cited_by)} : null;
const author = row => row ? {...row,expertise:parse(row.expertise)} : null;
function deletionOwner(value){const id=String(value);if(!/^[1-9][0-9]{0,9}$/.test(id)||Number(id)>2147483647)throw new TypeError('Valid platform owner required');return id;}
function keys(value) { return value && typeof value==='object' ? Object.entries(value).flatMap(([key,val])=>[key,...keys(val)]) : []; }
function opValue(value,op) {
  if (!value || typeof value!=='object') return undefined;
  for (const [key,val] of Object.entries(value)) { if (key===op) return val; const found=opValue(val,op); if (found!==undefined) return found; }
}
async function seed(client) {
  if ((await client.query('SELECT version FROM nova.seed_state WHERE version=1')).rowCount) return;
  for (const p of fixtures.PAPERS) await client.query('INSERT INTO nova.papers (paper_id,title,abstract,authors,topics,year,journal,citations,cited_by,url,access_level) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (paper_id) DO NOTHING', [p.paper_id,p.title,p.abstract,p.authors,p.topics,p.year,p.journal,p.citations,p.cited_by,p.url,['PAPER-2024-039','PAPER-2024-040'].includes(p.paper_id)?'restricted':'public']);
  for (const a of fixtures.AUTHORS) await client.query('INSERT INTO nova.authors (author_id,name,institution,expertise,paper_count,email,bio) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (author_id) DO NOTHING', [a.author_id,a.name,a.institution,a.expertise,a.paper_count,a.email,a.bio]);
  for (const r of fixtures.READING_LIST) await client.query('INSERT INTO nova.reading_lists (user_id,paper_id) VALUES ($1,$2) ON CONFLICT (user_id,paper_id) DO NOTHING', [r.user_id,r.paper_id]);
  for (const id of fixtures.NOSQLI_OBJECTIVE_IDS) await client.query('INSERT INTO nova.nosql_injection_solution_visibility (objective_id) VALUES ($1) ON CONFLICT DO NOTHING', [id]);
  for (const [id,s] of Object.entries(solutions)) await client.query('INSERT INTO nova.nosql_injection_solutions (objective_id,title,difficulty,hints,examples,approach,tips) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING', [id,s.title,s.difficulty,JSON.stringify(s.hints||[]),JSON.stringify(s.examples||[]),s.approach||'',JSON.stringify(s.tips||[])]);
  await client.query('INSERT INTO nova.seed_state (version) VALUES (1)');
}
function createNosqlWorkshopDb(pool) {
  const {all,get,run}=helpers(pool);
  const papers=async(sql,params=[]) => (await all(sql,params)).map(paper);
  const allPapers=()=>papers('SELECT * FROM nova.papers ORDER BY citations DESC');
  async function metadata() {
    const version=await get("SELECT current_setting('server_version') AS version");
    const collections=[];
    for (const table of ['papers','authors','reading_lists','chat_history']) {
      // Identifiers originate exclusively in the fixed allowlist above.
      const count=await get(`SELECT COUNT(*)::integer AS n FROM nova.${table}`);
      const indexes=await get("SELECT COUNT(*)::integer AS n FROM pg_indexes WHERE schemaname='nova' AND tablename=$1",[table]);
      collections.push({name:table,documents:count.n,indexes:indexes.n});
    }
    return [{type:'db_metadata',db_version:version.version,storage_engine:'PostgreSQL',simulation:'MongoDB-style operator injection on PostgreSQL',collections}];
  }
  async function schemaInfo() {
    const result=[];
    for (const table of ['papers','authors']) {
      const cols=await all(`SELECT a.attname AS name, format_type(a.atttypid,a.atttypmod) AS data_type,
        EXISTS(SELECT 1 FROM pg_index i WHERE i.indrelid=c.oid AND a.attnum=ANY(i.indkey)) AS indexed,
        EXISTS(SELECT 1 FROM pg_index i WHERE i.indrelid=c.oid AND i.indisunique AND i.indnkeyatts=1 AND a.attnum=ANY(i.indkey)) AS unique
        FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='nova' AND c.relname=$1 AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum`,[table]);
      result.push({type:'schema_info',collection:table,fields:cols.map(c=>({name:c.name,type:c.data_type==='integer'?'Integer':'String',indexed:c.indexed,unique:c.unique}))});
    }
    return result;
  }
  // Intentional teaching behavior: MongoDB-style operator interpretation is a simulation.
  // No attacker-controlled JavaScript is evaluated and no MongoDB engine is claimed.
  async function vulnerable(rawQuery) {
    const q=rawQuery||'';
    if (/email.*\$regex|\$regex.*email|author.*\$exists|\$exists.*author/i.test(q)) return (await all('SELECT author_id,name,institution,expertise,email,bio FROM nova.authors ORDER BY paper_count DESC')).map(author);
    if (/access_level.*\$ne|\$ne.*access_level|access_level.*restricted/i.test(q)) return allPapers();
    const match=q.match(/\{[\s\S]*\}/);
    if (match) {
      let operators;
      try { operators=JSON.parse(match[0]); } catch(e) { return {error:`MongoServerError: Failed to parse query: ${e.message}`}; }
      const allKeys=keys(operators);
      const supported=new Set(['$gt','$lt','$gte','$lte','$ne','$regex','$or','$and','$exists','$where','$in','$nin']);
      const invalid=allKeys.find(k=>k.startsWith('$')&&!supported.has(k));
      if (invalid) return {error:`MongoServerError: unknown operator: ${invalid}`};
      const has=op=>allKeys.includes(op);
      if (has('$gt')) return allPapers();
      if (has('$regex')) {
        const pattern='%'+String(opValue(operators,'$regex')||'').replace(/\.\*/g,'%').replace(/\^|\$/g,'')+'%';
        return papers('SELECT * FROM nova.papers WHERE title ILIKE $1 OR abstract ILIKE $1 ORDER BY citations DESC',[pattern]);
      }
      if (has('$or')||has('$exists')) return allPapers();
      if (has('$where')) {
        const value=String(opValue(operators,'$where')||'');
        if (/db\.version|buildInfo|serverStatus/i.test(value)) return metadata();
        if (/Object\.keys|keys\(this\)/i.test(value)) return schemaInfo();
        return allPapers();
      }
      if (has('$ne')) return papers('SELECT * FROM nova.papers WHERE LOWER(title)!=$1 ORDER BY citations DESC',[String(opValue(operators,'$ne')||'').toLowerCase()]);
      if (has('$in')) {
        const values=opValue(operators,'$in');
        if (Array.isArray(values)&&values.length) return papers('SELECT * FROM nova.papers WHERE EXISTS (SELECT 1 FROM unnest($1::text[]) AS term WHERE LOWER(topics) LIKE \'%\'||LOWER(term)||\'%\' OR LOWER(title) LIKE \'%\'||LOWER(term)||\'%\' OR year::text=term) ORDER BY citations DESC',[values.map(String)]);
      }
    }
    return papers('SELECT * FROM nova.papers WHERE access_level=\'public\' AND (LOWER(title) LIKE $1 OR LOWER(abstract) LIKE $1 OR LOWER(authors) LIKE $1) ORDER BY citations DESC LIMIT 10',[`%${q.toLowerCase()}%`]);
  }
  const api={
    async initializeNosqlWorkshopDb(migrationPool) {
      const owned=!migrationPool;
      migrationPool ||= createPool(process.env,'NOSQL_WORKSHOP_MIGRATION_DATABASE_URL');
      try { await initialize(pool,migrationPool,'nova',seed); }
      finally { if(owned) await migrationPool.end(); }
    },
    searchPapers(query,topic,year,mode='fixed') {
      if(mode==='vuln') return vulnerable(query||'');
      const params=[`%${(query||'').toLowerCase()}%`];
      let sql='SELECT * FROM nova.papers WHERE access_level=\'public\' AND (LOWER(title) LIKE $1 OR LOWER(abstract) LIKE $1 OR LOWER(authors) LIKE $1)';
      if(topic) {params.push(`%${topic.toLowerCase()}%`);sql+=` AND LOWER(topics) LIKE $${params.length}`;}
      if(year) {params.push(year);sql+=` AND year=$${params.length}`;}
      return papers(sql+' ORDER BY citations DESC LIMIT 10',params);
    },
    getPaperDetails:async paperId=>paper(await get('SELECT * FROM nova.papers WHERE paper_id=$1',[paperId])),
    listPapersByAuthor:authorName=>papers('SELECT * FROM nova.papers WHERE LOWER(authors) LIKE $1 ORDER BY year DESC',[`%${authorName.toLowerCase()}%`]),
    browseByTopic:topic=>papers('SELECT * FROM nova.papers WHERE LOWER(topics) LIKE $1 ORDER BY citations DESC LIMIT 10',[`%${topic.toLowerCase()}%`]),
    getAuthorProfile:async authorName=>author(await get('SELECT * FROM nova.authors WHERE LOWER(name) LIKE $1 ORDER BY id LIMIT 1',[`%${authorName.toLowerCase()}%`])),
    searchAuthors:async query=>(await all('SELECT * FROM nova.authors WHERE LOWER(name) LIKE $1 OR LOWER(institution) LIKE $1 OR LOWER(expertise) LIKE $1 ORDER BY paper_count DESC',[`%${query.toLowerCase()}%`])).map(author),
    async addToReadingList(userId,paperId,notes) {
      const p=await get('SELECT * FROM nova.papers WHERE paper_id=$1',[paperId]);
      if(!p) return {success:false,message:`Paper ${paperId} not found.`};
      const result=await run('INSERT INTO nova.reading_lists (user_id,paper_id,notes) VALUES ($1,$2,$3) ON CONFLICT (user_id,paper_id) DO NOTHING',[userId,paperId,notes||null]);
      return result.changes?{success:true,paperId,title:p.title}:{success:false,message:'Paper already in your reading list.'};
    },
    viewReadingList:async userId=>(await all('SELECT rl.paper_id,rl.added_at,rl.notes,p.title,p.authors,p.year,p.journal,p.citations FROM nova.reading_lists rl JOIN nova.papers p ON rl.paper_id=p.paper_id WHERE rl.user_id=$1 ORDER BY rl.added_at DESC,rl.id DESC',[userId])).map(r=>({...r,authors:parse(r.authors)})),
    async removeFromReadingList(userId,paperId) {const result=await run('DELETE FROM nova.reading_lists WHERE user_id=$1 AND paper_id=$2',[userId,paperId]);return {success:result.changes>0,removed:result.changes};},
    async getRecommendations(topic,paperId) {
      if(paperId) {const p=await api.getPaperDetails(paperId);if(!p||!p.topics.length)return [];return papers('SELECT * FROM nova.papers WHERE LOWER(topics) LIKE $1 AND paper_id!=$2 ORDER BY citations DESC LIMIT 5',[`%${p.topics[0].toLowerCase()}%`,paperId]);}
      if(topic)return papers('SELECT * FROM nova.papers WHERE LOWER(topics) LIKE $1 ORDER BY citations DESC LIMIT 5',[`%${topic.toLowerCase()}%`]);
      return papers('SELECT * FROM nova.papers ORDER BY citations DESC LIMIT 5');
    },
    async getTrendingTopics() {const counts=new Map();for(const row of await all('SELECT topics FROM nova.papers'))for(const topic of parse(row.topics))counts.set(topic,(counts.get(topic)||0)+1);return [...counts].sort((a,b)=>b[1]-a[1]).slice(0,10).map(([topic,paperCount])=>({topic,paperCount}));},
    async getCitationNetwork(paperId) {
      const p=await api.getPaperDetails(paperId);if(!p)return {success:false,message:`Paper ${paperId} not found.`};
      const citedBy=[];for(const id of p.cited_by){const row=await get('SELECT paper_id,title,year,citations FROM nova.papers WHERE paper_id=$1',[id]);if(row)citedBy.push(row);}
      const cites=await all('SELECT paper_id,title,year,citations FROM nova.papers WHERE cited_by LIKE $1',[`%${paperId}%`]);
      return {paper:{paper_id:p.paper_id,title:p.title},citedBy,cites};
    },
    saveMessage:(userId,messageType,message)=>run('INSERT INTO nova.chat_history (user_id,message_type,message) VALUES ($1,$2,$3) RETURNING id',[userId,messageType,message]),
    getHistory:async(userId,limit=20)=>(await all('SELECT message_type,message FROM nova.chat_history WHERE user_id=$1 ORDER BY id DESC LIMIT $2',[userId,limit])).reverse(),
    clearHistory:userId=>run('DELETE FROM nova.chat_history WHERE user_id=$1',[userId]),
    clearReadingList:userId=>run('DELETE FROM nova.reading_lists WHERE user_id=$1',[userId]),
    destroyOwner(userId){const id=deletionOwner(userId);return withTransaction(pool,async client=>{
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[id]);
      const reading=await client.query('DELETE FROM nova.reading_lists WHERE user_id=$1',[id]);
      const history=await client.query('DELETE FROM nova.chat_history WHERE user_id=$1',[id]);
      return {removed:reading.rowCount+history.rowCount};
    });},
  };
  return api;
}
const method=singleton(createNosqlWorkshopDb,'NOSQL_WORKSHOP_DATABASE_URL');
module.exports={createNosqlWorkshopDb,...Object.fromEntries(['initializeNosqlWorkshopDb','searchPapers','getPaperDetails','listPapersByAuthor','browseByTopic','getAuthorProfile','searchAuthors','addToReadingList','viewReadingList','removeFromReadingList','getRecommendations','getTrendingTopics','getCitationNetwork','saveMessage','getHistory','clearHistory','clearReadingList','destroyOwner'].map(name=>[name,method(name)]))};
