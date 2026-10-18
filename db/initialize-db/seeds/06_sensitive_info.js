// No default completions. Upgrade existing legacy result rows for durable judgments.
const sqlite3=require('sqlite3');
async function runSeed(dbPath){
 const db=new sqlite3.Database(dbPath);
 const run=sql=>new Promise((resolve,reject)=>db.run(sql,error=>error?reject(error):resolve()));
 try{
  const columns=await new Promise((resolve,reject)=>db.all('PRAGMA table_info(challenge_progress)',(error,rows)=>error?reject(error):resolve(rows)));
  for(const name of ['run_id','judgment'])if(!columns.some(column=>column.name===name))await run(`ALTER TABLE challenge_progress ADD COLUMN ${name} TEXT`);
  await run('CREATE UNIQUE INDEX IF NOT EXISTS legacy_sensitive_judgment_run ON challenge_progress(run_id,challenge_type)');
 }finally{await new Promise(resolve=>db.close(resolve));}
}
module.exports={runSeed};
