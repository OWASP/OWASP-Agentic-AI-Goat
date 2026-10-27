'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {createHash}=require('node:crypto');
const root=path.resolve(__dirname,'..');
const prior=fs.readFileSync(path.join(root,'db/postgres/identity-migrations/0133_ctf_teaching_content_command.sql'),'utf8');
const next=fs.readFileSync(path.join(root,'db/postgres/identity-migrations/0155_ctf_authenticated_publication_stale.sql'),'utf8');
const hash=value=>createHash('sha256').update(value).digest('hex');
const oldBranch="THEN RAISE EXCEPTION 'CTF publication scope stale' USING ERRCODE='42501'; END IF;";
const newBranch=`THEN
  IF o.scope_key IS NOT NULL AND o.owner_generation IS DISTINCT FROM d.owner_generation
  THEN RAISE EXCEPTION 'CTF publication scope stale' USING ERRCODE='PCT01'; END IF;
  RAISE EXCEPTION 'CTF publication scope stale' USING ERRCODE='42501'; END IF;`;
test('0155 changes only the authenticated 0133 scope-stale authorizer branch',()=>{
 assert.equal(hash(prior),'d49e13d93809ee7a7ae4001abc4511d0eaec8e6b505162baa7efe56eb339b8ff');
 const start=prior.indexOf('CREATE OR REPLACE FUNCTION identity.authorize_ctf_current_publication(');
 assert(start>=0);
 const bodyStart=prior.indexOf('AS $$',start)+5,end=prior.indexOf('$$;',bodyStart);
 assert(end>bodyStart);
 const body=prior.slice(bodyStart,end);
 assert.equal(hash(body),'85171d42258878579726015bb091e1159a618acb13e76413dd95a2efc0506588');
 assert.equal(body.split(oldBranch).length,2);
 assert(next.includes(`old_branch text := $old$${oldBranch}$old$;`));
 assert(next.includes(`new_branch text := $new$${newBranch}$new$;`));
 assert(next.includes("replace(original,old_branch,new_branch)"));
 assert(next.includes("p.proconfig=ARRAY['search_path=pg_catalog']"));
 assert(next.includes("p.prosecdef AND l.lanname='plpgsql'"));
 assert(next.includes('REVOKE ALL ON FUNCTION identity.authorize_ctf_current_publication(uuid,integer,integer,text) FROM PUBLIC;'));
 assert(next.includes('GRANT EXECUTE ON FUNCTION identity.authorize_ctf_current_publication(uuid,integer,integer,text) TO dvaia_identity_runtime;'));
 const revised=body.replace(oldBranch,newBranch);
 assert.equal(revised.split("ERRCODE='PCT01'").length,2);
 assert.equal(revised.split("ERRCODE='42501'").length,5,'foreign, non-generation scope, projection and receipt denial remain unchanged');
 assert(revised.indexOf("CTF publication unavailable")<revised.indexOf("SESSION_REVOKED"));
 assert(revised.indexOf("SESSION_REVOKED")<revised.indexOf("CTF publication scope stale"));
 assert(revised.indexOf("CTF publication scope stale")<revised.indexOf("CTF publication projection unavailable"));
});
