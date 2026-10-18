'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {project,candidates,stage,verifyPromoted}=require('./helpers/secureshopListingsCurriculumCandidate');
test('promoted Listings defaults exactly match reviewed content and staging is strict no-op',t=>{
 const source=fs.readFileSync('server/config/secureshopCurriculum.js','utf8');assert.equal(verifyPromoted(source),true);assert.throws(()=>project(source));
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'listings-curriculum-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));fs.mkdirSync(path.join(root,'server/config'),{recursive:true});const file=path.join(root,'server/config/secureshopCurriculum.js');fs.writeFileSync(file,source);assert.equal(stage(root).result,source);assert.equal(fs.readFileSync(file,'utf8'),source);
 for(const candidate of candidates){const changed=source.replace(JSON.stringify(candidate.action),JSON.stringify('Unreviewed content'));fs.writeFileSync(file,changed);assert.throws(()=>stage(root));assert.equal(fs.readFileSync(file,'utf8'),changed);}
});
