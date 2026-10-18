const fs=require('node:fs'),path=require('node:path');
test('avatar UI gates canonical completion on delivered preview and saved assessment',()=>{
 const hook=fs.readFileSync(path.join(__dirname,'useCustomerAvatarUploadLesson.js'),'utf8');
 const component=fs.readFileSync(path.join(__dirname,'../components/CustomerAvatarUploadLesson.jsx'),'utf8');
 expect(hook).toContain("result?.status==='completed'&&previewDelivered");
 expect(hook).toContain("request(BASE+'/assess'");
 expect(hook).toContain('assessmentRead(ref,controller,version)');
 expect(component).toMatch(/Assess saved avatar upload/);
 expect(component).toMatch(/Check saved avatar-upload assessment/);
 expect(component).toMatch(/Objective completed in canonical progress/);
 expect(component).toContain('onLoad={lesson.markPreviewDelivered}');
});

test('avatar UI keeps SVG execution assessment separate and canonical',()=>{
 const hook=fs.readFileSync(path.join(__dirname,'useCustomerAvatarUploadLesson.js'),'utf8');const component=fs.readFileSync(path.join(__dirname,'../components/CustomerAvatarUploadLesson.jsx'),'utf8');
 expect(hook).toContain("request(BASE+'/svg-assess'");expect(hook).toContain("request(BASE+'/svg-assess/'+saved.sessionId+'/'+saved.requestId");expect(hook).toContain("result?.status!=='completed'||!previewDelivered");expect(component).toContain('data-testid="avatar-svg-assess"');expect(component).toContain('data-testid="avatar-svg-assess-recover"');expect(component).toMatch(/Assess saved SVG browser execution/);expect(component).toMatch(/Open the saved SVG in the sandbox preview before assessing it/);expect(component).toMatch(/SVG objective completed in canonical progress/);
});
