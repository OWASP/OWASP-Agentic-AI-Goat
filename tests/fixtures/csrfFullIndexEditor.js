'use strict';
const assert=require('node:assert/strict');
async function replaceEditorText(page,editor,text){
 // CDP's native selectAll editing command avoids host-dependent Meta/Control
 // behavior in Chrome headless-shell. This is keyboard editing, not a DOM write.
 await editor.focus();await page.keyboard.press('KeyA',{commands:['selectAll']});
 await page.keyboard.press('Backspace');await editor.type(text);
 assert.equal(await editor.evaluate(e=>e.value),text,'Exact learner editor payload before execution');
}
module.exports={replaceEditorText};
