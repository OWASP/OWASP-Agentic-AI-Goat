'use strict';
// Serialized directly into the browser and tested against the mounted component.
function csrfAdminCardHasProgress({completed,total}){
 const titles=[...document.querySelectorAll('.title')].filter(e=>/CSRF/.test(e.textContent));
 if(titles.length!==1)return false;
 const card=titles[0].closest('.header')?.parentElement;
 if(!card?.querySelector('.description'))return false;
 const spans=[...card.querySelectorAll('span')].map(e=>e.textContent.trim());
 return spans.some(text=>new RegExp('^'+completed+'\\s*/\\s*'+total+'\\s+objectives$').test(text))&&spans.some(text=>/^(?:[1-9][0-9]*s|[1-9][0-9]*m|[1-9][0-9]*h(?: [0-9]+m)?)$/.test(text));
}
module.exports={csrfAdminCardHasProgress};
