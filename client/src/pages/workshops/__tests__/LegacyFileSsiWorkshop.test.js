import React,{act} from 'react';
import {createRoot} from 'react-dom/client';
import LegacyFileSsiWorkshop from '../LegacyFileSsiWorkshop';
const snapshot={workshopKey:'legacy_sensitive_file_ssi',mode:{effectiveMode:'vuln',allowedModes:['vuln','fixed']},objectives:[{id:'path_traversal',label:'Read protected file',description:'Admin-authored description',enabled:true,completed:false,showHints:false,hint:{hints:['private hint']},showSolutions:true,solution:{title:'Visible solution',approach:'Use the owned path.',examples:[{title:'Example',payload:'../secret/owned.txt',explanation:'Owned teaching artifact.'}],tips:['Do not use host paths.']}},{id:'ssi_injection',label:'Expand template',enabled:false}]};
let container,root;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);});
afterEach(()=>{act(()=>root.unmount());container.remove();});
test('canonical totals and independently gated guidance use existing baseline',()=>{
 act(()=>root.render(<LegacyFileSsiWorkshop snapshot={snapshot}/>));
 expect(container.querySelector('[data-workshop="legacy_sensitive_file_ssi"]')).not.toBeNull();
 expect(container.textContent).toContain('0 of 1');expect(container.textContent).toContain('Admin-authored description');expect(container.textContent).not.toContain('private hint');expect(container.textContent).toContain('Solution');
 act(()=>container.querySelector('[data-testid="solution-button-path_traversal"]').click());expect(document.body.textContent).toContain('Use the owned path.');expect(document.body.textContent).toContain('Do not use host paths.');
 act(()=>container.querySelector('[data-scenario-tab="templates"]').click());expect(container.textContent).toContain('No enabled objectives in this scenario.');
});
test('disabled objectives never become selectable',()=>{
 act(()=>root.render(<LegacyFileSsiWorkshop snapshot={snapshot}/>));expect(container.querySelectorAll('option')).toHaveLength(1);expect(container.querySelector('option').value).toBe('path_traversal');
});
test('missing canonical family remains unavailable',()=>{act(()=>root.render(<LegacyFileSsiWorkshop snapshot={{...snapshot,workshopKey:'sensitive_info'}}/>));expect(container.querySelector('form')).toBeNull();expect(container.textContent).toContain('unavailable');});
test('DPI/IPI shell contains the workspace and objective panel with bounded desktop and mobile surfaces',()=>{
 act(()=>root.render(<LegacyFileSsiWorkshop snapshot={snapshot}/>));
 const experience=container.querySelector('[data-workshop="legacy_sensitive_file_ssi"]'),surface=experience.parentElement,shell=surface.parentElement;
 expect(getComputedStyle(surface).maxWidth).toBe('1800px');expect(getComputedStyle(surface).boxSizing).toBe('border-box');
 expect(getComputedStyle(shell).padding).toBe('2rem');expect(getComputedStyle(surface).padding).toBe('2rem');
 expect(getComputedStyle(surface).borderRadius).toBe('24px');
 const workspace=container.querySelector('[aria-label="File traversal workspace"]'),objectives=container.querySelector('aside[aria-label="Exercise objectives"]');
 expect(workspace).not.toBeNull();expect(objectives).not.toBeNull();expect(workspace.parentElement).toBe(objectives.parentElement);
 expect(getComputedStyle(workspace.parentElement).display).toBe('grid');
 expect(getComputedStyle(workspace).backgroundColor).toBe('rgb(255, 255, 255)');expect(getComputedStyle(objectives).backgroundColor).toBe('rgb(255, 255, 255)');
 const css=[...document.styleSheets].flatMap(sheet=>[...sheet.cssRules].map(rule=>rule.cssText)).join('\n');
 expect(css).toContain('max-width: 600px');expect(css).toContain('padding: 1rem');expect(css).toContain('max-width: 1024px');
 expect(getComputedStyle(container.querySelector('textarea')).minHeight).toBe('120px');
 expect(container.querySelector('button[type="submit"]').disabled).toBe(true);
});
test('objective cards preserve canonical selection, completion, and independently gated help',()=>{
 const other={id:'combined_traversal_ssi',label:'Combined owned workflow',description:'Second canonical description',enabled:true,completed:true,showHints:true,hint:{hints:['Second hint']},showSolutions:false};
 act(()=>root.render(<LegacyFileSsiWorkshop snapshot={{...snapshot,objectives:[...snapshot.objectives,other]}}/>));
 const card=[...container.querySelectorAll('button[aria-pressed]')].find(button=>button.textContent.includes(other.label));
 expect(card.textContent).toContain('Completed');expect(card.getAttribute('aria-pressed')).toBe('false');
 act(()=>card.click());expect(card.getAttribute('aria-pressed')).toBe('true');expect(container.querySelector('select').value).toBe(other.id);
 expect(container.textContent).toContain(other.description);expect(container.textContent).toContain('1 of 2');
 expect(container.querySelector('[data-testid="hint-button-combined_traversal_ssi"]')).not.toBeNull();expect(container.querySelector('[data-testid="solution-button-combined_traversal_ssi"]')).toBeNull();
 expect(container.querySelector('[data-testid="solution-button-path_traversal"]')).toBeNull();
});
test('styled composer sends the same owned attempt and renders observed output as plain text',async()=>{
 const onAttempt=jest.fn().mockResolvedValue({rendered:'<img src=x onerror=alert(1)> Owned SSI observation'}),onRefresh=jest.fn().mockResolvedValue();
 act(()=>root.render(<LegacyFileSsiWorkshop snapshot={snapshot} onAttempt={onAttempt} onRefresh={onRefresh}/>));
 const input=container.querySelector('textarea');
 act(()=>{Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(input,'../secret/owned.txt');input.dispatchEvent(new Event('input',{bubbles:true}));});
 await act(async()=>{container.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));await Promise.resolve();});
 expect(onAttempt).toHaveBeenCalledWith({objectiveId:'path_traversal',input:'../secret/owned.txt'});expect(onRefresh).toHaveBeenCalledTimes(1);
 expect(container.querySelector('[aria-label="Observed result"]').textContent).toContain('<img src=x onerror=alert(1)>');expect(container.querySelector('[aria-label="Observed result"] img')).toBeNull();
 act(()=>container.querySelector('[data-scenario-tab="agent"]').click());expect(container.querySelector('[aria-label="File agent workspace"]')).not.toBeNull();expect(container.querySelector('[aria-label="Observed result"]')).toBeNull();
});
test('outer shell matches baseline navigation and separate large hero without inventing difficulty',()=>{
 act(()=>root.render(<LegacyFileSsiWorkshop snapshot={snapshot}/>));
 const link=container.querySelector('a[href="/workshop/challenges"]');expect(link.textContent).toContain('Back to Dashboard');
 const title=container.querySelector('h1');expect(container.querySelectorAll('h1')).toHaveLength(1);expect(title.textContent).toBe('File and SSI Security');
 const hero=container.querySelector('header[aria-labelledby="file-ssi-title"]'),surface=container.querySelector('[data-workshop]').parentElement;
 expect(hero).not.toBe(surface);expect(hero.parentElement).toBe(surface.parentElement);expect(hero.nextElementSibling).toBe(surface);
 expect(hero.textContent).toContain('Explore owned teaching files');expect(getComputedStyle(hero).borderRadius).toBe('24px');expect(getComputedStyle(title).fontSize).toBe('2.5rem');
 expect(surface.querySelector('h2').textContent).toBe('File and SSI workflows');expect(container.textContent).not.toMatch(/Intermediate|Advanced|Beginner/);
});
