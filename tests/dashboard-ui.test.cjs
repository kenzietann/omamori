const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const assets=path.join(__dirname,'../internal/dashboard/assets');
async function until(fn){const deadline=Date.now()+3000;while(!fn()){if(Date.now()>deadline)throw Error('UI did not settle');await new Promise(resolve=>setTimeout(resolve,5));}}
async function app(t,{width=1440,empty=false}={}){
 const dom=new JSDOM(fs.readFileSync(path.join(assets,'index.html'),'utf8'),{url:'http://127.0.0.1:8765/#token=test-token',runScripts:'outside-only',pretendToBeVisual:true});t.after(()=>dom.window.close());const w=dom.window;
 w.matchMedia=q=>({matches:q.includes('max-width')?width<=Number(q.match(/max-width:\s*(\d+)/)[1]):q.includes('min-width')?width>=Number(q.match(/min-width:\s*(\d+)/)[1]):false,addEventListener(){},removeEventListener(){}});
 w.Element.prototype.scrollIntoView=function(){};w.HTMLDialogElement.prototype.showModal=function(){this.setAttribute('open','')};w.HTMLDialogElement.prototype.close=function(){this.removeAttribute('open')};
 const alerts=Array.from({length:14},(_,i)=>({id:'a'+(i+1),run_id:'r_fixture',title:'Synthetic alert '+(i+1),rule:'fixture_rule',level:i===0?'critical':i<6?'high':'medium',count:1,time:`2026-11-10T${String(i).padStart(2,'0')}:00:00Z`,first:'2026-11-10T00:00:00Z',last:'2026-11-10T13:00:00Z',event_ids:['e'+(i+1)],group:{src_ip:'203.0.113.9'},payload:{analyst_evidence:{['a'+(i+1)+'_e1']:'e'+(i+1)}}}));
 const run={id:'r_fixture',label:'Synthetic UI test',mode:'detect',made:'2026-11-12T00:00:00Z',event_count:14,alert_count:14};const calls=[];let cases=[];
 w.fetch=async(url,options={})=>{assert.equal(options.headers.Authorization,'Bearer test-token');calls.push({url,...options});const u=new URL(url,'http://127.0.0.1:8765');let value;
 if(u.pathname==='/api/config')value={root:'/evidence',providers:[],provider:'',model:''};
 else if(u.pathname==='/api/runs')value=empty?[]:[run];
 else if(u.pathname==='/api/runs/r_fixture')value=run;
 else if(u.pathname==='/api/alerts')value=alerts;
 else if(u.pathname.match(/\/alerts\/a\d+$/))value=alerts.find(a=>a.id===u.pathname.split('/').pop());
 else if(u.pathname.match(/\/events\/e\d+$/)){const id=u.pathname.split('/').pop();value={id,run_id:run.id,time:'2026-11-10T00:00:00Z',ref:id+'.log:1',source:'syslog',fields:{action:'login',outcome:'failure',user:'<script>window.executed=true</script>',src_ip:'203.0.113.9'}};}
 else if(u.pathname==='/api/cases'&&options.method==='POST'){const input=JSON.parse(options.body);const c={id:'c_new',version:1,status:'open',alerts:[],...input};cases.push(c);value=c;}
 else if(u.pathname==='/api/cases')value=cases;
 else if(u.pathname==='/api/cases/c_new')value=cases[0];
 else if(u.pathname==='/api/jobs')value=[];
 else value=[];
 return {ok:true,status:200,json:async()=>structuredClone(value),text:async()=>JSON.stringify(value)};
 };
 for(const name of ['theme.js','chart-data.js','app.js'])w.eval(fs.readFileSync(path.join(assets,name),'utf8'));
 await until(()=>empty?w.document.querySelector('.empty'):w.document.querySelector('.inspector h2'));
 return {w,document:w.document,calls};
}
test('alert selection, tabs, evidence and theme remain functional',async t=>{
 const {w,document:d}=await app(t);assert.equal(d.querySelectorAll('.alert-row').length,14);assert.match(d.querySelector('.inspector h2').textContent,/Synthetic alert 1$/);
 d.querySelector('[data-alert="a14"]').click();await until(()=>d.querySelector('.inspector h2')?.textContent==='Synthetic alert 14');assert.equal(d.querySelector('[data-alert="a14"]').getAttribute('aria-pressed'),'true');assert.match(w.location.hash,/review\/r_fixture\/a14/);
 d.querySelector('[data-tab="rule"]').click();await until(()=>d.querySelector('#review-panel').textContent.includes('fixture_rule'));assert.equal(d.querySelector('#review-panel').getAttribute('aria-labelledby'),'review-tab-rule');
 d.querySelector('[data-tab="rule"]').focus();d.querySelector('[data-tab="rule"]').dispatchEvent(new w.KeyboardEvent('keydown',{key:'ArrowRight',bubbles:true}));await until(()=>d.querySelector('[data-tab="ai"]').getAttribute('aria-selected')==='true');
 d.querySelector('[data-tab="evidence"]').click();await until(()=>d.querySelector('.evidence-entry button'));d.querySelector('.evidence-entry button').click();await until(()=>d.querySelector('#detail-body').textContent.includes('e14.log:1'));assert.equal(w.executed,undefined);assert.equal(d.querySelectorAll('#detail-body script').length,0);
 d.querySelector('#close-detail').click();d.querySelector('#theme-toggle').click();assert.equal(d.documentElement.dataset.theme,'dark');assert.equal(w.localStorage.getItem('omamori-theme'),'dark');d.querySelector('#theme-toggle').click();assert.equal(d.documentElement.dataset.theme,'light');
 const severity=d.querySelector('select[name=severity]');severity.value='low';severity.dispatchEvent(new w.Event('change'));assert.equal(d.querySelectorAll('.alert-row').length,0);assert.match(d.querySelector('.queue-list').textContent,/No alerts/);
});
test('mobile charts disclose progressively and menu opens real routes',async t=>{
 const {w,document:d}=await app(t,{width:390});assert.equal(d.querySelector('.charts-disclosure').open,false);d.querySelector('.charts-disclosure summary').click();assert.equal(d.querySelector('.charts-disclosure').open,true);
 d.querySelector('#menu-toggle').click();assert.equal(d.querySelector('#menu-toggle').getAttribute('aria-expanded'),'true');d.querySelector('#mobile-nav a[href="#cases"]').click();await until(()=>d.querySelector('input[name=title]'));assert.equal(d.querySelector('#mobile-nav').hidden,true);
 d.querySelector('input[name=title]').value='Synthetic case';d.querySelector('textarea[name=notes]').value='<script>window.executed=true</script>';d.querySelector('main form').dispatchEvent(new w.Event('submit',{bubbles:true,cancelable:true}));await until(()=>d.querySelector('h1').textContent==='Case detail');assert.equal(w.executed,undefined);assert.equal(d.querySelectorAll('main script').length,0);
});
test('empty workspace does not invent chart data',async t=>{const {document:d}=await app(t,{empty:true});assert.equal(d.querySelectorAll('.histogram').length,0);assert.match(d.querySelector('main').textContent,/Start with your evidence/)});

test('selected-alert actions precede evidence and survive tab changes', async t => {
 const {document:d}=await app(t);
 const actions=d.querySelector('.inspector-actions');
 assert.match(actions.textContent,/Open alert details/);
 assert.ok(actions.compareDocumentPosition(d.querySelector('#review-panel')) & 4);
 d.querySelector('[data-tab="rule"]').click();
 await until(()=>d.querySelector('#review-panel').textContent.includes('fixture_rule'));
 assert.equal(d.querySelector('.inspector-actions'),actions);
 actions.querySelector('button').click();
 await until(()=>d.querySelector('#detail-body').textContent.includes('Synthetic alert 1'));
 assert.match(d.querySelector('#detail-body').textContent,/Synthetic alert 1/);
 const bars=d.querySelector('.histogram');
 assert.ok(parseInt(bars.style.minWidth)>=bars.children.length*48);
});
test('stacked alert selection moves focus to evidence and returns to the same row', async t => {
 const {document:d}=await app(t,{width:390});
 const row=d.querySelector('[data-alert="a14"]');
 row.focus();row.click();
 await until(()=>d.activeElement.id==='selected-alert-title');
 assert.equal(d.activeElement.textContent,'Synthetic alert 14');
 d.querySelector('.back-to-queue').click();
 assert.equal(d.activeElement,row);
 assert.equal(row.getAttribute('aria-pressed'),'true');
});
