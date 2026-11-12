const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const {severityCounts,timeBuckets} = require('../internal/dashboard/assets/chart-data.js');
const times = values => values.map(time => ({time}));
test('severity counts contain actual sample counts including zeros',()=>{
 assert.deepEqual(severityCounts([{level:'critical'},{level:'medium'},{level:'medium'}]),[['critical',1],['high',0],['medium',2],['low',0],['informational',0]]);
 assert.equal(severityCounts([]).reduce((sum,row)=>sum+row[1],0),0);
});
test('hourly buckets conserve counts and retain zero intervals',()=>{
 const result=timeBuckets(times(['2026-11-10T10:00:00Z','2026-11-10T10:59:00Z','2026-11-10T12:00:00Z']));
 assert.deepEqual(result.buckets.map(x=>x.count),[2,0,1]);
 assert.equal(new Date(result.start).toISOString(),'2026-11-10T10:00:00.000Z');
});
test('timezone offsets and long spans do not invent or drop alerts',()=>{
 const result=timeBuckets(times(['2026-11-10T00:00:00+09:00','2026-12-31T12:00:00Z']));
 assert.ok(result.buckets.length<=12);
 assert.equal(result.buckets.reduce((sum,b)=>sum+b.count,0),2);
 assert.equal(new Date(result.start).toISOString(),'2026-11-09T00:00:00.000Z');
 assert.deepEqual(timeBuckets([]).buckets,[]);
 assert.throws(()=>timeBuckets(times(['invalid'])));
});
function theme(saved,search='',blocked=false){const document={documentElement:{dataset:{}}};vm.runInNewContext(fs.readFileSync(require('node:path').join(__dirname,'../internal/dashboard/assets/theme.js'),'utf8'),{document,location:{search},URLSearchParams,localStorage:{getItem(){if(blocked)throw Error('blocked');return saved;}}});return document.documentElement.dataset.theme;}
test('light default, saved dark, explicit theme and blocked storage',()=>{
 assert.equal(theme(null),'light');assert.equal(theme('dark'),'dark');assert.equal(theme('dark','?theme=light'),'light');assert.equal(theme(null,'?theme=dark'),'dark');assert.equal(theme(null,'?theme=invalid'),'light');assert.equal(theme(null,'',true),'light');
});
