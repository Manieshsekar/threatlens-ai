// Exercise real route handlers with the local Cloudflare D1 emulator; no live site requests.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import ts from 'typescript';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const wranglerRequire=createRequire(require.resolve('wrangler/package.json'));
const {Miniflare}=wranglerRequire('miniflare');
const mf=new Miniflare({modules:true,script:'export default {fetch(){return new Response("test")}}',d1Databases:['DB'],compatibilityDate:'2026-05-15',cf:false});
const checks=[];
const done=name=>checks.push(name);
const urls=new Map();
function compile(file){
 if(urls.has(file))return urls.get(file);
 let source=fs.readFileSync(file,'utf8');
 source=source.replace(/import\s+(?:type\s+)?[^;]+?from\s+['"](@\/[^'"]+|\.\.\/artifacts\/model.json|\.\/psl.json)['"];?/g,(statement,path)=>{
  if(path.endsWith('.json'))return 'const '+(path.includes('model')?'model':'rules')+'='+fs.readFileSync(path.includes('model')?'artifacts/model.json':'lib/psl.json','utf8')+';';
  if(path==='@/db')return 'const getDatabase=()=>globalThis.__hostedTestDb;';
  const local=path.replace('@/','')+'.ts';return statement.replace(path,compile(local));
 });
 const js=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022}}).outputText;
 const url='data:text/javascript;base64,'+Buffer.from(js).toString('base64');urls.set(file,url);return url;
}
const origin='https://threatlens.test';
function request(path,method='GET',body,cookie,extra={}){return new Request(origin+'/api/v1/'+path,{method,headers:{origin,'content-type':'application/json',...(cookie?{cookie}:{}),...extra},...(body===undefined?{}:{body:JSON.stringify(body)})});}
const context=id=>({params:Promise.resolve({id})});
try{
 globalThis.__hostedTestDb=await mf.getD1Database('DB');const db=globalThis.__hostedTestDb;
 for(const file of fs.readdirSync('drizzle').filter(x=>x.endsWith('.sql')).sort())for(const sql of fs.readFileSync('drizzle/'+file,'utf8').split('--> statement-breakpoint').filter(s=>s.trim()))await db.prepare(sql).run();done('Generated migrations apply on D1');
 const system=await import(compile('app/api/v1/system/route.ts')),scan=await import(compile('app/api/v1/scan/route.ts')),hist=await import(compile('app/api/v1/history/route.ts')),detail=await import(compile('app/api/v1/scan/[id]/route.ts')),review=await import(compile('app/api/v1/scan/[id]/verification/route.ts')),feedback=await import(compile('app/api/v1/feedback/route.ts')),hosted=await import(compile('lib/hosted.ts'));
 const start=await system.GET(request('system'));assert.equal(start.status,200);assert.equal((await start.json()).mode,'public');const fullCookie=start.headers.get('set-cookie');assert.match(fullCookie,/Secure; HttpOnly; SameSite=Strict/);const cookie=fullCookie.split(';')[0];done('Anonymous workspace and secure cookie');
 const otherCookie=(await system.GET(request('system'))).headers.get('set-cookie').split(';')[0];assert.notEqual(cookie,otherCookie);
 assert.equal((await scan.POST(request('scan','POST',{url:'https://example.com'}))).status,401);done('Missing workspace rejected');
 assert.equal((await scan.POST(request('scan','POST',{url:'https://example.com'},cookie,{origin:'https://attacker.test'}))).status,403);done('Cross-origin writes rejected');
 assert.equal((await scan.POST(request('scan','POST',{url:'https://example.com'},cookie,{'content-type':'text/plain'}))).status,415);done('Non-JSON writes rejected');
 assert.equal((await scan.POST(request('scan','POST',{url:'https://example.com/'+'x'.repeat(13000)},cookie))).status,413);done('Oversized streamed input rejected');
 for(const url of ['javascript:alert(1)','https://me:secret@example.com','http://127.1'])assert.equal((await scan.POST(request('scan','POST',{url},cookie))).status,422);done('Invalid and credential-bearing URLs rejected');
 const result=await scan.POST(request('scan','POST',{url:'https://example.com/private-secret?token=private-secret'},cookie));assert.equal(result.status,200);const r=await result.json();assert.ok(!JSON.stringify(r).includes('private-secret'));done('Raw paths and queries excluded from stored report');
 assert.equal((await hist.GET(request('history','GET',undefined,cookie))).status,200);assert.equal((await (await hist.GET(request('history','GET',undefined,cookie))).json()).length,1);done('History survives independent requests');
 assert.equal((await detail.GET(request('scan/'+r.id,'GET',undefined,otherCookie),context(r.id))).status,404);assert.deepEqual(await (await hist.GET(request('history','GET',undefined,otherCookie))).json(),[]);done('Other visitor cannot read reports');
 const evidence={verdict:'clean',note:'Checked the known official destination independently.'};
 assert.equal((await review.POST(request('review','POST',evidence,otherCookie),context(r.id))).status,404);done('Other visitor cannot review reports');
 assert.equal((await review.POST(request('review','POST',{verdict:'clean',note:'short'},cookie),context(r.id))).status,422);done('Review rationale enforced');
 const saved=await review.POST(request('review','POST',evidence,cookie),context(r.id));assert.equal(saved.status,200);const reviewed=await saved.json();assert.equal(reviewed.verification.note,evidence.note);assert.deepEqual(reviewed.model,r.model);assert.equal(reviewed.risk_score,r.risk_score);assert.equal(reviewed.review_history.length,1);done('Review saved with audit event; model unchanged');
 assert.equal((await feedback.POST(request('feedback','POST',{investigation_id:r.id,category:'false_positive',note:''},cookie))).status,200);assert.equal((await (await detail.GET(request('detail','GET',undefined,cookie),context(r.id))).json()).feedback.category,'false_positive');done('Feedback flag persists separately');
 const dnsOriginal=globalThis.fetch;globalThis.fetch=async()=>{throw Error('Simulated provider outage');};
 const deep=await scan.POST(request('scan','POST',{url:'https://example.net',mode:'deep'},cookie));globalThis.fetch=dnsOriginal;assert.equal(deep.status,200);assert.ok((await deep.json()).observations.every(o=>o.status==='unavailable'));done('Deep provider failure remains unknown and report saves');
 assert.equal((await detail.DELETE(request('detail','DELETE',undefined,otherCookie),context(r.id))).status,404);done('Other visitor cannot delete reports');
 assert.equal((await detail.DELETE(request('detail','DELETE',undefined,cookie),context(r.id))).status,200);assert.equal(await db.prepare('SELECT count(*) AS n FROM reviews').first('n'),0);assert.equal(await db.prepare('SELECT count(*) AS n FROM feedback').first('n'),0);assert.equal(await db.prepare('SELECT count(*) AS n FROM review_events').first('n'),0);done('Delete cascades to notes, feedback and activity');
 const owner=(await hosted.session(request('system','GET',undefined,cookie))).owner;
 await db.prepare('UPDATE investigations SET expires=0 WHERE owner=?').bind(owner).run();assert.deepEqual(await hosted.history(owner),[]);await hosted.prune();assert.equal(await db.prepare('SELECT count(*) AS n FROM investigations').first('n'),0);done('Expired reports hidden and removed');
 for(let i=0;i<15;i++)await hosted.limit(request('scan'), 'unique-rate-owner');await assert.rejects(()=>hosted.limit(request('scan'),'unique-rate-owner'),e=>e.status===429);done('Atomic request rate cap enforced');
 await hosted.saveReport(owner,r);assert.equal((await hist.DELETE(request('history','DELETE',undefined,cookie))).status,200);assert.deepEqual(await hosted.history(owner),[]);done('Clear history removes owned records');
 console.log(JSON.stringify({passed:checks.length,checks},null,2));
}finally{delete globalThis.__hostedTestDb;await mf.dispose();}
