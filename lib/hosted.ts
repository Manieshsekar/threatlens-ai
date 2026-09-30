import {getDatabase} from '@/db';
import type {Report} from '@/lib/analysis';
const COOKIE='__Host-threatlens';
const DAY=86400000;
export class HttpError extends Error{constructor(public status:number,message:string){super(message);}}
export function json(value:unknown,status=200,headers:Record<string,string>={}){
 return Response.json(value,{status,headers:{'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff','X-Robots-Tag':'noindex, nofollow',...headers}});
}
export function failure(error:unknown){
 if(error instanceof HttpError)return json({detail:error.message},error.status,error.status===429?{'Retry-After':'60'}:{});
 console.error('ThreatLens storage or provider operation failed');
 return json({detail:'The service could not complete this request. Your input is still available; please retry.'},503);
}
function token(req:Request){return req.headers.get('cookie')?.split(';').map(s=>s.trim()).find(s=>s.startsWith(COOKIE+'='))?.slice(COOKIE.length+1);}
export async function digest(value:string){return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value)))).map(x=>x.toString(16).padStart(2,'0')).join('');}
export async function session(req:Request,create=false){
 let key=token(req),cookie:string|undefined;
 if(!key||! /^[a-f0-9]{64}$/.test(key)){
  if(!create)throw new HttpError(401,'Your workspace connection expired. Refresh this page to reconnect.');
  key=Array.from(crypto.getRandomValues(new Uint8Array(32))).map(x=>x.toString(16).padStart(2,'0')).join('');
  cookie=`${COOKIE}=${key}; Path=/; Max-Age=2592000; Secure; HttpOnly; SameSite=Strict`;
 }
 return {owner:await digest(key),cookie};
}
export function sameOrigin(req:Request){
 if(req.headers.get('origin')!==new URL(req.url).origin)throw new HttpError(403,'Open ThreatLens directly to perform this action.');
 if(!(req.headers.get('content-type')||'').startsWith('application/json'))throw new HttpError(415,'Send a JSON request.');
}
export async function input(req:Request):Promise<Record<string,unknown>>{
 sameOrigin(req);const reader=req.body?.getReader();if(!reader)throw new HttpError(422,'A request body is required.');
 let size=0;const chunks:Uint8Array[]=[];
 while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>12000){await reader.cancel();throw new HttpError(413,'Request too large.');}chunks.push(value);}
 const bytes=new Uint8Array(size);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}
 try{const b=JSON.parse(new TextDecoder().decode(bytes));if(!b||typeof b!=='object'||Array.isArray(b))throw Error();return b;}catch{throw new HttpError(422,'Enter valid JSON input.');}
}
export async function limit(req:Request,owner:string,action='scan'){
 const db=getDatabase(),minute=Math.floor(Date.now()/60000),expires=Date.now()+120000;
 // CF supplies this address at the edge. Never persist the raw address.
 const ip=req.headers.get('cf-connecting-ip');
 const keys:[[string,number],...Array<[string,number]>]=[[`${action}:owner:${owner}:${minute}`,action==='scan'?15:40],[`${action}:global:${minute}`,action==='scan'?120:400]];
 if(ip)keys.push([`${action}:network:${await digest(ip+':'+new Date().toISOString().slice(0,10))}:${minute}`,action==='scan'?30:100]);
 for(const [key,max] of keys){const row=await db.prepare('INSERT INTO rate_buckets (key,count,expires) VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1 WHERE count<? RETURNING count').bind(key,expires,max).first();if(!row)throw new HttpError(429,'Too many requests. Please wait one minute and try again.');}
}
export async function prune(){
 const db=getDatabase();await db.batch([
 db.prepare('DELETE FROM investigations WHERE id IN (SELECT id FROM investigations WHERE expires<=? LIMIT 100)').bind(Date.now()),
 db.prepare('DELETE FROM rate_buckets WHERE key IN (SELECT key FROM rate_buckets WHERE expires<=? LIMIT 100)').bind(Date.now())]);
}
export async function saveReport(owner:string,report:Report){
 const db=getDatabase(),now=Date.now();await db.batch([
 db.prepare('INSERT INTO investigations(id,owner,report,created,expires) VALUES(?,?,?,?,?)').bind(report.id,owner,JSON.stringify(report),now,now+30*DAY),
 db.prepare('DELETE FROM investigations WHERE id IN (SELECT id FROM investigations WHERE owner=? ORDER BY created DESC,id DESC LIMIT -1 OFFSET 200)').bind(owner)]);await prune();
}
export async function getReport(owner:string,id:string):Promise<Report>{
 const row=await getDatabase().prepare('SELECT report FROM investigations WHERE id=? AND owner=? AND expires>?').bind(id,owner,Date.now()).first<{report:string}>();
 if(!row)throw new HttpError(404,'Investigation not found in this browser workspace.');
 const report=JSON.parse(row.report) as Report;
 const review=await getDatabase().prepare('SELECT verdict,note,at FROM reviews WHERE investigation_id=?').bind(id).first<{verdict:string;note:string;at:string}>();
 if(review)report.verification={...review,analyst:'Your personal review'};
 const events=await getDatabase().prepare('SELECT action,at FROM review_events WHERE investigation_id=? ORDER BY at DESC,id DESC LIMIT 20').bind(id).all<{action:string;at:string}>();
 report.review_history=events.results;
 const flag=await getDatabase().prepare('SELECT category,note,at FROM feedback WHERE investigation_id=?').bind(id).first<{category:string;note:string;at:string}>();if(flag)report.feedback=flag;
 return report;
}
export async function history(owner:string){
 const rows=await getDatabase().prepare('SELECT i.report,r.verdict,r.note,r.at FROM investigations i LEFT JOIN reviews r ON r.investigation_id=i.id WHERE i.owner=? AND i.expires>? ORDER BY i.created DESC,i.id DESC LIMIT 200').bind(owner,Date.now()).all<{report:string;verdict:string|null;note:string;at:string}>();
 return rows.results.map(row=>({...JSON.parse(row.report),...(row.verdict?{verification:{verdict:row.verdict,note:row.note,at:row.at,analyst:'Your personal review'}}:{})}));
}
export async function review(owner:string,id:string,body:Record<string,unknown>){
 await getReport(owner,id);
 if(!['unsure','clean','malicious'].includes(String(body.verdict))||typeof body.note!=='string'||body.note.trim().length<10||body.note.length>2000)throw new HttpError(422,'Choose an assessment and enter 10–2000 characters of evidence.');
 const db=getDatabase(),at=new Date().toISOString();await db.batch([
 db.prepare('INSERT INTO reviews(investigation_id,verdict,note,at) VALUES(?,?,?,?) ON CONFLICT(investigation_id) DO UPDATE SET verdict=excluded.verdict,note=excluded.note,at=excluded.at').bind(id,body.verdict,body.note.trim(),at),
 db.prepare('INSERT INTO review_events(id,investigation_id,action,at) VALUES(?,?,?,?)').bind(crypto.randomUUID(),id,'Personal assessment saved: '+body.verdict,at),
 db.prepare('DELETE FROM review_events WHERE id IN (SELECT id FROM review_events WHERE investigation_id=? ORDER BY at DESC,id DESC LIMIT -1 OFFSET 20)').bind(id)]);
 return getReport(owner,id);
}
export async function flag(owner:string,id:string,body:Record<string,unknown>){
 await getReport(owner,id);
 if(!['unsure','false_positive','false_negative'].includes(String(body.category))||typeof body.note!=='string'||body.note.length>2000)throw new HttpError(422,'Choose a valid error category and a note up to 2000 characters.');
 const at=new Date().toISOString();await getDatabase().prepare('INSERT INTO feedback(investigation_id,category,note,at) VALUES(?,?,?,?) ON CONFLICT(investigation_id) DO UPDATE SET category=excluded.category,note=excluded.note,at=excluded.at').bind(id,body.category,body.note.trim(),at).run();
 return {saved:true};
}
