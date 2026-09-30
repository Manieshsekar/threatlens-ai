import {analyze} from '@/lib/analysis';
import {collect} from '@/lib/collectors';
import {session,input,limit,saveReport,json,failure,HttpError} from '@/lib/hosted';
export async function POST(req:Request){
 try{
  const body=await input(req),{owner}=await session(req);
  if(typeof body.url!=='string'||!['quick','deep',undefined].includes(body.mode as string|undefined))throw new HttpError(422,'Enter a URL and a valid scan mode.');
  let report;try{report=analyze(body.url);}catch(e){throw new HttpError(422,(e as Error).message);}
  await limit(req,owner);report.mode=body.mode as string||'quick';
  if(report.mode==='deep')report.observations=await collect(body.url);
  await saveReport(owner,report);
  return json(report);
 }catch(e){return failure(e);}
}
