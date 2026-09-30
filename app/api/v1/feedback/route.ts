import {session,input,flag,limit,json,failure,HttpError} from '@/lib/hosted';
export async function POST(req:Request){try{const body=await input(req),{owner}=await session(req);if(typeof body.investigation_id!=='string')throw new HttpError(422,'Select an investigation.');await limit(req,owner,'edit');return json(await flag(owner,body.investigation_id,body));}catch(e){return failure(e);}}
