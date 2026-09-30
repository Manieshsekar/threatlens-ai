import {session,history,json,failure,sameOrigin,limit} from '@/lib/hosted';
import {getDatabase} from '@/db';
export async function GET(req:Request){try{const {owner}=await session(req);return json(await history(owner));}catch(e){return failure(e);}}
export async function DELETE(req:Request){try{sameOrigin(req);const {owner}=await session(req);await limit(req,owner,'edit');await getDatabase().prepare('DELETE FROM investigations WHERE owner=?').bind(owner).run();return json({deleted:true});}catch(e){return failure(e);}}
