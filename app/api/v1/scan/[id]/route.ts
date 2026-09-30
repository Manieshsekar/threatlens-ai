import {session,getReport,json,failure,sameOrigin,limit} from '@/lib/hosted';
import {getDatabase} from '@/db';
type Context={params:Promise<{id:string}>};
export async function GET(req:Request,ctx:Context){try{const {owner}=await session(req);return json(await getReport(owner,(await ctx.params).id));}catch(e){return failure(e);}}
export async function DELETE(req:Request,ctx:Context){try{sameOrigin(req);const {owner}=await session(req),{id}=await ctx.params;await limit(req,owner,'edit');await getReport(owner,id);await getDatabase().prepare('DELETE FROM investigations WHERE id=? AND owner=?').bind(id,owner).run();return json({deleted:true});}catch(e){return failure(e);}}
