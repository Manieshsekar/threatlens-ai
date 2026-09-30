import {session,input,review,limit,json,failure} from '@/lib/hosted';
export async function POST(req:Request,ctx:{params:Promise<{id:string}>}){try{const body=await input(req),{owner}=await session(req);await limit(req,owner,'edit');return json(await review(owner,(await ctx.params).id,body));}catch(e){return failure(e);}}
