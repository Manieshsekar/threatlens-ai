import {model} from '@/lib/analysis';
import {session,json,failure} from '@/lib/hosted';
import {getDatabase} from '@/db';
export async function GET(req:Request){try{
 const {cookie}=await session(req,true);
 await getDatabase().prepare('SELECT id FROM investigations LIMIT 1').first();
 return json({mode:'public',role:'personal reviewer',model,database:'Saved online · 30 days',queue:'Bounded parallel lookups',providers:{DNS:true,RDAP:true},features:['scan','saved history','personal reviews','feedback flags','export','delete'],retention_days:30,history_limit:200},200,cookie?{'Set-Cookie':cookie}:{});
}catch(e){return failure(e);}}
