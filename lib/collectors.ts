import {normalize,Observation} from '@/lib/analysis';
export async function collect(url:string):Promise<Observation[]>{
 const n=normalize(url);
 if(n.is_private||n.is_ip||!n.hostname.includes('.')||/\.(example|invalid|test)$/.test(n.hostname))return [{provider:'Network inspection',status:'blocked',detail:'Nonpublic and literal-address destinations are not inspected.'}];
 async function dns():Promise<Observation>{
  const results=await Promise.all(['A','AAAA','MX','NS','CNAME','TXT'].map(async type=>{
   const response=await fetch('https://dns.google/resolve?name='+encodeURIComponent(n.hostname)+'&type='+type,{signal:AbortSignal.timeout(6000),redirect:'error'});
   if(!response.ok)throw Error('Resolver unavailable');const d=await response.json() as {Status:number;Answer?:{data:string;TTL:number}[]};if(![0,3].includes(d.Status))throw Error('Resolver could not answer');return [type,{status:d.Status===3?'domain not found':'answered',values:(d.Answer||[]).slice(0,20).map(x=>x.data),ttl:d.Answer?.[0]?.TTL}];
  }));
  return {provider:'DNS',status:'ok',detail:'Google public DNS observations; DNSSEC validation is not performed here.',records:Object.fromEntries(results),observed_at:new Date().toISOString()};
 }
 async function rdap():Promise<Observation>{
  const tld=n.domain.split('.').pop();const base=tld==='com'?'https://rdap.verisign.com/com/v1/domain/':tld==='net'?'https://rdap.verisign.com/net/v1/domain/':null;
  if(!base)return {provider:'RDAP',status:'unsupported registry',detail:'This registry is not enabled in the initial allowlist.'};
  const response=await fetch(base+encodeURIComponent(n.domain),{redirect:'error',signal:AbortSignal.timeout(6000)});if(!response.ok)throw Error('Registry returned HTTP '+response.status);
  const d=await response.json() as {events?:{eventAction:string;eventDate:string}[];nameservers?:{ldhName:string}[]};const created=d.events?.find(x=>x.eventAction==='registration')?.eventDate;
  return {provider:'RDAP',status:'ok',detail:'Registry metadata; domain age alone is not a phishing verdict.',created_at:created,age_days:created?Math.max(0,Math.floor((Date.now()-Date.parse(created))/86400000)):null,nameservers:d.nameservers?.map(x=>x.ldhName),observed_at:new Date().toISOString()};
 }
 const tasks=await Promise.allSettled([dns(),rdap()]);return tasks.map((x,i)=>x.status==='fulfilled'?x.value:{provider:i?'RDAP':'DNS',status:'unavailable',detail:'The provider did not return a usable response.'});
}
